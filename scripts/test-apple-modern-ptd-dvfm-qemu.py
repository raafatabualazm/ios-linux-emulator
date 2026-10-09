#!/usr/bin/env python3
"""Actual-CPU whole-machine gate for the opt-in PMP PTD board and CPU DVFM windows.

An owned AArch64 ROM runs at EL2 on the real CPU model and performs every access
as a load/store instruction (including a real 16-byte LDP on the Dashboard).
Apple firmware components are preparation inputs only; only the owned ROM
executes. A fault handler logs ELR/ESR/FAR for every data abort and resumes, so
each access has an exact outcome: a value, or a precise fault at its own PC with
its own ESR. Expectations come from an independent reference model written in
this file (not from the C core), so the C core, the QEMU memory-region wrapper,
the address plan and the CPU exception path are all exercised together.

Configurations (board options, all default off):
  none    no options                  -> every access faults (exact no-device oracle)
  ptd     modern-pmp-ptd=on           -> PTD ops succeed, DVFM ops fault
  dvfm    modern-cpu-dvfm=on          -> DVFM ops succeed, PTD ops fault
  both    both options on

Modes:
  normal    run all four configurations, twice each across system_reset, with
            exact QOM counters, read-only counter rejection, creation-only
            options, migration refusal naming the device, and host (HMP xp)
            corroboration of device state plus reset-to-zero. Exit 0 = all pass.
  mutation  run ONE configuration (--actual) against the expectations of another
            (--expect). Exit 0 only if the gate rejects the run, and the set of
            rejected accesses is EXACTLY the set predicted from the two
            expectation tables. Used against a binary that lacks a device (an
            older pin) or against the options being off.
  perturb   run the full board (both options) against expectations in which the
            first and last access of every case has been deliberately damaged.
            Exit 0 only if the live run rejects exactly those accesses, so every
            case is shown to be judged against the real CPU/device result.
  refusal   require that the binary refuses the options of --actual at startup.

Declared (not attested) behaviour is labelled in the header comments of
modern-pmp-ptd.h and modern-cpu-dvfm.h; this gate only qualifies the model as
implemented. It makes no claim about silicon, PMP firmware or calibration.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    'ptd_dvfm_transport_helpers',
    Path(__file__).with_name('test-apple-modern-sep-transport-qemu.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
mailbox, board = transport.mailbox, transport.board
require, digest = mailbox.require, mailbox.digest

# ---------------------------------------------------------------- geometry
PTD_DASH = 0x3003c0000          # /arm-io/mcc reg[6] (Dashboard), translated
PTD_UPDATE = 0x3003d0000        # /arm-io/mcc reg[7] (Update port), translated
PTD_SPAN = 0x4000
PTD_ENTRIES = PTD_SPAN // 16    # 1024 Dashboard entries of {msg, meta}
DVFM = (0x210e78000, 0x211e78000)   # E and P cluster DVFM state tables
DVFM_SPAN = 0x1000
DVFM_FRONTIER = (0x210e700a8, 0x211e700a8)   # E_ACC_CPM_DVFM selector-12 read, unmodelled
STATES = tuple(range(32)) + (63,)    # reader offset = 0x8 + state * 0x40
MASK64 = (1 << 64) - 1

SENTINEL = 0xbadc0ffee0ddf00d
DONE = 0xd0d0cafef00d5678
RESULT_SLOTS = 1024             # result slots at scratch + 0 .. 0x2000
CONTROL = 0x4000                # fault count, bad-vector count, bad ESR, bad ELR
FAULT_LOG = 0x4100              # 32-byte entries {ELR, ESR, FAR, 0}
FAULT_CAP = 1024
DUMP_SIZE = FAULT_LOG + FAULT_CAP * 32
VECTORS = 0xc000                # VBAR offset inside the owned ROM
BAD = 0xc800
MIN_AVAILABLE_KB = 7000000

CONFIGS = {
    'none': (frozenset(), ''),
    'ptd': (frozenset({'ptd'}), ',modern-pmp-ptd=on'),
    'dvfm': (frozenset({'dvfm'}), ',modern-cpu-dvfm=on'),
    'both': (frozenset({'ptd', 'dvfm'}), ',modern-pmp-ptd=on,modern-cpu-dvfm=on'),
}
DEVICES = {'ptd': ('pmp-ptd', 'apple-modern-pmp-ptd', 'modern-pmp-ptd'),
           'dvfm': ('cpu-dvfm', 'apple-modern-cpu-dvfm', 'modern-cpu-dvfm')}
COUNTERS = ('mmio-read-count', 'mmio-write-count')


def abort_esr(write, access_error):
    """Same-EL data abort, IL=1, DFSC=0x10 (synchronous external abort).

    A region that is unmapped, or whose MemoryRegionOps.valid rejects the access
    size, returns MEMTX_DECODE_ERROR (EA clear). A handler that returns
    MEMTX_ACCESS_ERROR sets EA (bit 9). WnR is bit 6.
    """
    return 0x96000010 | (int(write) << 6) | (int(access_error) << 9)


# ------------------------------------------------------- reference model
class Model:
    """Independent specification of the implemented behaviour (see headers)."""

    def __init__(self):
        self.msg, self.hidden = {}, {}
        self.dvfm = ({}, {})
        self.reads = {'ptd': 0, 'dvfm': 0}
        self.writes = {'ptd': 0, 'dvfm': 0}

    @staticmethod
    def route(address):
        if PTD_DASH <= address < PTD_DASH + PTD_SPAN:
            return 'ptd', 'dash', address - PTD_DASH
        if PTD_UPDATE <= address < PTD_UPDATE + PTD_SPAN:
            return 'ptd', 'update', address - PTD_UPDATE
        for window, base in enumerate(DVFM):
            if base <= address < base + DVFM_SPAN:
                return 'dvfm', window, address - base
        return None

    def load(self, address, width):
        target = self.route(address)
        if target is None:
            return 'fault', abort_esr(False, False)
        device, view, offset = target
        if device == 'ptd':
            if width != 8:
                return 'fault', abort_esr(False, False)       # valid.min_access_size = 8
            if view == 'update':
                return 'fault', abort_esr(False, True)        # write-only port
            self.reads['ptd'] += 1
            return 'ok', 0 if offset & 8 else self.msg.get(offset // 16, 0)
        if width not in (4, 8):
            return 'fault', abort_esr(False, False)           # valid.min_access_size = 4
        self.reads['dvfm'] += 1
        word = self.dvfm[view].get(offset // 8, 0)
        if width == 8:
            return 'ok', word
        return 'ok', (word >> 32) if offset & 4 else word & 0xffffffff

    def store(self, address, width, value):
        target = self.route(address)
        if target is None:
            return 'fault', abort_esr(True, False)
        device, view, offset = target
        if device == 'ptd':
            if width != 8:
                return 'fault', abort_esr(True, False)
            if view == 'dash':
                return 'fault', abort_esr(True, True)         # read-only Dashboard
            slot = offset // 8
            if slot < PTD_ENTRIES:
                self.msg[slot] = value & MASK64
            else:
                self.hidden[slot] = value & MASK64
            self.writes['ptd'] += 1
            return 'ok', None
        if width not in (4, 8):
            return 'fault', abort_esr(True, False)
        words = self.dvfm[view]
        word = words.get(offset // 8, 0)
        if width == 8:
            word = value & MASK64
        elif offset & 4:
            word = (word & 0xffffffff) | (value & 0xffffffff) << 32
        else:
            word = (word & ~0xffffffff & MASK64) | (value & 0xffffffff)
        words[offset // 8] = word
        self.writes['dvfm'] += 1
        return 'ok', None


class Op:
    def __init__(self, **fields):
        self.__dict__.update(fields)

    def absent(self):
        return 'fault', abort_esr(self.kind == 'st', False)

    def expected(self, enabled):
        return self.outcome if self.group in enabled else self.absent()


# ----------------------------------------------------------- ROM builder
def sysreg(name, register, read):
    op0, op1, crn, crm, op2 = {'ELR_EL2': (3, 4, 4, 0, 1), 'ESR_EL2': (3, 4, 5, 2, 0),
                               'FAR_EL2': (3, 4, 6, 0, 0)}[name]
    return (0xd5000000 | (int(read) << 21) | (op0 << 19) | (op1 << 16) | (crn << 12)
            | (crm << 8) | (op2 << 5) | register)


LD = {8: 0xf9400000, 4: 0xb9400000, 2: 0x79400000, 1: 0x39400000}
ST = {8: 0xf9000000, 4: 0xb9000000, 2: 0x79000000, 1: 0x39000000}


def ldr64(rt, rn, offset):
    return LD[8] | (offset // 8) << 10 | rn << 5 | rt


def str64(rt, rn, offset):
    return ST[8] | (offset // 8) << 10 | rn << 5 | rt


class GateROM(mailbox.ROM):
    def __init__(self):
        super().__init__()
        self.ops, self.model = [], Model()
        self.slots = 0
        self.group = self.case = None
        self.labels = set()

    def mov(self, register, value):
        halves = [(value >> (16 * h)) & 0xffff for h in range(4)]
        first = next((h for h in range(4) if halves[h]), 0)
        self.emit(0xd2800000 | first << 21 | halves[first] << 5 | register)
        for h in range(first + 1, 4):
            if halves[h]:
                self.emit(0xf2800000 | h << 21 | halves[h] << 5 | register)

    def section(self, group, case):
        self.group, self.case = group, case

    def pc(self):
        return mailbox.BASE + 4 * len(self.words)

    def slot(self):
        require(self.slots < RESULT_SLOTS - 1, 'Result slots stay inside their range')
        self.slots += 1
        return self.slots - 1

    def base_for(self, address, width):
        """Window base register plus an offset the unsigned-immediate form can encode."""
        for register, base, span in ((2, PTD_DASH, PTD_SPAN), (3, PTD_UPDATE, PTD_SPAN),
                                     (4, DVFM[0], DVFM_SPAN), (5, DVFM[1], DVFM_SPAN)):
            if base <= address < base + span and (address - base) // width < 4096:
                return register, address - base
        self.mov(1, address)
        return 1, 0

    def add_op(self, label, kind, width, address, value, outcome, pc, slots):
        require(label not in self.labels, 'Unique case label: ' + label)
        self.labels.add(label)
        self.ops.append(Op(label=label, case=self.case, group=self.group, kind=kind,
                           width=width, address=address, value=value, outcome=outcome,
                           pc=pc, slots=slots))

    def ld(self, label, address, width=8):
        outcome = self.model.load(address, width)
        register, offset = self.base_for(address, width)
        slot = self.slot()
        self.emit(0xaa0003e0 | 26 << 16 | 23)               # mov x23,x26 (sentinel)
        pc = self.pc()
        self.emit(LD[width] | (offset // width) << 10 | register << 5 | 23)
        self.store(23, slot * 8)
        self.add_op(label, 'ld', width, address, None, outcome, pc, (slot,))

    def ldp(self, label, address):
        first = self.model.load(address, 8)
        outcome = first
        if first[0] == 'ok':
            second = self.model.load(address + 8, 8)
            require(second[0] == 'ok', 'Both halves of a Dashboard entry load')
            outcome = ('ok', (first[1], second[1]))
        self.mov(1, address)
        slots = (self.slot(), self.slot())
        self.emit(0xaa0003e0 | 26 << 16 | 23)
        self.emit(0xaa0003e0 | 26 << 16 | 24)
        pc = self.pc()
        self.emit(0xa9400000 | 24 << 10 | 1 << 5 | 23)      # ldp x23,x24,[x1]
        self.store(23, slots[0] * 8)
        self.store(24, slots[1] * 8)
        self.add_op(label, 'ldp', 16, address, None, outcome, pc, slots)

    def st(self, label, address, width, value):
        outcome = self.model.store(address, width, value)
        self.mov(0, value)
        register, offset = self.base_for(address, width)
        pc = self.pc()
        self.emit(ST[width] | (offset // width) << 10 | register << 5 | 0)
        self.add_op(label, 'st', width, address, value, outcome, pc, ())

    # ---------------------------------------------------------------- cases
    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)                               # mov sp,x0
        self.emit(0xd5034fdf)                               # mask all interrupts
        self.set('VBAR_EL2', mailbox.BASE + VECTORS)
        for register, address in ((2, PTD_DASH), (3, PTD_UPDATE), (4, DVFM[0]), (5, DVFM[1])):
            self.mov(register, address)
        self.mov(26, SENTINEL)
        self.build_ptd()
        self.build_dvfm()
        require(len(self.ops) <= FAULT_CAP - 8, 'Every access can fault without overflowing the log')
        self.done_slot = self.slot()
        self.mov(0, DONE)
        self.store(0, self.done_slot * 8)
        self.branch(len(self.words))
        require(len(self.words) * 4 < VECTORS, 'Owned code stays below the vector table')
        self.vector_table()
        require(len(self.words) * 4 <= 0x10000, 'Owned ROM fits before the scratch range')
        return b''.join(struct.pack('<I', word) for word in self.words)

    def vector_table(self):
        bad_index = BAD // 4
        for offset in range(VECTORS, VECTORS + 0x800, 0x80):
            self.at(offset)
            if offset != VECTORS + 0x200:                   # only current-EL SPx sync is expected
                self.branch(bad_index)
                continue
            self.emit(sysreg('ELR_EL2', 9, True))
            self.emit(sysreg('ESR_EL2', 10, True))
            self.emit(sysreg('FAR_EL2', 11, True))
            self.emit(0xd3400000 | 26 << 16 | 63 << 10 | 10 << 5 | 14)    # lsr x14,x10,#26
            self.emit(0xf100001f | 0x25 << 10 | 14 << 5)                  # cmp x14,#0x25
            self.branch(bad_index, 1)                                      # b.ne bad: not a data abort
            self.emit(ldr64(12, 20, CONTROL))
            self.emit(0xf100001f | FAULT_CAP << 10 | 12 << 5)             # cmp x12,#cap
            self.branch(bad_index, 2)                                      # b.hs bad: log full
            self.emit(0xd3400000 | 59 << 16 | 58 << 10 | 12 << 5 | 13)   # lsl x13,x12,#5
            self.emit(0x8b000000 | 20 << 16 | 13 << 5 | 13)               # add x13,x13,x20
            self.emit(str64(9, 13, FAULT_LOG))
            self.emit(str64(10, 13, FAULT_LOG + 8))
            self.emit(str64(11, 13, FAULT_LOG + 16))
            self.emit(0x91000000 | 1 << 10 | 12 << 5 | 12)                # add x12,x12,#1
            self.emit(str64(12, 20, CONTROL))
            self.emit(0x91000000 | 4 << 10 | 9 << 5 | 9)                  # add x9,x9,#4: skip the access
            self.emit(sysreg('ELR_EL2', 9, False))
            self.emit(0xd69f03e0)                                          # eret
        self.at(BAD)
        self.emit(sysreg('ELR_EL2', 9, True))
        self.emit(sysreg('ESR_EL2', 10, True))
        self.emit(str64(9, 20, CONTROL + 0x18))
        self.emit(str64(10, 20, CONTROL + 0x10))
        self.emit(ldr64(12, 20, CONTROL + 8))
        self.emit(0x91000000 | 1 << 10 | 12 << 5 | 12)
        self.emit(str64(12, 20, CONTROL + 8))
        self.branch(len(self.words))                                       # b . (stop)

    def build_ptd(self):
        def value(index, variant=0):
            return 0x5054 << 48 | index << 16 | (0x4d51, 0xbeef, 0x7a7a)[variant]

        dash = lambda entry, half=0: PTD_DASH + entry * 16 + half * 8
        update = lambda slot: PTD_UPDATE + slot * 8
        self.section('ptd', 'ptd.reset-read')
        for entry in (0, 212, 423, 424, 432, 433, 434, 511, 512, 1023):
            self.ld(f'ptd_reset_msg_{entry}', dash(entry), 8)
            self.ld(f'ptd_reset_meta_{entry}', dash(entry, 1), 8)
        self.ldp('ptd_reset_ldp_424', dash(424))
        self.ldp('ptd_reset_ldp_0', dash(0))
        self.section('ptd', 'ptd.update-store-mirror')
        for index in range(433, 423, -1):           # driver order: 433 then 432
            self.st(f'ptd_update_store_{index}', update(index), 8, value(index))
        for index in range(424, 434):
            self.ld(f'ptd_mirror_msg_{index}', dash(index), 8)
            self.ld(f'ptd_mirror_meta_{index}', dash(index, 1), 8)
        self.ldp('ptd_mirror_ldp_433', dash(433))
        self.ldp('ptd_mirror_ldp_432', dash(432))
        self.section('ptd', 'ptd.neighbour-isolation')
        for entry in (423, 434):
            self.ld(f'ptd_neighbour_msg_{entry}', dash(entry), 8)
        # A same-offset mirror (Update offset == Dashboard offset) would land here.
        for offset in (424 * 8, 433 * 8):
            self.ld(f'ptd_not_same_offset_{offset:#x}', PTD_DASH + offset, 8)
        self.section('ptd', 'ptd.rewrite')
        self.st('ptd_rewrite_432', update(432), 8, value(432, 1))
        self.ld('ptd_rewrite_msg_432', dash(432), 8)
        self.ld('ptd_rewrite_meta_432', dash(432, 1), 8)
        self.ld('ptd_rewrite_msg_433_kept', dash(433), 8)
        self.section('ptd', 'ptd.boundary-slots')
        self.st('ptd_slot_0', update(0), 8, value(0, 2))
        self.st('ptd_slot_1023', update(1023), 8, value(1023, 2))
        self.st('ptd_slot_1024_hidden', update(1024), 8, value(1024, 2))
        self.st('ptd_slot_2047_hidden', update(2047), 8, value(2047, 2))
        for name, address in (('msg_0', dash(0)), ('meta_0', dash(0, 1)),
                              ('msg_1023', dash(1023)), ('meta_1023', dash(1023, 1)),
                              ('msg_512_no_wrap', dash(512)), ('msg_1_no_wrap', dash(1))):
            self.ld('ptd_boundary_' + name, address, 8)
        self.section('ptd', 'ptd.update-view-read-fault')
        self.ld('ptd_update_read_424', update(424), 8)
        self.ld('ptd_update_read_0', update(0), 8)
        self.ld('ptd_update_read_2047', update(2047), 8)
        self.section('ptd', 'ptd.dashboard-write-fault')
        self.st('ptd_dashboard_write_424', dash(424), 8, 0x1122334455667788)
        self.st('ptd_dashboard_write_meta_424', dash(424, 1), 8, 0x1122334455667788)
        self.ld('ptd_dashboard_write_ignored_424', dash(424), 8)
        self.ld('ptd_dashboard_write_ignored_meta_424', dash(424, 1), 8)
        self.section('ptd', 'ptd.width-fault')
        self.ld('ptd_dashboard_load32_0', PTD_DASH, 4)
        self.ld('ptd_dashboard_load32_hi_424', dash(424) + 4, 4)
        self.ld('ptd_dashboard_load8_424', dash(424), 1)
        self.ld('ptd_dashboard_load16_424', dash(424), 2)
        self.st('ptd_update_store32_424', update(424), 4, 0xdeadbeef)
        self.st('ptd_update_store32_hi_424', update(424) + 4, 4, 0xfeedface)
        self.st('ptd_update_store8_424', update(424), 1, 0xaa)
        self.st('ptd_update_store16_424', update(424), 2, 0xaaaa)
        self.ld('ptd_width_fault_left_msg_424_intact', dash(424), 8)
        self.ld('ptd_width_fault_left_msg_0_intact', dash(0), 8)
        self.section('ptd', 'ptd.out-of-window-fault')
        self.ld('ptd_below_dashboard', PTD_DASH - 8, 8)
        self.ld('ptd_above_dashboard', PTD_DASH + PTD_SPAN, 8)
        self.ld('ptd_gap_before_update_load', PTD_UPDATE - 8, 8)
        self.st('ptd_gap_before_update_store', PTD_UPDATE - 8, 8, 0x1)
        self.st('ptd_above_update_store', PTD_UPDATE + PTD_SPAN, 8, 0x1)
        self.ld('ptd_above_update_load', PTD_UPDATE + PTD_SPAN, 8)
        self.ld('ptd_after_faults_msg_433_intact', dash(433), 8)

    def build_dvfm(self):
        def tag(window, state, variant=0):
            field = (state * 5 + 1 + variant) & 0x1f          # driver field: bits [42:38]
            return ((0xe0 + window) << 56 | field << 38 | (state + 1) << 8 | 0x5a)

        word = lambda window, state, extra=0: DVFM[window] + 8 + state * 0x40 + extra
        self.section('dvfm', 'dvfm.reset-zero')
        for window, base in enumerate(DVFM):
            tagname = 'ep'[window]
            for offset in (0x0, 0x8, 0x800, 0xff8):
                self.ld(f'dvfm_{tagname}_reset64_{offset:#x}', base + offset, 8)
            for offset in (0x0, 0x4, 0x800, 0xffc):
                self.ld(f'dvfm_{tagname}_reset32_{offset:#x}', base + offset, 4)
            for state in STATES:
                self.ld(f'dvfm_{tagname}_reset_state{state}', word(window, state), 8)
        self.section('dvfm', 'dvfm.window-independence')
        for state in STATES:
            self.st(f'dvfm_e_store_state{state}', word(0, state), 8, tag(0, state))
        for state in STATES:
            self.ld(f'dvfm_p_untouched_state{state}', word(1, state), 8)
        for state in STATES:
            self.st(f'dvfm_p_store_state{state}', word(1, state), 8, tag(1, state))
        self.section('dvfm', 'dvfm.state-pattern-roundtrip')
        for window in (0, 1):
            tagname = 'ep'[window]
            for state in STATES:
                self.ld(f'dvfm_{tagname}_readback_state{state}', word(window, state), 8)
        self.section('dvfm', 'dvfm.neighbour-isolation')
        for window in (0, 1):
            tagname = 'ep'[window]
            for state in STATES:
                self.ld(f'dvfm_{tagname}_before_state{state}', word(window, state, -8), 8)
                self.ld(f'dvfm_{tagname}_after_state{state}', word(window, state, 8), 8)
        self.section('dvfm', 'dvfm.width-mixing')
        for window, base in enumerate(DVFM):
            tagname = 'ep'[window]
            self.ld(f'dvfm_{tagname}_low32_state5', word(window, 5), 4)
            self.ld(f'dvfm_{tagname}_high32_state5', word(window, 5, 4), 4)
            self.st(f'dvfm_{tagname}_store32_lo', base + 0x800, 4, 0x11223344)
            self.st(f'dvfm_{tagname}_store32_hi', base + 0x804, 4, 0x55667788)
            self.ld(f'dvfm_{tagname}_join64', base + 0x800, 8)
            self.ld(f'dvfm_{tagname}_load32_lo', base + 0x800, 4)
            self.ld(f'dvfm_{tagname}_load32_hi', base + 0x804, 4)
            self.st(f'dvfm_{tagname}_store64', base + 0x808, 8, 0xaabbccddeeff0011)
            self.ld(f'dvfm_{tagname}_split32_lo', base + 0x808, 4)
            self.ld(f'dvfm_{tagname}_split32_hi', base + 0x80c, 4)
            self.st(f'dvfm_{tagname}_overwrite32_hi', base + 0x80c, 4, 0x99887766)
            self.ld(f'dvfm_{tagname}_merge_hi', base + 0x808, 8)
            self.st(f'dvfm_{tagname}_overwrite32_lo', base + 0x808, 4, 0x01020304)
            self.ld(f'dvfm_{tagname}_merge_lo', base + 0x808, 8)
            self.st(f'dvfm_{tagname}_all_ones', base + 0xff8, 8, MASK64)
            self.ld(f'dvfm_{tagname}_all_ones_64', base + 0xff8, 8)
            self.ld(f'dvfm_{tagname}_all_ones_32', base + 0xffc, 4)
        self.section('dvfm', 'dvfm.subword-fault')
        for window, base in enumerate(DVFM):
            tagname = 'ep'[window]
            self.ld(f'dvfm_{tagname}_load8', base + 0x808, 1)
            self.ld(f'dvfm_{tagname}_load16', base + 0x808, 2)
            self.st(f'dvfm_{tagname}_store8', base + 0x808, 1, 0x77)
            self.st(f'dvfm_{tagname}_store16', base + 0x808, 2, 0x7777)
            self.ld(f'dvfm_{tagname}_subword_left_intact', base + 0x808, 8)
        self.section('dvfm', 'dvfm.out-of-window-fault')
        for window, base in enumerate(DVFM):
            tagname = 'ep'[window]
            self.ld(f'dvfm_{tagname}_below_load64', base - 8, 8)
            self.ld(f'dvfm_{tagname}_below_load32', base - 4, 4)
            self.st(f'dvfm_{tagname}_below_store64', base - 8, 8, 0x1)
            self.ld(f'dvfm_{tagname}_above_load64', base + DVFM_SPAN, 8)
            self.st(f'dvfm_{tagname}_above_store32', base + DVFM_SPAN, 4, 0x1)
            self.ld(f'dvfm_{tagname}_frontier_selector12', DVFM_FRONTIER[window], 8)
            self.ld(f'dvfm_{tagname}_edge_intact', base + 0xff8, 8)


# ---------------------------------------------------- result evaluation
def parse_dump(raw):
    require(len(raw) >= DUMP_SIZE, 'Complete result dump')
    slots = list(struct.unpack_from(f'<{RESULT_SLOTS}Q', raw, 0))
    count, bad, bad_esr, bad_elr = struct.unpack_from('<4Q', raw, CONTROL)
    require(count <= FAULT_CAP, 'Fault log count within capacity')
    faults = [struct.unpack_from('<3Q', raw, FAULT_LOG + 32 * i) for i in range(count)]
    return slots, faults, {'fault_count': count, 'bad_vector_count': bad,
                           'bad_esr': bad_esr, 'bad_elr': bad_elr}


def evaluate(rom, enabled, raw):
    """Return (mismatches, observed) for one dump against one expectation table."""
    slots, faults, control = parse_dump(raw)
    by_pc, mismatches, observed = {}, [], {}
    for elr, esr, far in faults:
        if elr in by_pc:
            mismatches.append({'label': f'duplicate fault at {elr:#x}', 'what': 'duplicate'})
        by_pc[elr] = (esr, far)
    known = {op.pc for op in rom.ops}
    for elr in by_pc:
        if elr not in known:
            mismatches.append({'label': f'unexpected fault at {elr:#x}', 'what': 'unexpected-fault',
                               'observed': hex(by_pc[elr][0])})
    if control['bad_vector_count']:
        mismatches.append({'label': 'bad vector', 'what': 'bad-vector',
                           'observed': [hex(control['bad_esr']), hex(control['bad_elr'])]})
    if control['fault_count'] != len(faults):
        mismatches.append({'label': 'fault count', 'what': 'count'})
    for op in rom.ops:
        want = op.expected(enabled)
        got_fault = by_pc.get(op.pc)
        values = tuple(slots[s] for s in op.slots)
        if got_fault:
            observed[op.label] = f'fault esr={got_fault[0]:#x} far={got_fault[1]:#x}'
        elif op.kind == 'st':
            observed[op.label] = 'stored'
        else:
            observed[op.label] = ' '.join(f'{v:#x}' for v in values)
        problem = None
        if want[0] == 'fault':
            if got_fault is None:
                problem = 'expected fault, none taken'
            elif got_fault != (want[1], op.address):
                problem = 'fault ESR/FAR differ'
            elif any(v != SENTINEL for v in values):
                problem = 'faulting load delivered data'
        else:
            if got_fault is not None:
                problem = 'unexpected fault'
            elif op.kind == 'ld' and values != (want[1],):
                problem = 'value differs'
            elif op.kind == 'ldp' and values != tuple(want[1]):
                problem = 'pair differs'
        if problem:
            expected_text = (f'fault esr={want[1]:#x} far={op.address:#x}' if want[0] == 'fault'
                             else 'stored' if op.kind == 'st' else
                             ' '.join(f'{v:#x}' for v in (want[1] if op.kind == 'ldp' else (want[1],))))
            mismatches.append({'label': op.label, 'case': op.case, 'group': op.group,
                               'what': problem, 'expected': expected_text,
                               'observed': observed[op.label], 'pc': hex(op.pc),
                               'address': hex(op.address)})
    return mismatches, observed


def synthesize(rom, enabled, perturb=None):
    """Perfect dump for an expectation table; `perturb` damages one op."""
    raw = bytearray(DUMP_SIZE)
    slots = [0] * RESULT_SLOTS
    faults = []
    for op in rom.ops:
        want = op.expected(enabled)
        if want[0] == 'fault':
            faults.append((op.pc, want[1], op.address))
            for s in op.slots:
                slots[s] = SENTINEL
        elif op.kind == 'ld':
            slots[op.slots[0]] = want[1]
        elif op.kind == 'ldp':
            slots[op.slots[0]], slots[op.slots[1]] = want[1]
    if perturb is not None:
        op = next(o for o in rom.ops if o.label == perturb)
        want = op.expected(enabled)
        if want[0] == 'fault':
            faults = [(pc, esr ^ 0x200 if pc == op.pc else esr, far) for pc, esr, far in faults]
        elif op.kind == 'st':
            faults.append((op.pc, abort_esr(True, False), op.address))
        else:
            slots[op.slots[0]] ^= 1
    struct.pack_into(f'<{RESULT_SLOTS}Q', raw, 0, *slots)
    struct.pack_into('<4Q', raw, CONTROL, len(faults), 0, 0, 0)
    for i, entry in enumerate(faults):
        struct.pack_into('<3Q', raw, FAULT_LOG + 32 * i, *entry)
    return bytes(raw)


def selftest(rom):
    """Exhaustive single-expectation perturbation of the evaluator, no guest."""
    detected = 0
    for name, (enabled, _) in CONFIGS.items():
        clean, _ = evaluate(rom, enabled, synthesize(rom, enabled))
        require(not clean, f'Evaluator accepts a perfect {name} dump: {clean[:2]}')
        for op in rom.ops:
            found, _ = evaluate(rom, enabled, synthesize(rom, enabled, op.label))
            require([m['label'] for m in found] == [op.label],
                    f'Evaluator flags exactly {op.label} in {name}: {found[:3]}')
            detected += 1
    return {'perturbations': detected, 'all_detected_exactly_once': True}


# -------------------------------------------------------------- QMP bits
class QMP(transport.QMP):
    def request_error(self, command, arguments):
        """Send a request that must fail and return the error object."""
        self.guard()
        self.sequence += 1
        request = {'execute': command, 'id': self.sequence, 'arguments': arguments}
        deadline = time.monotonic() + 3
        self.send(json.dumps(request).encode() + b'\n', deadline)
        while time.monotonic() < deadline:
            response = self.receive(deadline)
            if 'event' in response:
                self.events.append(response['event'])
                require(len(self.events) <= 64, 'QMP event bound')
                continue
            require(response.get('id') == self.sequence, 'QMP response ID')
            require('error' in response and 'return' not in response,
                    f'{command} must fail')
            return response['error']
        raise RuntimeError('QMP error-request deadline')

    def require_immutable(self, name):
        before = self.request('qom-get', {'path': '/machine', 'property': name})
        error = self.request_error('qom-set', {'path': '/machine', 'property': name,
                                               'value': not before})
        require(error.get('class') == 'GenericError' and error.get('desc') ==
                'apple-modern properties are fixed after initialization',
                'Mutation rejection must identify initialized board properties')
        after = self.request('qom-get', {'path': '/machine', 'property': name})
        require(after == before, 'Rejected board mutation leaves value unchanged')
        return {'before': before, 'attempted': not before, 'after': after, 'error': error}

    def require_migration_blocked(self, target, typenames):
        error = self.request_error('migrate', {'uri': 'file:' + str(target)})
        require('non-migratable' in error.get('desc', '') and
                any(name in error.get('desc', '') for name in typenames),
                'Migration rejection must name one of ' + str(typenames) + ': ' + str(error))
        require(not target.exists(), 'No partial migration file was created')
        return error


def hmp_xp64(qmp, address):
    out = qmp.request('human-monitor-command', {'command-line': f'xp /1gx {address:#x}'})
    match = re.search(r':\s+0x([0-9a-f]{16})\b', out)
    require(match is not None, f'xp output at {address:#x}: {out!r}')
    return int(match.group(1), 16)


# ------------------------------------------------------------ guest runs
def machine_argument(assets, config):
    return 'apple-modern,' + ','.join(
        name + '=' + str(assets[asset]) for name, asset in
        zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS)
    ) + ',prepare-only=true' + CONFIGS[config][1]


def launch(binary, assets, rom_path, zero_path, config, log_path):
    argv = [str(binary), '-M', machine_argument(assets, config), '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    with log_path.open('xb') as log:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=log, bufsize=0, preexec_fn=mailbox.child_limits)
    return argv, process


def run_guest(binary, assets, rom, content, output, label, actual, expect, check_extras):
    """One guest, two passes across system_reset. Returns a result dict."""
    enabled_actual, enabled_expect = CONFIGS[actual][0], CONFIGS[expect][0]
    rom_path, zero_path = output / f'{label}.rom', output / 'zero-scratch.bin'
    rom_path.write_bytes(content)
    if not zero_path.exists():
        zero_path.write_bytes(bytes(0x10000))
    log_path = output / f'emulator-{label}.log'
    started = time.monotonic()
    result = {'label': label, 'actual': actual, 'expect': expect, 'passes': [],
              'mismatches': [], 'extras': {}}
    argv, process = launch(binary, assets, rom_path, zero_path, actual, log_path)
    result['argv'] = argv
    qmp = None

    def guard():
        remaining = mailbox.MAX_WALL - (time.monotonic() - started)
        require(remaining > 0 and log_path.stat().st_size <= mailbox.MAX_LOG,
                'PTD/DVFM gate wall/log bound exceeded')
        return remaining

    try:
        try:
            qmp = QMP(None, guard, process)
        except Exception as error:
            tail = log_path.read_text(errors='replace')[-600:]
            raise RuntimeError(f'startup refused or failed ({error}): {tail.strip()}')
        with tempfile.TemporaryDirectory(prefix='ptd-dvfm-gate-') as temp:
            scratch = Path(temp)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}) is True,
                    'Only the owned ROM may execute')
            types = {t['name'] for t in qmp.request('qom-list-types',
                                                    {'implements': 'sys-bus-device',
                                                     'abstract': False})}
            props = {p['name'] for p in qmp.request('qom-list', {'path': '/machine'})}
            result['device_types_registered'] = {
                group: DEVICES[group][1] in types for group in DEVICES}
            result['board_option_present'] = {
                group: DEVICES[group][2] in props for group in DEVICES}
            result['children_present'] = {group: DEVICES[group][0] in props for group in DEVICES}
            for group, (child, typename, option) in DEVICES.items():
                on = group in enabled_actual
                require(result['children_present'][group] == on,
                        f'{child} exists exactly when {option} is on')
                if option in props:
                    require(qmp.request('qom-get', {'path': '/machine', 'property': option}) == on,
                            f'{option} reads back {on}')
                    result['extras'].setdefault('immutable', {})[option] = qmp.require_immutable(option)
                if not on:
                    result['extras'].setdefault('absent_object_errors', {})[child] = qmp.request_error(
                        'qom-get', {'path': '/machine/' + child, 'property': COUNTERS[0]})
            for iteration in range(2):
                if iteration:
                    qmp.request('system_reset')
                registers = board.parse_registers(qmp.request(
                    'human-monitor-command', {'command-line': 'info registers'}))
                require(registers['PC'] == mailbox.BASE and registers['PSTATE'] & 15 == 9,
                        'Owned ROM PC and EL2h selected before cont')
                require(qmp.request('query-status')['running'] is False, 'CPU stopped before cont')
                for group in sorted(enabled_actual):
                    require(transport.values(qmp, '/machine/' + DEVICES[group][0], COUNTERS) ==
                            dict.fromkeys(COUNTERS, 0), f'{group} counters zero after reset')
                verify = scratch / 'verify.bin'
                for address, expected in ((mailbox.BASE, content),
                                          (mailbox.SCRATCH, bytes(0x10000))):
                    qmp.request('pmemsave', {'val': address, 'size': len(expected),
                                             'filename': str(verify)})
                    require(verify.read_bytes() == expected,
                            'Exact owned ROM and zero scratch verified before cont')
                qmp.request('cont')
                deadline = time.monotonic() + 15
                dump = scratch / 'dump.bin'
                while True:
                    guard()
                    qmp.request('stop')
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH + rom.done_slot * 8,
                                             'size': 8, 'filename': str(dump)})
                    if struct.unpack('<Q', dump.read_bytes())[0] == DONE:
                        break
                    require(time.monotonic() < deadline, 'Owned ROM did not complete')
                    qmp.request('cont')
                    time.sleep(0.02)
                qmp.request('pmemsave', {'val': mailbox.SCRATCH, 'size': DUMP_SIZE,
                                         'filename': str(dump)})
                raw = dump.read_bytes()
                (output / f'results-{label}-pass{iteration}.bin').write_bytes(raw)
                mismatches, observed = evaluate(rom, enabled_expect, raw)
                _, _, control = parse_dump(raw)
                counters = {}
                for group in sorted(enabled_actual):
                    path = '/machine/' + DEVICES[group][0]
                    counters[group] = transport.values(qmp, path, COUNTERS)
                    want = {COUNTERS[0]: rom.model.reads[group], COUNTERS[1]: rom.model.writes[group]}
                    if counters[group] != want:
                        mismatches.append({'label': f'{group} QOM counters', 'what': 'counters',
                                           'expected': want, 'observed': counters[group]})
                    require(transport.values(qmp, path, COUNTERS) == counters[group],
                            'QOM reads do not increment MMIO counters')
                    for name in COUNTERS:
                        qmp.require_readonly(path, name)
                record = {'iteration': iteration, 'after_system_reset': bool(iteration),
                          'control': control, 'counters': counters,
                          'mismatch_count': len(mismatches), 'mismatches': mismatches,
                          'observed': observed}
                if check_extras and not mismatches:
                    if iteration == 0:
                        migrations = {}
                        for group in ('ptd', 'dvfm'):
                            if enabled_actual == {group}:
                                migrations[group] = qmp.require_migration_blocked(
                                    scratch / f'migration-{group}.bin', (DEVICES[group][1],))
                        if len(enabled_actual) == 2:
                            migrations['both'] = qmp.require_migration_blocked(
                                scratch / 'migration-both.bin',
                                (DEVICES['ptd'][1], DEVICES['dvfm'][1]))
                        result['extras']['migration_rejections'] = migrations
                    else:
                        result['extras']['host_xp'] = host_corroboration(qmp, rom, enabled_actual)
                result['passes'].append(record)
                result['mismatches'].extend(
                    dict(m, iteration=iteration) for m in mismatches)
            qmp.request('quit')
            require(process.wait(timeout=10) == 0, 'Emulator exited cleanly')
            process = None
    except Exception as error:
        result['error'] = str(error)
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
        if qmp is not None:
            qmp.close()
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return result


def host_corroboration(qmp, rom, enabled):
    """Read device state over the host bus (HMP xp), then reset and read again.

    This path does not execute guest code, so it checks the same state the CPU
    saw and that system_reset clears it, independent of the ROM re-running.
    """
    probes = {}
    if not enabled:
        return {}
    if 'ptd' in enabled:
        probes.update({
            'ptd_msg_433': PTD_DASH + 433 * 16, 'ptd_msg_432': PTD_DASH + 432 * 16,
            'ptd_msg_0': PTD_DASH, 'ptd_msg_1023': PTD_DASH + 1023 * 16,
            'ptd_meta_433': PTD_DASH + 433 * 16 + 8})
    if 'dvfm' in enabled:
        probes.update({'dvfm_e_state5': DVFM[0] + 8 + 5 * 0x40,
                       'dvfm_p_state31': DVFM[1] + 8 + 31 * 0x40,
                       'dvfm_e_merge': DVFM[0] + 0x808, 'dvfm_p_edge': DVFM[1] + 0xff8})
    model = rom.model        # final state after the program-order build
    final = {}
    for name, address in probes.items():
        device, view, offset = Model.route(address)
        if device == 'ptd':
            final[name] = 0 if offset & 8 else model.msg.get(offset // 16, 0)
        else:
            final[name] = model.dvfm[view].get(offset // 8, 0)
    before = {name: hmp_xp64(qmp, address) for name, address in probes.items()}
    require(before == final, f'Host bus sees the final device state: {before} vs {final}')
    require(any(final.values()), 'The corroborated state is non-trivial')
    qmp.request('system_reset')
    after_counters = {}
    for group in sorted(enabled):
        after_counters[group] = transport.values(qmp, '/machine/' + DEVICES[group][0], COUNTERS)
        require(after_counters[group] == dict.fromkeys(COUNTERS, 0), f'{group} counters zero after reset')
    after = {name: hmp_xp64(qmp, address) for name, address in probes.items()}
    require(after == dict.fromkeys(probes, 0), f'system_reset clears device state: {after}')
    for group in sorted(enabled):
        reads = transport.values(qmp, '/machine/' + DEVICES[group][0], COUNTERS)[COUNTERS[0]]
        require(reads == sum(1 for n in probes if n.startswith(group)),
                f'{group} host reads were serviced by the device')
    return {'before_reset': {k: hex(v) for k, v in before.items()},
            'after_reset': {k: hex(v) for k, v in after.items()}}


# -------------------------------------------------------------- modes
def perturbation_labels(rom):
    """First and last access of every case."""
    labels = set()
    for case in dict.fromkeys(op.case for op in rom.ops):
        members = [op for op in rom.ops if op.case == case]
        labels.update({members[0].label, members[-1].label})
    return sorted(labels)


def perturb_op(op):
    """Damage one expectation so that a correct device must be rejected."""
    kind, value = op.outcome
    if kind == 'fault':
        op.outcome = ('fault', value ^ 0x200)           # wrong decode/access class
    elif op.kind == 'st':
        op.outcome = ('fault', abort_esr(True, False))  # an accepted store expected to fault
    elif op.kind == 'ld':
        op.outcome = ('ok', value ^ 1)
    else:
        op.outcome = ('ok', (value[0] ^ 1, value[1]))


def count_markers(binary):
    """Occurrences of the two QOM type names in the executable (bounded read)."""
    require(binary.stat().st_size < 100 << 20, 'Executable is small enough to scan in memory')
    data = binary.read_bytes()
    return {name: data.count(name.encode())
            for name in ('apple-modern-pmp-ptd', 'apple-modern-cpu-dvfm')}


def available_kb():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1])
    raise RuntimeError('MemAvailable unreadable')


def run(args):
    binary, components, output = args.binary, args.components, args.output_dir
    started = time.monotonic()
    assets = {name: components / name for name in board.ASSETS}
    before = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes() for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch overlaps reserved component: ' + name)
    require(mailbox.DRAM <= mailbox.BASE < mailbox.PROBE_END <= mailbox.DRAM + board.RAM_SIZE,
            'Owned ROM lies in modern DRAM')
    require(shutil.disk_usage(output).free >= 64 << 20, 'Minimum evidence space')
    rom = GateROM()
    content = rom.build()
    report = {
        'scope': 'Actual-CPU whole-machine gate: opt-in PMP PTD board and CPU DVFM windows',
        'mode': args.mode, 'binary': str(binary), 'binary_sha256': digest(binary)['sha256'],
        'binary_markers': count_markers(binary),
        'script_sha256': digest(Path(__file__))['sha256'],
        'rom_sha256': hashlib.sha256(content).hexdigest(),
        'component_hashes_before': before, 'firmware_executed': False,
        'ios_boot_claim': False, 'declared_behaviour': [
            'Update slot < 1024 mirrors into Dashboard msg (declared)',
            'DVFM windows are zero-reset plain storage (declared, not calibration)',
            'no PMP responder'],
        'ops': len(rom.ops), 'rom_bytes': len(content),
        'selftest': selftest(rom), 'results': [], 'passed': False}
    try:
        if args.mode == 'refusal':
            refused = refusal(binary, assets, args.actual, output)
            report.update(refused)
            report['passed'] = refused['refused_as_expected']
        elif args.mode == 'mutation':
            result = run_guest(binary, assets, rom, content, output, f'{args.actual}-vs-{args.expect}',
                               args.actual, args.expect, False)
            report['results'].append(result)
            predicted = sorted(op.label for op in rom.ops
                               if op.expected(CONFIGS[args.expect][0]) !=
                               op.expected(CONFIGS[args.actual][0]))
            report['predicted_rejected_accesses'] = predicted
            seen = [sorted({m['label'] for m in p['mismatches'] if m.get('case')})
                    for p in result['passes']]
            report['observed_rejected_accesses_per_pass'] = [len(s) for s in seen]
            report['mutation_rejected_exactly_as_predicted'] = (
                'error' not in result and len(seen) == 2 and bool(predicted) and
                all(s == predicted for s in seen) and
                all(not [m for m in p['mismatches'] if not m.get('case')] for p in result['passes']))
            report['passed'] = report['mutation_rejected_exactly_as_predicted']
            groups = {}
            for op in rom.ops:
                if op.label in predicted:
                    groups[op.case] = groups.get(op.case, 0) + 1
            report['predicted_by_case'] = groups
        elif args.mode == 'perturb':
            labels = perturbation_labels(rom)
            for op in rom.ops:
                if op.label in labels:
                    perturb_op(op)
            result = run_guest(binary, assets, rom, content, output, 'both-perturbed',
                               'both', 'both', False)
            report['results'].append(result)
            report['perturbed_accesses'] = labels
            seen = [sorted({m['label'] for m in p['mismatches'] if m.get('case')})
                    for p in result['passes']]
            report['perturbation_rejected_exactly'] = (
                'error' not in result and len(seen) == 2 and all(s == labels for s in seen) and
                all(not [m for m in p['mismatches'] if not m.get('case')]
                    for p in result['passes']))
            report['passed'] = report['perturbation_rejected_exactly']
        else:
            for name in ('none', 'ptd', 'dvfm', 'both'):
                report['results'].append(run_guest(
                    binary, assets, rom, content, output, name, name, name, True))
            report['case_counts'] = case_counts(rom, report['results'])
            report['pin_registers_both_device_types'] = all(
                all(r.get('device_types_registered', {}).get(g) for g in DEVICES)
                for r in report['results'])
            report['passed'] = report['pin_registers_both_device_types'] and all(
                'error' not in r and not r['mismatches'] for r in report['results'])
    except Exception as error:
        report['error'] = str(error)
    after = {name: digest(path) for name, path in assets.items()}
    report['component_hashes_after'] = after
    report['binary_sha256_after'] = digest(binary)['sha256']
    unchanged = after == before and report['binary_sha256_after'] == report['binary_sha256']
    report['inputs_unchanged'] = unchanged
    report['passed'] = bool(report['passed']) and unchanged and 'error' not in report
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    for result in report['results']:                 # keep report.json readable
        for record in result['passes']:
            (output / f"observed-{result['label']}-pass{record['iteration']}.json").write_text(
                json.dumps(record.pop('observed'), indent=1) + '\n')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'mode': args.mode,
                      'error': report.get('error') or next(
                          (r['error'] for r in report['results'] if 'error' in r), None),
                      'binary_sha256': report['binary_sha256'],
                      'mismatches': {r['label']: len(r['mismatches']) for r in report['results']},
                      'elapsed_seconds': report['elapsed_seconds']}))
    return 0 if report['passed'] else 1


def case_counts(rom, results):
    """Per case: access count and, per configuration, how many matched."""
    counts = {}
    for op in rom.ops:
        counts.setdefault(op.case, {'accesses': 0})['accesses'] += 1
    for result in results:
        bad = {m['label'] for m in result['mismatches'] if m.get('case')}
        for op in rom.ops:
            row = counts[op.case]
            row[result['label']] = row.get(result['label'], 0) + (op.label not in bad)
    return counts


def refusal(binary, assets, config, output):
    machine = machine_argument(assets, config)
    run_ = subprocess.run([str(binary), '-M', machine, '-m', '8G', '-smp', '1', '-nodefaults',
                           '-display', 'none', '-serial', 'none', '-monitor', 'none', '-S'],
                          capture_output=True, text=True, timeout=30,
                          preexec_fn=mailbox.child_limits)
    (output / f'refusal-{config}.log').write_text(run_.stdout + run_.stderr)
    wanted = [DEVICES[g][2] for g in sorted(CONFIGS[config][0])]
    refused = run_.returncode != 0 and any(
        re.search(r"Property '[^']*" + re.escape(option) + r"' not found", run_.stderr)
        for option in wanted)
    return {'refusal': {'exit_code': run_.returncode, 'stderr': run_.stderr.strip()[-400:]},
            'refused_as_expected': refused}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--mode', choices=['normal', 'mutation', 'perturb', 'refusal'], default='normal')
    parser.add_argument('--actual', choices=sorted(CONFIGS), default='both',
                        help='mutation/refusal: options the guest is started with')
    parser.add_argument('--expect', choices=sorted(CONFIGS), default='both',
                        help='mutation: expectation table the run is judged against')
    args = parser.parse_args()
    if args.mode == 'mutation':
        require(args.actual != args.expect, 'A mutation needs different actual and expected configs')
    if available_kb() < MIN_AVAILABLE_KB:
        print(json.dumps({'passed': False, 'error': f'MemAvailable {available_kb()} kB below '
                                                    f'{MIN_AVAILABLE_KB} kB; guest not started'}))
        return 2
    args.output_dir.mkdir(parents=True, exist_ok=False)
    args.binary, args.components = args.binary.resolve(), args.components.resolve()
    args.output_dir = args.output_dir.resolve()
    return run(args)


if __name__ == '__main__':
    sys.exit(main())
