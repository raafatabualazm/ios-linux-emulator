#!/usr/bin/env python3
"""Actual CPU gate for the T8140 DCS performance block; no firmware runs.

Preparation inputs are only loaded. An owned AArch64 ROM reads every DCS0-2
control and counter at reset, replays the AppleT8140MCC driver's exact boot
sweep (configure, counter read64, masked RMW of +0x580/+0x584, +0x58c select
RMW, +0x588 clear-bit RMW, the bounded clear poll and the final enable write)
with the 39 BootKC descriptors, reads everything back, replays the save-path
sample-and-disable sweep, and then performs rejected operations whose exact PC
and ESR are captured by an EL2 vector. Every traced value is predicted by an
independent Python model of the declared profile. QOM diagnostics, reset,
creation-only properties, migration and the absent-device oracle are checked.
The virtual profile has no connected DRAM event producer. v3: the board's
declared-profile warning text changed and must appear exactly when mapped.
v4: the warning says the virtual reset applies to "(all counters)" (it was
"(event counters)"; the core resets every event and duration counter).
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('perf_gate_helpers',
    Path(__file__).with_name('test-apple-modern-pmgr-qemu.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
mailbox, board = helper.mailbox, helper.board
require, digest = helper.require, helper.digest

BANK_BASES = (0x220400000, 0x220600000, 0x220800000)
DCS3_BASE = 0x220a00000          # ADT reg[11]; no perf descriptor, never mapped
CONTROL, CONTROL_SPAN = 0x580, 0x100
COUNTER, COUNTER_SPAN = 0x4000, 0x70
CLEAR_BITS = 0x11110000
RESET = 0xfedcba9876543210
DONE = 0xdc5f00d0c0ffee11
VECTOR_OFFSET = 0xc000
SCRATCH_SIZE = 0x10000           # SCRATCH .. NORMAL_SP, all initialized by the loader
FAULT_META = 0x6000              # count, last ESR, last ELR, first ELR/ESR, first-store ELR/ESR
FAULT_LOG = 0x6100
LOG_CAPACITY = (SCRATCH_SIZE - FAULT_LOG) // 16
COUNTERS = ('mmio-read-count', 'mmio-write-count', 'clear-request-count',
            'event-update-count')
QOM_PATH = '/machine/mcc-dcs-perf'
TYPE = 'apple-modern-mcc-dcs-perf'
DEFAULT_DESCRIPTORS = ('modern-emulator/evidence/features-20261008/mcc-provider-review/'
                       'dcs-dsid-review/descriptors.json')
# Syndromes. Decode errors (unmapped, or a width the region's valid range
# refuses) leave EA clear; a device callback returning MEMTX_ACCESS_ERROR sets
# EA (bit 9). Alignment faults on Device memory are raised before any MMIO.
READ_DECODE = 0x96000010
WRITE_DECODE = 0x96000050
WRITE_DEVICE_REJECT = 0x96000250
ALIGN_READ = 0x96000021
ALIGN_WRITE = 0x96000061
# Measured on the pinned binary: an aligned 8-byte CPU access to a 4-byte
# control view is split by QEMU's subpage dispatch into two accepted 4-byte
# device transactions (low word first) instead of being rejected.
CONTROL_DOUBLEWORD = 'split'
# Independent constants for the driver-programmed state of each bank.
COMMAND = (0x3ff1, 0x3ff1, 0x7f1)
EVENT_ENABLE = (0x3ff, 0x3ff, 0x7f)
SELECT = (0x023f023f, 0x08040804, 0x20102010)


def load_descriptors(path):
    entries = [item for item in json.loads(path.read_text()) if item['slot'] == 2]
    require(len(entries) == 39, 'Expected 39 DCS descriptors')
    result = []
    for position, item in enumerate(entries):
        w = {int(key, 16): int(value, 16) & 0xffffffff for key, value in item['words'].items()}
        d = {'index': position, 'name': item['name'], 'kind': item['kind'],
             'bank': item['bank'], 'channel': item['channel'], 'enable_reg': w[0x20],
             'enable': w[0x28], 'request': w[0x30], 'command_reg': w[0x34],
             'command': w[0x38], 'select_reg': w[0x40], 'select_mask': w[0x44],
             'select_value': w[0x48], 'data_reg': w[0x58], 'counter': w[0x5c],
             'param_count': w[0x6c], 'params': [w[0x70 + 8 * i] for i in range(6)]}
        ch = d['channel']
        require(item['index'] == position and d['bank'] < 3, 'Descriptor order/bank')
        if d['kind'] in (3, 4):
            require(d['enable_reg'] == 0x584 and d['enable'] == 1 << ch and
                    d['command_reg'] == 0x580 and d['command'] == (1 << (ch + 4)) | 1 and
                    d['data_reg'] == 0x590 + 0x18 * ch and d['param_count'] == 6 and
                    d['counter'] == COUNTER + 8 * ch, 'Event descriptor derivation')
        else:
            require(d['kind'] == 5 and ch < 4 and d['select_reg'] == 0x58c and
                    d['data_reg'] == 0x588 and d['request'] == 0x10000 << (4 * ch) and
                    d['enable'] == 1 << (4 * ch) and d['select_mask'] == 0x3f << (8 * ch) and
                    d['counter'] == COUNTER + 8 * (10 + ch), 'Duration descriptor derivation')
        result.append(d)
    per_bank = [sum(d['kind'] != 5 and d['bank'] == b for d in result) for b in range(3)]
    require(per_bank == [10, 10, 7], 'Event channel partition 10/10/7')
    return result


class Model:
    """Independent model of the declared profile, from the driver contract."""

    def __init__(self):
        self.controls = [[0] * 64 for _ in range(3)]
        self.values = [[RESET] * 14 for _ in range(3)]
        self.reads = self.writes = self.clears = 0

    def read(self, bank, offset):
        self.reads += 1
        if CONTROL <= offset < CONTROL + CONTROL_SPAN:
            require(offset % 4 == 0, 'Model control alignment')
            return self.controls[bank][(offset - CONTROL) // 4]
        require(COUNTER <= offset < COUNTER + COUNTER_SPAN and offset % 8 == 0,
                'Model counter access')
        return self.values[bank][(offset - COUNTER) // 8]

    def write(self, bank, offset, value):
        require(CONTROL <= offset < CONTROL + CONTROL_SPAN and offset % 4 == 0 and
                0 <= value <= 0xffffffff, 'Model control write')
        index = (offset - CONTROL) // 4
        if index == 2:
            for i in range(4):
                if value >> (16 + 4 * i) & 1:
                    self.values[bank][10 + i] = 0
                    self.clears += 1
            value &= ~CLEAR_BITS & 0xffffffff
        self.controls[bank][index] = value
        self.writes += 1


class QMP(helper.QMP):
    def expect_error(self, command, arguments):
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
                    f'{command} must be rejected')
            return response['error']
        raise RuntimeError('QMP rejection deadline')

    def require_immutable(self, name):
        before = self.request('qom-get', {'path': '/machine', 'property': name})
        attempted = not before if isinstance(before, bool) else before ^ 0xffffffffffffffff
        error = self.expect_error('qom-set', {'path': '/machine', 'property': name,
                                              'value': attempted})
        require(error.get('class') == 'GenericError' and error.get('desc') ==
                'apple-modern properties are fixed after initialization',
                'Mutation rejection must identify initialized board properties')
        after = self.request('qom-get', {'path': '/machine', 'property': name})
        require(after == before, 'Rejected board mutation leaves value unchanged')
        return {'before': before, 'attempted': attempted, 'after': after, 'error': error}

    def require_migration_blocked(self, target):
        error = self.expect_error('migrate', {'uri': 'file:' + str(target)})
        require(TYPE in error.get('desc', '') and 'non-migratable' in error.get('desc', ''),
                'Migration rejection must identify the DCS performance state')
        require(not target.exists(), 'No partial migration file')
        return error


class ROM(helper.ROM):
    def __init__(self, descriptors):
        super().__init__()
        self.model = Model()
        self.descriptors = descriptors
        self.bank = None
        self.dcs = []          # every instruction that addresses a DCS bank
        self.faults = []
        self.sweeps = {}

    def pc(self):
        return mailbox.BASE + len(self.words) * 4

    def trace(self, label, expected, name=None, register=0):
        require(label not in self.expected, 'Unique trace label: ' + label)
        super().trace(label, expected, name, register)

    def select(self, bank):
        if self.bank != bank:
            self.mov(19, BANK_BASES[bank])
            self.bank = bank

    def movw(self, register, value):
        require(0 <= value <= 0xffffffff, 'movw range')
        self.emit(0x52800000 | ((value & 0xffff) << 5) | register)       # movz w
        self.emit(0x72a00000 | ((value >> 16) << 5) | register)          # movk w, lsl 16

    def note(self, kind, address, width):
        self.dcs.append({'pc': self.pc(), 'kind': kind, 'address': address, 'width': width})

    def ldr32(self, offset, register):
        require(CONTROL <= offset < CONTROL + CONTROL_SPAN and offset % 4 == 0, 'ldr32')
        self.note('load', BANK_BASES[self.bank] + offset, 4)
        self.emit(0xb9400000 | (offset // 4 << 10) | (19 << 5) | register)
        return self.model.read(self.bank, offset)

    def ldr64(self, offset, register):
        require(offset % 8 == 0 and offset // 8 < 4096, 'ldr64 encoding')
        self.note('load', BANK_BASES[self.bank] + offset, 8)
        self.emit(0xf9400000 | (offset // 8 << 10) | (19 << 5) | register)
        if COUNTER <= offset:
            return self.model.read(self.bank, offset)
        require(CONTROL_DOUBLEWORD == 'split', 'Measured control doubleword handling')
        low = self.model.read(self.bank, offset)
        return low | self.model.read(self.bank, offset + 4) << 32

    def str32(self, offset, register, value):
        self.note('store', BANK_BASES[self.bank] + offset, 4)
        self.emit(0xb9000000 | (offset // 4 << 10) | (19 << 5) | register)
        self.model.write(self.bank, offset, value)

    def check32(self, offset, label):
        self.trace(label, self.ldr32(offset, 23), register=23)

    def check64(self, offset, label):
        value = self.ldr64(offset, 23)
        self.trace(label, value, register=23)
        return value

    def write(self, offset, value):
        self.movw(0, value)
        self.str32(offset, 0, value)

    def rmw(self, offset, mask, value, label):
        """Driver slot 0x7b0: one read32, then (old & ~mask) | (value & mask)."""
        old = self.ldr32(offset, 2)
        self.trace(label + '_old', old, register=2)
        self.movw(4, mask)
        self.movw(5, value)
        self.emit(0x0a240043)  # bic w3,w2,w4
        self.emit(0x0a0400a5)  # and w5,w5,w4
        self.emit(0x2a050063)  # orr w3,w3,w5
        new = (old & ~mask) | (value & mask)
        self.str32(offset, 3, new)
        self.trace(label + '_new', new, register=3)
        return old

    def poll(self, offset, request, label):
        """The driver's bounded clear poll: up to ten reads until bits clear."""
        self.movw(4, request)
        self.emit(0xd2800006)  # movz x6,#0
        loop = len(self.words)
        last = self.ldr32(offset, 2)
        self.emit(0x910004c6)  # add x6,x6,#1
        self.emit(0x6a04005f)  # tst w2,w4
        self.emit(0x54000060)  # b.eq +3 (past the retry branch)
        self.emit(0xf10028df)  # cmp x6,#10
        self.branch(loop, 3)   # b.lo loop
        require(not last & request, 'Model clears at once')
        self.trace(label + '_reads', 1, register=6)
        self.trace(label + '_last', last, register=2)
        return last

    def final(self, offset, last, enable_mask, enable, label):
        self.movw(4, enable_mask)
        self.emit(0x0a240043)  # bic w3,w2,w4
        if enable:
            self.emit(0x2a040063)  # orr w3,w3,w4
        value = (last & ~enable_mask) | (enable_mask if enable else 0)
        self.str32(offset, 3, value)
        self.trace(label, value, register=3)

    def dispatch(self, d, enable, tag):
        """Driver slot 0x770 -> 0x758 for one descriptor."""
        self.select(d['bank'])
        self.check64(d['counter'], tag + '_counter')
        if d['kind'] == 5:
            self.rmw(d['select_reg'], d['select_mask'], d['select_value'], tag + '_select')
            self.rmw(d['data_reg'], d['request'], d['request'], tag + '_clear')
            last = self.poll(d['data_reg'], d['request'], tag + '_poll')
            self.final(d['data_reg'], last, d['enable'], enable, tag + '_final')
        else:
            if enable:
                self.rmw(d['command_reg'], d['command'], d['command'], tag + '_command')
            self.rmw(d['enable_reg'], d['enable'], d['enable'] if enable else 0,
                     tag + '_enable')

    def sweep(self, name, enable):
        reads, writes, clears = self.model.reads, self.model.writes, self.model.clears
        for d in self.descriptors:
            tag = f'{name}_{d["index"]:02d}'
            self.select(d['bank'])
            if enable and d['kind'] in (3, 4):
                for word in range(min(d['param_count'], 6)):
                    self.write(d['data_reg'] + 4 * word, d['params'][word])
                    if not hasattr(self, 'first_store_pc'):
                        self.first_store_pc = self.dcs[-1]['pc']
            if not enable:
                self.check64(d['counter'], tag + '_sample')  # slot 0x718 readSingleValue
            self.dispatch(d, enable, tag)
        self.sweeps[name] = {'reads': self.model.reads - reads,
                             'writes': self.model.writes - writes,
                             'clears': self.model.clears - clears}

    def readback(self, name):
        for bank in range(3):
            self.select(bank)
            for index in range(64):
                self.check32(CONTROL + 4 * index, f'{name}_control_{bank}_{CONTROL + 4 * index:03x}')
            for index in range(14):
                self.check64(COUNTER + 8 * index, f'{name}_counter_{bank}_{index:02d}')

    def fault(self, name, kind, width, address, esr):
        if kind == 'store':
            self.mov(0, 0xa5a5a5a5a5a5a5a5 if width == 8 else 0xa5a5a5a5)
        self.mov(1, address)
        opcodes = {('load', 1): 0x39400037, ('load', 2): 0x79400037,
                   ('load', 4): 0xb9400037, ('load', 8): 0xf9400037,
                   ('store', 1): 0x39000020, ('store', 2): 0x79000020,
                   ('store', 4): 0xb9000020, ('store', 8): 0xf9000020}
        if any(base <= address < base + 0x8000 for base in (*BANK_BASES, DCS3_BASE)):
            self.dcs.append({'pc': self.pc(), 'kind': kind, 'address': address,
                             'width': width})
        self.faults.append({'name': name, 'kind': kind, 'width': width,
                            'address': address, 'pc': self.pc(), 'esr': esr})
        self.emit(opcodes[kind, width])  # x19 (bank base) is untouched here

    def build(self):
        model = self.model
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)  # mov sp,x0
        self.emit(0xd5034fdf)  # mask all interrupts
        self.set('VBAR_EL2', mailbox.BASE + VECTOR_OFFSET)
        # A. Reset: controls 0, counters the virtual reset value, all banks.
        self.readback('reset')
        self.first_dcs_pc = self.dcs[0]['pc']
        require(all(v == 0 for bank in model.controls for v in bank) and
                all(v == RESET for bank in model.values for v in bank), 'Reset model')
        # B. Boot sweep (slot 0x700), table order, real descriptor constants.
        self.sweep('enable', True)
        require(self.sweeps['enable'] == {'reads': 129, 'writes': 252, 'clears': 12},
                'Boot sweep matches the pinned guest probe (129 reads, 252 writes)')
        for bank in range(3):
            require(model.controls[bank][:4] == [COMMAND[bank], EVENT_ENABLE[bank], 0x1111,
                                                 SELECT[bank]], 'Programmed bank state')
            require(model.values[bank] == [RESET] * 10 + [0] * 4,
                    'Duration counters cleared, event counters untouched')
        # C. Everything reads back; then the measured doubleword control path.
        self.readback('enabled')
        self.select(0)
        self.split = []
        for bank, offset in ((0, 0x580), (1, 0x588), (0, 0x678)):
            self.select(bank)
            pc = self.pc()
            value = self.check64(offset, f'doubleword_load_{bank}_{offset:03x}')
            self.split.append({'kind': 'load', 'pc': pc, 'address': BANK_BASES[bank] + offset,
                               'value': value})
        require(self.split[0]['value'] == COMMAND[0] | EVENT_ENABLE[0] << 32 and
                self.split[1]['value'] == 0x1111 | SELECT[1] << 32, 'Doubleword model')
        self.select(2)
        self.mov(0, 0x1122334455667788)
        pc = self.pc()
        self.note('store', BANK_BASES[2] + 0x670, 8)
        self.emit(0xf9000000 | (0x670 // 8 << 10) | (19 << 5) | 0)  # str x0,[x19,#0x670]
        model.write(2, 0x670, 0x55667788)
        model.write(2, 0x674, 0x11223344)
        self.split.append({'kind': 'store', 'pc': pc, 'address': BANK_BASES[2] + 0x670,
                           'value': 0x1122334455667788})
        self.check32(0x670, 'doubleword_store_low')
        self.check32(0x674, 'doubleword_store_high')
        # D. Save path (slot 0x718 with its flag): sample, then disable.
        self.sweep('disable', False)
        require(self.sweeps['disable'] == {'reads': 141, 'writes': 63, 'clears': 12},
                'Save sweep accounting')
        for bank in range(3):
            require(model.controls[bank][:4] == [COMMAND[bank], 0, 0, SELECT[bank]],
                    'Disabled bank state keeps command and select')
        self.readback('disabled')
        accepted = (model.reads, model.writes, model.clears)
        # F. Rejected operations: exact PC and ESR for each.
        for bank, base in enumerate(BANK_BASES):
            c, k = base + COUNTER, base + CONTROL
            self.fault(f'before_control_{bank}', 'load', 4, k - 4, READ_DECODE)
            self.fault(f'after_control_{bank}', 'load', 4, k + CONTROL_SPAN, READ_DECODE)
            self.fault(f'after_control_store_{bank}', 'store', 4, k + CONTROL_SPAN, WRITE_DECODE)
            self.fault(f'dramcfg_word_unclaimed_{bank}', 'load', 4, base + 0x1d48, READ_DECODE)
            self.fault(f'before_counter_{bank}', 'load', 8, c - 8, READ_DECODE)
            self.fault(f'after_counter_{bank}', 'load', 8, c + COUNTER_SPAN, READ_DECODE)
            self.fault(f'after_counter_store_{bank}', 'store', 8, c + COUNTER_SPAN, WRITE_DECODE)
            self.fault(f'counter_load32_low_{bank}', 'load', 4, c, READ_DECODE)
            self.fault(f'counter_load32_high_{bank}', 'load', 4, c + COUNTER_SPAN - 4, READ_DECODE)
            self.fault(f'counter_load16_{bank}', 'load', 2, c + 8, READ_DECODE)
            self.fault(f'counter_store32_{bank}', 'store', 4, c + 0x50, WRITE_DECODE)
            for index in range(14):
                self.fault(f'counter_store64_{bank}_{index:02d}', 'store', 8, c + 8 * index,
                           WRITE_DEVICE_REJECT)
            self.fault(f'control_load8_{bank}', 'load', 1, k, READ_DECODE)
            self.fault(f'control_load16_{bank}', 'load', 2, k + 4, READ_DECODE)
            self.fault(f'control_store8_{bank}', 'store', 1, k + 4, WRITE_DECODE)
            self.fault(f'control_store16_{bank}', 'store', 2, k + 8, WRITE_DECODE)
            self.fault(f'control_misaligned_load_{bank}', 'load', 4, k + 2, ALIGN_READ)
            self.fault(f'control_misaligned_store_{bank}', 'store', 4, k + 6, ALIGN_WRITE)
            self.fault(f'control_load64_misaligned_{bank}', 'load', 8, k + 4, ALIGN_READ)
            self.fault(f'counter_misaligned_load_{bank}', 'load', 8, c + 4, ALIGN_READ)
            self.fault(f'counter_misaligned_store_{bank}', 'store', 8, c + 4, ALIGN_WRITE)
        self.fault('dcs3_control_load', 'load', 4, DCS3_BASE + CONTROL, READ_DECODE)
        self.fault('dcs3_param_store', 'store', 4, DCS3_BASE + 0x590, WRITE_DECODE)
        self.fault('dcs3_duration_control_store', 'store', 4, DCS3_BASE + 0x588, WRITE_DECODE)
        self.fault('dcs3_counter_load', 'load', 8, DCS3_BASE + COUNTER, READ_DECODE)
        require((model.reads, model.writes, model.clears) == accepted,
                'Rejected operations are not accepted device transactions')
        # G. Nothing changed: all counters and the shared controls.
        for bank in range(3):
            self.select(bank)
            for index in range(14):
                self.check64(COUNTER + 8 * index, f'after_faults_counter_{bank}_{index:02d}')
            for offset in (0x580, 0x584, 0x588, 0x58c, 0x670, 0x674):
                self.check32(offset, f'after_faults_control_{bank}_{offset:03x}')
        self.mov(0, DONE)
        self.trace('completion', DONE)
        self.branch(len(self.words))
        require(len(self.words) * 4 <= VECTOR_OFFSET, 'Owned main code precedes vectors')
        for offset in range(VECTOR_OFFSET, VECTOR_OFFSET + 0x800, 0x80):
            self.at(offset)
            start = len(self.words)
            self.emit(0xf9400000 | (FAULT_META // 8 << 10) | (20 << 5))          # ldr x0,count
            self.emit(0xd53c4029)                                                # mrs x9,ELR_EL2
            self.emit(mailbox.sysreg('ESR_EL2', 11, True))                       # mrs x11,ESR_EL2
            self.emit(0xf100001f | (LOG_CAPACITY << 10))                         # cmp x0,#cap
            self.emit(0x54000082)                                                # b.hs +4
            self.emit(0x8b00128a)                                                # add x10,x20,x0,lsl #4
            self.emit(0xf9000000 | (FAULT_LOG // 8 << 10) | (10 << 5) | 9)       # str x9,log.pc
            self.emit(0xf9000000 | ((FAULT_LOG + 8) // 8 << 10) | (10 << 5) | 11)  # str x11,log.esr
            self.emit(0xb5000060)                                                # cbnz x0,+3
            self.store(9, FAULT_META + 0x18)                                     # first ELR
            self.store(11, FAULT_META + 0x20)                                    # first ESR
            self.emit(0x363000ab)                                                # tbz w11,#6,+5
            self.emit(0xf9400000 | ((FAULT_META + 0x28) // 8 << 10) | (20 << 5) | 12)
            self.emit(0xb500006c)                                                # cbnz x12,+3
            self.store(9, FAULT_META + 0x28)                                     # first store ELR
            self.store(11, FAULT_META + 0x30)                                    # first store ESR
            self.emit(0x91000400)                                                # add x0,x0,#1
            self.store(0, FAULT_META)
            self.store(11, FAULT_META + 8)
            self.store(9, FAULT_META + 0x10)
            self.emit(0x91001129)                                                # add x9,x9,#4
            self.emit(0xd51c4029)                                                # msr ELR_EL2,x9
            self.emit(0xd69f03e0)                                                # eret
            require(len(self.words) - start <= 32, 'Vector fits its slot')
        require(len(self.words) * 4 <= 0x10000 and len(self.expected) * 8 <= FAULT_META,
                'Owned ROM/results/fault ranges stay separate')
        polls = sum(1 for item in self.expected if item.endswith('_poll_reads'))
        require(polls == 24 and len(self.dcs) + polls * 9 <= LOG_CAPACITY,
                'Fault log holds every fault, also with the device absent')
        return b''.join(struct.pack('<I', value) for value in self.words)


def run(binary, components, output, descriptors_path, no_device):
    assets = {name: components / name for name in board.ASSETS}
    hashes = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes() for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch outside preparation assets: ' + name)
    require(mailbox.DRAM <= mailbox.BASE < mailbox.PROBE_END <=
            mailbox.DRAM + board.RAM_SIZE, 'Owned ROM lies in modern DRAM')
    require(mailbox.SCRATCH + SCRATCH_SIZE <= mailbox.NORMAL_SP, 'Scratch below the stack')
    require(shutil.disk_usage(output).free >= 64 << 20, 'Minimum evidence space')
    descriptors = load_descriptors(descriptors_path)
    rom = ROM(descriptors)
    content = rom.build()
    rom_path = output / 'owned-mcc-dcs-perf.rom'
    rom_path.write_bytes(content)
    zero = bytes(SCRATCH_SIZE)
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(zero)
    machine = 'apple-modern,' + ','.join(name + '=' + str(assets[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true'
    if not no_device:
        machine += ',modern-mcc-dcs-perf=on,mcc-dcs-perf-reset=' + hex(RESET)
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    expected_counters = dict(zip(COUNTERS, (rom.model.reads, rom.model.writes,
                                            rom.model.clears, 0)))
    report = {'passed': False, 'argv': argv, 'binary': str(binary),
              'binary_sha256': digest(binary), 'script_sha256': digest(Path(__file__)),
              'rom_sha256': digest(rom_path), 'descriptors': str(descriptors_path),
              'descriptors_sha256': digest(descriptors_path),
              'firmware_executed': False, 'ios_boot_claim': False,
              'reset_is_virtual_profile': True, 'reset_value': hex(RESET),
              'physical_reset_contents_known': False, 'event_producer_connected': False,
              'clear_bit_timing_is_declared': True,
              'component_hashes_before': hashes, 'no_device_oracle': no_device,
              'child_reaped': False, 'expected_counters': expected_counters,
              'sweeps': rom.sweeps, 'rom_instructions': len(rom.words),
              'traced_values': len(rom.expected), 'rejected_operations': len(rom.faults),
              'device_addressing_instructions': len(rom.dcs),
              'control_doubleword_measured': CONTROL_DOUBLEWORD,
              'doubleword_control_operations': [
                  {**item, 'pc': hex(item['pc']), 'address': hex(item['address']),
                   'value': hex(item['value'])} for item in rom.split],
              'passes': []}
    process = qmp = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='mcc-dcs-perf-mmio-') as temp, \
             (output / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, bufsize=0,
                preexec_fn=mailbox.child_limits)

            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and
                        (output / 'emulator.log').stat().st_size < mailbox.MAX_LOG,
                        'DCS performance gate wall/log bound')
                return remaining
            qmp = QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'})
                    is True, 'Only owned ROM may execute')
            require(qmp.request('qom-get', {'path': '/machine',
                    'property': 'modern-mcc-dcs-perf'}) == (not no_device),
                    'DCS performance option matches oracle')
            if no_device:
                report['default_off_validated'] = True
                children = {item['name'] for item in
                            qmp.request('qom-list', {'path': '/machine'})}
                require('mcc-dcs-perf' not in children, 'No device when the option is off')
            else:
                require(qmp.request('qom-get', {'path': '/machine',
                        'property': 'mcc-dcs-perf-reset'}) == RESET, 'Reset property value')
                require(qmp.request('qom-get', {'path': QOM_PATH, 'property': 'type'}) == TYPE,
                        'Device type')
                regions = []
                for item in qmp.request('qom-list', {'path': QOM_PATH}):
                    if item['type'] == 'child<memory-region>':
                        path = QOM_PATH + '/' + item['name']
                        regions.append({'name': item['name'],
                            'addr': qmp.request('qom-get', {'path': path, 'property': 'addr'}),
                            'size': qmp.request('qom-get', {'path': path, 'property': 'size'})})
                mapped = sorted((region['addr'], region['size']) for region in regions)
                expected_map = sorted((base + offset, span) for base in BANK_BASES
                                      for offset, span in ((CONTROL, CONTROL_SPAN),
                                                           (COUNTER, COUNTER_SPAN)))
                require(mapped == expected_map, f'Exactly six sparse DCS0-2 views: {mapped}')
                report['mapped_regions'] = [{**region, 'addr': hex(region['addr']),
                                             'size': hex(region['size'])} for region in regions]
                report['immutable_property_checks'] = {
                    name: qmp.require_immutable(name)
                    for name in ('modern-mcc-dcs-perf', 'mcc-dcs-perf-reset')}
                report['migration_rejection'] = qmp.require_migration_blocked(
                    Path(temp) / 'migration.state')
                report['device_add_rejection'] = qmp.expect_error(
                    'device_add', {'driver': TYPE, 'id': 'second-dcs-perf'})
            for iteration in range(2):
                if iteration:
                    qmp.request('system_reset')
                regs = board.parse_registers(qmp.request('human-monitor-command',
                                                         {'command-line': 'info registers'}))
                require(regs['PC'] == mailbox.BASE and regs['PSTATE'] & 15 == 9,
                        'Owned ROM PC and EL2h selected before cont')
                require(qmp.request('query-status')['running'] is False,
                        'Owned CPU stopped before cont')
                if not no_device:
                    reset = {name: qmp.request('qom-get', {'path': QOM_PATH,
                             'property': name}) for name in COUNTERS}
                    require(reset == dict.fromkeys(COUNTERS, 0), 'Diagnostics reset')
                    readonly = {name: qmp.require_readonly(QOM_PATH, name)
                                for name in COUNTERS}
                verify = Path(temp) / 'verify.bin'
                for address, expected in ((mailbox.BASE, content), (mailbox.SCRATCH, zero)):
                    qmp.request('pmemsave', {'val': address, 'size': len(expected),
                                             'filename': str(verify)})
                    require(verify.read_bytes() == expected,
                            'Exact owned ROM/results verified before cont')
                qmp.request('cont')
                deadline = time.monotonic() + 15
                dump = Path(temp) / 'results.bin'
                while True:
                    guard()
                    qmp.request('stop')
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH, 'size': SCRATCH_SIZE,
                                             'filename': str(dump)})
                    raw = dump.read_bytes()
                    if struct.unpack_from('<Q', raw, (len(rom.expected) - 1) * 8)[0] == DONE:
                        break
                    if time.monotonic() >= deadline:
                        (output / f'results-pass{iteration}.bin').write_bytes(raw)
                        raise RuntimeError('Owned ROM completion deadline; fault meta ' +
                            str([hex(v) for v in struct.unpack_from('<7Q', raw, FAULT_META)]))
                    qmp.request('cont')
                    time.sleep(0.03)
                (output / f'results-pass{iteration}.bin').write_bytes(raw)
                count, esr, elr, first, first_esr, first_store, first_store_esr = \
                    struct.unpack_from('<7Q', raw, FAULT_META)
                logged = list(struct.unpack_from('<' + 'Q' * (2 * min(count, LOG_CAPACITY)),
                                                 raw, FAULT_LOG))
                by_pc = {item['pc']: item for item in rom.faults}
                dcs_pcs = {item['pc'] for item in rom.dcs}
                observed_faults = [{'pc': hex(pc), 'esr': hex(syndrome),
                                    'name': by_pc[pc]['name'] if pc in by_pc else
                                    ('device-access' if pc in dcs_pcs else 'unexpected')}
                                   for pc, syndrome in zip(logged[::2], logged[1::2])]
                if no_device:
                    report['no_device_fault_summary'] = {
                        'faults': count, 'first_elr': hex(first), 'first_esr': hex(first_esr),
                        'first_store_elr': hex(first_store),
                        'first_store_esr': hex(first_store_esr),
                        'expected_first_access': hex(rom.first_dcs_pc),
                        'expected_first_store': hex(rom.first_store_pc),
                        'first_store_address': hex(next(item['address'] for item in rom.dcs
                                                        if item['pc'] == rom.first_store_pc))}
                    require(count <= LOG_CAPACITY, 'Absent-device fault log complete')
                    require(first == rom.first_dcs_pc and first_esr == READ_DECODE,
                            'Absent device: first DCS load faults at its exact PC')
                    require(first_store == rom.first_store_pc and
                            first_store_esr == WRITE_DECODE,
                            'Absent device: first DCS store (DCS0 +0x590) faults with 0x96000050')
                    faulted = set(logged[::2])
                    require(dcs_pcs <= faulted, 'Absent device: every DCS access faulted')
                    require(faulted <= dcs_pcs | set(by_pc), 'Absent device: no other fault')
                    report['no_device_oracle_validated'] = True
                    report['no_device_fault_log'] = observed_faults
                    break
                observed = {}
                mismatches = []
                for index, (name, expected) in enumerate(rom.expected.items()):
                    value = struct.unpack_from('<Q', raw, index * 8)[0]
                    observed[name] = hex(value)
                    if value != expected:
                        mismatches.append(f'{name}: expected {expected:#x}, observed {value:#x}')
                if mismatches or count != len(rom.faults):
                    report['observed_faults'] = observed_faults
                    report['mismatches'] = mismatches[:64]
                require(not mismatches, f'{len(mismatches)} traced values differ; first: ' +
                        (mismatches[0] if mismatches else ''))
                require(count == len(rom.faults),
                        f'Fault count {count} != {len(rom.faults)} expected rejections')
                require(logged[::2] == [item['pc'] for item in rom.faults] and
                        logged[1::2] == [item['esr'] for item in rom.faults],
                        'Every rejected operation faults at exact PC with exact ESR')
                stores = [item for item in rom.faults if item['esr'] >> 6 & 1]
                require(first == rom.faults[0]['pc'] and first_esr == rom.faults[0]['esr'] and
                        first_store == stores[0]['pc'] and first_store_esr == stores[0]['esr'] and
                        elr == rom.faults[-1]['pc'] and esr == rom.faults[-1]['esr'],
                        'Fault metadata')
                counters = {name: qmp.request('qom-get', {'path': QOM_PATH,
                            'property': name}) for name in COUNTERS}
                require(counters == expected_counters,
                        f'Actual accepted MMIO counts {counters} != {expected_counters}')
                require({name: qmp.request('qom-get', {'path': QOM_PATH, 'property': name})
                         for name in COUNTERS} == counters, 'QOM reads do not count')
                report['passes'].append({'iteration': iteration,
                    'after_system_reset': bool(iteration), 'counters': counters,
                    'readonly_rejections': readonly, 'faults': observed_faults,
                    'observed': observed})
            qmp.request('quit')
            report['child_exit_code'] = process.wait(timeout=10)
            report['child_reaped'] = process.poll() is not None
            require(report['child_exit_code'] == 0, 'Clean emulator exit')
            process = None
            log.flush()
            report['emulator_log'] = (output / 'emulator.log').read_text(errors='replace')
            announced = ('apple-modern: opt-in sparse DCS performance block on DCS0-2; '
                         f'declared profile: virtual reset 0x{RESET:016x} (all counters), '
                         'clear bits complete at once and zero their duration counter, '
                         'counter stores abort; no DRAM event source connected'
                         ) in report['emulator_log']
            require(announced == (not no_device), 'Board announces the declared profile '
                    'exactly when the device is mapped')
            # The absent-device oracle must never pass: its accesses all faulted.
            require(not no_device, 'No-device oracle rejected on actual MMIO faults (' +
                    str(report.get('no_device_fault_summary')) + ')')
            report['passed'] = len(report['passes']) == 2
    except Exception as error:
        report['error'] = str(error)
    finally:
        if process:
            process.kill()
            report['child_exit_code'] = process.wait(timeout=10)
            report['child_reaped'] = process.poll() is not None
        if qmp:
            qmp.close()
        report['component_hashes_after'] = {name: digest(path) for name, path in assets.items()}
        if report['component_hashes_after'] != hashes:
            report['passed'] = False
            report['error'] = 'Preparation inputs changed'
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in
                      ('passed', 'error', 'expected_counters', 'elapsed_seconds')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--descriptors', type=Path)
    parser.add_argument('--no-device', action='store_true')
    args = parser.parse_args()
    workspace = next(parent for parent in Path(__file__).resolve().parents
                     if (parent / 'modern-emulator' / 'evidence').is_dir())
    args.output_dir.mkdir(parents=True, exist_ok=False)
    sys.exit(run(args.binary.resolve(), args.components.resolve(),
                 args.output_dir.resolve(),
                 (args.descriptors or workspace / DEFAULT_DESCRIPTORS).resolve(),
                 args.no_device))
