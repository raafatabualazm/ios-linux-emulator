#!/usr/bin/env python3
"""Actual CPU gate for the AMCC SLC way/flush cells; no firmware runs.

Preparation inputs are only loaded. An owned AArch64 ROM replays the pinned
BootKC's mccEnableCacheMode / mccWaitForWaysPwrOn and cacheFlush cell
sequences, checks the 7-bit way-status fields on all four planes, write-only
global and read-only plane cells, exact external-abort PC/ESR pairs, and the
whole sequence again after system_reset.

v3: every plane's +0x2804 reads 0x0c000c00 from reset (requested-ways
0x8000000c, the 12-way handover state m1n1 PR #664 read back per plane on
t604x/t8140-family Macs, analogy) and still 12 ways after the driver sequence. The read-only QOM
cells requested-ways, control-82c and flush-request are checked exactly at
reset (also after system_reset) and after the ROM, and must reject qom-set.
The board's memory map is read back (HMP info mtree, tree and flat view): the
11 SLC views lie at their planned addresses, views inside the compatibility
aperture are mapped at priority 1 and every other view plainly (priority 0),
and the flat view shows the aperture minus exactly those views. The board's
declared-profile warning must appear exactly when the device is mapped.

With a served tree that carries Darwin's compatibility AMCC aperture
(/chosen/lock-regs/amcc, read-zero/write-ignore except the CTRR bound
registers), the board carves plane 0's +0x2804/+0x2844 out of the aperture's
exclusion and maps the SLC cells above it. The ROM then proves that (a)
plane-0 +0x2804 returns the SLC status, not the aperture's zero, (b) every
served CTRR bound register still resets, stores and reads back, and (c) the
aperture offsets next to the carved cells still read zero and ignore stores.
It also pins that an aligned 64-bit access starting in the aperture at
+0x2800/+0x2840 is answered wholly by the aperture, shadowing the carved cell
in its upper half. Without the aperture the same offsets are unmapped and must
fault.

v4: the board's declared-profile warning names the per-plane readback on
t604x/t8140-family Macs (m1n1 PR #664) instead of a MacBook-class T8140
measurement. Board construction now refuses an in-aperture SLC view that
overlaps the aperture's lock word (+0..+7) or a CTRR bound register; that
refusal is gated by test-apple-modern-mcc-amcc-board-qemu.py.
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
spec = importlib.util.spec_from_file_location('slc_gate_helpers',
    Path(__file__).with_name('test-apple-modern-pmgr-qemu.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
mailbox, board = helper.mailbox, helper.board
require, digest = helper.require, helper.digest
AMCC = 0x220000000
PLANE = 0x40000
GLOBAL = AMCC + 0x100000
WAYS = GLOBAL + 0x2800
BYPASS = GLOBAL + 0x82c
FLUSH_REQUEST = GLOBAL + 0x2844
PLANES = 4
DRIVER_WAYS = 0xc
DONE = 0xf05e1234face5678
VECTOR_OFFSET = 0xc000
FAULT_META = 0x2400
FAULT_LOG = 0x2500
SCRATCH_SIZE = 0x3000
COUNTERS = ('mmio-read-count', 'mmio-write-count')
CELLS = ('requested-ways', 'control-82c', 'flush-request')
RESET_WAYS = 0x8000000c          # PR #664 handover state (analogy); status 0x0c000c00
FINAL_82C = 0xc0de082c           # Distinct 32-bit patterns pin the QOM cells exactly.
FINAL_FLUSH = 0xf1a52844
RESET_CELLS = dict(zip(CELLS, (RESET_WAYS, 0, 0)))
FINAL_CELLS = dict(zip(CELLS, (DRIVER_WAYS, FINAL_82C, FINAL_FLUSH)))
QOM_PATH = '/machine/mcc-slc'
REGION = 'apple-modern.mcc-slc'
APERTURE_REGION = 'apple-modern.amcc'
ANNOUNCEMENT = ('apple-modern: opt-in AMCC SLC way/flush cells; declared profile: '
                '12-way handover state (per-plane readback on t604x/t8140-family '
                'Macs, m1n1 PR #664, analogy), '
                'global writes broadcast and requested ways report powered at once; '
                'no cache model')
BANKS = ('amcc-ctrr-a', 'amcc-ctrr-b', 'amcc-ctrr-c', 'amcc-ctrr-d')
READ_FAULT_ESR = 0x96000010    # Unmapped or rejected-width load: decode error, EA=0.
WRITE_FAULT_ESR = 0x96000050   # Unmapped or rejected-width store: decode error, WnR.
ACCESS_READ_ESR = 0x96000210   # Mapped write-only cell rejects the load: EA.
ACCESS_WRITE_ESR = 0x96000250  # Mapped read-only cell rejects the store: EA and WnR.
ALIGN_READ_ESR = 0x96000021    # CPU Device-memory alignment fault before MMIO.
ALIGN_WRITE_ESR = 0x96000061


def status(plane):
    return AMCC + plane * PLANE + 0x2804


VIEW_ADDRESSES = ([WAYS, BYPASS, FLUSH_REQUEST] + [AMCC + p * PLANE + 0x2804 for p in range(4)] +
                  [AMCC + p * PLANE + 0x2844 for p in range(4)])
MTREE_LINE = __import__('re').compile(
    r'^\s*([0-9a-f]{16})-([0-9a-f]{16}) \(prio (-?\d+), ([a-z/ -]+)\): (\S+)(?: @([0-9a-f]+))?')


def mtree_section(text, flat):
    """Entries of the system-memory listing (tree) or its flat view."""
    lines, entries, inside = text.splitlines(), [], False
    for index, line in enumerate(lines):
        if not inside:
            if flat:
                inside = (line.startswith('FlatView') and index + 1 < len(lines) and
                          any(item.strip().startswith('AS "memory"')
                              for item in lines[index + 1:index + 4]))
            else:
                inside = line.strip() == 'address-space: memory'
            continue
        if not line.strip():
            break
        match = MTREE_LINE.match(line)
        if match:
            entries.append({'start': int(match.group(1), 16), 'end': int(match.group(2), 16),
                            'prio': int(match.group(3)), 'kind': match.group(4),
                            'name': match.group(5),
                            'offset': int(match.group(6), 16) if match.group(6) else None})
    require(inside, 'HMP info mtree lists system memory')
    return entries


def expected_layout(aperture, no_device):
    """Board map v3 must produce: views inside the aperture above it, others plain."""
    if no_device:
        return {'views': [], 'aperture_pieces': [] if not aperture else
                [(aperture['base'], aperture['base'] + aperture['size'] - 1)]}
    base = aperture['base'] if aperture else None
    end = base + aperture['size'] if aperture else None
    views = sorted((address, address + 3, 1 if aperture and base <= address < end else 0)
                   for address in VIEW_ADDRESSES)
    pieces = []
    if aperture:
        cursor = base
        for address in sorted(a for a in VIEW_ADDRESSES if base <= a < end):
            if address > cursor:
                pieces.append((cursor, address - 1))
            cursor = address + 4
        if cursor < end:
            pieces.append((cursor, end - 1))
    return {'views': views, 'aperture_pieces': pieces}


def check_memory_layout(qmp, aperture, no_device):
    tree_text = qmp.request('human-monitor-command', {'command-line': 'info mtree'})
    flat_text = qmp.request('human-monitor-command', {'command-line': 'info mtree -f'})
    tree, flat = mtree_section(tree_text, False), mtree_section(flat_text, True)
    expected = expected_layout(aperture, no_device)
    views = sorted((e['start'], e['end'], e['prio']) for e in tree if e['name'] == REGION)
    require(views == expected['views'], 'SLC views at planned addresses and priorities: ' +
            str([(hex(a), hex(b), p) for a, b, p in views]))
    require(all(e['kind'] == 'i/o' for e in tree if e['name'] == REGION), 'SLC views are I/O')
    flat_views = sorted((e['start'], e['end'], e['prio']) for e in flat if e['name'] == REGION)
    require(flat_views == expected['views'], 'Every SLC view is visible in the flat view')
    apertures = [e for e in tree if e['name'] == APERTURE_REGION]
    require(len(apertures) == (1 if aperture else 0) and
            all((e['start'], e['end'], e['prio']) ==
                (aperture['base'], aperture['base'] + aperture['size'] - 1, 0)
                for e in apertures), 'Compatibility aperture present exactly with the served tree')
    pieces = sorted((e['start'], e['end']) for e in flat if e['name'] == APERTURE_REGION)
    require(pieces == expected['aperture_pieces'],
            'Flat view: aperture minus exactly the SLC views inside it: ' +
            str([(hex(a), hex(b)) for a, b in pieces]))
    for e in flat:
        if e['name'] == APERTURE_REGION:
            require((e['offset'] or 0) == e['start'] - aperture['base'],
                    'Aperture pieces keep their aperture offsets')
    return {'slc_views': [{'start': hex(a), 'end': hex(b), 'prio': p} for a, b, p in views],
            'priority_1_views': [hex(a) for a, _, p in views if p == 1],
            'plainly_mapped_views': [hex(a) for a, _, p in views if p == 0],
            'aperture_flat_pieces': [[hex(a), hex(b)] for a, b in pieces],
            'aperture_present': bool(apertures)}


def flush(plane):
    return AMCC + plane * PLANE + 0x2844


def field(ways):
    return ((ways & 0x7f) << 24) | ((ways & 0x7f) << 8)


def served_aperture(tree):
    """Aperture and CTRR bound offsets from the served ADT, as map_amcc reads them."""
    nodes, _ = mailbox.metadata.parse_adt(tree)
    node = nodes.get('/chosen/lock-regs/amcc', {})
    if 'aperture-phys-addr' not in node:
        return None
    base = struct.unpack('<Q', node['aperture-phys-addr']['value'])[0]
    size = struct.unpack('<I', node['aperture-size']['value'])[0]
    banks = []
    for name in BANKS:
        props = nodes.get('/chosen/lock-regs/amcc/' + name, {})
        if 'lower-limit-reg-offset' not in props:
            banks.append(None)
            continue
        banks.append(tuple(struct.unpack('<I', props[key]['value'])[0]
                           for key in ('lower-limit-reg-offset', 'upper-limit-reg-offset')))
    return {'base': base, 'size': size, 'banks': banks}


class QMP(helper.QMP):
    def require_immutable(self, name):
        before = self.request('qom-get', {'path': '/machine', 'property': name})
        attempted = not before if isinstance(before, bool) else before ^ 0xffffffffffffffff
        self.guard()
        self.sequence += 1
        request = {'execute': 'qom-set', 'id': self.sequence,
                   'arguments': {'path': '/machine', 'property': name,
                                 'value': attempted}}
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
                    'Creation-only board property must reject mutation: ' + name)
            error = response['error']
            require(error.get('class') == 'GenericError' and error.get('desc') ==
                    'apple-modern properties are fixed after initialization',
                    'Mutation rejection must identify initialized board properties')
            after = self.request('qom-get', {'path': '/machine', 'property': name})
            require(after == before, 'Rejected board mutation leaves value unchanged')
            return {'before': before, 'attempted': attempted, 'after': after,
                    'error': error}
        raise RuntimeError('Creation-only property deadline')

    def require_migration_blocked(self, target):
        self.guard()
        self.sequence += 1
        request = {'execute': 'migrate', 'id': self.sequence,
                   'arguments': {'uri': 'file:' + str(target)}}
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
                    'Migration must reject the SLC request state')
            error = response['error']
            require('apple-modern-mcc-slc' in error.get('desc', '') and
                    'non-migratable' in error.get('desc', ''),
                    'Migration rejection must identify the SLC state')
            require(not target.exists(), 'No partial migration file')
            return error
        raise RuntimeError('Migration rejection deadline')


class ROM(helper.ROM):
    def __init__(self, aperture, bank_c_reset):
        super().__init__()
        self.aperture = aperture
        self.bank_c_reset = bank_c_reset
        self.accepted_reads = 0
        self.accepted_writes = 0
        self.faults = []
        self.first_load_pc = None
        self.bounds = []

    def pc(self):
        return mailbox.BASE + (len(self.words) - 1) * 4

    def load(self, address, width):
        self.mov(1, address)
        opcode = {1: 0x39400000, 2: 0x79400000, 4: 0xb9400000, 8: 0xf9400000}[width]
        self.emit(opcode | (1 << 5) | 23)

    def store(self, *args):
        if len(args) == 2:  # Scratch result store, as in the base emitter.
            return super().store(*args)
        address, value, width = args
        self.mov(1, address)
        self.mov(0, value)
        opcode = {1: 0x39000000, 2: 0x79000000, 4: 0xb9000000, 8: 0xf9000000}[width]
        self.emit(opcode | (1 << 5))

    def check_value(self, name, address, value, width=4, slc_reads=1):
        """slc_reads: accepted SLC transactions (0 for aperture-only loads)."""
        self.load(address, width)
        if self.first_load_pc is None:
            self.first_load_pc = self.pc()
        self.accepted_reads += slc_reads
        self.trace(name, value, register=23)

    def slc_write(self, address, value):
        self.store(address, value, 4)
        self.accepted_writes += 1

    def aperture_write(self, address, value, width):
        self.store(address, value, width)

    def fault(self, kind, address, width, esr, reason):
        if kind == 'read':
            self.load(address, width)
        else:
            self.store(address, 0x5a5a5a5aa5a5a5a5, width)
        self.faults.append({'kind': kind, 'address': address, 'width': width,
                            'pc': self.pc(), 'esr': esr, 'reason': reason})

    def check_planes(self, prefix, ways):
        for plane in range(PLANES):
            self.check_value(f'{prefix}_status_{plane}', status(plane), field(ways))
            self.check_value(f'{prefix}_flush_{plane}', flush(plane), 0)

    def check_bounds(self, prefix, values):
        for (bank, which, address), value in zip(self.bounds, values):
            self.check_value(f'{prefix}_ctrr_{bank}_{which}', address, value, 8, 0)

    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)  # mov sp,x0
        self.emit(0xd5034fdf)  # mask all interrupts
        self.set('VBAR_EL2', mailbox.BASE + VECTOR_OFFSET)
        # Reset: the 12-way handover state is reported powered (0x0c000c00).
        # Planes 1..3 first: unmapped when off.
        for plane in (1, 2, 3, 0):
            self.check_value(f'reset_status_{plane}', status(plane), field(RESET_WAYS))
            self.check_value(f'reset_flush_{plane}', flush(plane), 0)
        reset_bounds = []
        if self.aperture:
            base = self.aperture['base']
            for index, offsets in enumerate(self.aperture['banks']):
                if offsets is None:
                    continue
                for which, offset in zip(('lower', 'upper'), offsets):
                    self.bounds.append((BANKS[index], which, base + offset))
                    reset_bounds.append(self.bank_c_reset[which == 'upper']
                                        if index == 2 else 0)
            self.check_bounds('reset', reset_bounds)
            self.check_value('aperture_offset0_reset', base, 0, 8, 0)
        # mccEnableCacheMode + mccWaitForWaysPwrOn: [30:24] then [14:8] per plane.
        self.slc_write(WAYS, DRIVER_WAYS)
        for plane in range(PLANES):
            self.check_value(f'ways_upper_field_{plane}', status(plane), field(DRIVER_WAYS))
            self.check_value(f'ways_lower_field_{plane}', status(plane), field(DRIVER_WAYS))
        self.slc_write(BYPASS, 0)
        # cacheFlush: +0x82c = 1, +0x2844 = 1, then each plane's bit 0 clear.
        self.slc_write(BYPASS, 1)
        self.slc_write(FLUSH_REQUEST, 1)
        for plane in range(PLANES):
            self.check_value(f'flush_complete_{plane}', flush(plane), 0)
        # Stored requests report only bits [6:0] in each status field.
        for ways in (0xffffffff, 0x80, 0x7f, 0x8c, RESET_WAYS, DRIVER_WAYS):
            self.slc_write(WAYS, ways)
            self.check_planes(f'ways_{ways:x}', ways)
        # Distinct 32-bit values for the QOM control-82c / flush-request cells;
        # the status is re-checked below (after_faults) and stays 12-way.
        self.slc_write(BYPASS, FINAL_82C)
        self.slc_write(FLUSH_REQUEST, FINAL_FLUSH)
        if self.aperture:
            base = self.aperture['base']
            # (b) CTRR bound registers store and read back full 64-bit values.
            written = []
            for position, (bank, which, address) in enumerate(self.bounds):
                value = 0xc7a0000000000000 | position << 40 | (address & 0xffff) << 8 | 0x5a
                self.aperture_write(address, value, 8)
                written.append(value)
            self.check_bounds('written', written)
            self.aperture_write(base, 0xffffffff, 4)
            self.check_value('aperture_offset0_ignores_stores', base, 0, 4, 0)
            # (a) Plane 0's carved cells are the SLC, not the aperture's zero.
            self.check_value('plane0_status_is_slc', status(0), field(DRIVER_WAYS))
            # (c) Neighbours of the carved cells still read zero from the
            # aperture and ignore stores; the SLC is not disturbed.
            for offset in (0x2800, 0x2808, 0x2840, 0x2848):
                self.check_value(f'aperture_{offset:x}_reads_zero', base + offset, 0, 4, 0)
                self.aperture_write(base + offset, 0xffffffff, 4)
                self.check_value(f'aperture_{offset:x}_ignores_store', base + offset, 0, 4, 0)
            for offset in (0x2808, 0x2848):
                self.check_value(f'aperture_{offset:x}_reads_zero_64', base + offset, 0, 8, 0)
            self.check_value('plane0_status_after_aperture_stores', status(0),
                             field(DRIVER_WAYS))
            self.check_value('plane0_flush_after_aperture_stores', flush(0), 0)
            # Measured QEMU behaviour: MMIO dispatch does not clamp a
            # transaction to the flat-view section it starts in, only to the
            # starting region's own access size. An aligned 64-bit access
            # that starts in the aperture at +0x2800/+0x2840 is therefore
            # answered wholly by the aperture (reads zero, store ignored), and
            # the carved SLC cell in its upper half is never consulted. The
            # driver only issues 32-bit accesses here.
            for offset in (0x2800, 0x2840):
                self.check_value(f'wide64_aperture_{offset:x}_shadows_slc', base + offset,
                                 0, 8, 0)
                self.aperture_write(base + offset, 0xffffffffffffffff, 8)
            self.check_value('plane0_status_after_wide_stores', status(0), field(DRIVER_WAYS))
            self.check_value('plane0_flush_after_wide_stores', flush(0), 0)
        else:
            for offset in (0x2800, 0x2808, 0x2840, 0x2848):
                self.fault('read', AMCC + offset, 4, READ_FAULT_ESR,
                           'no aperture: plane-0 neighbour is unmapped')
            for offset in (0x2800, 0x2840):
                self.fault('read', AMCC + offset, 8, READ_FAULT_ESR,
                           'no aperture: straddling 64-bit plane-0 load is rejected')
            self.fault('write', AMCC + 0x2800, 8, WRITE_FAULT_ESR,
                       'no aperture: straddling 64-bit plane-0 store is rejected')
        for address in (WAYS, BYPASS, FLUSH_REQUEST):
            self.fault('read', address, 4, ACCESS_READ_ESR, 'write-only global cell load')
        for plane in range(PLANES):
            self.fault('write', status(plane), 4, ACCESS_WRITE_ESR, 'read-only way-status store')
            self.fault('write', flush(plane), 4, ACCESS_WRITE_ESR, 'read-only flush-status store')
        self.fault('write', WAYS, 8, WRITE_FAULT_ESR, '64-bit global store')
        self.fault('write', BYPASS, 2, WRITE_FAULT_ESR, '16-bit global store')
        self.fault('write', FLUSH_REQUEST, 1, WRITE_FAULT_ESR, '8-bit global store')
        self.fault('read', WAYS, 8, READ_FAULT_ESR, '64-bit global load')
        for plane in range(1, PLANES):
            self.fault('read', status(plane) - 4, 8, READ_FAULT_ESR,
                       'straddling 64-bit plane status load')
        self.fault('read', flush(1) - 4, 8, READ_FAULT_ESR, 'straddling 64-bit plane flush load')
        self.fault('write', status(2) - 4, 8, WRITE_FAULT_ESR, 'straddling 64-bit plane store')
        # The status cells sit at 4 mod 8: a 64-bit access there is an
        # architectural alignment fault on every plane, before any MMIO.
        for plane in range(PLANES):
            self.fault('read', status(plane), 8, ALIGN_READ_ESR, 'misaligned 64-bit status load')
        self.fault('read', flush(0), 8, ALIGN_READ_ESR, 'misaligned 64-bit flush load')
        self.fault('write', status(0), 8, ALIGN_WRITE_ESR, 'misaligned 64-bit status store')
        self.fault('write', BYPASS, 8, ALIGN_WRITE_ESR, 'misaligned 64-bit bypass store')
        self.fault('read', status(0), 2, READ_FAULT_ESR, '16-bit plane-0 status load')
        self.fault('read', flush(2), 2, READ_FAULT_ESR, '16-bit plane flush load')
        self.fault('read', status(3), 1, READ_FAULT_ESR, '8-bit plane status load')
        for address in (WAYS, BYPASS, FLUSH_REQUEST):
            for neighbour in (address - 4, address + 4):
                self.fault('read', neighbour, 4, READ_FAULT_ESR, 'unmapped global neighbour')
        for plane in range(1, PLANES):
            for address in (status(plane), flush(plane)):
                for neighbour in (address - 4, address + 4):
                    self.fault('read', neighbour, 4, READ_FAULT_ESR, 'unmapped plane neighbour')
        self.fault('write', WAYS + 4, 4, WRITE_FAULT_ESR, 'unmapped global neighbour store')
        self.fault('read', status(1) + 2, 4, ALIGN_READ_ESR, 'misaligned plane load')
        self.fault('write', WAYS + 2, 4, ALIGN_WRITE_ESR, 'misaligned global store')
        # Every rejected operation left the SLC (and the aperture) unchanged.
        self.check_planes('after_faults', DRIVER_WAYS)
        if self.aperture:
            self.check_bounds('after_faults', written)
        self.mov(0, DONE)
        self.trace('completion', DONE)
        self.branch(len(self.words))
        require(len(self.words) * 4 < VECTOR_OFFSET, 'Owned main code precedes vectors')
        for offset in range(VECTOR_OFFSET, VECTOR_OFFSET + 0x800, 0x80):
            self.at(offset)
            self.emit(0xf9400000 | (FAULT_META // 8 << 10) | (20 << 5))
            self.emit(0xf100001f | (len(self.faults) << 10))  # cmp x0,#fault bound
            self.emit(0x54000043)  # b.lo +8; otherwise halt without log overflow
            self.emit(0x14000000)
            self.emit(0xd53c4029)  # mrs x9,ELR_EL2
            self.emit(0x8b00128a)  # add x10,x20,x0,lsl #4
            self.emit(0xf9000000 | (FAULT_LOG // 8 << 10) | (10 << 5) | 9)
            self.emit(mailbox.sysreg('ESR_EL2', 9, True))
            self.emit(0xf9000000 | ((FAULT_LOG + 8) // 8 << 10) | (10 << 5) | 9)
            self.emit(0xb50000a0)  # cbnz x0,skip first-fault capture
            self.emit(0xd53c4029)  # reread ELR; x9 previously held ESR
            self.store(9, FAULT_META + 0x18)
            self.emit(mailbox.sysreg('ESR_EL2', 9, True))
            self.store(9, FAULT_META + 0x20)
            self.emit(0x91000400)  # add x0,x0,#1
            self.store(0, FAULT_META)
            self.emit(mailbox.sysreg('ESR_EL2', 0, True))
            self.store(0, FAULT_META + 8)
            self.emit(0xd53c4020)  # mrs x0,ELR_EL2
            self.store(0, FAULT_META + 0x10)
            self.emit(0x91001000)  # add x0,x0,#4
            self.emit(0xd51c4020)  # msr ELR_EL2,x0
            self.emit(0xd69f03e0)  # eret
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < FAULT_META,
                'Owned ROM/results/fault ranges stay separate')
        require(FAULT_LOG + len(self.faults) * 16 <= SCRATCH_SIZE,
                'Exact fault pairs fit initialized scratch')
        pin = PIN_APERTURE if self.aperture else PIN_PLAIN
        require((len(self.faults), self.accepted_reads, self.accepted_writes) == pin,
                'Owned ROM operation accounting')
        return b''.join(struct.pack('<I', value) for value in self.words)


# (faults, accepted SLC reads, accepted SLC writes) for each tree shape.
PIN_APERTURE = (51, 81, 12)
PIN_PLAIN = (58, 76, 12)


def run(binary, components, dtree, output, no_device):
    assets = {name: (dtree if name == 'dtree' and dtree else components / name)
              for name in board.ASSETS}
    hashes = {name: digest(path) for name, path in assets.items()}
    blobs = {name: path.read_bytes() for name, path in assets.items()}
    layout = board.expected_layout(blobs)
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch outside preparation assets: ' + name)
    require(mailbox.DRAM <= mailbox.BASE < mailbox.PROBE_END <=
            mailbox.DRAM + board.RAM_SIZE, 'Owned ROM lies in modern DRAM')
    require(shutil.disk_usage(output).free >= 64 << 20, 'Minimum evidence space')
    aperture = served_aperture(blobs['dtree'])
    if aperture:
        # The board carves exactly these two cells; the rest of this gate
        # assumes the matched served geometry.
        require(aperture['base'] == AMCC and aperture['size'] == 0x4000 and
                aperture['banks'] == [(0x10, 0x20), (0x110, 0x120), (0x210, 0x220),
                                      (0x310, 0x320)],
                'Served compatibility aperture geometry')
    # Bank C mirrors ACC_CTRR_C: DeviceTree first page .. SPTM-rx last page.
    tree_region, sptm_rx = layout['regions']['DeviceTree'], layout['regions']['SPTM-rx']
    bank_c = (tree_region[0], sptm_rx[0] + sptm_rx[1] - 0x1000)
    rom = ROM(aperture, bank_c)
    content = rom.build()
    rom_path = output / 'owned-mcc-slc.rom'
    rom_path.write_bytes(content)
    zero = bytes(SCRATCH_SIZE)
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(zero)
    machine = 'apple-modern,' + ','.join(name + '=' + str(assets[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true'
    if not no_device:
        machine += ',modern-mcc-slc=on'
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    report = {'passed': False, 'argv': argv, 'binary_sha256': digest(binary),
              'script_sha256': digest(Path(__file__)), 'rom_sha256': digest(rom_path),
              'dtree': str(assets['dtree']), 'firmware_executed': False,
              'ios_boot_claim': False,
              'compatibility_aperture': None if not aperture else {
                  'base': hex(aperture['base']), 'size': hex(aperture['size']),
                  'ctrr_offsets': {bank: [hex(v) for v in offsets] for bank, offsets
                                   in zip(BANKS, aperture['banks']) if offsets},
                  'bank_c_reset': [hex(v) for v in bank_c]},
              'reset_requested_ways': hex(RESET_WAYS),
              'reset_way_status': hex(field(RESET_WAYS)),
              'reset_state_is_analogy': 'm1n1 PR #664, per-plane readback on '
                                        't604x/t8140-family Macs (machine not stated)',
              'broadcast_is_declared_profile': True,
              'immediate_power_and_flush_completion_is_declared_profile': True,
              'cache_model_connected': False,
              'component_hashes_before': hashes, 'no_device_oracle': no_device,
              'child_reaped': False,
              'expected_counters': dict(zip(COUNTERS, (rom.accepted_reads,
                                                      rom.accepted_writes))) | FINAL_CELLS,
              'expected_reset_cells': RESET_CELLS,
              'passes': []}
    process = qmp = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='mcc-slc-mmio-') as temp, \
             (output / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, bufsize=0,
                preexec_fn=mailbox.child_limits)

            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and (output / 'emulator.log').stat().st_size < mailbox.MAX_LOG,
                        'SLC gate wall/log bound')
                return remaining
            qmp = QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}) is True,
                    'Only owned ROM may execute')
            require(qmp.request('qom-get', {'path': '/machine',
                    'property': 'modern-mcc-slc'}) == (not no_device),
                    'SLC option matches oracle')
            for other in ('modern-mcc-quota', 'modern-mcc-perf', 'modern-mcc-socni',
                          'modern-mcc-socni-command', 'modern-mcc-dcs-perf',
                          'modern-mcc-dsid', 'modern-mcc-dramcfg', 'modern-pmgr'):
                require(qmp.request('qom-get', {'path': '/machine', 'property': other}) is False,
                        'Only the device under test is enabled: ' + other)
            if no_device:
                report['default_off_validated'] = True
            else:
                report['immutable_property_checks'] = {
                    name: qmp.require_immutable(name) for name in ('modern-mcc-slc',)}
                report['migration_rejection'] = qmp.require_migration_blocked(
                    Path(temp) / 'migration.state')
            report['memory_layout'] = check_memory_layout(qmp, aperture, no_device)
            for iteration in range(2):
                if iteration:
                    qmp.request('system_reset')
                regs = board.parse_registers(qmp.request('human-monitor-command',
                                                     {'command-line': 'info registers'}))
                require(regs['PC'] == mailbox.BASE and regs['PSTATE'] & 15 == 9,
                        'Owned ROM PC and EL2h selected before cont')
                require(qmp.request('query-status')['running'] is False,
                        'Owned CPU stopped before cont')
                readonly = {}
                if not no_device:
                    names = COUNTERS + CELLS
                    reset = {name: qmp.request('qom-get', {'path': QOM_PATH,
                             'property': name}) for name in names}
                    require(reset == dict.fromkeys(COUNTERS, 0) | RESET_CELLS,
                            'Diagnostics and cells reset exactly: ' + str(reset))
                    readonly = {name: qmp.require_readonly(QOM_PATH, name)
                                for name in names}
                    require({name: qmp.request('qom-get', {'path': QOM_PATH,
                             'property': name}) for name in names} == reset,
                            'Rejected qom-set leaves every SLC property unchanged')
                verify = Path(temp) / 'verify.bin'
                for address, expected in ((mailbox.BASE, content), (mailbox.SCRATCH, zero)):
                    qmp.request('pmemsave', {'val': address, 'size': len(expected),
                                            'filename': str(verify)})
                    require(verify.read_bytes() == expected,
                            'Exact owned ROM/results verified before cont')
                qmp.request('cont')
                deadline = time.monotonic() + 10
                dump = Path(temp) / 'results.bin'
                while True:
                    guard()
                    qmp.request('stop')
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH, 'size': SCRATCH_SIZE,
                                            'filename': str(dump)})
                    raw = dump.read_bytes()
                    (output / f'results-pass{iteration}.bin').write_bytes(raw)
                    fault, esr, elr = struct.unpack_from('<3Q', raw, FAULT_META)
                    if fault:
                        first = struct.unpack_from('<Q', raw, FAULT_META + 0x18)[0]
                        first_esr = struct.unpack_from('<Q', raw, FAULT_META + 0x20)[0]
                        if no_device:
                            require(first == rom.first_load_pc and first_esr == READ_FAULT_ESR,
                                    'No-device oracle faults at the first plane-1 status load')
                            report['no_device_oracle_validated'] = True
                            report['actual_missing_device_fault'] = {
                                'first_elr': hex(first), 'esr': hex(first_esr),
                                'expected_first_load': hex(rom.first_load_pc)}
                            require(False, 'No-device oracle rejected on actual MMIO fault before diagnostics: ' +
                                    hex(first))
                        require(first == rom.faults[0]['pc'] and first_esr == rom.faults[0]['esr'],
                                'First fault is the first owned rejected operation')
                        matching = [item for item in rom.faults if item['pc'] == elr]
                        require(len(matching) == 1 and esr == matching[0]['esr'],
                                f'Unexpected MMIO fault: ESR={esr:#x}, ELR={elr:#x}')
                    if struct.unpack_from('<Q', raw, (len(rom.expected) - 1) * 8)[0] == DONE:
                        break
                    require(time.monotonic() < deadline, 'Owned ROM completion deadline')
                    qmp.request('cont')
                    time.sleep(0.03)
                observed = {}
                for index, (name, expected) in enumerate(rom.expected.items()):
                    value = struct.unpack_from('<Q', raw, index * 8)[0]
                    require(value == expected,
                            f'{name}: expected {expected:#x}, observed {value:#x}')
                    observed[name] = hex(value)
                require(fault == len(rom.faults) and esr == rom.faults[-1]['esr'] and
                        elr == rom.faults[-1]['pc'], 'All unsupported operations faulted')
                fault_log = list(struct.unpack_from('<' + 'Q' * (2 * len(rom.faults)),
                                                    raw, FAULT_LOG))
                require(fault_log[::2] == [item['pc'] for item in rom.faults] and
                        fault_log[1::2] == [item['esr'] for item in rom.faults],
                        'Every unsupported operation faults at exact PC with exact ESR')
                counters = {name: qmp.request('qom-get', {'path': QOM_PATH,
                            'property': name}) for name in COUNTERS + CELLS}
                require(counters == report['expected_counters'],
                        'Actual accepted MMIO counts and exact SLC cells: ' + str(counters))
                require({name: qmp.request('qom-get', {'path': QOM_PATH, 'property': name})
                         for name in COUNTERS + CELLS} == counters,
                        'QOM reads do not change the diagnostics')
                report['passes'].append({'iteration': iteration,
                    'after_system_reset': bool(iteration), 'counters': counters,
                    'readonly_rejections': readonly,
                    'faults': [{**item, 'address': hex(item['address']),
                                'pc': hex(item['pc']), 'esr': hex(item['esr'])}
                               for item in rom.faults], 'observed': observed})
            qmp.request('quit')
            report['child_exit_code'] = process.wait(timeout=10)
            report['child_reaped'] = process.poll() is not None
            require(report['child_exit_code'] == 0, 'Clean emulator exit')
            process = None
            log.flush()
            text = (output / 'emulator.log').read_text(errors='replace')
            report['board_announcement'] = ANNOUNCEMENT in text
            require(report['board_announcement'] == (not no_device),
                    'Board announces the v4 declared profile exactly when mapped')
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
        if 'board_announcement' not in report and (output / 'emulator.log').is_file():
            report['board_announcement'] = ANNOUNCEMENT in (output / 'emulator.log').read_text(
                errors='replace')
        report['component_hashes_after'] = {name: digest(path) for name, path in assets.items()}
        if report['component_hashes_after'] != hashes:
            report['passed'] = False
            report['error'] = 'Preparation inputs changed'
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in ('passed', 'error', 'elapsed_seconds')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--dtree', type=Path,
                        help='machine dtree instead of <components>/dtree; use the served '
                             'tree with /chosen/lock-regs/amcc to qualify the aperture carve')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--no-device', action='store_true')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    sys.exit(run(args.binary.resolve(), args.components.resolve(),
                 args.dtree.resolve() if args.dtree else None,
                 args.output_dir.resolve(), args.no_device))
