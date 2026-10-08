#!/usr/bin/env python3
"""Actual CPU gate for the sparse AMCC DSID profile cells; no firmware runs.

Preparation inputs are only loaded. An owned AArch64 ROM replays the pinned
BootKC's enableDsidProfileCounters stores and perf slot 3 counter loads, then
checks full-width independent readback, read-only counters, exact external
abort PC/ESR pairs for unmapped neighbours (including plane 1..3 +0x2a010 and
plane 1..3 counters), wrong widths, counter stores and misalignment, and the
whole sequence again after system_reset. The declared profile connects no
DSID event producer, so the counters must stay at the virtual reset value.
v3 changes only plan validation (optional amcc-plane-enable-mask, AMCC-window
bound); the board map is read back (HMP info mtree: nine DSID views at their
planned addresses and spans, priority 0) and the board's declared-profile
warning must appear exactly when the device is mapped.
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
spec = importlib.util.spec_from_file_location('dsid_gate_helpers',
    Path(__file__).with_name('test-apple-modern-pmgr-qemu.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
mailbox, board = helper.mailbox, helper.board
require, digest = helper.require, helper.digest
AMCC = 0x220000000
PLANE = 0x40000
CONTROL = 0x2a000
INTERVAL = 0x2e000
COUNTER = 0x2a058
PLANES = 4
CONFIG = (0x1, 0x8, 0xf, 0x11)  # /arm-io/pmp/iop-pmp-nub mc-dsid-ptd-config
RESET = 0xd51d0123456789ab
DONE = 0xf05e1234face5678
VECTOR_OFFSET = 0xc000
FAULT_META = 0x2400
FAULT_LOG = 0x2500
SCRATCH_SIZE = 0x3000
COUNTERS = ('mmio-read-count', 'mmio-write-count', 'event-update-count')
QOM_PATH = '/machine/mcc-dsid'
REGION = 'apple-modern.mcc-dsid'
ANNOUNCEMENT = ('apple-modern: opt-in sparse AMCC DSID profile cells; counter virtual '
                f'reset 0x{RESET:016x}; no DSID event source connected')
MTREE_LINE = __import__('re').compile(
    r'^\s*([0-9a-f]{16})-([0-9a-f]{16}) \(prio (-?\d+), ([a-z/ -]+)\): (\S+)')


def planned_views():
    views = ([(control(p, 0), 8 * cells(p)) for p in range(PLANES)] +
             [(interval(p), 4) for p in range(PLANES)] + [(counter(0, 0), 16)])
    return sorted((address, address + span - 1, 0) for address, span in views)


def check_memory_layout(qmp, no_device):
    text = qmp.request('human-monitor-command', {'command-line': 'info mtree'})
    lines, inside, views = text.splitlines(), False, []
    for line in lines:
        if not inside:
            inside = line.strip() == 'address-space: memory'
            continue
        if not line.strip():
            break
        match = MTREE_LINE.match(line)
        if match and match.group(5) == REGION:
            views.append((int(match.group(1), 16), int(match.group(2), 16),
                          int(match.group(3))))
    require(inside, 'HMP info mtree lists system memory')
    expected = [] if no_device else planned_views()
    require(sorted(views) == expected, 'DSID views at planned addresses/spans, priority 0: ' +
            str([(hex(a), hex(b), p) for a, b, p in sorted(views)]))
    return [{'start': hex(a), 'end': hex(b), 'prio': p} for a, b, p in sorted(views)]
FAULTS, READS, WRITES = 64, 81, 26  # Owned ROM accounting pin
READ_FAULT_ESR = 0x96000010   # Unmapped or rejected-width load: decode error, EA=0.
WRITE_FAULT_ESR = 0x96000050  # Unmapped or rejected-width store: decode error, WnR.
ACCESS_WRITE_ESR = 0x96000250  # Mapped counter-store rejection: EA and WnR.
ALIGN_READ_ESR = 0x96000021   # CPU Device-memory alignment fault before MMIO.
ALIGN_WRITE_ESR = 0x96000061  # The same for a store (WnR).


def control(plane, cell):
    return AMCC + plane * PLANE + CONTROL + cell * 8


def interval(plane):
    return AMCC + plane * PLANE + INTERVAL


def counter(plane, index):
    return AMCC + plane * PLANE + COUNTER + index * 8


def cells(plane):
    return 3 if plane == 0 else 2


def pattern(plane, cell):
    return 0x8123456789ab000e | plane << 8 | cell << 4


def interval_pattern(plane):
    return 0xa5c3000f | plane << 4


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
                    'Migration must reject the DSID profile state')
            error = response['error']
            require('apple-modern-mcc-dsid' in error.get('desc', '') and
                    'non-migratable' in error.get('desc', ''),
                    'Migration rejection must identify the DSID profile state')
            require(not target.exists(), 'No partial migration file')
            return error
        raise RuntimeError('Migration rejection deadline')


class ROM(helper.ROM):
    def __init__(self):
        super().__init__()
        self.accepted_reads = 0
        self.accepted_writes = 0
        self.faults = []
        self.first_load_pc = None

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

    def check_value(self, name, address, value, width):
        self.load(address, width)
        if self.first_load_pc is None:
            self.first_load_pc = self.pc()
        self.accepted_reads += 1
        self.trace(name, value, register=23)

    def mmio_write(self, address, value, width):
        self.store(address, value, width)
        self.accepted_writes += 1

    def fault(self, kind, address, width, esr, reason):
        if kind == 'read':
            self.load(address, width)
        else:
            self.store(address, RESET ^ 0xffffffffffffffff, width)
        self.faults.append({'kind': kind, 'address': address, 'width': width,
                            'pc': self.pc(), 'esr': esr, 'reason': reason})

    def check_state(self, prefix, controls, intervals):
        for plane in range(PLANES):
            for cell in range(cells(plane)):
                self.check_value(f'{prefix}_control_{plane}_{cell}', control(plane, cell),
                                 controls[plane][cell], 8)
            self.check_value(f'{prefix}_interval_{plane}', interval(plane),
                             intervals[plane], 4)
        for index in range(2):
            self.check_value(f'{prefix}_counter_{index}', counter(0, index), RESET, 8)

    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)  # mov sp,x0
        self.emit(0xd5034fdf)  # mask all interrupts
        self.set('VBAR_EL2', mailbox.BASE + VECTOR_OFFSET)
        # Perf slot 3 samples "DSID 0 Hits"/"DSID 0 Misses" before the enable.
        for index in range(2):
            self.check_value(f'reset_sample_{index}', counter(0, index), RESET, 8)
        controls = [[0] * cells(plane) for plane in range(PLANES)]
        intervals = [0] * PLANES
        self.check_state('reset', controls, intervals)
        # enableDsidProfileCounters, exactly as the guest issued it.
        self.mmio_write(control(0, 2), 0x10000000, 8)
        controls[0][2] = 0x10000000
        for plane in range(PLANES):
            self.mmio_write(interval(plane), 0x100, 4)
            self.mmio_write(control(plane, 1), CONFIG[plane], 8)
            self.mmio_write(control(plane, 0), 0x11 if plane == 0 else 0x1, 8)
            intervals[plane] = 0x100
            controls[plane][1] = CONFIG[plane]
            controls[plane][0] = 0x11 if plane == 0 else 0x1
        # Enabled with no event producer: counters stay at the virtual reset.
        self.check_state('driver', controls, intervals)
        # Full-width independent cells: each store changes only its own cell.
        for plane in range(PLANES):
            for cell in range(cells(plane)):
                self.mmio_write(control(plane, cell), pattern(plane, cell), 8)
                controls[plane][cell] = pattern(plane, cell)
                self.check_value(f'full_control_{plane}_{cell}', control(plane, cell),
                                 pattern(plane, cell), 8)
                if plane + 1 < PLANES and cell < cells(plane + 1):
                    self.check_value(f'next_plane_untouched_{plane}_{cell}',
                                     control(plane + 1, cell), controls[plane + 1][cell], 8)
            self.mmio_write(interval(plane), interval_pattern(plane), 4)
            intervals[plane] = interval_pattern(plane)
            self.check_value(f'full_interval_{plane}', interval(plane),
                             interval_pattern(plane), 4)
        self.check_state('independent', controls, intervals)
        views = ([(control(p, 0), 8 * cells(p), 8) for p in range(PLANES)] +
                 [(interval(p), 4, 4) for p in range(PLANES)] + [(counter(0, 0), 16, 8)])
        for address, span, width in views:
            self.fault('read', address - width, width, READ_FAULT_ESR, 'unmapped preceding neighbour')
            self.fault('read', address + span, width, READ_FAULT_ESR,
                       'unmapped following neighbour' + (' (+0x2a010 off plane 0)'
                       if span == 16 and address != counter(0, 0) else ''))
        for plane in range(1, PLANES):
            self.fault('write', control(plane, 2), 8, WRITE_FAULT_ESR,
                       f'plane {plane} +0x2a010 store is unmapped')
            for index in range(2):
                self.fault('read', counter(plane, index), 8, READ_FAULT_ESR,
                           f'plane {plane} counter {index} is unmapped')
        self.fault('write', control(0, 3), 8, WRITE_FAULT_ESR, 'plane 0 +0x2a018 is unmapped')
        for plane in range(PLANES):
            self.fault('read', control(plane, 0), 4, READ_FAULT_ESR, '32-bit control load')
            self.fault('read', control(plane, 0) + 4, 4, READ_FAULT_ESR, '32-bit control upper load')
            self.fault('write', control(plane, 1), 4, WRITE_FAULT_ESR, '32-bit control store')
            self.fault('read', interval(plane), 8, READ_FAULT_ESR, '64-bit interval load')
            self.fault('write', interval(plane), 8, WRITE_FAULT_ESR, '64-bit interval store')
        self.fault('read', control(0, 2), 2, READ_FAULT_ESR, '16-bit control load')
        self.fault('write', control(0, 2), 2, WRITE_FAULT_ESR, '16-bit control store')
        self.fault('read', interval(0), 2, READ_FAULT_ESR, '16-bit interval load')
        self.fault('write', interval(0), 1, WRITE_FAULT_ESR, '8-bit interval store')
        for index in range(2):
            self.fault('read', counter(0, index), 4, READ_FAULT_ESR, '32-bit counter load')
            self.fault('read', counter(0, index) + 4, 4, READ_FAULT_ESR, '32-bit counter upper load')
            self.fault('write', counter(0, index), 8, ACCESS_WRITE_ESR, 'read-only counter store')
            self.fault('write', counter(0, index), 4, WRITE_FAULT_ESR, '32-bit counter store')
        self.fault('read', control(0, 0) + 4, 8, ALIGN_READ_ESR, 'misaligned 64-bit control load')
        self.fault('write', control(1, 1) + 4, 8, ALIGN_WRITE_ESR, 'misaligned 64-bit control store')
        self.fault('read', interval(2) + 2, 4, ALIGN_READ_ESR, 'misaligned 32-bit interval load')
        self.fault('write', counter(0, 1) + 4, 8, ALIGN_WRITE_ESR, 'misaligned counter store')
        # Every rejected operation left every cell unchanged.
        self.check_state('after_faults', controls, intervals)
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
        require(len(self.faults) == FAULTS and self.accepted_reads == READS and
                self.accepted_writes == WRITES, 'Owned ROM operation accounting')
        return b''.join(struct.pack('<I', value) for value in self.words)


def run(binary, components, dtree, output, no_device):
    assets = {name: (dtree if name == 'dtree' and dtree else components / name)
              for name in board.ASSETS}
    hashes = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes() for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch outside preparation assets: ' + name)
    require(mailbox.DRAM <= mailbox.BASE < mailbox.PROBE_END <=
            mailbox.DRAM + board.RAM_SIZE, 'Owned ROM lies in modern DRAM')
    require(shutil.disk_usage(output).free >= 64 << 20, 'Minimum evidence space')
    rom = ROM()
    content = rom.build()
    rom_path = output / 'owned-mcc-dsid.rom'
    rom_path.write_bytes(content)
    zero = bytes(SCRATCH_SIZE)
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(zero)
    machine = 'apple-modern,' + ','.join(name + '=' + str(assets[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true'
    if not no_device:
        machine += ',modern-mcc-dsid=on,mcc-dsid-reset=' + hex(RESET)
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    report = {'passed': False, 'argv': argv, 'binary_sha256': digest(binary),
              'script_sha256': digest(Path(__file__)), 'rom_sha256': digest(rom_path),
              'dtree': str(assets['dtree']), 'firmware_executed': False,
              'ios_boot_claim': False, 'reset_is_virtual_profile': True,
              'reset_value': hex(RESET), 'physical_reset_contents_known': False,
              'event_producer_connected': False, 'bit_meanings_known': False,
              'driver_values_source': 'enableDsidProfileCounters + mc-dsid-ptd-config',
              'component_hashes_before': hashes, 'no_device_oracle': no_device,
              'child_reaped': False,
              'expected_counters': dict(zip(COUNTERS, (rom.accepted_reads,
                                                      rom.accepted_writes, 0))),
              'passes': []}
    process = qmp = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='mcc-dsid-mmio-') as temp, \
             (output / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, bufsize=0,
                preexec_fn=mailbox.child_limits)

            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and (output / 'emulator.log').stat().st_size < mailbox.MAX_LOG,
                        'DSID gate wall/log bound')
                return remaining
            qmp = QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}) is True,
                    'Only owned ROM may execute')
            require(qmp.request('qom-get', {'path': '/machine',
                    'property': 'modern-mcc-dsid'}) == (not no_device),
                    'DSID option matches oracle')
            for other in ('modern-mcc-quota', 'modern-mcc-perf', 'modern-mcc-socni',
                          'modern-mcc-socni-command', 'modern-mcc-dcs-perf',
                          'modern-mcc-slc', 'modern-mcc-dramcfg', 'modern-pmgr'):
                require(qmp.request('qom-get', {'path': '/machine', 'property': other}) is False,
                        'Only the device under test is enabled: ' + other)
            if no_device:
                report['default_off_validated'] = True
            else:
                report['immutable_property_checks'] = {
                    name: qmp.require_immutable(name)
                    for name in ('modern-mcc-dsid', 'mcc-dsid-reset')}
                report['migration_rejection'] = qmp.require_migration_blocked(
                    Path(temp) / 'migration.state')
            report['memory_layout'] = check_memory_layout(qmp, no_device)
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
                                    'No-device oracle faults at first counter load with exact ESR')
                            report['no_device_oracle_validated'] = True
                            report['actual_missing_device_fault'] = {
                                'first_elr': hex(first), 'esr': hex(first_esr),
                                'expected_first_load': hex(rom.first_load_pc)}
                            require(False, 'No-device oracle rejected on actual MMIO fault before diagnostics: ' +
                                    hex(first))
                        require(first == rom.faults[0]['pc'] and first_esr == rom.faults[0]['esr'],
                                'First fault is exact preceding unmapped neighbour')
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
                            'property': name}) for name in COUNTERS}
                require(counters == report['expected_counters'],
                        'Actual accepted MMIO/event counts: ' + str(counters))
                require({name: qmp.request('qom-get', {'path': QOM_PATH, 'property': name})
                         for name in COUNTERS} == counters,
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
                    'Board announces the declared profile exactly when mapped')
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
                        help='machine dtree instead of <components>/dtree')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--no-device', action='store_true')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    sys.exit(run(args.binary.resolve(), args.components.resolve(),
                 args.dtree.resolve() if args.dtree else None,
                 args.output_dir.resolve(), args.no_device))
