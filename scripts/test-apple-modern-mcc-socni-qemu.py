#!/usr/bin/env python3
"""Actual CPU gate for sparse SOCNI performance snapshots; no firmware runs.

Preparation inputs are only loaded. An owned AArch64 ROM checks exact control/counter
widths, independent controls, counter snapshots, reset and real external
abort syndromes. The virtual profile has no connected hardware event producer.
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
BANK_BASES = (0x24f008000, 0x250008000, 0x251008000)
BANK_COUNTS = (31, 36, 35)
COUNTER_OFFSET = 0x4000
RESET = 0xfedcba9876543210
DONE = 0xf05e1234face5678
VECTOR_OFFSET = 0xc000
FAULT_META = 0x2400
FAULT_LOG = 0x2500
SCRATCH_SIZE = 0x3000
COUNTERS = ('mmio-read-count', 'mmio-write-count', 'event-update-count')
QOM_PATH = '/machine/mcc-socni'
READ_FAULT_ESR = 0x96000010  # Unmapped same-EL synchronous external abort.
WIDTH_FAULT_ESR = 0x96000010  # QEMU rejects 32-bit counter-load transactions.
ALIGNMENT_FAULT_ESR = 0x96000021  # CPU Device-memory alignment fault, before MMIO.
ACCESS_WRITE_ESR = 0x96000250  # Mapped counter-store rejection sets EA and WnR.


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
                    'Migration must reject sparse SOCNI snapshot state')
            error = response['error']
            require('apple-modern-mcc-socni' in error.get('desc', '') and
                    'non-migratable' in error.get('desc', ''),
                    'Migration rejection must identify SOCNI performance state')
            require(not target.exists(), 'No partial migration file')
            return error
        raise RuntimeError('Migration rejection deadline')


class ROM(helper.ROM):
    def __init__(self):
        super().__init__()
        self.accepted_reads = 0
        self.accepted_writes = 0
        self.faults = []

    def check_value(self, name, address, value, width):
        (self.read64 if width == 8 else self.read32)(address, 23)
        self.accepted_reads += 1
        self.trace(name, value, register=23)

    def control_write(self, address, value):
        self.write32(address, value)
        self.accepted_writes += 1

    def check_split_control(self, name, address, low, high):
        # The sparse subpage path clamps each callback transaction to 4 bytes.
        # Qualify the aggregate LDR X result and the two accepted transactions.
        self.read64(address, 23)
        self.accepted_reads += 2
        self.trace(name, low | (high << 32), register=23)

    def fault(self, kind, address, width, esr):
        if kind == 'read':
            (self.read64 if width == 8 else self.read32)(address, 23)
        else:
            require(kind == 'write' and width == 8, 'Owned fault operation')
            self.write64(address, RESET ^ 0xffffffffffffffff)
        self.faults.append({'kind': kind, 'address': address, 'width': width,
                           'pc': mailbox.BASE + (len(self.words) - 1) * 4,
                           'esr': esr})

    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)  # mov sp,x0
        self.emit(0xd5034fdf)  # mask all interrupts
        self.set('VBAR_EL2', mailbox.BASE + VECTOR_OFFSET)
        for bank, count in enumerate(BANK_COUNTS):
            for counter in range(count):
                self.check_value(f'reset_counter_{bank}_{counter}',
                                 BANK_BASES[bank] + COUNTER_OFFSET + counter * 8,
                                 RESET, 8)
                if bank == counter == 0:
                    self.first_load_pc = mailbox.BASE + (len(self.words) - 2) * 4
        for bank, count in enumerate(BANK_COUNTS):
            for counter in range(count):
                self.check_value(f'reset_control_{bank}_{counter}',
                                 BANK_BASES[bank] + counter * 4, 0, 4)
        for bank, count in enumerate(BANK_COUNTS):
            for counter in range(count):
                word = 0x81230000 | bank << 12 | counter << 2
                address = BANK_BASES[bank] + counter * 4
                self.control_write(address, word)
                self.check_value(f'full_control_{bank}_{counter}', address, word, 4)
                # Future neighbors remain reset; on the edge, the preceding
                # control retains its distinct full-width word.
                other = counter + 1 if counter + 1 < count else counter - 1
                expected = 0 if other > counter else 0x81230000 | bank << 12 | other << 2
                self.check_value(f'adjacent_control_{bank}_{counter}',
                                 BANK_BASES[bank] + other * 4, expected, 4)
        for bank, count in enumerate(BANK_COUNTS):
            for counter in range(count):
                self.check_value(f'all_banks_independent_{bank}_{counter}',
                                 BANK_BASES[bank] + counter * 4,
                                 0x81230000 | bank << 12 | counter << 2, 4)
            for counter in (0, 2):
                self.check_split_control(f'split_control_{bank}_{counter}',
                    BANK_BASES[bank] + counter * 4,
                    0x81230000 | bank << 12 | counter << 2,
                    0x81230000 | bank << 12 | (counter + 1) << 2)
        # The observed SOCNI consumer performs independent plain 32-bit stores
        # of 3 and 0, rather than AMCC's shared mask-preserving control RMW.
        for phase, word in [('enable', 3), ('disable', 0)]:
            for bank, count in enumerate(BANK_COUNTS):
                for counter in range(count):
                    address = BANK_BASES[bank] + counter * 4
                    self.control_write(address, word)
                    self.check_value(f'{phase}_{bank}_{counter}', address, word, 4)
        for bank, count in enumerate(BANK_COUNTS):
            for counter in range(count):
                self.check_value(f'counter_after_controls_{bank}_{counter}',
                                 BANK_BASES[bank] + COUNTER_OFFSET + counter * 8,
                                 RESET, 8)
        views = [(base + (COUNTER_OFFSET if kind else 0), count * (8 if kind else 4),
                  8 if kind else 4)
                 for base, count in zip(BANK_BASES, BANK_COUNTS) for kind in range(2)]
        for address, span, width in views:
            for neighbor in (address - width, address + span):
                self.fault('read', neighbor, width, READ_FAULT_ESR)
        for address, span, width in views:
            if width == 8:
                for lane in (address, address + span - 4):
                    self.fault('read', lane, 4, WIDTH_FAULT_ESR)
        for address, span, width in views:
            self.fault('read', address + 1, width, ALIGNMENT_FAULT_ESR)
        for bank, count in enumerate(BANK_COUNTS):
            for counter in range(count):
                self.fault('write', BANK_BASES[bank] + COUNTER_OFFSET + counter * 8,
                           8, ACCESS_WRITE_ESR)
        for bank, count in enumerate(BANK_COUNTS):
            for counter in range(count):
                self.check_value(f'counter_after_rejected_store_{bank}_{counter}',
                                 BANK_BASES[bank] + COUNTER_OFFSET + counter * 8,
                                 RESET, 8)
                self.check_value(f'control_after_faults_{bank}_{counter}',
                                 BANK_BASES[bank] + counter * 4, 0, 4)
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
        require(len(self.faults) == 126 and self.accepted_reads == 1032 and
                self.accepted_writes == 306, 'Owned ROM operation accounting')
        return b''.join(struct.pack('<I', value) for value in self.words)


def run(binary, components, output, no_device):
    assets = {name: components / name for name in board.ASSETS}
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
    rom_path = output / 'owned-mcc-socni.rom'
    rom_path.write_bytes(content)
    zero = bytes(SCRATCH_SIZE)
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(zero)
    machine = 'apple-modern,' + ','.join(name + '=' + str(assets[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true'
    if not no_device:
        machine += ',modern-mcc-socni=on,mcc-socni-reset=' + hex(RESET)
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    report = {'passed': False, 'argv': argv, 'binary_sha256': digest(binary),
              'script_sha256': digest(Path(__file__)), 'rom_sha256': digest(rom_path),
              'firmware_executed': False, 'ios_boot_claim': False,
              'reset_is_virtual_profile': True, 'reset_value': hex(RESET),
              'physical_reset_contents_known': False, 'event_producer_connected': False,
              'enable_value_is_driver_inference': True,
              'component_hashes_before': hashes, 'no_device_oracle': no_device,
              'child_reaped': False,
              'expected_counters': dict(zip(COUNTERS, (rom.accepted_reads,
                                                      rom.accepted_writes, 0))),
              'passes': []}
    process = qmp = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='mcc-socni-mmio-') as temp, \
             (output / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, bufsize=0,
                preexec_fn=mailbox.child_limits)
            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and (output / 'emulator.log').stat().st_size < mailbox.MAX_LOG,
                        'SOCNI performance gate wall/log bound')
                return remaining
            qmp = QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}) is True,
                    'Only owned ROM may execute')
            require(qmp.request('qom-get', {'path': '/machine',
                    'property': 'modern-mcc-socni'}) == (not no_device),
                    'Performance option matches oracle')
            if no_device:
                report['default_off_validated'] = True
            if not no_device:
                report['immutable_property_checks'] = {
                    name: qmp.require_immutable(name)
                    for name in ('modern-mcc-socni', 'mcc-socni-reset')}
                report['migration_rejection'] = qmp.require_migration_blocked(
                    Path(temp) / 'migration.state')
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
                    for name in COUNTERS:
                        qmp.require_readonly(QOM_PATH, name)
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
                                'First fault is exact preceding unmapped neighbor')
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
                require(counters == report['expected_counters'], 'Actual accepted MMIO/event counts')
                report['passes'].append({'iteration': iteration, 'counters': counters,
                    'faults': [{**item, 'address': hex(item['address']),
                                'pc': hex(item['pc']), 'esr': hex(item['esr'])}
                               for item in rom.faults], 'observed': observed})
            qmp.request('quit')
            report['child_exit_code'] = process.wait(timeout=10)
            report['child_reaped'] = process.poll() is not None
            require(report['child_exit_code'] == 0, 'Clean emulator exit')
            process = None
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
    print(json.dumps({key: report.get(key) for key in ('passed', 'error', 'elapsed_seconds')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--no-device', action='store_true')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    sys.exit(run(args.binary.resolve(), args.components.resolve(),
                 args.output_dir.resolve(), args.no_device))
