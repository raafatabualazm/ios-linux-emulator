#!/usr/bin/env python3
"""Actual CPU gate for sparse ordinary DSID quota storage; no firmware runs."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('fuse_gate_helpers',
    Path(__file__).with_name('test-apple-modern-pmgr-qemu.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
mailbox, board = helper.mailbox, helper.board
require, digest = helper.require, helper.digest
BASE = 0x22000a000
SPAN = 128
RESET = 0x5a5a1234
DONE = 0xf05e1234face5678
COUNTERS = ('mmio-read-count', 'mmio-write-count', 'broadcast-write-count')
READ_FAULT_ESR = 0x96000010  # same-EL synchronous external abort on unmapped load
ACCESS_FAULT_ESR = 0x96000210  # mapped handler rejects access, external-abort EA bit


class QMP(helper.QMP):
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
                    'Migration must reject the sparse configuration state')
            error = response['error']
            require('apple-modern-mcc-quota' in error.get('desc', '') and
                    'non-migratable' in error.get('desc', ''),
                    'Migration rejection must identify MCC quota state')
            require(not target.exists(), 'No partial migration file')
            return error
        raise RuntimeError('Migration rejection deadline')


class ROM(helper.ROM):
    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)
        self.emit(0xd5034fdf)
        self.set('VBAR_EL2', mailbox.BASE + 0x4000)
        for plane in range(4):
            for group in (0, 11, 31):
                address = BASE + plane * 0x40000 + group * 4
                self.check(f'reset_{plane}_{group}', address, RESET)
                if plane == group == 0:
                    self.first_load_pc = mailbox.BASE + (len(self.words) - 2) * 4
                word = 0x81234080 | plane << 8 | group
                self.write32(address, word)
                self.check(f'written_{plane}_{group}', address, word)
        self.write32(BASE + 0x100000 + 11 * 4, 0xfedcba98)
        for plane in range(4):
            self.check(f'broadcast_{plane}_11', BASE + plane * 0x40000 + 11 * 4,
                       0xfedcba98)
        self.write32(BASE + 2 * 0x40000 + 11 * 4, 0xa5a5f00d)
        self.check('plane0_independent', BASE + 11 * 4, 0xfedcba98)
        self.check('plane2_changed', BASE + 2 * 0x40000 + 11 * 4, 0xa5a5f00d)
        for plane in range(4):
            for group in (0, 31):
                self.check(f'group_independent_{plane}_{group}',
                           BASE + plane * 0x40000 + group * 4,
                           0x81234080 | plane << 8 | group)
        self.fault_pcs = []
        self.fault_addresses = []
        self.fault_esrs = []
        for view in range(5):
            for address in (BASE + view * 0x40000 - 4,
                            BASE + view * 0x40000 + SPAN):
                self.read32(address, 23)
                self.fault_pcs.append(mailbox.BASE + (len(self.words) - 1) * 4)
                self.fault_addresses.append(address)
                self.fault_esrs.append(READ_FAULT_ESR)
        # The global quota read view is deliberately unqualified, even though
        # its write view is mapped. This must raise a real CPU external abort.
        self.read32(BASE + 0x100000 + 11 * 4, 23)
        self.fault_pcs.append(mailbox.BASE + (len(self.words) - 1) * 4)
        self.fault_addresses.append(BASE + 0x100000 + 11 * 4)
        self.fault_esrs.append(ACCESS_FAULT_ESR)
        self.check('word_after_faults', BASE + 11 * 4, 0xfedcba98)
        self.write32(BASE + 0x100000 + 31 * 4, 0xffffffff)
        for plane in range(4):
            self.check(f'edge_broadcast_{plane}_31', BASE + plane * 0x40000 + 31 * 4,
                       0xffffffff)
        self.mov(0, DONE)
        self.trace('completion', DONE)
        self.branch(len(self.words))
        for offset in range(0x4000, 0x4800, 0x80):
            self.at(offset)
            self.emit(0xf9400000 | (0x500 // 8 << 10) | (20 << 5))
            self.emit(0xd53c4029)  # mrs x9,ELR_EL2
            self.emit(0x8b00128a)  # add x10,x20,x0,lsl #4 (PC/ESR fault log)
            self.emit(0xf9000000 | (0x600 // 8 << 10) | (10 << 5) | 9)
            self.emit(mailbox.sysreg('ESR_EL2', 9, True))
            self.emit(0xf9000000 | (0x608 // 8 << 10) | (10 << 5) | 9)
            self.emit(0xb50000a0)  # cbnz x0,skip first-fault capture (5 instructions)
            self.emit(0xd53c4029)  # mrs x9,ELR_EL2 for first-fault capture
            self.store(9, 0x518)
            self.emit(mailbox.sysreg('ESR_EL2', 9, True))
            self.store(9, 0x520)
            self.emit(0x91000400)  # add x0,x0,#1
            self.store(0, 0x500)
            self.emit(mailbox.sysreg('ESR_EL2', 0, True))
            self.store(0, 0x508)
            self.emit(0xd53c4020)  # mrs x0,ELR_EL2
            self.store(0, 0x510)
            self.emit(0x91001000)  # add x0,x0,#4
            self.emit(0xd51c4020)  # msr ELR_EL2,x0
            self.emit(0xd69f03e0)  # eret
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < 0x500,
                'Owned ROM/results/fault ranges stay separate')
        return b''.join(struct.pack('<I', value) for value in self.words)


def run(binary, components, output, no_device):
    assets = {name: components / name for name in board.ASSETS}
    hashes = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes() for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch outside preparation assets: ' + name)
    rom = ROM()
    rom_path = output / 'owned-mcc-quota.rom'
    rom_path.write_bytes(rom.build())
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(bytes(0x700))
    machine = 'apple-modern,' + ','.join(name + '=' + str(assets[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true'
    if not no_device:
        machine += ',modern-mcc-quota=on,mcc-quota-reset=' + hex(RESET)
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    report = {'passed': False, 'argv': argv, 'binary_sha256': digest(binary),
              'script_sha256': digest(Path(__file__)), 'firmware_executed': False,
              'ios_boot_claim': False, 'reset_is_virtual_profile': True,
              'reset_value': hex(RESET), 'broadcast_is_virtual_inference': True,
              'physical_reset_contents_known': False, 'component_hashes_before': hashes,
              'no_device_oracle': no_device, 'passes': []}
    process = qmp = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='mcc-mmio-') as temp, \
             (output / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, bufsize=0,
                preexec_fn=mailbox.child_limits)
            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and (output / 'emulator.log').stat().st_size < mailbox.MAX_LOG,
                        'MCC gate wall/log bound')
                return remaining
            qmp = QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}),
                    'Only owned ROM may execute')
            if not no_device:
                blocked = qmp.require_migration_blocked(Path(temp) / 'migration.state')
                require('apple-modern-mcc-quota' in blocked['desc'],
                        'Migration rejection identifies the sparse MCC quota state')
                report['migration_rejection'] = blocked
            for iteration in range(2):
                if iteration:
                    qmp.request('system_reset')
                regs = board.parse_registers(qmp.request('human-monitor-command',
                                                     {'command-line': 'info registers'}))
                require(regs['PC'] == mailbox.BASE, 'Owned ROM PC selected before cont')
                if not no_device:
                    reset = {n: qmp.request('qom-get', {'path': '/machine/mcc-quota',
                             'property': n}) for n in COUNTERS}
                    require(reset == dict.fromkeys(COUNTERS, 0), 'Counters reset')
                    for name in COUNTERS:
                        qmp.require_readonly('/machine/mcc-quota', name)
                qmp.request('cont')
                deadline = time.monotonic() + 10
                dump = Path(temp) / 'results.bin'
                while True:
                    guard()
                    qmp.request('stop')
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH, 'size': 0x700,
                                            'filename': str(dump)})
                    raw = dump.read_bytes()
                    (output / f'results-pass{iteration}.bin').write_bytes(raw)
                    fault, esr, elr = struct.unpack_from('<3Q', raw, 0x500)
                    if fault:
                        first = struct.unpack_from('<Q', raw, 0x518)[0]
                        if no_device:
                            require(first == rom.first_load_pc and
                                    struct.unpack_from('<Q', raw, 0x520)[0] == READ_FAULT_ESR,
                                    'No-device oracle must fault at the first owned load with the exact external-abort ESR')
                            report['no_device_oracle_validated'] = True
                            report['actual_missing_device_fault'] = {
                                'first_elr': hex(first), 'esr': hex(struct.unpack_from('<Q', raw, 0x520)[0]),
                                'expected_first_load': hex(rom.first_load_pc)}
                            require(False, 'No-device oracle rejected on actual MMIO fault before diagnostics: ' +
                                    hex(first))
                        require(first == rom.fault_pcs[0], 'First fault is preceding unmapped neighbor')
                        require(elr in rom.fault_pcs and
                                esr == rom.fault_esrs[rom.fault_pcs.index(elr)],
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
                require(fault == len(rom.fault_pcs) and esr == ACCESS_FAULT_ESR and
                        elr == rom.fault_pcs[-1], 'All unsupported loads faulted')
                fault_log = list(struct.unpack_from('<' + 'Q' * (2 * len(rom.fault_pcs)), raw, 0x600))
                require(fault_log[::2] == rom.fault_pcs and fault_log[1::2] == rom.fault_esrs,
                        'Every unsupported load faulted at its exact PC with its exact ESR')
                counters = {n: qmp.request('qom-get', {'path': '/machine/mcc-quota',
                           'property': n}) for n in COUNTERS}
                require(counters == dict(zip(COUNTERS, (43, 15, 2))), 'Actual MMIO read/write counters')
                report['passes'].append({'iteration': iteration, 'counters': counters,
                                        'unsupported_read_esrs': [hex(v) for v in fault_log[1::2]],
                                        'fault_pcs': [hex(v) for v in fault_log[::2]],
                                        'fault_addresses': [hex(v) for v in rom.fault_addresses],
                                        'observed': observed})
            qmp.request('quit')
            require(process.wait(timeout=10) == 0, 'Clean emulator exit')
            process = None
            report['passed'] = len(report['passes']) == 2
    except Exception as error:
        report['error'] = str(error)
    finally:
        if process:
            process.kill(); process.wait(timeout=10)
        if qmp:
            qmp.close()
        report['component_hashes_after'] = {name: digest(path) for name, path in assets.items()}
        if report['component_hashes_after'] != hashes:
            report['passed'] = False; report['error'] = 'Preparation inputs changed'
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
