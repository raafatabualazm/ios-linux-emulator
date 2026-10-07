#!/usr/bin/env python3
"""Qualify PMGR power-cell MMIO and reset with an owned AArch64 ROM.

Apple firmware components are preparation inputs only; only the owned ROM
executes. Both SEP_AON and SEP power cells are selected from the matched T8140
ADT. The gate checks request/actual fields, minimum state, controls, unknown
register handling, 64-bit splitting, read-only counters and reset. A no-device
oracle must fail on MMIO behaviour before instrumented counters are checked.
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
spec = importlib.util.spec_from_file_location(
    'pmgr_transport_helpers',
    Path(__file__).with_name('test-apple-modern-sep-transport-qemu.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
mailbox, board = transport.mailbox, transport.board
require, digest = mailbox.require, mailbox.digest
COUNTERS = ('mmio-read-count', 'mmio-write-count', 'unknown-read-count',
            'unknown-write-count', 'power-transition-count')
FINAL = dict(zip(COUNTERS, (16, 13, 2, 2, 7)))
COMPLETION = 0xfacefeed12345678
AON = 0x300700060
SEP = 0x300700c00
EXISTING_RAM = 0x3082dc000  # Existing SEP reg-block within PMGR container 1.


class QMP(transport.QMP):
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
                    'Migration must reject the unmigratable power-state device')
            error = response['error']
            require('apple-modern-pmgr' in error.get('desc', '') and
                    'non-migratable' in error.get('desc', ''),
                    'Migration rejection must name the PMGR state, not another failure')
            require(not target.exists(), 'No partial migration file was created')
            return error
        raise RuntimeError('PMGR migration-rejection deadline')


class ROM(mailbox.ROM):
    def check(self, name, address, value, wide=False):
        (self.read64 if wide else self.read32)(address, 23)
        self.trace(name, value, register=23)

    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)  # mov sp,x0
        self.emit(0xd5034fdf)  # mask all interrupts
        self.set('VBAR_EL2', mailbox.BASE + 0x4000)
        self.check('aon_reset', AON, 0)
        self.check('sep_reset', SEP, 0)
        self.write32(AON, 0xf)
        self.check('aon_active', AON, 0xff)
        self.write32(SEP, 0xf)
        self.check('sep_active', SEP, 0xff)
        self.write32(SEP, 0x100000ff)
        self.check('sep_auto_control', SEP, 0x100000ff)
        self.write32(SEP, 0x8000040f)
        self.check('sep_reset_control', SEP, 0x800004ff)
        self.write32(SEP, 0x0000040f)
        self.check('sep_disable_control', SEP, 0x000004ff)
        self.write32(SEP, 0x0000000f)
        self.check('sep_controls_cleared', SEP, 0xff)
        self.write32(SEP, 0x00040000)
        self.check('sep_minimum_retention', SEP, 0x00040040)
        self.write32(SEP, 0x000000f0)
        self.check('sep_actual_readonly', SEP, 0)
        self.write64(SEP, 0xffffffffffffffff)
        self.check('sep_doubleword', SEP, 0x900f04ff, wide=True)
        self.write32(SEP + 4, 0xabcdef01)
        self.check('unknown_neighbor', SEP + 4, 0)
        self.check('sep_neighbor_write_ignored', SEP, 0x900f04ff)
        self.write32(AON, 0)
        self.check('aon_off', AON, 0)
        self.write32(SEP, 0)
        self.check('sep_off', SEP, 0)
        # A nonterminating PMGR container must preserve this preexisting RAM
        # leaf in its hole. No real device or firmware uses these owned bytes.
        self.write64(EXISTING_RAM, 0x123456789abcdef0)
        self.check('existing_ram_preserved', EXISTING_RAM,
                   0x123456789abcdef0, wide=True)
        self.mov(0, COMPLETION)
        self.trace('completion', COMPLETION)
        self.branch(len(self.words))
        for offset in range(0x4000, 0x4800, 0x80):
            self.at(offset)
            self.mov(0, 1)
            self.store(0, 0x500)
            self.emit(mailbox.sysreg('ESR_EL2', 0, True))
            self.store(0, 0x508)
            self.emit(0x14000000)
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < 0x500,
                'Owned ROM/result/fault ranges are bounded and separate')
        return b''.join(struct.pack('<I', value) for value in self.words)


def run(binary, components, output, oracle):
    started = time.monotonic()
    assets = {name: components / name for name in board.ASSETS}
    before = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes()
                                    for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch overlaps reserved component: ' + name)
    require(mailbox.DRAM <= mailbox.BASE < mailbox.PROBE_END <=
            mailbox.DRAM + board.RAM_SIZE, 'Owned ROM lies in modern DRAM')
    require(shutil.disk_usage(output).free >= 64 << 20, 'Minimum evidence space')
    rom = ROM()
    content = rom.build()
    rom_path = output / 'pmgr.rom'
    rom_path.write_bytes(content)
    zero = bytes(0x510)
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(zero)
    report = {'scope': 'Owned-ROM PMGR MMIO, counters and reset',
              'binary': str(binary), 'binary_sha256': digest(binary)['sha256'],
              'script_sha256': digest(Path(__file__))['sha256'],
              'rom_sha256': digest(rom_path)['sha256'],
              'component_hashes_before': before, 'firmware_executed': False,
              'ios_boot_claim': False, 'oracle': oracle,
              'aon_physical': hex(AON), 'sep_physical': hex(SEP),
              'passes': [], 'passed': False}
    process = qmp = None
    log_path = output / 'emulator.log'
    try:
        with tempfile.TemporaryDirectory(prefix='pmgr-qemu-gate-') as temp:
            scratch = Path(temp)
            machine = 'apple-modern,' + ','.join(
                name + '=' + str(assets[asset]) for name, asset in
                zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
            enabled = oracle != 'no-device'
            machine += ',prepare-only=true,modern-pmgr=' + ('on' if enabled else 'off')
            argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
                    '-nodefaults', '-display', 'none', '-serial', 'none',
                    '-monitor', 'none', '-device',
                    f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
                    '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
                    '-S', '-qmp', 'stdio']
            report['argv'] = argv
            with log_path.open('xb') as log:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=log,
                                           bufsize=0, preexec_fn=mailbox.child_limits)

                def guard():
                    remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                    require(remaining > 0 and log_path.stat().st_size <= mailbox.MAX_LOG,
                            'PMGR gate wall/log bound exceeded')
                    return remaining

                qmp = QMP(None, guard, process)
                require(qmp.request('qom-get', {'path': '/machine',
                                               'property': 'prepare-only'}) is True,
                        'Preparation mode remains enabled')
                require(qmp.request('qom-get', {'path': '/machine',
                                               'property': 'modern-pmgr'}) == enabled,
                        'PMGR option matches the oracle')
                path = '/machine/pmgr'
                for iteration in range(2):
                    if iteration:
                        qmp.request('system_reset')
                    registers = board.parse_registers(qmp.request(
                        'human-monitor-command', {'command-line': 'info registers'}))
                    require(registers['PC'] == mailbox.BASE and
                            registers['PSTATE'] & 15 == 9,
                            'Owned ROM PC and EL2h selected before cont')
                    require(qmp.request('query-status')['running'] is False,
                            'CPU stopped before owned ROM cont')
                    if enabled:
                        require(transport.values(qmp, path, COUNTERS) ==
                                dict.fromkeys(COUNTERS, 0), 'PMGR counters reset')
                    verify = scratch / 'verify.bin'
                    for address, expected in ((mailbox.BASE, content),
                                               (mailbox.SCRATCH, zero)):
                        qmp.request('pmemsave', {'val': address, 'size': len(expected),
                                                 'filename': str(verify)})
                        require(verify.read_bytes() == expected,
                                'Exact owned ROM/results verified before cont')
                    qmp.request('cont')
                    deadline = time.monotonic() + 10
                    raw_path = scratch / 'result.bin'
                    while True:
                        guard()
                        qmp.request('stop')
                        qmp.request('pmemsave', {'val': mailbox.SCRATCH,
                                                 'size': 0x510,
                                                 'filename': str(raw_path)})
                        raw = raw_path.read_bytes()
                        if struct.unpack_from('<Q', raw,
                            (len(rom.expected) - 1) * 8)[0] == COMPLETION:
                            break
                        require(struct.unpack_from('<Q', raw, 0x500)[0] == 0,
                                'Owned ROM received an unexpected MMIO exception')
                        require(time.monotonic() < deadline, 'Owned ROM did not complete')
                        qmp.request('cont')
                        time.sleep(0.02)
                    observed = {}
                    for i, (label, expected) in enumerate(rom.expected.items()):
                        actual = struct.unpack_from('<Q', raw, i * 8)[0]
                        observed[label] = hex(actual)
                        require(actual == expected,
                                f'{label}: expected {expected:#x}, observed {actual:#x}')
                    require(struct.unpack_from('<2Q', raw, 0x500) == (0, 0),
                            'No unexpected guest exception')
                    counters = transport.values(qmp, path, COUNTERS)
                    require(counters == FINAL, 'Exact MMIO counters: ' + str(counters))
                    require(transport.values(qmp, path, COUNTERS) == counters,
                            'QOM reads do not increment MMIO counters')
                    readonly = {name: qmp.require_readonly(path, name) for name in COUNTERS}
                    migration = qmp.require_migration_blocked(scratch / 'migration.bin')
                    report['passes'].append({'iteration': iteration,
                                             'after_system_reset': bool(iteration),
                                             'observed': observed, 'counters': counters,
                                             'readonly_rejections': readonly,
                                             'migration_rejection': migration})
                qmp.request('quit')
                require(process.wait(timeout=10) == 0, 'Emulator exited cleanly')
                process = None
        report['passed'] = len(report['passes']) == 2
    except Exception as error:
        report['error'] = str(error)
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
        if qmp is not None:
            qmp.close()
        after = {name: digest(path) for name, path in assets.items()}
        report['component_hashes_after'] = after
        if after != before:
            report['passed'] = False
            report['error'] = 'Firmware preparation inputs changed'
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'passes': len(report['passes']),
                      'binary_sha256': report['binary_sha256'],
                      'error': report.get('error')}))
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--oracle', choices=['normal', 'no-device'], default='normal')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    return run(args.binary.resolve(), args.components.resolve(),
               args.output_dir.resolve(), args.oracle)


if __name__ == '__main__':
    sys.exit(main())
