#!/usr/bin/env python3
"""Actual CPU MMIO gate for an explicit owned fuse image; no firmware runs."""
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
BASE = 0x3082c8000
SIZE = 0x4000
DONE = 0xf05e1234face5678
COUNTERS = ('mmio-read-count', 'rejected-write-count')
WRITE_FAULT_ESR = 0x96000250  # same-EL external abort, write, EA=1 (access error)


class ROM(helper.ROM):
    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)
        self.emit(0xd5034fdf)
        self.set('VBAR_EL2', mailbox.BASE + 0x4000)
        for offset in (0, 0x114, 0x124, 0x214, SIZE - 4):
            self.check('word_' + hex(offset), BASE + offset, self.word(offset))
        self.check('doubleword', BASE + 0x118,
                   self.word(0x118) | self.word(0x11c) << 32, wide=True)
        self.write32(BASE + 0x114, 0x5a5a5a5a)
        self.write_pc = mailbox.BASE + (len(self.words) - 1) * 4
        self.check('word_after_rejected_write', BASE + 0x114, self.word(0x114))
        self.mov(0, DONE)
        self.trace('completion', DONE)
        self.branch(len(self.words))
        for offset in range(0x4000, 0x4800, 0x80):
            self.at(offset)
            self.mov(0, 1)
            self.store(0, 0x500)
            self.emit(mailbox.sysreg('ESR_EL2', 0, True))
            self.store(0, 0x508)
            self.emit(0xd53c4020)  # mrs x0,ELR_EL2 (S3_4_C4_C0_1)
            self.store(0, 0x510)
            self.emit(0x91001000)  # add x0,x0,#4
            self.emit(0xd51c4020)  # msr ELR_EL2,x0
            self.emit(0xd69f03e0)  # eret; continue after the rejected store
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < 0x500,
                'Owned ROM/results/fault ranges stay separate')
        return b''.join(struct.pack('<I', value) for value in self.words)

    @staticmethod
    def word(offset):
        return int.from_bytes(owned_image()[offset:offset + 4], 'little')


def owned_image():
    return bytes(((i * 17) ^ (i >> 7) ^ 0xa5) & 255 for i in range(SIZE))


def run(binary, components, output, no_input):
    assets = {name: components / name for name in board.ASSETS}
    hashes = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes() for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch outside preparation assets: ' + name)
    rom = ROM()
    image_path = output / 'owned-fuse-input.bin'
    image_path.write_bytes(owned_image())
    rom_path = output / 'owned-fuse.rom'
    rom_path.write_bytes(rom.build())
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(bytes(0x518))
    machine = 'apple-modern,' + ','.join(name + '=' + str(assets[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true'
    if not no_input:
        machine += ',pmgr-aon-fuse-image=' + str(image_path)
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    report = {'passed': False, 'argv': argv, 'binary_sha256': digest(binary),
              'script_sha256': digest(Path(__file__)), 'firmware_executed': False,
              'ios_boot_claim': False, 'image_is_owned_fixture': True,
              'input_sha256': digest(image_path), 'component_hashes_before': hashes,
              'no_input_oracle': no_input, 'passes': []}
    process = qmp = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='fuse-mmio-') as temp, \
             (output / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, bufsize=0,
                preexec_fn=mailbox.child_limits)
            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and (output / 'emulator.log').stat().st_size < mailbox.MAX_LOG,
                        'Fuse gate wall/log bound')
                return remaining
            qmp = helper.QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}),
                    'Only owned ROM may execute')
            if not no_input:
                blocked = qmp.require_migration_blocked(Path(temp) / 'migration.state')
                require('apple-modern-pmgr-fuse' in blocked['desc'],
                        'Migration rejection identifies the immutable fuse input')
                report['migration_rejection'] = blocked
            for iteration in range(2):
                if iteration:
                    qmp.request('system_reset')
                regs = board.parse_registers(qmp.request('human-monitor-command',
                                                     {'command-line': 'info registers'}))
                require(regs['PC'] == mailbox.BASE, 'Owned ROM PC selected before cont')
                if not no_input:
                    reset = {n: qmp.request('qom-get', {'path': '/machine/pmgr-fuse',
                             'property': n}) for n in COUNTERS}
                    require(reset == dict.fromkeys(COUNTERS, 0), 'Counters reset')
                    for name in COUNTERS:
                        qmp.require_readonly('/machine/pmgr-fuse', name)
                qmp.request('cont')
                deadline = time.monotonic() + 10
                dump = Path(temp) / 'results.bin'
                while True:
                    guard()
                    qmp.request('stop')
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH, 'size': 0x518,
                                            'filename': str(dump)})
                    raw = dump.read_bytes()
                    (output / f'results-pass{iteration}.bin').write_bytes(raw)
                    fault, esr, elr = struct.unpack_from('<3Q', raw, 0x500)
                    if fault:
                        require(esr == WRITE_FAULT_ESR and elr == rom.write_pc,
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
                require(fault == 1 and esr == WRITE_FAULT_ESR and elr == rom.write_pc,
                        'Exactly the owned write instruction faulted')
                counters = {n: qmp.request('qom-get', {'path': '/machine/pmgr-fuse',
                           'property': n}) for n in COUNTERS}
                require(counters == dict(zip(COUNTERS, (8, 1))), 'Actual MMIO read/write counters')
                report['passes'].append({'iteration': iteration, 'counters': counters,
                                        'write_esr': hex(esr), 'observed': observed})
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
        if report['component_hashes_after'] != hashes or digest(image_path) != report['input_sha256']:
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
    parser.add_argument('--no-input', action='store_true')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    sys.exit(run(args.binary.resolve(), args.components.resolve(),
                 args.output_dir.resolve(), args.no_input))
