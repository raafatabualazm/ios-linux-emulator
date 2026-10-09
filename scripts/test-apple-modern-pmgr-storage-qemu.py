#!/usr/bin/env python3
"""Actual CPU MMIO gate for the declared PMGR storage and CPU DVFM windows.

An owned AArch64 ROM (the only code that runs; Apple components are preparation
inputs) loads and stores through the machine's address space and records, for
every access, the value read and whether it took an external abort. A Python
reference model of the planned register set predicts every result. Two runs:

  default:    modern-pmgr-storage=on,modern-cpu-dvfm=on  -> the model's accepted
              accesses succeed, hole / past-the-end / status-word accesses fault,
              the QOM read/write counters equal the model's, and a system reset
              restores zero values and zero counters (two passes are identical).
  --no-device negative oracle: both options off -> the very first access faults
              and no later access succeeds, so the on-run's results cannot come
              from anything but the devices.
"""
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
spec = importlib.util.spec_from_file_location('storage_gate_helpers',
    Path(__file__).with_name('test-apple-modern-pmgr-qemu.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
mailbox, board = helper.mailbox, helper.board
require, digest = helper.require, helper.digest

SENTINEL = 0x5e57e11a5e57e11a
FLAG = 0x800          # fault flag written by the owned vector handler
LAST_ESR = 0x808
LAST_ELR = 0x810
RESULT_BYTES = 0x818
DONE = 0xf05e1234face5678
ESR_DATA_ABORT_SAME_EL = 0x25
ESR_SYNC_EXTERNAL_ABORT = 0x10     # DFSC

G6 = 0x30827b800                   # PMGRCLKGEN_AON_TOP + 0x7b800
G7 = 0x3082b4000                   # PMGR_AON + 0x34000
WAKE = 0x308004008                 # NUB_FR_GLOBAL_AP_CONTROLS + 0x8
PTD = 0x3003c0000                  # PMS_PTS_PTD: banks at +0x18200, +0x18300, config +0x18400
CLUSTER = 0x300780000              # PMGR_SOC_CLUSTER_CTL +0x0 and +0x4
PWRGATE = 0x300724000              # PMGR_SOC_PWRGATE +0x0 and +0x40
DPE = 0x300208000                  # PMGR_SOC_DPE: ten channels of 3 registers (channel 7: 2)
DVFM_WINDOWS = (0x210e78000, 0x211e78000, 0x210e70000, 0x211e70000)
DVFM_SPAN = 0x1000


def storage_registers():
    regs = {G6 + 0, G7 + 0}
    regs |= {G6 + 0x100 + 0x20 * k for k in range(6)}
    regs |= {G7 + 0x100 + 0x20 * k for k in range(69)}
    regs |= {WAKE + 4 * i for i in range(8)}
    regs |= {PTD + 0x18200 + 4 * i for i in range(32)}
    regs |= {PTD + 0x18300 + 4 * i for i in range(32)}
    regs |= {PTD + 0x18400 + 4 * i for i in range(256)}
    regs |= {CLUSTER, CLUSTER + 4, PWRGATE, PWRGATE + 0x40}
    for channel in range(10):
        base = DPE + 0x2400 + 0x400 * channel
        regs |= {base + 0x200, base + 0x300}
        if channel != 7:
            regs.add(base)
    return regs


class Model:
    """Reference model of what the two devices accept; None means 'faults'."""

    def __init__(self, enabled):
        self.enabled = enabled
        self.values = {}
        self.regs = storage_registers() if enabled else set()
        self.reads = {'dvfm': 0, 'storage': 0}
        self.writes = {'dvfm': 0, 'storage': 0}

    def device(self, address, size):
        if not self.enabled or size not in (4, 8) or address % size:
            return None
        for window in DVFM_WINDOWS:
            if window <= address and address + size <= window + DVFM_SPAN:
                return 'dvfm'
        if all(address + 4 * s in self.regs for s in range(size // 4)):
            return 'storage'
        return None

    def read(self, address, size):
        kind = self.device(address, size)
        if kind is None:
            return None
        self.reads[kind] += 1
        value = 0
        for s in range(size // 4):
            value |= self.values.get(address + 4 * s, 0) << (32 * s)
        return value

    def write(self, address, size, value):
        kind = self.device(address, size)
        if kind is None:
            return False
        self.writes[kind] += 1
        for s in range(size // 4):
            self.values[address + 4 * s] = (value >> (32 * s)) & 0xffffffff
        return True


# (operation, address, value) in program order.
PROGRAM = [
    ('r64', 0x210e700a8, None),                 # the step-1 frontier
    ('w64', 0x210e700a8, 0x00001234_56789abc),
    ('r64', 0x210e700a8, None),
    ('r32', 0x210e700a8, None),
    ('r32', 0x210e700ac, None),
    ('r64', 0x211e700d8, None),
    ('w32', 0x211e700d8, 0xa5a5a5a5),
    ('r64', 0x211e700d8, None),
    ('r64', 0x210e78048, None),                 # a state-table window
    ('w64', 0x210e78048, 0x1f << 38),
    ('r64', 0x210e78048, None),
    ('r64', 0x210e70ff8, None),                 # last word of a control page
    ('r32', 0x210e71000, None),                 # first byte past it
    ('r32', 0x210e6fffc, None),                 # last word before it
    ('r64', 0x211e70f00, None),
    ('r32', G7 + 0x100, None),                  # the step-2 frontier
    ('w32', G7 + 0x100, 4),
    ('r32', G7 + 0x100, None),
    ('r32', G7 + 0x104, None),                  # hole inside the window
    ('w32', G7 + 0x104, 0x77),
    ('r32', G7 + 0x104, None),
    ('r64', G7 + 0x100, None),                  # 8 bytes over a hole
    ('r32', G7 + 0x980, None),                  # last listed register
    ('w32', G7 + 0x980, 0x80000000),
    ('r32', G7 + 0x980, None),
    ('r32', G7 + 0x984, None),                  # past the end
    ('r32', G7 + 0x7c0, None),
    ('r32', G7 + 0x7e4, None),
    ('r32', G7 - 4, None),
    ('r32', G7 + 0, None),
    ('w32', G7 + 0, 2),
    ('r32', G7 + 0, None),
    ('r32', G6 + 0, None),
    ('w32', G6 + 0, 2),
    ('r32', G6 + 0, None),
    ('r32', G6 + 0x1a0, None),
    ('r32', G6 + 0x1c0, None),
    ('r32', G6 + 0xfc, None),
    ('w32', WAKE, 0xdeadbeef),                  # the step-3 frontier
    ('r64', WAKE, None),
    ('w64', WAKE + 8, 0x1122334455667788),
    ('r32', WAKE + 0xc, None),
    ('r64', WAKE + 0x18, None),
    ('r32', WAKE + 0x20, None),                 # status words: not listed
    ('r32', WAKE - 4, None),
    ('r64', 0x308004000, None),
    ('w32', WAKE + 0x20, 1),
    ('r32', PTD + 0x18400, None),               # the step-4 frontier
    ('w32', PTD + 0x18400, 0x1300),
    ('r32', PTD + 0x18400, None),
    ('w32', PTD + 0x18600, 0x00ff0000),
    ('r64', PTD + 0x18600, None),               # two adjacent config words
    ('r32', PTD + 0x187fc, None),               # last config word
    ('r32', PTD + 0x18800, None),               # past the config array
    ('w32', PTD + 0x18200, 0x20),               # enable-set bank
    ('r32', PTD + 0x18200, None),
    ('w32', PTD + 0x1827c, 0x80000000),
    ('r32', PTD + 0x18280, None),               # past the set bank
    ('w32', PTD + 0x18300, 0x20),               # enable-clear bank
    ('r32', PTD + 0x18300, None),
    ('r32', PTD + 0x183fc, None),               # between the clear bank and the config array
    ('r32', PTD + 0x18100, None),               # the enable register: not listed
    ('r32', PTD + 0x18000, None),               # the status bank: not listed
    ('r64', PTD + 0x18000, None),
    ('r32', CLUSTER, None),                     # the step-5 frontier
    ('w32', CLUSTER, 0xf),                      # (v & ~0xf) | 0xf
    ('r32', CLUSTER, None),                     # the wait polls (v & 0x10) == 0
    ('r32', CLUSTER + 4, None),                 # the step-6 frontier (index 1)
    ('w32', CLUSTER + 4, 0xf),
    ('r64', CLUSTER, None),                     # both registers in one access
    ('r32', CLUSTER + 8, None),                 # past them
    ('r64', CLUSTER + 8, None),
    ('r32', CLUSTER - 4, None),
    ('r32', PWRGATE, None),                     # the step-7 frontier
    ('w32', PWRGATE, 0x80000000),
    ('r32', PWRGATE, None),
    ('r32', PWRGATE + 0x40, None),
    ('w32', PWRGATE + 0x40, 0x80000000),
    ('r32', PWRGATE + 0x40, None),
    ('r32', PWRGATE + 4, None),                 # neighbours: not listed
    ('r32', PWRGATE + 0x44, None),
    ('r32', PWRGATE + 0x3c, None),
    ('r32', DPE + 0x2600, None),                # the step-8 frontier (channel 0, +0x200)
    ('w32', DPE + 0x2600, 1),
    ('r32', DPE + 0x2600, None),
    ('r32', DPE + 0x2400, None),
    ('w32', DPE + 0x2400, 1),
    ('r32', DPE + 0x2700, None),
    ('r32', DPE + 0x2404, None),                # hole
    ('r32', DPE + 0x2500, None),                # hole
    ('r64', DPE + 0x2600, None),                # 8 bytes over a hole
    ('r32', DPE + 0x4000, None),                # channel 7 has no +0x0
    ('r32', DPE + 0x4200, None),
    ('w32', DPE + 0x4300, 1),
    ('r32', DPE + 0x4300, None),
    ('r32', DPE + 0x4400, None),                # channel 8
    ('r32', DPE + 0x4b00, None),                # last register
    ('r32', DPE + 0x4b04, None),                # past it
    ('r32', DPE + 0x23fc, None),                # before the first channel
]


def expected_results(enabled):
    """Per-probe expected (value or None, faulted) plus the final counters."""
    model = Model(enabled)
    out = []
    for op, address, value in PROGRAM:
        size = 8 if op.endswith('64') else 4
        if op[0] == 'r':
            got = model.read(address, size)
            out.append((op, address, got, got is None))
        else:
            ok = model.write(address, size, value)
            out.append((op, address, None, not ok))
    return out, model


class ROM(helper.ROM):
    def probe(self, number, op, address, value, expected):
        _, _, got, faulted = expected
        tag = f'{number:03d}:{op}@{address:#x}'
        self.store(31, FLAG)                          # str xzr,[x20,#FLAG]
        if op[0] == 'r':
            self.mov(23, SENTINEL)
            (self.read64 if op == 'r64' else self.read32)(address, 23)
            self.trace(tag, SENTINEL if got is None else got, register=23)
        else:
            (self.write64 if op == 'w64' else self.write32)(address, value)
        self.emit(0xf9400000 | ((FLAG // 8) << 10) | (20 << 5) | 22)  # ldr x22,[x20,#FLAG]
        self.trace(tag + '.fault', int(faulted), register=22)

    def build(self, enabled):
        results, _ = expected_results(enabled)
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)
        self.emit(0xd5034fdf)
        self.set('VBAR_EL2', mailbox.BASE + 0x4000)
        for number, ((op, address, value), expected) in enumerate(zip(PROGRAM, results)):
            self.probe(number, op, address, value, expected)
        self.mov(0, DONE)
        self.trace('completion', DONE)
        self.branch(len(self.words))
        for offset in range(0x4000, 0x4800, 0x80):
            self.at(offset)
            self.mov(0, 1)
            self.store(0, FLAG)
            self.emit(mailbox.sysreg('ESR_EL2', 0, True))
            self.store(0, LAST_ESR)
            self.emit(0xd53c4020)  # mrs x0,ELR_EL2
            self.store(0, LAST_ELR)
            self.emit(0x91001000)  # add x0,x0,#4
            self.emit(0xd51c4020)  # msr ELR_EL2,x0
            self.emit(0xd69f03e0)  # eret; continue after the rejected access
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < FLAG,
                'Owned ROM/results/fault ranges stay separate')
        return b''.join(struct.pack('<I', value) for value in self.words)


def run(binary, components, output, no_device):
    started = time.monotonic()
    enabled = not no_device
    assets = {name: components / name for name in board.ASSETS}
    hashes = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes() for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch outside preparation assets: ' + name)
    rom = ROM()
    rom_path = output / 'owned-storage.rom'
    rom_path.write_bytes(rom.build(enabled))
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(bytes(RESULT_BYTES))
    expected, model = expected_results(enabled)
    machine = 'apple-modern,' + ','.join(name + '=' + str(assets[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true'
    if enabled:
        machine += ',modern-cpu-dvfm=on,modern-pmgr-storage=on'
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    report = {'passed': False, 'argv': argv, 'binary_sha256': digest(binary),
              'script_sha256': digest(Path(__file__)), 'rom_sha256': digest(rom_path),
              'firmware_executed': False, 'ios_boot_claim': False,
              'no_device_oracle': no_device, 'probes': len(PROGRAM),
              'expected_faults': sum(1 for e in expected if e[3]),
              'component_hashes_before': hashes, 'passes': []}
    process = qmp = None
    try:
        with tempfile.TemporaryDirectory(prefix='pmgr-storage-gate-') as temp, \
             (output / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, bufsize=0,
                preexec_fn=mailbox.child_limits)

            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and (output / 'emulator.log').stat().st_size < mailbox.MAX_LOG,
                        'Storage gate wall/log bound')
                return remaining
            qmp = helper.QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}),
                    'Only owned ROM may execute')
            for prop in ('modern-cpu-dvfm', 'modern-pmgr-storage'):
                require(qmp.request('qom-get', {'path': '/machine', 'property': prop}) == enabled,
                        prop + ' matches the oracle')
            for iteration in range(2):
                if iteration:
                    qmp.request('system_reset')
                regs = board.parse_registers(qmp.request('human-monitor-command',
                                                     {'command-line': 'info registers'}))
                require(regs['PC'] == mailbox.BASE, 'Owned ROM PC selected before cont')
                if enabled:
                    for path in ('/machine/cpu-dvfm', '/machine/pmgr-storage'):
                        for prop in ('mmio-read-count', 'mmio-write-count'):
                            require(qmp.request('qom-get', {'path': path, 'property': prop}) == 0,
                                    f'{path} {prop} reset')
                qmp.request('cont')
                deadline = time.monotonic() + 20
                dump = Path(temp) / 'results.bin'
                while True:
                    guard()
                    qmp.request('stop')
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH, 'size': RESULT_BYTES,
                                            'filename': str(dump)})
                    raw = dump.read_bytes()
                    (output / f'results-pass{iteration}.bin').write_bytes(raw)
                    if struct.unpack_from('<Q', raw, (len(rom.expected) - 1) * 8)[0] == DONE:
                        break
                    require(time.monotonic() < deadline, 'Owned ROM completion deadline')
                    qmp.request('cont')
                    time.sleep(0.03)
                observed = {}
                for index, (name, want) in enumerate(rom.expected.items()):
                    value = struct.unpack_from('<Q', raw, index * 8)[0]
                    require(value == want, f'{name}: expected {want:#x}, observed {value:#x}')
                    observed[name] = hex(value)
                esr = struct.unpack_from('<Q', raw, LAST_ESR)[0]
                faults = [e for e in expected if e[3]]
                if faults:
                    require(esr >> 26 == ESR_DATA_ABORT_SAME_EL and
                            esr & 0x3f == ESR_SYNC_EXTERNAL_ABORT,
                            f'Last fault is not a synchronous external data abort: {esr:#x}')
                counters = {}
                if enabled:
                    for path, kind in (('/machine/cpu-dvfm', 'dvfm'),
                                       ('/machine/pmgr-storage', 'storage')):
                        got = {prop: qmp.request('qom-get', {'path': path, 'property': prop})
                               for prop in ('mmio-read-count', 'mmio-write-count')}
                        require(got == {'mmio-read-count': model.reads[kind],
                                        'mmio-write-count': model.writes[kind]},
                                f'{path} counters {got} != {model.reads[kind]}/{model.writes[kind]}')
                        counters[path] = got
                else:
                    successes = [e for e in expected if not e[3]]
                    require(not successes, 'Without the devices no access may succeed')
                    require(all(e[3] for e in expected), 'Every access faults without the devices')
                report['passes'].append({'iteration': iteration, 'counters': counters,
                                         'last_fault_esr': hex(esr),
                                         'faults': len(faults), 'observed': len(observed)})
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
