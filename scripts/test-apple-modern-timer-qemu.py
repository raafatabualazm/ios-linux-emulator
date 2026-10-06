#!/usr/bin/env python3
"""Exercise Darwin-compatible Apple timer views with an owned AArch64 ROM.

Uses ordinary QMP over child stdio pipes, without sockets, Apple firmware,
guest patches or host semihosting. Checks opt-in isolation, real instructions,
generic-timer expiry/status, ordinary access faults, VHE aliases and reset.
Apple offset/control hardware effects and migration are not qualified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import struct
import subprocess
import tempfile
import time


RAM = 0x40000000
REGS = {
    'HCR_EL2': (3, 4, 1, 1, 0), 'VBAR_EL2': (3, 4, 12, 0, 0),
    'VBAR_EL1': (3, 0, 12, 0, 0), 'ELR_EL2': (3, 4, 4, 0, 1),
    'ELR_EL1': (3, 0, 4, 0, 1), 'ESR_EL2': (3, 4, 5, 2, 0),
    'ESR_EL1': (3, 0, 5, 2, 0), 'SPSR_EL2': (3, 4, 4, 0, 0),
    'CNTHCTL_EL2': (3, 4, 14, 1, 0), 'CNTVOFF_EL2': (3, 4, 14, 0, 3),
    'CNTKCTL_EL1': (3, 0, 14, 1, 0), 'CNTFRQ_EL0': (3, 3, 14, 0, 0),
    'CNTPCT_EL0': (3, 3, 14, 0, 1), 'CNTVCT_EL0': (3, 3, 14, 0, 2),
    'CNTP_CTL_EL0': (3, 3, 14, 2, 1), 'CNTV_CTL_EL0': (3, 3, 14, 3, 1),
    'CNTP_TVAL_EL0': (3, 3, 14, 2, 0), 'CNTV_TVAL_EL0': (3, 3, 14, 3, 0),
    'CNTP_CVAL_EL0': (3, 3, 14, 2, 2), 'CNTV_CVAL_EL0': (3, 3, 14, 3, 2),
    'AGTCNTP_CTL_EL0': (3, 1, 15, 13, 4),
    'AGTCNTV_CTL_EL0': (3, 1, 15, 0, 5),
    'AGTCNTP_TVAL_EL0': (3, 1, 15, 11, 4),
    'AGTCNTV_TVAL_EL0': (3, 1, 15, 15, 4),
    'ACNTPCT_EL0': (3, 4, 15, 10, 5), 'ACNTVCT_EL0': (3, 4, 15, 10, 6),
    'AGTCNTPCT_EL0': (3, 4, 15, 11, 6), 'AGTCNTVCT_EL0': (3, 4, 15, 11, 7),
    'AGTCNTVOFF_EL2': (3, 1, 15, 9, 4),
    'AGTCNTKCTL_EL1': (3, 4, 15, 9, 6),
    'AGTCNTRDIR_EL1': (3, 1, 15, 1, 5),
    'AGTCNTRDIR_EL2': (3, 4, 15, 14, 5),
    'AGTCNTRDIR_EL12': (3, 4, 15, 14, 6),
}
APPLE = [name for name in REGS if name.startswith(('AGT', 'ACNT'))]


def sysreg(name, register, read):
    op0, op1, crn, crm, op2 = REGS[name]
    return (0xd5000000 | (int(read) << 21) | (op0 << 19) | (op1 << 16)
            | (crn << 12) | (crm << 8) | (op2 << 5) | register)


class ROM:
    def __init__(self, enabled):
        self.words = []
        self.expected = {}
        self.enabled = enabled

    def emit(self, word):
        self.words.append(word)

    def mov(self, register, value):
        for half in range(4):
            self.emit((0xd2800000 if half == 0 else 0xf2800000)
                      | (half << 21) | (((value >> (half * 16)) & 0xffff) << 5)
                      | register)

    def set(self, name, value):
        self.mov(0, value)
        self.emit(sysreg(name, 0, False))

    def store(self, register, offset):
        assert offset % 8 == 0 and offset < 32768
        self.emit(0xf9000000 | ((offset // 8) << 10) | (20 << 5) | register)

    def trace(self, label, expected, name=None, register=0):
        if name:
            self.emit(sysreg(name, register, True))
        self.store(register, len(self.expected) * 8)
        self.expected[label] = expected

    def handler(self, el, at):
        while len(self.words) * 4 < at:
            self.emit(0)
        assert len(self.words) * 4 == at
        self.emit(0x910006b5)  # add x21,x21,#1
        self.emit(sysreg(f'ESR_EL{el}', 22, True))
        self.store(22, 0x300 if el == 2 else 0x308)
        self.emit(sysreg(f'ELR_EL{el}', 23, True))
        self.emit(0x910012f7)  # add x23,x23,#4
        self.emit(sysreg(f'ELR_EL{el}', 23, False))
        self.emit(0xd69f03e0)

    def counter_views(self, kind):
        names = ('CNTPCT_EL0', 'ACNTPCT_EL0', 'AGTCNTPCT_EL0', 'CNTPCT_EL0')
        if kind == 'virt':
            names = tuple(name.replace('PCT', 'VCT') for name in names)
        for index, name in enumerate(names):
            self.trace(f'{kind}_counter_{index}', None, name)

    def expiry(self, kind):
        p = 'P' if kind == 'phys' else 'V'
        # 1000 ticks is 1us at the deterministic 1GHz test frequency.
        self.set(f'AGTCNT{p}_TVAL_EL0', 1000)
        self.set(f'AGTCNT{p}_CTL_EL0', 3)  # enable, mask interrupt output
        self.trace(f'{kind}_enable_shared', 3, f'CNT{p}_CTL_EL0')
        self.trace(f'{kind}_tval_arch', None, f'CNT{p}_TVAL_EL0')
        self.trace(f'{kind}_tval_apple', None, f'AGTCNT{p}_TVAL_EL0')
        self.emit(sysreg(f'CNT{p}_CVAL_EL0', 2, True))
        poll = len(self.words)
        self.emit(sysreg(f'AGTCNT{p}CT_EL0', 3, True))
        self.emit(0xeb02007f)  # cmp x3,x2
        self.emit(0x54000003 | (((poll - len(self.words)) & 0x7ffff) << 5))  # b.lo
        self.trace(f'{kind}_expired_arch', 7, f'CNT{p}_CTL_EL0')
        self.trace(f'{kind}_expired_apple', 7, f'AGTCNT{p}_CTL_EL0')
        self.set(f'CNT{p}_CTL_EL0', 0)
        self.trace(f'{kind}_disable_shared', 0, f'AGTCNT{p}_CTL_EL0')

    def build(self):
        self.mov(20, RAM)
        self.mov(21, 0)
        self.store(31, 0x300)
        self.store(31, 0x308)
        self.set('HCR_EL2', 1 << 31)
        self.set('CNTHCTL_EL2', 3)
        self.set('VBAR_EL2', 0x2000)
        self.set('VBAR_EL1', 0x3000)
        self.trace('frequency', 1_000_000_000, 'CNTFRQ_EL0')
        if not self.enabled:
            for name in APPLE:
                self.emit(sysreg(name, 0, True))
            self.trace('disabled_apple_faults', len(APPLE), register=21)
        else:
            for name in ('AGTCNTVOFF_EL2', 'AGTCNTKCTL_EL1',
                         'AGTCNTRDIR_EL1', 'AGTCNTRDIR_EL2'):
                self.trace('reset_' + name, 0, name)
            for name in ('AGTCNTP_CTL_EL0', 'AGTCNTV_CTL_EL0'):
                self.trace('reset_' + name, 0, name)
            self.set('AGTCNTVOFF_EL2', 0xfedcba9876543210)
            self.trace('offset_store', 0xfedcba9876543210, 'AGTCNTVOFF_EL2')
            self.trace('architectural_offset_unchanged', 0, 'CNTVOFF_EL2')
            self.set('AGTCNTKCTL_EL1', 0x1234567890abcdef)
            self.trace('kctl_store', 0x1234567890abcdef, 'AGTCNTKCTL_EL1')
            self.trace('architectural_access_control_unchanged', 0, 'CNTKCTL_EL1')
            self.set('AGTCNTRDIR_EL1', 0x1111)
            self.set('AGTCNTRDIR_EL2', 0x2222)
            self.trace('rdir_bank1', 0x1111, 'AGTCNTRDIR_EL1')
            self.set('HCR_EL2', (1 << 31) | (1 << 34))
            self.trace('rdir_e2h_redirect', 0x2222, 'AGTCNTRDIR_EL1')
            self.trace('rdir_el12_bank1', 0x1111, 'AGTCNTRDIR_EL12')
            self.set('AGTCNTRDIR_EL12', 0x3333)
            self.set('HCR_EL2', 1 << 31)
            self.trace('rdir_alias_write_bank1', 0x3333, 'AGTCNTRDIR_EL1')
            self.trace('rdir_independent_bank2', 0x2222, 'AGTCNTRDIR_EL2')
            self.counter_views('phys')
            self.counter_views('virt')
            self.expiry('phys')
            self.expiry('virt')
            self.emit(sysreg('AGTCNTRDIR_EL12', 0, True))  # UNDEF without E2H
            self.emit(sysreg('AGTCNTPCT_EL0', 0, False))  # read-only counter
            self.trace('el2_access_faults', 2, register=21)
            self.set('SPSR_EL2', 0x3c5)  # ordinary EL1h, interrupts masked
            fixup = len(self.words)
            self.mov(0, 0)
            self.emit(sysreg('ELR_EL2', 0, False))
            self.emit(0xd69f03e0)
            target = len(self.words) * 4
            for half in range(4):
                self.words[fixup + half] = ((0xd2800000 if half == 0 else 0xf2800000)
                    | (half << 21) | (((target >> (16 * half)) & 0xffff) << 5))
            self.emit(sysreg('AGTCNTVOFF_EL2', 0, True))  # PL2 only
            self.emit(sysreg('AGTCNTRDIR_EL2', 0, True))
            self.trace('el1_kctl_store', 0x1234567890abcdef, 'AGTCNTKCTL_EL1')
            self.trace('total_access_faults', 4, register=21)
        self.mov(0, 0xfeedfacecafebeef)
        self.trace('completion', 0xfeedfacecafebeef)
        terminal = len(self.words) * 4
        self.emit(0x14000000)
        assert terminal < 0x2000 and len(self.expected) * 8 < 0x300
        self.handler(2, 0x2200)
        self.handler(1, 0x3200)
        return b''.join(struct.pack('<I', word) for word in self.words), terminal


class QMP:
    def __init__(self, process):
        self.process = process
        self.buffer = b''
        self.sequence = 0
        if 'QMP' not in self.read(5):
            raise RuntimeError('Invalid QMP greeting')
        self.request('qmp_capabilities')

    def read(self, timeout=3):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError('QMP response timeout')
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                raise RuntimeError('QMP closed before response')
            self.buffer += data
        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line)

    def request(self, command, arguments=None):
        self.sequence += 1
        message = {'execute': command, 'id': self.sequence}
        if arguments is not None:
            message['arguments'] = arguments
        self.process.stdin.write(json.dumps(message).encode() + b'\n')
        self.process.stdin.flush()
        deadline = time.monotonic() + 5
        while True:
            result = self.read(max(0.01, deadline - time.monotonic()))
            if result.get('id') == self.sequence:
                if 'error' in result:
                    raise RuntimeError(str(result['error']))
                return result['return']
            if time.monotonic() >= deadline:
                raise RuntimeError('QMP command deadline')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(rom, values):
    actual = dict(zip(rom.expected, values))
    for label, expected in rom.expected.items():
        if expected is not None and actual[label] != expected:
            raise RuntimeError(f'{label}: expected {expected:#x}, got {actual[label]:#x}')
    if rom.enabled:
        for kind in ('phys', 'virt'):
            counters = [actual[f'{kind}_counter_{i}'] for i in range(4)]
            if counters != sorted(counters) or counters[-1] - counters[0] > 1000:
                raise RuntimeError(f'{kind}: counter views do not share the deterministic clock')
            arch = actual[f'{kind}_tval_arch']
            apple = actual[f'{kind}_tval_apple']
            if not 0 < apple <= arch <= 1000:
                raise RuntimeError(f'{kind}: TVAL views do not share the countdown')
    if values[0x300 // 8] >> 26 or values[0x308 // 8] >> 26:
        raise RuntimeError('Access faults did not report ordinary UNDEF')
    return actual


def run(binary, output):
    report = {'scope': 'Owned ROM only; Darwin-compatible simplified timer model',
              'binary_sha256': digest(binary), 'passes': [], 'passed': False,
              'ios_boot_claim': False, 'apple_hardware_fidelity_claim': False}
    try:
        for enabled in (False, True):
            rom = ROM(enabled)
            content, terminal = rom.build()
            name = 'enabled' if enabled else 'disabled'
            rom_path = output / f'{name}.rom'
            rom_path.write_bytes(content)
            args = [str(binary), '-M', 'virt,virtualization=on,secure=off',
                    '-cpu', f'max,has_el2=on,has_el3=off,apple-modern-timers={"on" if enabled else "off"},cntfrq=1000000000',
                    '-m', '128M', '-smp', '1', '-bios', str(rom_path),
                    '-nodefaults', '-display', 'none', '-serial', 'none',
                    '-monitor', 'none', '-S', '-icount', 'shift=0,sleep=off', '-qmp', 'stdio']
            with (output / f'{name}-emulator.log').open('wb') as log:
                process = subprocess.Popen(args, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=log)
                try:
                    qmp = QMP(process)
                    for iteration in range(2):
                        if iteration:
                            qmp.request('system_reset')
                        deadline = time.monotonic() + 3
                        while True:
                            regs = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                            pc = re.search(r'PC=([0-9a-fA-F]+)', regs)
                            if pc and int(pc[1], 16) == 0:
                                break
                            if time.monotonic() > deadline:
                                raise RuntimeError('Reset did not reach ROM entry')
                            time.sleep(0.02)
                        qmp.request('cont')
                        deadline = time.monotonic() + 5
                        while True:
                            regs = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                            pc = re.search(r'PC=([0-9a-fA-F]+)', regs)
                            if pc and int(pc[1], 16) == terminal:
                                break
                            if time.monotonic() > deadline:
                                (output / f'{name}-failed-registers.txt').write_text(regs)
                                raise RuntimeError('Owned ROM did not reach completion')
                            time.sleep(0.02)
                        qmp.request('stop')
                        dump = output / f'{name}-ram-{iteration}.bin'
                        qmp.request('pmemsave', {'val': RAM, 'size': 0x310, 'filename': str(dump)})
                        values = struct.unpack('<98Q', dump.read_bytes())
                        actual = verify(rom, values)
                        (output / f'{name}-registers-{iteration}.txt').write_text(regs)
                        report['passes'].append({'enabled': enabled, 'iteration': iteration,
                                                 'actual': actual, 'argv': args,
                                                 'rom_sha256': digest(rom_path)})
                    qmp.request('quit')
                    if process.wait(timeout=5):
                        raise RuntimeError('QEMU returned nonzero')
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
                    process.stdin.close()
                    process.stdout.close()
                    report[f'{name}_child_reaped'] = process.poll() is not None
                    report[f'{name}_exit_code'] = process.returncode
        if digest(binary) != report['binary_sha256']:
            raise RuntimeError('Binary changed during test')
        report['passed'] = True
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit('Binary must be a regular executable')
    if args.output_dir:
        output = args.output_dir.resolve()
        output.mkdir(parents=True, exist_ok=False)
        report = run(binary, output)
    else:
        with tempfile.TemporaryDirectory(prefix='apple-timer-rom-') as directory:
            report = run(binary, Path(directory))
    print(json.dumps({'passed': report['passed'], 'real_cpu_passes': len(report['passes']),
                      'binary_sha256': report['binary_sha256'], 'ios_boot_claim': False}))


if __name__ == '__main__':
    main()
