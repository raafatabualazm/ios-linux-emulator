#!/usr/bin/env python3
"""Execute an owned AArch64 register ROM through public QMP on generic virt.

No Apple firmware, filesystem, guest patch, external service or signing change
is used. This checks real MSR/MRS, exception delivery and reset; it does not
qualify guarded execution, SPTM, a T8140 CPU or iOS boot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
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
    'CurrentEL': (3, 0, 4, 2, 2), 'CURRENTG': (3, 6, 15, 8, 0),
    'ENTRY1': (3, 6, 15, 8, 1), 'ENTRY2': (3, 6, 15, 12, 0),
    'ENTRY12': (3, 6, 15, 15, 2), 'ASPSR1': (3, 6, 15, 10, 4),
    'ASPSR2': (3, 6, 15, 11, 4), 'ASPSR12': (3, 6, 15, 9, 4),
}


def sysreg(name, reg, read):
    op0, op1, crn, crm, op2 = REGS[name]
    return (0xd5000000 | (int(read) << 21) | (op0 << 19) | (op1 << 16)
            | (crn << 12) | (crm << 8) | (op2 << 5) | reg)


class ROM:
    def __init__(self):
        self.words = []
        self.expected = {}

    def emit(self, word):
        self.words.append(word)

    def mov(self, reg, value):
        for half in range(4):
            self.emit((0xd2800000 if half == 0 else 0xf2800000)
                      | (half << 21) | (((value >> (half * 16)) & 0xffff) << 5) | reg)

    def set(self, name, value):
        self.mov(0, value)
        self.emit(sysreg(name, 0, False))

    def store(self, reg, offset):
        assert offset % 8 == 0 and offset < 32768
        self.emit(0xf9000000 | ((offset // 8) << 10) | (20 << 5) | reg)

    def trace(self, label, expected, name=None, reg=0):
        if name:
            self.emit(sysreg(name, reg, True))
        offset = len(self.expected) * 8
        assert offset < 0x100
        self.store(reg, offset)
        self.expected[label] = expected

    def handler(self, el, at):
        while len(self.words) * 4 < at:
            self.emit(0)
        assert len(self.words) * 4 == at
        self.emit(0x910006b5)  # add x21, x21, #1
        self.emit(sysreg(f'ESR_EL{el}', 22, True))
        self.store(22, 0x108 if el == 2 else 0x110)
        self.emit(sysreg(f'ELR_EL{el}', 23, True))
        self.emit(0x910012f7)  # add x23, x23, #4
        self.emit(sysreg(f'ELR_EL{el}', 23, False))
        self.emit(0xd69f03e0)  # eret

    def build(self):
        self.mov(20, RAM)
        self.mov(21, 0)
        self.set('HCR_EL2', 1 << 31)  # ordinary AArch64 EL1 configuration
        self.set('VBAR_EL2', 0x1000)
        self.set('VBAR_EL1', 0x2000)
        self.trace('initial_el', 8, 'CurrentEL')
        for name in ('ENTRY1', 'ENTRY2', 'ASPSR1', 'ASPSR2', 'CURRENTG'):
            self.trace('reset_' + name, 0, name)
        self.set('ENTRY1', 0x1111)
        self.set('ENTRY2', 0x2222)
        self.trace('entry1_no_e2h', 0x1111, 'ENTRY1')
        self.trace('entry2', 0x2222, 'ENTRY2')
        self.set('HCR_EL2', (1 << 31) | (1 << 34))
        self.trace('entry1_e2h_redirect', 0x2222, 'ENTRY1')
        self.set('ENTRY1', 0x3333)
        self.trace('entry12_reverse_alias', 0x1111, 'ENTRY12')
        self.set('ENTRY12', 0x4444)
        self.set('ASPSR1', 0x5555)  # redirects to bank 2
        self.set('ASPSR12', 0x6666)  # reaches bank 1
        self.trace('aspsr1_e2h_redirect', 0x5555, 'ASPSR1')
        self.trace('aspsr12_reverse_alias', 0x6666, 'ASPSR12')
        self.set('HCR_EL2', 1 << 31)
        self.trace('entry1_after_alias_write', 0x4444, 'ENTRY1')
        self.trace('entry2_after_redirect_write', 0x3333, 'ENTRY2')
        self.trace('aspsr1_independent', 0x6666, 'ASPSR1')
        self.trace('aspsr2_independent', 0x5555, 'ASPSR2')
        self.emit(sysreg('ENTRY12', 0, True))  # must UNDEF without E2H
        self.set('CURRENTG', 1)  # must UNDEF, CURRENTG is read-only
        self.trace('currentg_after_forbidden_write', 0, 'CURRENTG')
        self.trace('el2_access_fault_count', 2, reg=21)
        self.set('SPSR_EL2', 0x3c5)  # EL1h with interrupts masked
        target_fixup = len(self.words)
        self.mov(0, 0)
        self.emit(sysreg('ELR_EL2', 0, False))
        self.emit(0xd69f03e0)
        el1_start = len(self.words) * 4
        for half in range(4):
            self.words[target_fixup + half] = ((0xd2800000 if half == 0 else 0xf2800000)
                | (half << 21) | (((el1_start >> (16 * half)) & 0xffff) << 5))
        self.emit(sysreg('ENTRY2', 0, True))  # PL2-only register at EL1
        self.emit(sysreg('ENTRY12', 0, True))  # PL2-only alias at EL1
        self.trace('el1_bank', 0x4444, 'ENTRY1')
        self.trace('final_el', 4, 'CurrentEL')
        self.trace('el1_currentg', 0, 'CURRENTG')
        self.trace('total_access_fault_count', 4, reg=21)
        self.mov(0, 0xfeedfacecafebeef)
        self.trace('completion', 0xfeedfacecafebeef)
        terminal = len(self.words) * 4
        self.emit(0x14000000)  # own terminal loop, no host semihosting
        assert terminal < 0x1000
        self.handler(2, 0x1200)
        self.handler(1, 0x2200)
        return b''.join(struct.pack('<I', w) for w in self.words), terminal


class QMP:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(2)
        self.stream = None
        try:
            self.sock.connect(str(path))
            self.stream = self.sock.makefile('rwb')
            greeting = json.loads(self.stream.readline())
            if 'QMP' not in greeting:
                raise RuntimeError('Invalid QMP greeting')
            self.request('qmp_capabilities')
        except BaseException:
            if self.stream:
                self.stream.close()
            self.sock.close()
            raise

    def request(self, command, arguments=None):
        obj = {'execute': command}
        if arguments is not None:
            obj['arguments'] = arguments
        self.stream.write(json.dumps(obj).encode() + b'\n')
        self.stream.flush()
        deadline = time.monotonic() + 2
        while True:
            if time.monotonic() > deadline:
                raise RuntimeError('QMP response deadline exceeded')
            line = self.stream.readline()
            if not line:
                raise RuntimeError('QMP closed before response')
            result = json.loads(line)
            if 'error' in result:
                raise RuntimeError(str(result['error']))
            if 'return' in result:
                return result['return']

    def close(self):
        try:
            self.stream.close()
        finally:
            self.sock.close()


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(binary, output):
    rom = ROM()
    content, terminal = rom.build()
    rom_file = output / 'register-probe.rom'
    rom_file.write_bytes(content)
    report = {'scope': 'Synthetic register CPU test; no Apple firmware or iOS boot',
              'binary': str(binary), 'binary_sha256': sha(binary),
              'rom_sha256': sha(rom_file), 'terminal_pc': hex(terminal),
              'expected': rom.expected, 'passes': [], 'modern_boot_claim': False,
              'passed': False, 'rejected_profiles': [],
              'legacy_gxf_mix_check': 'component fixture only; virt rejects Apple CPU types before realization'}
    for name, cpu, expected_error in [
        ('PAC-noop', 'max,has_el2=on,has_el3=off,apple-modern-gxf=on,pauth-noop=on',
         'requires pauth=true and pauth-noop=false'),
        ('PAC-disabled', 'max,has_el2=on,has_el3=off,apple-modern-gxf=on,pauth=off,pauth-noop=off',
         'requires pauth=true and pauth-noop=false'),
    ]:
        rejected = subprocess.run([str(binary), '-M', 'virt,virtualization=on,secure=off',
            '-cpu', cpu, '-m', '128M', '-bios', str(rom_file), '-nodefaults',
            '-display', 'none', '-serial', 'none', '-monitor', 'none', '-S'],
            capture_output=True, text=True, timeout=5)
        (output / ('rejected-' + name + '.log')).write_text(rejected.stdout + rejected.stderr)
        if not rejected.returncode or expected_error not in rejected.stderr:
            raise RuntimeError('Modern CPU did not reject profile: ' + name)
        report['rejected_profiles'].append({'profile': name, 'exit_code': rejected.returncode,
                                           'expected_error_observed': True})
    with tempfile.TemporaryDirectory(prefix='gxf-qmp-') as directory:
        qmp_path = Path(directory) / 'qmp.sock'
        args = [str(binary), '-M', 'virt,virtualization=on,secure=off',
                '-cpu', 'max,has_el2=on,has_el3=off,apple-modern-gxf=on,pauth=on,pauth-noop=off',
                '-m', '128M', '-smp', '1', '-bios', str(rom_file), '-nodefaults',
                '-display', 'none', '-serial', 'none', '-monitor', 'none', '-S',
                '-qmp', f'unix:{qmp_path},server=on,wait=off']
        report['argv'] = args
        qmp = None
        with (output / 'emulator.log').open('wb') as log:
            process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 8
                while qmp is None:
                    if process.poll() is not None:
                        raise RuntimeError('QEMU exited during startup; inspect emulator.log')
                    if time.monotonic() >= deadline:
                        raise RuntimeError('QMP startup timeout')
                    try:
                        qmp = QMP(qmp_path)
                    except (FileNotFoundError, ConnectionRefusedError):
                        time.sleep(0.02)
                for iteration in range(2):
                    if iteration:
                        qmp.request('system_reset')
                    # system_reset is asynchronous. Establish reset completion
                    # before executing, so stale RAM/terminal PC cannot qualify it.
                    reset_deadline = time.monotonic() + 2
                    while True:
                        reset_regs = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                        reset_pc = re.search(r'PC=([0-9a-fA-F]+)', reset_regs)
                        if reset_pc and int(reset_pc[1], 16) == 0:
                            break
                        if time.monotonic() >= reset_deadline:
                            raise RuntimeError('CPU did not complete reset to the owned BIOS entry')
                        time.sleep(0.02)
                    reset_pstate = re.search(r'PSTATE=([0-9a-fA-F]+)', reset_regs)
                    if not reset_pstate or int(reset_pstate[1], 16) & 0xf != 9:
                        raise RuntimeError('CPU reset did not select AArch64 EL2h')
                    (output / f'reset-registers-{iteration}.txt').write_text(reset_regs)
                    qmp.request('cont')
                    deadline = time.monotonic() + 5
                    while True:
                        regs = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                        match = re.search(r'PC=([0-9a-fA-F]+)', regs)
                        if match and int(match[1], 16) == terminal:
                            break
                        if time.monotonic() >= deadline:
                            (output / f'registers-failed-{iteration}.txt').write_text(regs)
                            raise RuntimeError('CPU did not reach the owned ROM terminal loop')
                        time.sleep(0.02)
                    qmp.request('stop')
                    dump = output / f'ram-{iteration}.bin'
                    qmp.request('pmemsave', {'val': RAM, 'size': 0x118, 'filename': str(dump)})
                    values = struct.unpack('<35Q', dump.read_bytes())
                    actual = dict(zip(rom.expected, values))
                    (output / f'registers-{iteration}.txt').write_text(regs)
                    report['passes'].append({'iteration': iteration, 'after_system_reset': bool(iteration),
                                             'actual': actual, 'el2_esr': hex(values[33]),
                                             'el1_esr': hex(values[34])})
                    if actual != rom.expected or values[33] >> 26 or values[34] >> 26:
                        raise RuntimeError('Actual MSR/MRS/alias/reset/access-fault results differ')
                qmp.request('quit')
                if process.wait(timeout=5):
                    raise RuntimeError('QEMU returned nonzero')
                report['passed'] = True
                if sha(binary) != report['binary_sha256']:
                    raise RuntimeError('Probe binary changed during execution')
            except BaseException as error:
                report['passed'] = False
                report['error'] = str(error)
                raise
            finally:
                if qmp:
                    try:
                        qmp.close()
                    except OSError as error:
                        report['passed'] = False
                        report['cleanup_error'] = str(error)
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                report['exit_code'] = process.returncode
                report['child_reaped'] = process.poll() is not None
                (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit('Binary must be a regular executable file')
    if args.output_dir:
        output = args.output_dir.resolve()
        output.mkdir(parents=True, exist_ok=False)
        report = run(binary, output)
    else:
        with tempfile.TemporaryDirectory(prefix='modern-cpu-probe-') as directory:
            report = run(binary, Path(directory))
    print(json.dumps({'passed': report['passed'], 'binary_sha256': report['binary_sha256'],
                      'real_cpu_passes': len(report['passes']), 'modern_boot_claim': False}))
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
