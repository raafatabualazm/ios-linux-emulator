#!/usr/bin/env python3
"""Test opt-in modern guarded CPU transitions using an owned AArch64 ROM.

No Apple firmware, guest patches, sockets or semihosting are used. The checks
exercise EL1/EL2 entry, exit, ordinary nested exceptions/ERET, independent SP
and saved-state banks, context faults, opt-in isolation and reset. Modern
memory protection, guarded EL0/AArch32 and migration remain unqualified.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time


# Reuse only the bounded QMP-over-pipes transport from the owned timer gate.
spec = importlib.util.spec_from_file_location(
    'owned_timer_gate', Path(__file__).with_name('test-apple-modern-timer-qemu.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
QMP = transport.QMP
RAM = 0x40000000
REGS = {
    'HCR_EL2': (3, 4, 1, 1, 0),
    'SCTLR_EL2': (3, 4, 1, 0, 0),
    'APIAKEYLO_EL1': (3, 0, 2, 1, 0), 'APIAKEYHI_EL1': (3, 0, 2, 1, 1),
    'VBAR_EL2': (3, 4, 12, 0, 0), 'VBAR_EL1': (3, 0, 12, 0, 0),
    'SP_EL2': (3, 6, 4, 1, 0), 'SP_EL1': (3, 4, 4, 1, 0),
    'ELR_EL2': (3, 4, 4, 0, 1), 'ELR_EL1': (3, 0, 4, 0, 1),
    'ESR_EL2': (3, 4, 5, 2, 0), 'ESR_EL1': (3, 0, 5, 2, 0),
    'SPSR_EL2': (3, 4, 4, 0, 0), 'SPSR_EL1': (3, 0, 4, 0, 0),
    'CURRENTG': (3, 6, 15, 8, 0), 'CURRENTEL': (3, 0, 4, 2, 2),
    'NZCV': (3, 3, 4, 2, 0),
    'GXF_ENTRY_EL1': (3, 6, 15, 8, 1),
    'GXF_ENTRY_EL2': (3, 6, 15, 12, 0),
}
for el, crm in ((1, 10), (2, 11)):
    for opc2, name in enumerate(('SP', 'TPIDR', 'VBAR', 'SPSR',
                                  'ASPSR', 'ESR', 'ELR', 'FAR')):
        REGS[f'{name}_GL{el}'] = (3, 6, 15, crm, opc2)


def sysreg(name, register, read):
    op0, op1, crn, crm, op2 = REGS[name]
    return (0xd5000000 | (int(read) << 21) | (op0 << 19) | (op1 << 16)
            | (crn << 12) | (crm << 8) | (op2 << 5) | register)


class ROM:
    def __init__(self, enabled):
        self.words = []
        self.labels = {}
        self.fixups = []
        self.expected = {}
        self.enabled = enabled

    def emit(self, word):
        self.words.append(word)

    def label(self, name):
        self.labels[name] = len(self.words) * 4

    def at(self, address):
        if len(self.words) * 4 > address:
            raise RuntimeError('ROM blocks overlap')
        self.words.extend([0] * (address // 4 - len(self.words)))

    def mov(self, register, value):
        if isinstance(value, str):
            self.fixups.append((len(self.words), register, value))
            value = 0
        for half in range(4):
            self.emit((0xd2800000 if half == 0 else 0xf2800000)
                      | (half << 21) | (((value >> (half * 16)) & 0xffff) << 5)
                      | register)

    def set(self, name, value):
        self.mov(0, value)
        self.emit(sysreg(name, 0, False))

    def sp(self, value):
        self.mov(0, value)
        self.emit(0x9100001f)  # mov sp,x0 (add sp,x0,#0)

    def store(self, register, offset):
        assert offset % 8 == 0 and offset < 32768
        self.emit(0xf9000000 | ((offset // 8) << 10) | (20 << 5) | register)

    def trace(self, label, expected, name=None, register=0, sp=False):
        if name:
            self.emit(sysreg(name, register, True))
        if sp:
            self.emit(0x910003e0 | register)  # mov xN,sp
        self.store(register, len(self.expected) * 8)
        self.expected[label] = expected

    def normal_handler(self, el, address):
        self.at(address)
        self.emit(0x910006b5)  # add x21,x21,#1
        self.emit(sysreg(f'ESR_EL{el}', 22, True))
        self.store(22, 0x600 if el == 2 else 0x608)
        self.emit(sysreg(f'ELR_EL{el}', 23, True))
        self.emit(0x910012f7)  # add x23,x23,#4
        self.emit(sysreg(f'ELR_EL{el}', 23, False))
        self.emit(0xd69f03e0)  # eret

    def build(self):
        self.mov(20, RAM)
        self.mov(21, 0)
        self.set('NZCV', 0)
        self.set('HCR_EL2', 1 << 31)
        if self.enabled:
            self.set('APIAKEYLO_EL1', 0x1122334455667788)
            self.set('APIAKEYHI_EL1', 0x8877665544332211)
            self.emit(sysreg('SCTLR_EL2', 0, True))
            self.mov(1, 1 << 31)  # SCTLR_EL2.EnIA
            self.emit(0xaa010000)  # orr x0,x0,x1
            self.emit(sysreg('SCTLR_EL2', 0, False))
        self.set('VBAR_EL2', 0x4000)
        self.set('VBAR_EL1', 0x5000)
        self.sp(RAM + 0x10000)
        self.set('SP_EL1', RAM + 0x40000)
        self.set('SP_GL2', RAM + 0x20000)
        self.set('SP_GL1', RAM + 0x30000)
        self.set('VBAR_GL2', 0x6000)
        self.set('VBAR_GL1', 0x7000)
        self.set('GXF_ENTRY_EL2', 0x1000)
        self.set('GXF_ENTRY_EL1', 0x2000)
        self.trace('reset_currentg', 0, 'CURRENTG')
        self.trace('initial_sp', RAM + 0x10000, sp=True)
        self.trace('reset_aspsr2', 0, 'ASPSR_GL2')
        self.trace('reset_aspsr1', 0, 'ASPSR_GL1')
        self.set('SPSR_EL2', 0x123)
        self.set('ELR_EL2', 0x555)
        self.emit(0x00201427)  # genter #7
        self.label('el2_resume')
        if self.enabled:
            self.trace('el2_exit_currentg', 0, 'CURRENTG')
            self.trace('el2_exit_sp', RAM + 0x10000, sp=True)
            self.trace('el2_saved_gl_sp', RAM + 0x20800, 'SP_GL2')
            self.trace('el2_ordinary_spsr_preserved', 0x123, 'SPSR_EL2')
            self.trace('el2_ordinary_elr_preserved', 0x555, 'ELR_EL2')
        self.emit(0x00201400)  # GEXIT outside GL: ordinary UNDEF
        self.trace('el2_context_faults', 1 if self.enabled else 2, register=21)
        self.set('SPSR_EL2', 0x3c5)
        self.set('ELR_EL2', 'el1_start')
        self.emit(0xd69f03e0)
        self.label('el1_start')
        self.trace('el1_initial_level', 4, 'CURRENTEL')
        self.trace('el1_initial_sp', RAM + 0x40000, sp=True)
        self.emit(0x00201429)  # genter #9
        self.label('el1_resume')
        if self.enabled:
            self.trace('el1_exit_currentg', 0, 'CURRENTG')
            self.trace('el1_exit_sp', RAM + 0x40000, sp=True)
            self.trace('el1_saved_gl_sp', RAM + 0x30800, 'SP_GL1')
        self.emit(0x00201400)  # GEXIT outside GL
        self.trace('el1_context_faults', 2 if self.enabled else 4, register=21)
        # EL0 must not be allowed to enter or leave guarded execution.
        self.set('SPSR_EL1', 0x3c0)
        self.set('ELR_EL1', 'el0_start')
        self.emit(0xd69f03e0)
        self.label('el0_start')
        self.emit(0x00201421)  # genter #1 at EL0 -> UNDEF
        self.emit(0x00201400)  # gexit at EL0 -> UNDEF
        self.trace('total_context_faults', 4 if self.enabled else 6, register=21)
        self.mov(0, 0xfeedfacecafebeef)
        self.trace('completion', 0xfeedfacecafebeef)
        terminal = len(self.words) * 4
        self.emit(0x14000000)

        if self.enabled:
            self.at(0x1000)
            self.trace('gl2_currentg', 1, 'CURRENTG')
            self.trace('gl2_sp', RAM + 0x20000, sp=True)
            self.trace('gl2_entry_aspsr', 0, 'ASPSR_GL2')
            self.trace('gl2_entry_esr', 7, 'ESR_GL2')
            self.trace('gl2_entry_elr', 'el2_resume', 'ELR_GL2')
            self.trace('gl2_entry_spsr', 0x3c9, 'SPSR_GL2')
            self.trace('gl2_other_bank_sp', RAM + 0x30000, 'SP_GL1')
            for name, register in (('SPSR_GL2', 25), ('ELR_GL2', 26), ('ASPSR_GL2', 27)):
                self.emit(sysreg(name, register, True))
            self.emit(0xd4000841)  # svc #0x42, normal GL exception path
            self.label('gl2_svc_resume')
            self.trace('gl2_eret_currentg', 1, 'CURRENTG')
            self.trace('gl2_eret_sp', RAM + 0x20000, sp=True)
            for name, register in (('SPSR_GL2', 25), ('ELR_GL2', 26), ('ASPSR_GL2', 27)):
                self.emit(sysreg(name, register, False))
            self.sp(RAM + 0x20800)
            self.emit(0x00201400)
            self.at(0x2000)
            self.trace('gl1_currentg', 1, 'CURRENTG')
            self.trace('gl1_sp', RAM + 0x30000, sp=True)
            self.trace('gl1_entry_aspsr', 0, 'ASPSR_GL1')
            self.trace('gl1_entry_esr', 9, 'ESR_GL1')
            self.trace('gl1_entry_elr', 'el1_resume', 'ELR_GL1')
            self.trace('gl1_entry_spsr', 0x3c5, 'SPSR_GL1')
            self.sp(RAM + 0x30800)
            self.emit(0x00201400)

        self.normal_handler(2, 0x4200)
        self.normal_handler(1, 0x5200)
        self.normal_handler(1, 0x5400)
        if self.enabled:
            self.at(0x6200)
            self.trace('gl2_svc_currentg', 1, 'CURRENTG')
            self.trace('gl2_svc_aspsr', 1, 'ASPSR_GL2')
            self.trace('gl2_svc_esr', 0x56000042, 'ESR_GL2')
            self.trace('gl2_svc_elr', 'gl2_svc_resume', 'ELR_GL2')
            self.trace('gl2_svc_ordinary_spsr', 0x123, 'SPSR_EL2')
            self.trace('gl2_svc_ordinary_elr', 0x555, 'ELR_EL2')
            # Sign and authenticate a normal exception-return address using
            # the actual architectural instruction key and live GL stack.
            self.emit(sysreg('ELR_GL2', 0, True))
            self.emit(0xdac103e0)  # pacia x0,sp
            self.emit(sysreg('ELR_GL2', 0, False))
            self.emit(0xd69f0bff)  # eretaa
        assert len(self.expected) * 8 < 0x600
        for index, register, label in self.fixups:
            value = self.labels[label]
            for half in range(4):
                self.words[index + half] = ((0xd2800000 if half == 0 else 0xf2800000)
                    | (half << 21) | (((value >> (half * 16)) & 0xffff) << 5) | register)
        self.expected = {label: self.labels.get(value, value)
                         for label, value in self.expected.items()}
        return b''.join(struct.pack('<I', word) for word in self.words), terminal


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(binary, output):
    report = {'scope': 'Owned ROM; scoped Darwin modern guarded execution port',
              'binary_sha256': digest(binary), 'passes': [], 'passed': False,
              'ios_boot_claim': False, 'modern_memory_protection_claim': False}
    try:
        for enabled in (False, True):
            rom = ROM(enabled)
            content, terminal = rom.build()
            name = 'enabled' if enabled else 'disabled'
            rom_path = output / f'{name}.rom'
            rom_path.write_bytes(content)
            args = [str(binary), '-M', 'virt,virtualization=on,secure=off',
                    '-cpu', 'max,has_el2=on,has_el3=off,pauth=on,'
                    'pauth-noop=off,apple-modern-gxf=on,'
                    f'apple-modern-guarded={"on" if enabled else "off"}',
                    '-m', '128M', '-smp', '1', '-bios', str(rom_path),
                    '-nodefaults', '-display', 'none', '-serial', 'none',
                    '-monitor', 'none', '-S', '-qmp', 'stdio']
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
                                raise RuntimeError('Owned guarded ROM did not reach completion')
                            time.sleep(0.02)
                        qmp.request('stop')
                        dump = output / f'{name}-ram-{iteration}.bin'
                        qmp.request('pmemsave', {'val': RAM, 'size': 0x610, 'filename': str(dump)})
                        values = struct.unpack('<194Q', dump.read_bytes())
                        actual = dict(zip(rom.expected, values))
                        for label, expected in rom.expected.items():
                            if actual[label] != expected:
                                raise RuntimeError(f'{label}: expected {expected:#x}, got {actual[label]:#x}')
                        if values[0x600 // 8] != 0x2000000 or values[0x608 // 8] != 0x2000000:
                            raise RuntimeError('Context faults did not report ordinary UNDEF')
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
        with tempfile.TemporaryDirectory(prefix='apple-guarded-rom-') as directory:
            report = run(binary, Path(directory))
    print(json.dumps({'passed': report['passed'], 'real_cpu_passes': len(report['passes']),
                     'binary_sha256': report['binary_sha256'], 'ios_boot_claim': False}))


if __name__ == '__main__':
    main()
