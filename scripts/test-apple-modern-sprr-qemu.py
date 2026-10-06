#!/usr/bin/env python3
"""Check modern SPRR with actual CPU instructions and ordinary MMU faults.

An owned AArch64 ROM builds standard 4 KiB stage-1 page tables on virt. It
checks EL2/GL2 R/W/X, EL1 guarded AT bank selection, user AT permissions,
register reset and permission changes without guest TLBI. GL fault returns
use real PACIA/ERETAA. No Apple firmware or semihosting is used. This is an
emulator compatibility gate, not Apple hardware equivalence or an iOS boot.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import struct
import subprocess
import tempfile
import time


spec = importlib.util.spec_from_file_location(
    'owned_timer_gate', Path(__file__).with_name('test-apple-modern-timer-qemu.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
QMP = transport.QMP
RAM = 0x40000000
ROOT = RAM + 0x100000
FLASH_L2 = ROOT + 0x1000
FLASH_L3 = ROOT + 0x2000
RAM_L2 = ROOT + 0x3000
RAM_L3 = ROOT + 0x4000
CODE_WORDS = 0xd65f03c091000673  # add x19,x19,#1; ret
READ_SENTINEL = 0x1122334455667788
COMPLETE = 0xfeedfacecafebeef
REGS = {
    'HCR_EL2': (3, 4, 1, 1, 0),
    'SCTLR_EL2': (3, 4, 1, 0, 0), 'SCTLR_EL1': (3, 0, 1, 0, 0),
    'TCR_EL2': (3, 4, 2, 0, 2), 'TCR_EL1': (3, 0, 2, 0, 2),
    'TTBR0_EL2': (3, 4, 2, 0, 0), 'TTBR0_EL1': (3, 0, 2, 0, 0),
    'MAIR_EL2': (3, 4, 10, 2, 0), 'MAIR_EL1': (3, 0, 10, 2, 0),
    'VBAR_EL2': (3, 4, 12, 0, 0),
    'ELR_EL2': (3, 4, 4, 0, 1), 'SPSR_EL2': (3, 4, 4, 0, 0),
    'ESR_EL2': (3, 4, 5, 2, 0), 'FAR_EL2': (3, 4, 6, 0, 0),
    'APIAKEYLO_EL1': (3, 0, 2, 1, 0),
    'APIAKEYHI_EL1': (3, 0, 2, 1, 1),
    'PAR_EL1': (3, 0, 7, 4, 0),
    'CURRENTG': (3, 6, 15, 8, 0),
    'GXF_ENTRY_EL2': (3, 6, 15, 12, 0),
    'SP_GL2': (3, 6, 15, 11, 0),
    'VBAR_GL2': (3, 6, 15, 11, 2),
    'SPSR_GL2': (3, 6, 15, 11, 3),
    'ASPSR_GL2': (3, 6, 15, 11, 4),
    'ESR_GL2': (3, 6, 15, 11, 5),
    'ELR_GL2': (3, 6, 15, 11, 6),
    'FAR_GL2': (3, 6, 15, 11, 7),
    'SPRR_CONFIG_EL1': (3, 6, 15, 1, 0),
    'SPRR_CONFIG_EL2': (3, 6, 15, 14, 2),
    'SPRR_PPERM_EL1': (3, 6, 15, 1, 6),
    'SPRR_PPERM_EL2': (3, 6, 15, 1, 7),
    'SPRR_UPERM_EL0': (3, 6, 15, 1, 5),
    'AT_S1E2R': (1, 4, 7, 8, 0), 'AT_S1E2W': (1, 4, 7, 8, 1),
    'AT_S1E1R': (1, 0, 7, 8, 0), 'AT_S1E1W': (1, 0, 7, 8, 1),
    'AT_S1E0R': (1, 0, 7, 8, 2), 'AT_S1E0W': (1, 0, 7, 8, 3),
}
SPRR_REGS = tuple(name for name in REGS if name.startswith('SPRR_'))
# Explicit expected access sets: these are independent of the decoder source.
CASES = (
    ('a', 4, '', 'RX'),
    ('b', 6, 'RW', ''),
    ('c', 8, 'R', ''),
    ('d', 2, 'X', 'R'),
    ('e', 13, 'R', 'RW'),
)


def sysreg(name, register, read=False):
    op0, op1, crn, crm, op2 = REGS[name]
    return (0xd5000000 | (int(read) << 21) | (op0 << 19) | (op1 << 16)
            | (crn << 12) | (crm << 8) | (op2 << 5) | register)


def table(entries):
    values = [5] * 16
    values[15] = 15
    for index, value in entries.items():
        values[index] = value
    return sum(value << (4 * index) for index, value in enumerate(values))


PPERM2 = table({4: 4, 6: 3, 8: 2, 2: 9, 13: 14})
PPERM1 = table({4: 2, 6: 12})
UPERM = table({4: 2, 6: 3})


def leaf(address, index):
    # AP[7:6], UXN/PXN[54:53], AF, inner shareable, AttrIndx=0, page.
    return address | ((index >> 2) << 6) | ((index & 3) << 53) | 0x703


def write_value(page):
    return 0xc001000000000000 | page


class ROM:
    def __init__(self, enabled):
        self.enabled = enabled
        self.words = []
        self.labels = {}
        self.fixups = []
        self.expected = {}
        self.faults = 0
        self.executed = 0

    def emit(self, value):
        self.words.append(value)

    def at(self, offset):
        if len(self.words) * 4 > offset:
            raise RuntimeError('Owned ROM blocks overlap')
        self.words.extend([0] * (offset // 4 - len(self.words)))

    def label(self, name):
        if name in self.labels:
            raise RuntimeError('Duplicate ROM label: ' + name)
        self.labels[name] = len(self.words) * 4

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
        self.emit(sysreg(name, 0))

    def put(self, address, value):
        self.mov(1, address)
        self.mov(0, value)
        self.emit(0xf9000020)  # str x0,[x1]

    def trace(self, label, expected, name=None, register=0, mask=None):
        if name:
            self.emit(sysreg(name, register, True))
        offset = len(self.expected) * 8
        if offset >= 32768:
            raise RuntimeError('Trace exceeds immediate store range')
        self.emit(0xf9000000 | ((offset // 8) << 10) | (20 << 5) | register)
        self.expected[label] = {'value': expected, 'mask': mask}

    def translation(self, label, address, kind, allowed):
        self.mov(10, address)
        self.emit(sysreg('AT_' + kind, 10))
        self.emit(0xd5033fdf)  # isb
        if allowed:
            self.trace(label, address, 'PAR_EL1', mask=0x000ffffffffff001)
        else:
            self.trace(label, 0x1f, 'PAR_EL1', mask=0x7f)  # F + FSC=permission L3

    def probe(self, label, address, operation, allowed, read_value=CODE_WORDS):
        self.mov(22, 0)
        self.mov(23, 0)
        self.mov(24, label + '_resume')
        self.mov(10, address)
        self.mov(0, READ_SENTINEL if operation == 'R' else write_value(address))
        self.emit({'R': 0xf9400140, 'W': 0xf9000140, 'X': 0xd63f0140}[operation])
        self.label(label + '_resume')
        if not allowed:
            self.faults += 1
        if operation == 'X' and allowed:
            self.executed += 1
        if operation == 'R':
            self.trace(label + '_value', read_value if allowed else READ_SENTINEL)
        if operation == 'X':
            self.trace(label + '_executed', self.executed, register=19)
        self.trace(label + '_fault_count', self.faults, register=21)
        syndrome = 0
        if not allowed:
            syndrome = (0x8600000f if operation == 'X' else
                        0x9600000f | (0x40 if operation == 'W' else 0))
        self.trace(label + '_esr', syndrome, register=22)
        self.trace(label + '_far', address if not allowed else 0, register=23)

    def matrix(self, guarded):
        mode = 'gl2' if guarded else 'el2'
        for index, (name, raw, normal, gl) in enumerate(CASES):
            address = RAM + 0x20000 + index * 0x1000
            permissions = gl if guarded else normal
            # Read and execute before a permitted write changes this page.
            for operation in 'RXW':
                allowed = operation in permissions
                label = mode + '_' + name + '_' + operation.lower()
                if operation in 'RW':
                    self.translation(label + '_at', address,
                                     'S1E2' + operation, allowed)
                self.probe(label, address, operation, allowed)

    def handler(self, offset, guarded=False):
        self.at(offset)
        suffix = 'GL2' if guarded else 'EL2'
        self.emit(0x910006b5)  # add x21,x21,#1
        self.emit(sysreg('ESR_' + suffix, 22, True))
        self.emit(sysreg('FAR_' + suffix, 23, True))
        if guarded:
            self.emit(0xaa1803fc)  # mov x28,x24
            self.emit(0xdac103fc)  # pacia x28,sp
            self.emit(sysreg('ELR_GL2', 28))
            self.emit(0xd69f0bff)  # eretaa, real matching-key authentication
        else:
            self.emit(sysreg('ELR_EL2', 24))
            self.emit(0xd69f03e0)  # eret

    def build(self):
        self.mov(20, RAM)
        self.mov(21, 0)
        self.mov(19, 0)
        self.set('HCR_EL2', 1 << 31)  # EL1 is AArch64; stage 2 disabled
        self.set('VBAR_EL2', 0x8000)
        if not self.enabled:
            for name in SPRR_REGS:
                for read in (True, False):
                    self.mov(24, 'off_' + name + '_' + str(read))
                    self.emit(sysreg(name, 0, read))
                    self.label('off_' + name + '_' + str(read))
            self.trace('disabled_register_faults', len(SPRR_REGS) * 2, register=21)
            self.trace('disabled_last_esr', 0x02000000, register=22)
            self.mov(0, COMPLETE)
            self.trace('completion', COMPLETE)
            terminal = len(self.words) * 4
            self.emit(0x14000000)
            self.handler(0x8200)
            return self.finish(), terminal

        for name in SPRR_REGS:
            self.trace('reset_' + name, 0, name)
        self.trace('reset_currentg', 0, 'CURRENTG')
        self.set('SPRR_PPERM_EL1', PPERM1)
        self.set('SPRR_PPERM_EL2', PPERM2)
        self.set('SPRR_UPERM_EL0', UPERM)
        self.set('SPRR_CONFIG_EL2', 1)
        for name, value in (('SPRR_CONFIG_EL1', 0), ('SPRR_CONFIG_EL2', 1),
                            ('SPRR_PPERM_EL1', PPERM1),
                            ('SPRR_PPERM_EL2', PPERM2), ('SPRR_UPERM_EL0', UPERM)):
            self.trace('stored_' + name, value, name)
        self.set('APIAKEYLO_EL1', 0x1122334455667788)
        self.set('APIAKEYHI_EL1', 0x8877665544332211)
        self.mov(0, RAM + 0x10000)
        self.emit(0x9100001f)  # mov sp,x0
        self.set('SP_GL2', RAM + 0x11000)
        self.set('VBAR_GL2', 0x9000)
        self.set('GXF_ENTRY_EL2', 0x4000)

        # T0SZ=25: 39-bit addresses, level 1 start, identity mapped via L3.
        for address, value in ((ROOT, FLASH_L2 | 3), (ROOT + 8, RAM_L2 | 3),
                               (FLASH_L2, FLASH_L3 | 3), (RAM_L2, RAM_L3 | 3)):
            self.put(address, value)
        for index in range(16):
            self.put(FLASH_L3 + index * 8, leaf(index * 0x1000, 0))
        self.put(RAM_L3, leaf(RAM, 15))
        for index, (_, raw, _, _) in enumerate(CASES):
            address = RAM + 0x20000 + index * 0x1000
            self.put(RAM_L3 + (0x20 + index) * 8, leaf(address, raw))
            self.put(address, CODE_WORDS)
        self.set('MAIR_EL2', 0xff)
        self.set('MAIR_EL1', 0xff)
        self.set('TTBR0_EL2', ROOT)
        self.set('TTBR0_EL1', ROOT)
        self.set('TCR_EL2', 0x80023519)  # 40-bit PA, inner shareable WB
        self.set('TCR_EL1', (2 << 32) | (1 << 23) | 0x3519)
        self.emit(0xd5033f9f)  # dsb sy
        for name, extra in (('SCTLR_EL1', 1), ('SCTLR_EL2', (1 << 31) | 1)):
            self.emit(sysreg(name, 0, True))
            self.mov(1, extra)
            self.emit(0xaa010000)  # orr x0,x0,x1
            self.emit(sysreg(name, 0))
            self.emit(0xd5033fdf)  # isb
        self.matrix(False)
        page_b = RAM + 0x21000
        self.translation('el2_at_el1_bank_read_denied', page_b, 'S1E1R', False)
        self.translation('el2_at_el1_bank_write_denied', page_b, 'S1E1W', False)
        self.translation('el2_at_user_bank_read', page_b, 'S1E0R', True)
        self.translation('el2_at_user_bank_write', page_b, 'S1E0W', True)
        self.translation('el2_at_user_a_read', RAM + 0x20000, 'S1E0R', True)
        self.translation('el2_at_user_a_write_denied', RAM + 0x20000, 'S1E0W', False)

        # Page C's read is already cached. A real permission-register write
        # must remove that grant, without any guest TLBI instruction.
        self.set('SPRR_PPERM_EL2', PPERM2 & ~(15 << 32))
        self.probe('el2_changed_cached_read_denied', RAM + 0x22000, 'R', False)
        self.set('SPRR_PPERM_EL2', PPERM2)
        self.probe('el2_restored_cached_read', RAM + 0x22000, 'R', True)
        ordinary_faults, ordinary_executed = self.faults, self.executed
        self.emit(0x00201427)  # genter #7
        self.label('el2_resume')
        self.trace('gexit_currentg', 0, 'CURRENTG')
        self.trace('gexit_ordinary_faults', ordinary_faults + 10, register=21)
        self.trace('gexit_execute_count', ordinary_executed + 1, register=19)
        self.faults, self.executed = ordinary_faults + 10, ordinary_executed + 1
        self.probe('gexit_normal_read_view', RAM + 0x22000, 'R', True,
                   read_value=write_value(RAM + 0x22000))
        self.mov(0, COMPLETE)
        self.trace('completion', COMPLETE)
        terminal = len(self.words) * 4
        self.emit(0x14000000)

        self.at(0x4000)
        self.faults, self.executed = ordinary_faults, ordinary_executed
        self.trace('gl2_currentg', 1, 'CURRENTG')
        for name, register in (('SPSR_GL2', 25), ('ELR_GL2', 26), ('ASPSR_GL2', 27)):
            self.emit(sysreg(name, register, True))
        self.matrix(True)
        # This must use Stage1_GE1, PPERM_EL1 and GL's table, independently
        # of the active GL2 table, whose same page denies both accesses.
        self.translation('gl2_at_ge1_bank_read', page_b, 'S1E1R', True)
        self.translation('gl2_at_ge1_bank_write', page_b, 'S1E1W', True)
        self.translation('gl2_at_user_bank_read', page_b, 'S1E0R', True)
        self.translation('gl2_at_user_bank_write', page_b, 'S1E0W', True)
        self.set('SPRR_PPERM_EL2', (PPERM2 & ~(15 << 32)) | (12 << 32))
        self.probe('gl2_changed_cached_read', RAM + 0x22000, 'R', True)
        self.probe('gl2_changed_cached_write', RAM + 0x22000, 'W', True)
        self.set('SPRR_PPERM_EL2', PPERM2)
        self.trace('gl2_synchronous_fault_total', self.faults, register=21)
        self.trace('gl2_ordinary_esr_preserved', 0x9600000f, 'ESR_EL2')
        for name, register in (('SPSR_GL2', 25), ('ELR_GL2', 26), ('ASPSR_GL2', 27)):
            self.emit(sysreg(name, register))
        self.emit(0x00201400)  # same-EL GEXIT back to ordinary EL2
        self.handler(0x8200)
        self.handler(0x9200, guarded=True)
        return self.finish(), terminal

    def finish(self):
        for index, register, label in self.fixups:
            value = self.labels[label]
            for half in range(4):
                self.words[index + half] = ((0xd2800000 if half == 0 else 0xf2800000)
                    | (half << 21) | (((value >> (half * 16)) & 0xffff) << 5)
                    | register)
        return b''.join(struct.pack('<I', word) for word in self.words)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))


def wait_pc(qmp, wanted, timeout):
    deadline = time.monotonic() + timeout
    while True:
        registers = qmp.request('human-monitor-command', {'command-line': 'info registers'})
        found = re.search(r'PC=([0-9a-fA-F]+)', registers)
        if found and int(found[1], 16) == wanted:
            return registers
        if time.monotonic() >= deadline:
            raise RuntimeError('ROM PC deadline; wanted ' + hex(wanted) + '\n' + registers)
        time.sleep(0.02)


def run(binary, output):
    report = {'scope': 'Owned ROM; actual stage-1 SPRR CPU/MMU compatibility gate',
              'binary_sha256': digest(binary), 'passes': [], 'passed': False,
              'ios_boot_claim': False, 'apple_hardware_equivalence_claim': False,
              'migration_claim': False, 'guarded_el0_claim': False,
              'enabled_instructions_per_pass': {
                  'actual_permission_accesses': 35, 'address_translations': 30,
                  'synchronous_permission_faults': 21,
                  'authenticated_guarded_fault_returns': 10,
                  'genter': 1, 'same_el_gexit': 1,
                  'permission_change_guest_tlbi': 0},
              'ordinary_faults': 'Permission faults at level 3; not vulnerability reproduction'}
    try:
        for name, enabled, option in (('default', False, None),
                                      ('disabled', False, 'off'),
                                      ('enabled', True, 'on')):
            rom = ROM(enabled)
            content, terminal = rom.build()
            rom_path = output / (name + '.rom')
            rom_path.write_bytes(content)
            cpu = ('max,has_el2=on,has_el3=off,pauth=on,pauth-noop=off,'
                   'apple-modern-gxf=on,apple-modern-guarded=on,apple-modern-timers=on')
            if option is not None:
                cpu += ',apple-modern-sprr=' + option
            args = [str(binary), '-M', 'virt,virtualization=on,secure=off',
                    '-cpu', cpu,
                    '-accel', 'tcg,tb-size=16', '-m', '128M', '-smp', '1',
                    '-bios', str(rom_path), '-nodefaults', '-display', 'none',
                    '-serial', 'none', '-monitor', 'none', '-S', '-qmp', 'stdio']
            with (output / (name + '-emulator.log')).open('wb') as log:
                process = subprocess.Popen(args, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=log,
                                           preexec_fn=limits)
                try:
                    qmp = QMP(process)
                    for iteration in range(2):
                        if iteration:
                            qmp.request('system_reset')
                        wait_pc(qmp, 0, 3)
                        qmp.request('cont')
                        registers = wait_pc(qmp, terminal, 8)
                        qmp.request('stop')
                        dump = output / f'{name}-trace-{iteration}.bin'
                        qmp.request('pmemsave', {'val': RAM, 'size': len(rom.expected) * 8,
                                                'filename': str(dump)})
                        values = struct.unpack('<' + 'Q' * len(rom.expected), dump.read_bytes())
                        actual = dict(zip(rom.expected, values))
                        for label, expected in rom.expected.items():
                            mask = expected['mask']
                            value = actual[label] if mask is None else actual[label] & mask
                            if value != expected['value']:
                                raise RuntimeError(f'{label}: expected {expected}, got {actual[label]:#x}')
                        physical_writes = {}
                        if enabled:
                            pages = output / f'enabled-pages-{iteration}.bin'
                            qmp.request('pmemsave', {'val': RAM + 0x20000, 'size': 0x5000,
                                                    'filename': str(pages)})
                            contents = pages.read_bytes()
                            for index, (label, _, normal, gl) in enumerate(CASES):
                                address = RAM + 0x20000 + index * 0x1000
                                observed = struct.unpack_from('<Q', contents, index * 0x1000)[0]
                                expected = (write_value(address) if 'W' in normal + gl or label == 'c'
                                            else CODE_WORDS)
                                if observed != expected:
                                    raise RuntimeError('Physical write effects differ for page ' + label)
                                physical_writes[label] = observed
                        (output / f'{name}-registers-{iteration}.txt').write_text(registers)
                        report['passes'].append({'profile': name, 'enabled': enabled,
                                                'iteration': iteration,
                                                'checks': len(actual), 'actual': actual,
                                                'physical_writes': physical_writes,
                                                'argv': args, 'rom_sha256': digest(rom_path)})
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
                    report[name + '_child_reaped'] = process.poll() is not None
                    report[name + '_exit_code'] = process.returncode
        if digest(binary) != report['binary_sha256']:
            raise RuntimeError('Binary changed during test')
        report['passed'] = True
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        report['evidence_bytes'] = sum(path.stat().st_size for path in output.iterdir() if path.is_file())
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
        with tempfile.TemporaryDirectory(prefix='apple-sprr-rom-') as directory:
            report = run(binary, Path(directory))
    print(json.dumps({'passed': report['passed'], 'real_cpu_passes': len(report['passes']),
                     'binary_sha256': report['binary_sha256'], 'ios_boot_claim': False}))


if __name__ == '__main__':
    main()
