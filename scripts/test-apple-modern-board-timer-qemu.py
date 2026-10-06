#!/usr/bin/env python3
"""Qualify the modern board's hypervirtual timer-to-FIQ wire with an owned ROM.

Stock decoded assets are loaded only for normal board metadata; their code is
never selected for execution. Standard generic-loader sets CPU0 to a separate
owned ROM, whose entry PC and bytes are verified while stopped before every
cont. Tests Apple virtual timer E2H redirection, masking, ordinary and guarded
FIQ delivery, timer disable, ERET and reset. No production device changes,
firmware patches, signatures, semihosting or sockets are involved.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shutil
import struct
import subprocess
import tempfile
import time
import traceback


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


board = module('board_preparation_gate', 'test-apple-modern-machine.py')
metadata = module('board_metadata_oracle', 'test-apple-modern-boot-metadata.py')
DRAM = 1 << 40
BASE = DRAM + 0x100000
SCRATCH = BASE + 0x10000
NORMAL_SP = BASE + 0x20000
GUARDED_SP = BASE + 0x30000
PROBE_END = GUARDED_SP + 0x1000
MAX_LOG = 1024 * 1024
MAX_WALL = 45
REGS = {
    'HCR_EL2': (3, 4, 1, 1, 0), 'VBAR_EL2': (3, 4, 12, 0, 0),
    'ESR_EL2': (3, 4, 5, 2, 0), 'ELR_EL2': (3, 4, 4, 0, 1),
    'SPSR_EL2': (3, 4, 4, 0, 0), 'CurrentEL': (3, 0, 4, 2, 2),
    'CNTHV_TVAL_EL2': (3, 4, 14, 3, 0),
    'CNTHV_CTL_EL2': (3, 4, 14, 3, 1),
    'AGTCNTV_TVAL_EL0': (3, 1, 15, 15, 4),
    'AGTCNTV_CTL_EL0': (3, 1, 15, 0, 5),
    'CURRENTG': (3, 6, 15, 8, 0),
    'GXF_ENTRY_EL2': (3, 6, 15, 12, 0),
    'SP_GL2': (3, 6, 15, 11, 0), 'VBAR_GL2': (3, 6, 15, 11, 2),
    'SPSR_GL2': (3, 6, 15, 11, 3), 'ASPSR_GL2': (3, 6, 15, 11, 4),
    'ELR_GL2': (3, 6, 15, 11, 6),
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sysreg(name, register, read):
    op0, op1, crn, crm, op2 = REGS[name]
    return (0xd5000000 | (int(read) << 21) | (op0 << 19) | (op1 << 16)
            | (crn << 12) | (crm << 8) | (op2 << 5) | register)


class ROM:
    def __init__(self):
        self.words, self.fixups = [], []
        self.labels, self.expected = {}, {}

    def emit(self, word):
        self.words.append(word)

    def label(self, name):
        self.labels[name] = BASE + len(self.words) * 4

    def at(self, offset):
        require(len(self.words) * 4 <= offset, 'Owned ROM blocks overlap')
        self.words.extend([0] * (offset // 4 - len(self.words)))

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

    def store(self, register, offset):
        require(offset % 8 == 0 and 0 <= offset < 32768, 'Owned scratch store bounds')
        self.emit(0xf9000000 | ((offset // 8) << 10) | (20 << 5) | register)

    def trace(self, label, expected, name=None, register=0, sp=False):
        if name:
            self.emit(sysreg(name, register, True))
        if sp:
            self.emit(0x910003e0 | register)  # mov xN,sp
        self.store(register, len(self.expected) * 8)
        self.expected[label] = expected

    def branch(self, target_index, condition=None):
        displacement = target_index - len(self.words)
        if condition is None:
            self.emit(0x14000000 | (displacement & 0x3ffffff))
        else:
            self.emit(0x54000000 | ((displacement & 0x7ffff) << 5) | condition)

    def await_expiry(self):
        poll = len(self.words)
        self.emit(sysreg('AGTCNTV_CTL_EL0', 2, True))
        self.emit(0xf1001c5f)  # cmp x2,#7 (enabled+masked+expired)
        self.branch(poll, 1)  # b.ne

    def await_count(self, count):
        poll = len(self.words)
        self.emit(0xf10002bf | (count << 10))  # cmp x21,#count
        self.branch(poll, 1)  # b.ne

    def exception_stop(self, offset, guarded):
        self.at(offset)
        self.emit(0x91000718)  # add x24,x24,#1
        self.store(24, 0x500)
        self.emit(sysreg('CURRENTG', 0, True))
        self.store(0, 0x508)
        if not guarded:
            self.emit(sysreg('ESR_EL2', 0, True))
            self.store(0, 0x510)
        self.emit(0x14000000)

    def fiq_handler(self, offset, guarded):
        self.at(offset)
        self.trace(('gl' if guarded else 'el') + '_fiq_currentg', int(guarded), 'CURRENTG')
        self.trace(('gl' if guarded else 'el') + '_fiq_level', 8, 'CurrentEL')
        self.trace(('gl' if guarded else 'el') + '_fiq_sp',
                   GUARDED_SP if guarded else NORMAL_SP, sp=True)
        self.trace(('gl' if guarded else 'el') + '_fiq_source_status', 5, 'CNTHV_CTL_EL2')
        self.trace(('gl' if guarded else 'el') + '_fiq_saved_pc', None,
                   'ELR_GL2' if guarded else 'ELR_EL2')
        if guarded:
            self.trace('gl_fiq_aspsr', 1, 'ASPSR_GL2')
        self.set('AGTCNTV_CTL_EL0', 0)
        self.emit(0x910006b5)  # add x21,x21,#1
        self.emit(0xd69f03e0)  # eret

    def build(self):
        self.mov(20, SCRATCH)
        self.mov(21, 0)
        self.mov(24, 0)
        for offset in (0x500, 0x508, 0x510):
            self.store(31, offset)
        self.mov(0, NORMAL_SP)
        self.emit(0x9100001f)  # mov sp,x0
        # Ordinary AArch64/E2H with FIQ routing to EL2 (HCR.FMO).
        self.set('HCR_EL2', (1 << 31) | (1 << 34) | (1 << 3))
        self.set('VBAR_EL2', BASE + 0x4000)
        self.set('SP_GL2', GUARDED_SP)
        self.set('VBAR_GL2', BASE + 0x6000)
        self.set('GXF_ENTRY_EL2', BASE + 0x1000)
        self.trace('initial_currentg', 0, 'CURRENTG')
        self.trace('reset_hypervirtual_ctl', 0, 'CNTHV_CTL_EL2')
        self.set('AGTCNTV_TVAL_EL0', 50000)
        self.set('AGTCNTV_CTL_EL0', 3)
        self.await_expiry()
        self.trace('timer_masked_count', 0, register=21)
        self.trace('timer_masked_hypervirtual_status', 7, 'CNTHV_CTL_EL2')
        self.set('AGTCNTV_CTL_EL0', 1)
        self.trace('cpu_masked_count', 0, register=21)
        self.trace('cpu_masked_hypervirtual_status', 5, 'CNTHV_CTL_EL2')
        self.label('ordinary_unmask')
        self.emit(0xd50341ff)  # msr daifclr,#1 (unmask FIQ only)
        self.await_count(1)
        self.label('ordinary_resumed')
        self.trace('ordinary_return_count', 1, register=21)
        self.trace('ordinary_return_currentg', 0, 'CURRENTG')
        self.trace('ordinary_return_timer_disabled', 0, 'CNTHV_CTL_EL2')
        self.trace('ordinary_return_sp', NORMAL_SP, sp=True)
        self.emit(0xd50341df)  # msr daifset,#1
        self.emit(0x00201422)  # genter #2
        self.label('normal_after_gexit')
        self.trace('gexit_currentg', 0, 'CURRENTG')
        self.trace('gexit_sp', NORMAL_SP, sp=True)
        self.trace('final_fiq_count', 2, register=21)
        self.trace('final_timer_disabled', 0, 'CNTHV_CTL_EL2')
        self.mov(0, 0xfeedfacecafebeef)
        self.trace('completion', 0xfeedfacecafebeef)
        self.label('terminal')
        self.emit(0x14000000)

        self.at(0x1000)
        self.trace('gl_entry_currentg', 1, 'CURRENTG')
        self.trace('gl_entry_sp', GUARDED_SP, sp=True)
        for name, register in (('SPSR_GL2', 25), ('ELR_GL2', 26), ('ASPSR_GL2', 27)):
            self.emit(sysreg(name, register, True))
        self.set('AGTCNTV_TVAL_EL0', 50000)
        self.set('AGTCNTV_CTL_EL0', 1)
        self.label('guarded_unmask')
        self.emit(0xd50341ff)
        self.await_count(2)
        self.label('guarded_resumed')
        self.trace('gl_eret_currentg', 1, 'CURRENTG')
        self.trace('gl_eret_sp', GUARDED_SP, sp=True)
        self.trace('gl_eret_fiq_count', 2, register=21)
        self.trace('gl_eret_timer_disabled', 0, 'CNTHV_CTL_EL2')
        self.emit(0xd50341df)
        for name, register in (('SPSR_GL2', 25), ('ELR_GL2', 26), ('ASPSR_GL2', 27)):
            self.emit(sysreg(name, register, False))
        self.emit(0x00201400)
        self.exception_stop(0x4200, False)
        self.fiq_handler(0x4300, False)
        self.exception_stop(0x6200, True)
        self.fiq_handler(0x6300, True)
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < 0x500,
                'Owned ROM and scratch ranges remain separate')
        for index, register, label in self.fixups:
            value = self.labels[label]
            for half in range(4):
                self.words[index + half] = ((0xd2800000 if half == 0 else 0xf2800000)
                    | (half << 21) | (((value >> (half * 16)) & 0xffff) << 5) | register)
        return b''.join(struct.pack('<I', word) for word in self.words)


def digest(path):
    with path.open('rb') as stream:
        return {'bytes': path.stat().st_size,
                'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
    resource.setrlimit(resource.RLIMIT_AS, (16 << 30, 16 << 30))


def run(binary, components, output):
    started = time.monotonic()
    asset_paths = {name: components / name for name in board.ASSETS}
    before = {name: digest(path) for name, path in asset_paths.items()}
    blobs = {name: path.read_bytes() for name, path in asset_paths.items()}
    layout = board.expected_layout(blobs)
    reserved = [{'name': name, 'physical_address': address, 'size': size}
                for name, (address, size) in layout['regions'].items()]
    for region in reserved:
        require(PROBE_END <= region['physical_address'] or
                BASE >= region['physical_address'] + region['size'],
                'Owned ROM/scratch/SP range overlaps boot reservation: ' + region['name'])
    require(DRAM <= BASE < PROBE_END <= DRAM + board.RAM_SIZE,
            'Owned probe lies inside modern DRAM')
    require(shutil.disk_usage(output).free >= 256 * 1024 * 1024, 'Minimum evidence free space')
    rom = ROM()
    content = rom.build()
    rom_path = output / 'board-fiq.rom'
    rom_path.write_bytes(content)
    report = {'scope': 'Actual modern board timer/FIQ acceptance; owned ROM only',
              'binary': str(binary), 'binary_sha256': digest(binary)['sha256'],
              'rom_sha256': digest(rom_path)['sha256'],
              'component_hashes_before': before, 'passes': [], 'passed': False,
              'qmp_transport': 'stdio', 'firmware_executed': False,
              'ios_boot_claim': False, 'modern_aic_claim': False,
              'owned_range': {'start': hex(BASE), 'end': hex(PROBE_END)},
              'reserved_regions': reserved,
              'limits': {'wall_seconds': MAX_WALL, 'cpu_seconds': 30,
                         'log_bytes': MAX_LOG, 'file_bytes': MAX_LOG,
                         'virtual_memory_bytes': 16 << 30}}
    process = qmp = None
    log_path = output / 'emulator.log'
    try:
        with tempfile.TemporaryDirectory(prefix='board-fiq-gate-') as temporary:
            scratch = Path(temporary)
            machine = 'apple-modern,' + ','.join(
                name + '=' + str(asset_paths[asset]) for name, asset in
                zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
            machine += ',prepare-only=true,boot-command-line=' + board.COMMAND_LINE
            argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
                    '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
                    '-device', f'loader,file={rom_path},addr={BASE},cpu-num=0,force-raw=true',
                    '-S', '-qmp', 'stdio']
            report['argv'] = argv
            with log_path.open('xb') as log:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=log, bufsize=0, preexec_fn=child_limits)

                def guard():
                    remaining = MAX_WALL - (time.monotonic() - started)
                    require(remaining > 0 and log_path.stat().st_size <= MAX_LOG,
                            'Board FIQ wall/log bound exceeded')
                    return remaining

                qmp = board.QMP(None, guard, process)
                require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}) is True,
                        'Board remains preparation-only')
                require(qmp.request('qom-get', {'path': '/machine', 'property': 'mte'}) is False,
                        'MTE profile remains off for this gate')
                for iteration in range(2):
                    if iteration:
                        qmp.request('system_reset')
                    deadline = time.monotonic() + 3
                    while True:
                        registers = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                        values = board.parse_registers(registers)
                        if values['PC'] == BASE:
                            break
                        require(time.monotonic() < deadline,
                                'Loader did not select owned PC; no cont issued')
                        time.sleep(0.02)
                    require(values['PSTATE'] & 15 == 9, 'Owned ROM starts at AArch64 EL2h')
                    require(qmp.request('query-status')['running'] is False, 'CPU is stopped before owned cont')
                    before_dump = scratch / 'owned-before.bin'
                    qmp.request('pmemsave', {'val': BASE, 'size': len(content), 'filename': str(before_dump)})
                    require(before_dump.read_bytes() == content, 'Owned ROM bytes are exact before cont')
                    before_dump.unlink()
                    observation = board.audit(qmp, scratch, blobs, layout, metadata.parse_adt)
                    (output / f'owned-reset-registers-{iteration}.txt').write_text(registers)
                    report['passes'].append({'iteration': iteration,
                                            'after_system_reset': bool(iteration),
                                            'owned_pc_verified_before_cont': hex(values['PC']),
                                            'owned_rom_verified_before_cont': True,
                                            'stopped_metadata_observation': observation,
                                            'completed': False})
                    qmp.request('cont')
                    deadline = time.monotonic() + 5
                    while True:
                        guard()
                        registers = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                        pc = board.parse_registers(registers)['PC']
                        if pc == rom.labels['terminal']:
                            break
                        require(BASE <= pc < BASE + len(content), 'Observed PC escaped owned ROM')
                        if time.monotonic() >= deadline:
                            (output / f'failed-registers-{iteration}.txt').write_text(registers)
                            qmp.request('stop')
                            qmp.request('pmemsave', {'val': SCRATCH, 'size': 0x518,
                                                     'filename': str(output / f'failed-scratch-{iteration}.bin')})
                            raise RuntimeError('Owned FIQ ROM did not reach completion')
                        time.sleep(0.01)
                    qmp.request('stop')
                    dump = output / f'owned-scratch-{iteration}.bin'
                    qmp.request('pmemsave', {'val': SCRATCH, 'size': 0x518, 'filename': str(dump)})
                    saved = struct.unpack('<163Q', dump.read_bytes())
                    actual = dict(zip(rom.expected, saved))
                    for label, expected in rom.expected.items():
                        if expected is not None:
                            require(actual[label] == expected,
                                    f'{label}: expected {expected:#x}, got {actual[label]:#x}')
                    require(not saved[0x500 // 8], 'No unexpected synchronous exception')
                    for kind, first, last in (
                        ('el', 'ordinary_unmask', 'ordinary_resumed'),
                        ('gl', 'guarded_unmask', 'guarded_resumed')):
                        require(rom.labels[first] <= actual[kind + '_fiq_saved_pc'] <= rom.labels[last],
                                'FIQ saved PC belongs to its owned interrupted block')
                    (output / f'owned-final-registers-{iteration}.txt').write_text(registers)
                    report['passes'][-1].update({'completed': True, 'actual': actual,
                        'ordinary_fiq_vector': hex(BASE + 0x4300),
                        'guarded_fiq_vector': hex(BASE + 0x6300),
                        'fiq_count': actual['final_fiq_count'], 'unexpected_sync_count': 0})
                qmp.request('quit')
                require(process.wait(timeout=5) == 0, 'Requested QEMU shutdown is clean')
        report['passed'] = True
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        (output / 'error-traceback.txt').write_text(traceback.format_exc())
    finally:
        if qmp is not None:
            try:
                qmp.close()
            except Exception as error:
                report['cleanup_error'] = str(error)
                report['passed'] = False
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            report['exit_code'] = process.returncode
            report['child_reaped'] = process.poll() is not None
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()
        try:
            after = {name: digest(path) for name, path in asset_paths.items()}
            report['component_hashes_after'] = after
            report['components_unchanged'] = before == after
            report['binary_unchanged'] = digest(binary)['sha256'] == report['binary_sha256']
            report['rom_unchanged'] = digest(rom_path)['sha256'] == report['rom_sha256']
            require(report['components_unchanged'] and report['binary_unchanged'] and report['rom_unchanged'],
                    'All original inputs and owned ROM stayed unchanged')
        except Exception as error:
            report['preservation_error'] = str(error)
            report['passed'] = False
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    components = args.components.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), 'Executable binary required')
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = run(binary, components, output)
    print(json.dumps({'passed': report['passed'],
                      'actual_board_passes': sum(p['completed'] for p in report['passes']),
                      'binary_sha256': report['binary_sha256'],
                      'firmware_executed': False, 'ios_boot_claim': False,
                      'error': report.get('error')}))
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
