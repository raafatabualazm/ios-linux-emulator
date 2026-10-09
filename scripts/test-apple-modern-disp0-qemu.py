#!/usr/bin/env python3
"""Actual-CPU gate for the opt-in T8140 disp0 unified display pipe.

Apple firmware components are preparation inputs only; the CPU is stopped and
only the owned AArch64 ROM executes. The ROM drives the real MMIO path through
the real CPU at the plan's own addresses and proves, in two passes separated by
a system reset:

  * the frame-size register answers the geometry the board was given, in the
    t8030 (width << 16) | height encoding;
  * every shadow alias of the pipe aperture answers identically, and the gap
    between the end of the block map and the first shadow alias FAULTS;
  * interrupt enable/status round-trip and status is write-one-to-clear;
  * a GenPipe register round-trips independently per pipe;
  * an UNMODELLED offset inside the mapped pipe aperture takes a synchronous
    external abort rather than reading zero, and is reported in the frontier;
  * a mapped-but-opaque window (reg[1]) faults on its very first access;
  * the two windows the plan leaves to their owners (reg[4] = /arm-io/dcp,
    reg[5] = inside /arm-io/pmgr) are not mapped by this device at all.

A no-device oracle must fail on the first owned load, with the exact
external-abort ESR, before any instrumented counter is consulted. Two startup
refusal oracles are run as well: disp0-pipe together with boot-display, and a
tree whose disp0 dot-pitch has been changed by one byte.

Run under the shared QEMU lock.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import resource
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    'disp0_pmgr_helpers',
    Path(__file__).with_name('test-apple-modern-pmgr-qemu.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
mailbox, board = helper.mailbox, helper.board
require, digest = helper.require, helper.digest

MACHINE_KEYS = ('bootkc', 'sptm', 'txm', 'dtree', 'tc')
PIPE = 0x410000000
OPAQUE = 0x412240000
DCP_WINDOW = 0x412800000
PMGR_WINDOW = 0x302800000
SHADOW_STRIDE = 0x200000
BLOCK_SPAN = 0xFC000
SHADOW_COPIES = 5
FRAME_SIZE = 0x4603C
INT_STATUS = 0x45818
INT_ENABLE = 0x4581C
KICK = 0x4602C
GP_BASE = 0x50000
GP_BLOCK_STRIDE = 0x8000
GP_STRIDE_REG = 0x60
WIDTH, HEIGHT = 1024, 768
FRAME = (WIDTH << 16) | HEIGHT
UNMODELLED = 0x1000          # inside the pipe aperture, no register there
DONE = 0xD15F0ACE12345678
COUNTERS = ('mmio-read-count', 'mmio-write-count', 'mmio-fault-count',
            'kick-count')
# Exact MMIO pin for the ROM below.
FINAL = dict(zip(COUNTERS, (12, 4, 4, 1)))
# A rejected access to a region this device OWNS is reported with the external
# abort type bit (ISS bit 9) set, which is how the guest can tell it apart from
# an access to an address nothing is mapped at. Measured, both directions.
UNMAPPED_READ_ESR = 0x96000010   # nothing mapped there at all (no-device)
REJECT_READ_ESR = 0x96000210     # mapped, this model rejected the load
REJECT_WRITE_ESR = 0x96000250    # mapped, this model rejected the store
EXPECTED_MAP = (
    '0:0x410000000:0xafc000:pipe:mapped,'
    '1:0x412240000:0x10000:opaque:mapped,'
    '2:0x4123a8000:0x4000:opaque:mapped,'
    '3:0x4123ac000:0x4000:opaque:mapped,'
    '4:0x412800000:0x800000:dcp:skipped,'
    '5:0x302800000:0xbc000:pmgr:skipped')


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
                    'Migration must reject the unmigratable disp0 pipe state')
            error = response['error']
            require('apple-modern-disp0' in error.get('desc', '') and
                    'non-migratable' in error.get('desc', ''),
                    'Migration rejection must name the disp0 pipe state')
            require(not target.exists(), 'No partial migration file')
            return error
        raise RuntimeError('disp0 migration-rejection deadline')


def child_limits():
    """As the other actual-CPU gates, but with room for one QEMU console.

    graphic_console_init allocates its placeholder surface through a memfd and
    ftruncate()s it to 640 x 480 x 4 = 1,228,800 bytes, which exceeds the 1 MiB
    RLIMIT_FSIZE the register-only gates use and kills the child with SIGXFSZ.
    The emulator log stays bounded by guard() either way.
    """
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 << 20, 32 << 20))
    resource.setrlimit(resource.RLIMIT_AS, (16 << 30, 16 << 30))


class ROM(helper.ROM):
    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001F)          # mov sp, x0
        self.emit(0xD5034FDF)          # isb
        self.set('VBAR_EL2', mailbox.BASE + 0x4000)

        # 1. geometry, from the base block map and from every shadow alias
        self.check('frame_size', PIPE + FRAME_SIZE, FRAME)
        self.first_load_pc = mailbox.BASE + (len(self.words) - 2) * 4
        for copy in range(1, SHADOW_COPIES + 1):
            self.check('frame_size_shadow_%d' % copy,
                       PIPE + copy * SHADOW_STRIDE + FRAME_SIZE, FRAME)

        # 2. interrupt enable round-trip and write-one-to-clear status
        self.write32(PIPE + INT_ENABLE, 1 << 10)
        self.check('int_enable', PIPE + INT_ENABLE, 1 << 10)
        self.check('int_status_clear', PIPE + INT_STATUS, 0)

        # 3. per-GenPipe independence
        for gp in range(2):
            address = PIPE + GP_BASE + gp * GP_BLOCK_STRIDE + GP_STRIDE_REG
            self.write32(address, 0x1000 + gp)
        for gp in range(2):
            address = PIPE + GP_BASE + gp * GP_BLOCK_STRIDE + GP_STRIDE_REG
            self.check('gp%d_stride' % gp, address, 0x1000 + gp)

        # 4. the kick register is write-only and counted
        self.write32(PIPE + KICK, 1 << 12)

        # 5. the faults. Each of these must take a synchronous external abort;
        #    the handler records the first ELR/ESR and steps over.
        self.fault_pcs = []
        self.read32(PIPE + UNMODELLED, 23)
        self.fault_pcs.append(mailbox.BASE + (len(self.words) - 1) * 4)
        # The gap between the end of the block map and the first shadow alias
        # is inside the window and mapped, and must still be rejected.
        self.read32(PIPE + BLOCK_SPAN, 23)
        self.fault_pcs.append(mailbox.BASE + (len(self.words) - 1) * 4)
        self.read32(OPAQUE, 23)
        self.fault_pcs.append(mailbox.BASE + (len(self.words) - 1) * 4)
        self.write32(PIPE + UNMODELLED, 1)
        self.fault_pcs.append(mailbox.BASE + (len(self.words) - 1) * 4)

        # 6. the model is intact afterwards
        self.check('frame_size_after_faults', PIPE + FRAME_SIZE, FRAME)
        self.check('int_enable_after_faults', PIPE + INT_ENABLE, 1 << 10)

        self.mov(0, DONE)
        self.trace('completion', DONE)
        self.branch(len(self.words))
        for offset in range(0x4000, 0x4800, 0x80):
            self.at(offset)
            self.emit(0xF9400000 | (0x500 // 8 << 10) | (20 << 5))
            self.emit(0xB5000060)      # cbnz x0, skip first-fault capture
            self.emit(0xD53C4029)      # mrs x9, ELR_EL2
            self.store(9, 0x518)
            self.emit(0x91000400)      # add x0, x0, #1
            self.store(0, 0x500)
            self.emit(mailbox.sysreg('ESR_EL2', 0, True))
            self.store(0, 0x508)
            self.emit(0xD53C4020)      # mrs x0, ELR_EL2
            self.store(0, 0x510)
            self.emit(0x91001000)      # add x0, x0, #4
            self.emit(0xD51C4020)      # msr ELR_EL2, x0
            self.emit(0xD69F03E0)      # eret
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < 0x500,
                'Owned ROM/results/fault ranges stay separate')
        return b''.join(struct.pack('<I', value) for value in self.words)


def mutate_dot_pitch(tree: Path, target: Path) -> dict:
    """Byte-exact copy of the served tree with disp0's dot-pitch changed.

    The Apple device tree stores a property as name[32] + size(u32) + data, so
    the 460 the plan anchors on is found by its name and its value. Nothing is
    written back to the input, and the copy is the same length.
    """
    raw = bytearray(tree.read_bytes())
    found = []
    needle = b'dot-pitch\0'
    at = raw.find(needle)
    while at >= 0:
        size = struct.unpack_from('<I', raw, at + 32)[0] & 0x7FFFFFFF
        if size == 4 and struct.unpack_from('<I', raw, at + 36)[0] == 460:
            found.append(at + 36)
        at = raw.find(needle, at + 1)
    require(len(found) == 1,
            'exactly one disp0 dot-pitch of 460 in the served tree, found %d'
            % len(found))
    struct.pack_into('<I', raw, found[0], 461)
    target.write_bytes(bytes(raw))
    require(target.stat().st_size == tree.stat().st_size,
            'the mutated tree is the same length')
    return {'offset': hex(found[0]), 'from': 460, 'to': 461}


def refusal(binary: Path, assets: dict, extra: str, wanted: str,
            output: Path, label: str) -> dict:
    machine = 'apple-modern,' + ','.join(
        key + '=' + str(assets[name]) for key, name in
        zip(MACHINE_KEYS, board.ASSETS))
    machine += ',prepare-only=true' + extra
    # 2 GiB: these never reach the ROM, they must refuse during board init,
    # and a second 8 GiB reservation can fail on a loaded host for the wrong
    # reason.
    argv = [str(binary), '-M', machine, '-m', '2G', '-smp', '1', '-nodefaults',
            '-display', 'none', '-serial', 'none', '-monitor', 'none', '-S']
    done = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    (output / (label + '.log')).write_text(done.stdout + done.stderr)
    require(done.returncode != 0,
            '%s must refuse to start (exit %d)' % (label, done.returncode))
    require(wanted in done.stdout + done.stderr,
            '%s must say why: %r' % (label, wanted))
    return {'label': label, 'exit': done.returncode, 'argv': argv,
            'message': wanted}


def run(binary, components, output, tree, no_device):
    assets = {name: (tree if name == 'dtree' else components / name)
              for name in board.ASSETS}
    hashes = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes()
                                    for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch outside preparation assets: ' + name)
    rom = ROM()
    rom_path = output / 'owned-disp0.rom'
    rom_path.write_bytes(rom.build())
    zero_path = output / 'zero-results.bin'
    zero_path.write_bytes(bytes(0x520))
    machine = 'apple-modern,' + ','.join(
        key + '=' + str(assets[name]) for key, name in
        zip(MACHINE_KEYS, board.ASSETS))
    machine += ',prepare-only=true'
    if not no_device:
        machine += ',disp0-pipe=on'
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1', '-nodefaults',
            '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={mailbox.BASE},'
                       'cpu-num=0,force-raw=true',
            '-device', f'loader,file={zero_path},addr={mailbox.SCRATCH},'
                       'force-raw=true',
            '-S', '-qmp', 'stdio']
    report = {'passed': False, 'argv': argv, 'binary_sha256': digest(binary),
              'script_sha256': digest(Path(__file__)),
              'firmware_executed': False, 'ios_boot_claim': False,
              'register_offsets_attested': False,
              'register_offsets_label': 'analogy from the in-tree A13/t8030 '
                                        'apple_displaypipe_v4.c',
              'component_hashes_before': hashes, 'no_device_oracle': no_device,
              'passes': [], 'refusals': []}
    process = qmp = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='disp0-qemu-') as temp, \
             (output / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=log,
                                       bufsize=0,
                                       preexec_fn=child_limits)

            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and
                        (output / 'emulator.log').stat().st_size < mailbox.MAX_LOG,
                        'disp0 gate wall/log bound')
                return remaining

            qmp = QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine',
                                            'property': 'prepare-only'}),
                    'Only the owned ROM may execute')
            if not no_device:
                blocked = qmp.require_migration_blocked(
                    Path(temp) / 'migration.state')
                require('apple-modern-disp0' in blocked['desc'],
                        'Migration rejection names the disp0 pipe state')
                report['migration_rejection'] = blocked
                report['window_map'] = qmp.request(
                    'qom-get', {'path': '/machine/disp0',
                                'property': 'window-map'})
                require(report['window_map'] == EXPECTED_MAP,
                        'window map is the ADT-derived plan: %r'
                        % (report['window_map'],))
            for iteration in range(2):
                if iteration:
                    qmp.request('system_reset')
                regs = board.parse_registers(qmp.request(
                    'human-monitor-command', {'command-line': 'info registers'}))
                require(regs['PC'] == mailbox.BASE,
                        'Owned ROM PC selected before cont')
                if not no_device:
                    reset = {name: qmp.request(
                        'qom-get', {'path': '/machine/disp0',
                                    'property': name}) for name in COUNTERS}
                    require(reset == dict.fromkeys(COUNTERS, 0),
                            'Counters reset: %r' % (reset,))
                    require(qmp.request('qom-get', {'path': '/machine/disp0',
                                                    'property': 'frontier'}) == '',
                            'Frontier table reset')
                    for name in COUNTERS:
                        qmp.require_readonly('/machine/disp0', name)
                qmp.request('cont')
                deadline = time.monotonic() + 15
                dump = Path(temp) / 'results.bin'
                while True:
                    guard()
                    qmp.request('stop')
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH,
                                             'size': 0x520,
                                             'filename': str(dump)})
                    raw = dump.read_bytes()
                    (output / f'results-pass{iteration}.bin').write_bytes(raw)
                    fault, esr, elr = struct.unpack_from('<3Q', raw, 0x500)
                    if fault and no_device:
                        first = struct.unpack_from('<Q', raw, 0x518)[0]
                        require(first == rom.first_load_pc and
                                esr == UNMAPPED_READ_ESR,
                                'No-device oracle must fault at the first '
                                'owned load with the exact external-abort ESR')
                        report['no_device_oracle_validated'] = True
                        report['actual_missing_device_fault'] = {
                            'first_elr': hex(first), 'esr': hex(esr),
                            'expected_first_load': hex(rom.first_load_pc)}
                        require(False, 'No-device oracle rejected on actual '
                                       'MMIO fault before diagnostics: '
                                       + hex(first))
                    if struct.unpack_from(
                            '<Q', raw, (len(rom.expected) - 1) * 8)[0] == DONE:
                        break
                    require(time.monotonic() < deadline,
                            'Owned ROM completion deadline')
                    qmp.request('cont')
                    time.sleep(0.03)
                observed = {}
                for index, (name, expected) in enumerate(rom.expected.items()):
                    value = struct.unpack_from('<Q', raw, index * 8)[0]
                    require(value == expected,
                            f'{name}: expected {expected:#x}, '
                            f'observed {value:#x}')
                    observed[name] = hex(value)
                first = struct.unpack_from('<Q', raw, 0x518)[0]
                require(fault == len(rom.fault_pcs),
                        'Exactly the four owned faulting accesses faulted, '
                        'observed %d' % fault)
                require(first == rom.fault_pcs[0],
                        'First fault is the unmodelled pipe read, at %#x'
                        % first)
                require(elr == rom.fault_pcs[-1] and esr == REJECT_WRITE_ESR,
                        'Last fault is the owned store to a mapped window, '
                        'ELR %#x ESR %#x' % (elr, esr))
                counters = {name: qmp.request(
                    'qom-get', {'path': '/machine/disp0', 'property': name})
                    for name in COUNTERS}
                require(counters == FINAL,
                        'Actual MMIO counters %r, expected %r'
                        % (counters, FINAL))
                frontier = qmp.request('qom-get', {'path': '/machine/disp0',
                                                   'property': 'frontier'})
                require(frontier.split(',') == [
                            '0:0x410001000:0x1000:r',
                            '0:0x4100fc000:0xfc000:r',
                            '1:0x412240000:0x0:r',
                            '0:0x410001000:0x1000:w'],
                        'Frontier records each distinct rejected access once, '
                        'in order: %r' % (frontier,))
                report['passes'].append({'iteration': iteration,
                                         'counters': counters,
                                         'frontier': frontier,
                                         'faults': fault,
                                         'first_fault_esr': hex(esr),
                                         'observed': observed})
            qmp.request('quit')
            require(process.wait(timeout=10) == 0, 'Clean emulator exit')
            process = None
        if not no_device:
            report['refusals'].append(refusal(
                binary, assets, ',disp0-pipe=on,boot-display=on',
                'disp0-pipe replaces boot-display', output, 'both-displays'))
            with tempfile.TemporaryDirectory(prefix='disp0-tree-') as temp:
                bad = Path(temp) / 'dtree-bad-dot-pitch'
                report['mutated_tree'] = mutate_dot_pitch(
                    Path(assets['dtree']), bad)  # the served tree, read-only
                mutated = dict(assets, dtree=bad)
                report['refusals'].append(refusal(
                    binary, mutated, ',disp0-pipe=on',
                    'dot-pitch 461 is not the attested 460', output,
                    'mutated-dot-pitch'))
        report['passed'] = len(report['passes']) == 2 and (
            no_device or len(report['refusals']) == 2)
    except Exception as error:
        report['error'] = '%s: %s' % (type(error).__name__, error)
    finally:
        if process:
            process.kill()
            process.wait(timeout=10)
        if qmp:
            qmp.close()
        report['component_hashes_after'] = {name: digest(path)
                                            for name, path in assets.items()}
        if report['component_hashes_after'] != hashes:
            report['passed'] = False
            report['error'] = 'Preparation inputs changed'
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report.get(key)
                      for key in ('passed', 'error', 'elapsed_seconds')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--dtree', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--no-device', action='store_true')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    sys.exit(run(args.binary.resolve(), args.components.resolve(),
                 args.output_dir.resolve(), args.dtree.resolve(),
                 args.no_device))
