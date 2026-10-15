#!/usr/bin/env python3
"""Actual ARM64 SART width/reset gate with normal board mappings enabled.

The loader pins PC to an owned ROM before each cont; firmware never executes.
This qualifies register storage only, not SART DMA enforcement or ANS firmware.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--components', type=Path, required=True)
    ap.add_argument('--output-dir', type=Path, required=True)
    a = ap.parse_args()
    spec = importlib.util.spec_from_file_location(
        'ans_sart_helpers', Path(__file__).with_name('test-apple-modern-ans-qemu.py'))
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    mb, board, require = h.mb, h.board, h.require
    out = a.output_dir.resolve()
    out.mkdir(exist_ok=False)
    binary = a.binary.resolve()
    assets = {k: a.components.resolve() / k for k in board.ASSETS}
    nodes, _ = mb.metadata.parse_adt(assets['dtree'].read_bytes())
    reg = nodes['/arm-io/sart-ans']['reg']['value']
    require(len(reg) == 48, 'matched three SART apertures')
    base, stock_span = struct.unpack_from('<QQ', reg)
    require(stock_span == 0xc000, 'matched first SART aperture size')
    # The current adapter only maps the first 0x4000 bytes of reg[0].
    # Testing that subset does not qualify the full three-aperture device.
    span = 0x4000
    ranges = nodes['/arm-io']['ranges']['value']
    matches = [(child, parent, length) for child, parent, length in struct.iter_unpack('<QQQ', ranges)
               if base >= child and base - child + span <= length]
    require(len(matches) == 1, 'unique SART bus translation')
    sart = base - matches[0][0] + matches[0][1]
    layout = board.expected_layout({k: p.read_bytes() for k, p in assets.items()})
    for name, (lo, size) in layout['regions'].items():
        require(mb.PROBE_END <= lo or mb.BASE >= lo + size,
                'owned buffers outside firmware: ' + name)
    done = 0x5a47574944544832

    class ROM(mb.ROM):
        def trace(self, *args, **kwargs):
            super().trace(*args, **kwargs)
            self.write64(mb.SCRATCH + 0xf00, len(self.expected))

        def check(self, name, address, value, size=8):
            (self.read64 if size == 8 else self.read32)(address, 23)
            self.trace(name, value, register=23)

        def build(self):
            self.mov(20, mb.SCRATCH)
            self.mov(0, mb.NORMAL_SP)
            self.emit(0x9100001f)
            self.emit(0xd5034fdf)
            self.check('reset_first_qword', sart, 0)
            self.check('reset_last_qword', sart + span - 8, 0)
            for offset in (0, 0x100, span - 16):
                tag = hex(offset)
                value = 0x1122334455667788
                neighbor = 0xaabbccddeeff0099
                self.write64(sart + offset + 8, neighbor)
                self.write64(sart + offset, value)
                self.check(tag + '_64bit_roundtrip', sart + offset, value)
                self.check(tag + '_low_word', sart + offset, value & 0xffffffff, 4)
                self.check(tag + '_high_word', sart + offset + 4, value >> 32, 4)
                self.check(tag + '_neighbor_preserved', sart + offset + 8, neighbor)
                self.write32(sart + offset, 0x89abcdef)
                self.check(tag + '_low_write_preserves_high', sart + offset, 0x1122334489abcdef)
                self.write32(sart + offset + 4, 0xfedcba98)
                self.check(tag + '_high_write_preserves_low', sart + offset, 0xfedcba9889abcdef)
                self.check(tag + '_neighbor_still_preserved', sart + offset + 8, neighbor)
            self.write64(sart + span - 8, 0x123456789abcdef0)
            self.check('last_valid_64bit_roundtrip', sart + span - 8, 0x123456789abcdef0)
            self.mov(0, done)
            self.trace('done', done)
            self.branch(len(self.words))
            raw = struct.pack('<' + 'I' * len(self.words), *self.words)
            require(len(raw) < 0x10000 and len(self.expected) * 8 < 0xf00,
                    'owned ROM and result bounds')
            return raw

    rom = ROM()
    raw = rom.build()
    (out / 'owned-sart.rom').write_bytes(raw)
    (out / 'zero.bin').write_bytes(bytes(4096))
    machine = 'apple-modern,' + ','.join(k + '=' + str(assets[v]) for k, v in
        zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=off,modern-aic=on,modern-ans=on'
    args = [str(binary), '-M', machine, '-m', '8G', '-smp', '1', '-nodefaults',
            '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={out}/owned-sart.rom,addr={mb.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={out}/zero.bin,addr={mb.SCRATCH},force-raw=true',
            '-S', '-qmp', 'stdio']
    inputs = {str(p): digest(p) for p in [binary, *assets.values()]}
    report = {'passed': False, 'argv': args, 'sart_address': hex(sart),
              'stock_aperture_sizes': [x[1] for x in struct.iter_unpack('<QQ', reg)],
              'modeled_span': span, 'complete_sart_mapping_qualified': False,
              'script_sha256': digest(Path(__file__)), 'inputs_before': inputs,
              'firmware_executed': False, 'sart_dma_enforcement_qualified': False,
              'passes': []}
    start = time.monotonic()
    process = None

    def guard():
        require(time.monotonic() - start < 25, 'owned SART gate deadline')
        require((out / 'emulator.log').stat().st_size < 4 << 20, 'bounded log')
        return 25 - (time.monotonic() - start)

    try:
        with (out / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=log, bufsize=0, start_new_session=True)
            report['pid'] = process.pid
            qmp = h.h.QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}) is False,
                    'normal ANS mapping path enabled')
            for iteration in range(2):
                require(not qmp.request('query-status')['running'], 'stopped before owned entry')
                registers = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                require(int(re.search(r'PC=([0-9a-fA-F]+)', registers)[1], 16) == mb.BASE,
                        'PC points to owned ROM before cont')
                with tempfile.TemporaryDirectory(prefix='ans-sart-') as tmp:
                    target = Path(tmp) / 'dump'
                    for address, expected in ((mb.BASE, raw), (mb.SCRATCH, bytes(4096))):
                        qmp.request('pmemsave', {'val': address, 'size': len(expected), 'filename': str(target)})
                        require(target.read_bytes() == expected, 'exact prelaunch owned bytes')
                    qmp.request('cont')
                    while True:
                        guard()
                        time.sleep(.05)
                        qmp.request('stop')
                        qmp.request('pmemsave', {'val': mb.SCRATCH, 'size': 4096, 'filename': str(target)})
                        result = target.read_bytes()
                        (out / f'results-{iteration}.bin').write_bytes(result)
                        progress = struct.unpack_from('<Q', result, 0xf00)[0]
                        require(progress <= len(rom.expected), 'progress bounded')
                        values = struct.unpack_from('<' + 'Q' * len(rom.expected), result)
                        report['last_progress'] = progress
                        for (label, expected), observed in zip(list(rom.expected.items())[:progress], values):
                            require(observed == expected,
                                    f'{label}: expected {expected:#x}, observed {observed:#x}')
                        if progress == len(rom.expected):
                            break
                        qmp.request('cont')
                report['passes'].append({'iteration': iteration, 'checks': len(rom.expected),
                                         'cpu_results': dict(zip(rom.expected, values))})
                if iteration == 0:
                    qmp.request('system_reset')
            qmp.request('quit')
            require(process.wait(timeout=5) == 0, 'clean QEMU exit')
            report['passed'] = True
    except Exception as e:
        report['error'] = str(e)
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        report['child_reaped'] = process is not None and process.poll() is not None
        report['qemu_returncode'] = process.returncode if process else None
        report['inputs_unchanged'] = inputs == {p: digest(Path(p)) for p in inputs}
        report['elapsed_seconds'] = time.monotonic() - start
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    require(report['passed'] and report['inputs_unchanged'], report.get('error', 'SART gate failed'))
    print('PASS: actual ARM64 SART 32/64-bit storage, edges, neighbors and system reset; normal mappings enabled')


if __name__ == '__main__':
    main()
