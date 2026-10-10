#!/usr/bin/env python3
"""Owned ARM ROM control: COW delta must reproduce an independent complete QMP snapshot."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=pathlib.Path, required=True)
parser.add_argument('--out', type=pathlib.Path, required=True)
args = parser.parse_args()
out = args.out.resolve(); out.mkdir()
spec = importlib.util.spec_from_file_location('cow', pathlib.Path(__file__).with_name('capture-apple-modern-ramdisk-cow.py'))
cow = importlib.util.module_from_spec(spec); spec.loader.exec_module(cow)
source = out / 'owned-ram.bin'
size = 64 << 20
with source.open('wb') as f:
    f.truncate(size)
    f.seek(32 << 20)  # virt may write its boot data at the beginning of RAM
    f.write(b'UNCHANGED-CONTROL'.ljust(4096, b'X'))
source_hash = cow.sha256(source)
asm = out / 'owned.S'
asm.write_text('.global _start\n_start:\n ldr x0, address\n mov w1, #0x1234\n str w1, [x0, #0x1000]\nloop:\n wfi\n b loop\n .balign 8\naddress: .quad 0x40000000\n')
subprocess.run(['clang', '--target=aarch64-none-elf', '-c', str(asm), '-o', str(out / 'owned.o')], check=True)
subprocess.run(['llvm-objcopy-21', '-O', 'binary', str(out / 'owned.o'), str(out / 'owned.bin')], check=True)
socket_directory = tempfile.TemporaryDirectory(prefix='cow-qmp-')
socket = pathlib.Path(socket_directory.name) / 'qmp.sock'
argv = [str(args.binary.resolve()), '-M', 'virt,memory-backend=owned', '-cpu', 'cortex-a57',
        '-m', '64M', '-smp', '1', '-object', f'memory-backend-file,id=owned,size={size},mem-path={source},share=off,x-use-canonical-path-for-ramblock-id=off',
        '-bios', str(out / 'owned.bin'), '-nodefaults', '-display', 'none', '-serial', 'none',
        '-qmp', f'unix:{socket},server=on,wait=off']
(out / 'argv.json').write_text(json.dumps(argv, indent=2) + '\n')
with (out / 'qemu.log').open('wb') as log:
    child = subprocess.Popen(argv, stdout=log, stderr=log)
    qmp = None
    try:
        deadline = time.monotonic() + 20
        while not socket.exists():
            if child.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('owned QEMU failed to start')
            time.sleep(.1)
        qmp = cow.QMP(socket, child.pid)
        while True:
            probe = out / 'probe.bin'
            qmp.command('pmemsave', dict(val=0x40001000, size=4, filename=str(probe)))
            if probe.read_bytes() == b'\x34\x12\0\0':
                break
            if time.monotonic() > deadline:
                raise RuntimeError('owned ROM did not write witness')
            time.sleep(.1)
        qmp.command('stop')
        full = out / 'oracle-full.bin'
        qmp.command('pmemsave', dict(val=0x40000000, size=size, filename=str(full)))
        qmp.file.close(); qmp.socket.close(); qmp = None
        subprocess.run(['python3', str(pathlib.Path(__file__).with_name('capture-apple-modern-ramdisk-cow.py')),
                        '--pid', str(child.pid), '--qmp', str(socket), '--image', str(source),
                        '--out', str(out / 'capture'), '--region', 'owned'], check=True)
        manifest = json.loads((out / 'capture/manifest.json').read_text())
        delta = (out / 'capture/delta.bin').read_bytes()
        oracle = full.read_bytes()
        reconstructed = bytearray(source.read_bytes())
        for block in manifest['blocks']:
            value = delta[block['delta_offset']:block['delta_offset'] + block['size']]
            reconstructed[block['offset']:block['offset'] + block['size']] = value
        assert bytes(reconstructed) == oracle
        assert reconstructed[0x1000:0x1004] == b'\x34\x12\0\0'
        assert reconstructed[32 << 20:(32 << 20) + 4096] == source.read_bytes()[32 << 20:(32 << 20) + 4096]
        assert source_hash == cow.sha256(source)
        # A no-delta mutant must fail the independent complete-snapshot oracle.
        assert source.read_bytes() != oracle
        # Bounded capture refuses before writing a purported complete manifest.
        refusal = subprocess.run(['python3', str(pathlib.Path(__file__).with_name('capture-apple-modern-ramdisk-cow.py')),
                                  '--pid', str(child.pid), '--qmp', str(socket), '--image', str(source),
                                  '--out', str(out / 'budget-refused'), '--region', 'owned',
                                  '--max-bytes', '1'], capture_output=True)
        (out / 'budget-refused.log').write_bytes(refusal.stdout + refusal.stderr)
        assert refusal.returncode != 0 and not (out / 'budget-refused/manifest.json').exists()
        result = dict(passed=True, source_sha256=source_hash,
                      oracle_sha256=hashlib.sha256(oracle).hexdigest(),
                      reconstructed_sha256=hashlib.sha256(reconstructed).hexdigest(),
                      changed_pages=manifest['changed_pages'], saved_bytes=manifest['saved_bytes'],
                      no_delta_mutant_rejected=True, budget_oracle_rejected=True,
                      scope='Owned ARM virt ROM; no Apple firmware, no production-root capture yet')
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
    finally:
        if qmp:
            qmp.file.close(); qmp.socket.close()
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait()
        socket_directory.cleanup()
