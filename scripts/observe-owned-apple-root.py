#!/usr/bin/env python3
"""Bind a declared owned root run, watch milestones and export after teardown.

Read-only guest observation: no QMP, signals, writes to images or guest launch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def option(argv, name):
    if argv.count(name) != 1:
        raise ValueError('missing or repeated option ' + name)
    return argv[argv.index(name) + 1]


def validate_declaration(argv, inputs, run, image, image_sha, binary, binary_sha):
    if not argv or argv[0] != str(binary):
        raise ValueError('declared executable differs')
    if inputs.get(str(image)) != image_sha or inputs.get(str(binary)) != binary_sha:
        raise ValueError('declared image/binary pins differ')
    if option(argv, '-serial') != 'file:' + str(run / 'serial.log'):
        raise ValueError('declared serial path differs')
    machine = option(argv, '-M').split(',')
    if machine[0] != 'apple-modern' or machine.count('ramdisk=' + str(image)) != 1:
        raise ValueError('declared machine/image differs')
    if 'large-ramdisk=on' not in machine:
        raise ValueError('declared root is not the large RAM disk')


def process(pid):
    proc = Path('/proc') / str(pid)
    if proc.stat().st_uid != os.getuid():
        raise PermissionError('process has another owner')
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    if fields[0] == 'Z':
        raise ProcessLookupError('process already exited')
    argv = (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    return fields[19], int(fields[1]), [v.decode() for v in argv]


def discover(argv, run, image, binary, launcher):
    candidates = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            birth, parent, actual = process(int(proc.name))
            if actual != argv:
                continue
            if (proc / 'exe').resolve() != binary:
                raise ValueError('matching guest executable inode path differs')
            _, _, parent_argv = process(parent)
            parent_cwd = (Path('/proc') / str(parent) / 'cwd').resolve()
            if not any((parent_cwd / token).resolve() == launcher for token in parent_argv):
                raise ValueError('matching guest has an unqualified launcher')
            for key, value in (('--out', run), ('--image', image), ('--binary', binary)):
                if (parent_cwd / option(parent_argv, key)).resolve() != value:
                    raise ValueError('matching guest launcher declaration differs')
            candidates.append({'pid': int(proc.name), 'start_ticks': birth,
                               'parent_pid': parent, 'parent_argv': parent_argv})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    if len(candidates) > 1:
        raise ValueError('multiple processes match the exact owned run')
    return candidates[0] if candidates else None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('run', 'out', 'image', 'binary', 'launcher', 'watcher', 'reader',
                 'export_tool', 'exporter', 'decoder'):
        p.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    p.add_argument('--image-sha256', required=True)
    p.add_argument('--binary-sha256', required=True)
    p.add_argument('--wait-seconds', type=int, default=7200)
    p.add_argument('--watch-seconds', type=int, default=4200)
    p.add_argument('--job', action='append', default=[])
    a = p.parse_args()
    if a.wait_seconds <= 0 or a.watch_seconds <= 0:
        p.error('positive observation budgets required')
    for name in ('run', 'out', 'image', 'binary', 'launcher', 'watcher', 'reader',
                 'export_tool', 'exporter', 'decoder'):
        setattr(a, name, getattr(a, name).resolve())
    deadline = time.monotonic() + a.wait_seconds
    while not all((a.run / n).exists() for n in ('argv.json', 'inputs.json')):
        if time.monotonic() >= deadline:
            raise SystemExit('declared run did not appear within observer budget')
        time.sleep(10)
    argv = json.loads((a.run / 'argv.json').read_text())
    inputs = json.loads((a.run / 'inputs.json').read_text())
    validate_declaration(argv, inputs, a.run, a.image, a.image_sha256,
                         a.binary, a.binary_sha256)
    if digest(a.image) != a.image_sha256 or digest(a.binary) != a.binary_sha256:
        raise SystemExit('actual image/binary differ from declared pins')
    observer_pins = {'reader': '0d98c728cd5cfe10ae0360108eca658efc60c36524196cf6dc09ccd6ae96d043',
                     'watcher': 'f4f0a3925dbd2966d7c436a047872afa85b8ecfb84ba75aa89fcc6c0406e71ee',
                     'export_tool': '58b4ec1b282d4e47024e611f457b87809b1acf7769d67577c7800f4d0ffd937d'}
    for name, expected in observer_pins.items():
        if digest(getattr(a, name)) != expected:
            raise SystemExit('observer tool differs from qualified pin: ' + name)
    while True:
        if (a.run / 'result.json').exists():
            raise SystemExit('run completed before live observer could bind')
        owned = discover(argv, a.run, a.image, a.binary, a.launcher)
        if owned:
            break
        if time.monotonic() >= deadline:
            raise SystemExit('exact owned guest did not start within observer budget')
        time.sleep(10)
    if process(owned['pid'])[0] != owned['start_ticks']:
        raise SystemExit('owned PID identity changed before observer launch')
    os.umask(0o077)
    a.out.mkdir(parents=True, exist_ok=False)
    binding = dict(owned, run=str(a.run), argv_sha256=digest(a.run/'argv.json'),
                   inputs_sha256=digest(a.run/'inputs.json'),
                   image_sha256=a.image_sha256, binary_sha256=a.binary_sha256,
                   observer_tools={str(getattr(a, n)): digest(getattr(a, n)) for n in
                       ('launcher', 'watcher', 'reader', 'export_tool', 'exporter', 'decoder')},
                   guest_control_performed=False)
    (a.out/'binding.json').write_text(json.dumps(binding, indent=2)+'\n')
    watch = ['python3', str(a.watcher), '--pid', str(owned['pid']), '--log',
             str(a.run/'serial.log'), '--out', str(a.out/'live'), '--reader', str(a.reader),
             '--max-seconds', str(a.watch_seconds)]
    for job in a.job:
        watch += ['--job', job]
    export = ['python3', str(a.export_tool), '--run', str(a.run), '--out',
              str(a.out/'postcapture'), '--exporter', str(a.exporter), '--decoder',
              str(a.decoder), '--wait-seconds', str(a.watch_seconds + 1800)]
    (a.out/'observer-argv.json').write_text(json.dumps({'watch':watch,'export':export}, indent=2)+'\n')
    with (a.out/'watch.log').open('wb') as w, (a.out/'export.log').open('wb') as e:
        watcher = subprocess.Popen(watch, stdout=w, stderr=subprocess.STDOUT)
        exporter = subprocess.Popen(export, stdout=e, stderr=subprocess.STDOUT)
        # Only analysis children are waited on. The launcher owns guest lifetime.
        codes = {'watcher': watcher.wait(), 'exporter': exporter.wait()}
    if (a.run/'result.json').exists():
        result = json.loads((a.run/'result.json').read_text())
        if result.get('qemu_pid') != owned['pid']:
            codes['error'] = 'final result PID differs from live binding'
    (a.out/'orchestration-result.json').write_text(json.dumps(codes, indent=2)+'\n')
    if any(v != 0 for v in codes.values()):
        raise SystemExit('observer/export qualification failed; inspect retained reports')


if __name__ == '__main__':
    main()
