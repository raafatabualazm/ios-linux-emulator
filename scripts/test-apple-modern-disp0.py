#!/usr/bin/env python3
"""Run the T8140 disp0 pipe core/plan gate on owned data, twice.

Compiled with ASan+UBSan (-fno-sanitize-recover=all) and again with
-DNDEBUG -O2; both must report the same number of checks. --refuse-dtree
names a tree the builder must REFUSE (the A13/t8030 ADT is the natural one).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dtree', type=Path, required=True)
    parser.add_argument('--refuse-dtree', type=Path)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sources = ['hw/arm/apple-silicon/modern-boot-layout.c',
               'hw/arm/apple-silicon/modern-boot-metadata.c',
               'hw/arm/apple-silicon/modern-disp0.c',
               'include/hw/arm/apple-silicon/modern-disp0.h',
               'scripts/test-apple-modern-disp0.c',
               'scripts/test-apple-modern-disp0.py']
    before = {name: digest(root / name) for name in sources}
    trees = {str(args.dtree): digest(args.dtree)}
    if args.refuse_dtree:
        trees[str(args.refuse_dtree)] = digest(args.refuse_dtree)
    runs = []
    with tempfile.TemporaryDirectory(prefix='modern-disp0-core-') as temp:
        for mode, flags in [('sanitizers', ['-fsanitize=address,undefined',
                                            '-fno-sanitize-recover=all',
                                            '-fno-omit-frame-pointer', '-g']),
                            ('production-ndebug', ['-DNDEBUG', '-O2'])]:
            binary = Path(temp) / mode
            command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                       '-DAPPLE_MODERN_LAYOUT_STANDALONE',
                       '-I' + str(root / 'include'), *flags,
                       *(str(root / name) for name in sources
                         if name.endswith('.c')), '-o', str(binary)]
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=180)
            if built.returncode:
                raise SystemExit(built.stdout + built.stderr)
            argv = [str(binary), str(args.dtree.resolve())]
            if args.refuse_dtree:
                argv.append(str(args.refuse_dtree.resolve()))
            executed = subprocess.run(argv, capture_output=True, text=True,
                                      timeout=120,
                                      env=dict(os.environ,
                                               ASAN_OPTIONS='detect_leaks=0'))
            runs.append({'mode': mode, 'exit': executed.returncode,
                         'stdout': executed.stdout.strip(),
                         'stderr': executed.stderr.strip()})
            if executed.returncode:
                raise SystemExit(executed.stdout + executed.stderr)
    checks = {json.loads(run['stdout'])['checks'] for run in runs}
    if len(checks) != 1:
        raise SystemExit('check counts differ between modes: %r' % (checks,))
    if before != {name: digest(root / name) for name in sources} or \
            trees != {path: digest(path) for path in trees}:
        raise SystemExit('Inputs changed during qualification')
    report = {'passed': True, 'checks': checks.pop(), 'runs': runs,
              'source_sha256': before, 'dtree_sha256': trees,
              'firmware_executed': False,
              'qemu_mmio_wrapper_exercised': False,
              'scope': 'T8140 /arm-io/disp0 six-window plan, shadow fold, '
                       'faulting pipe decode, frontier recorder and reset'}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
