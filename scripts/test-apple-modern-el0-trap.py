#!/usr/bin/env python3
"""Run the EL0 BRK classifier core checks twice: sanitizers and production NDEBUG.

Also runs a negative oracle: a deliberately wrong expectation must make the same
test binary fail, so a pass means the checks can fail.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

SOURCES = ['hw/arm/apple-silicon/modern-el0-trap.c',
           'include/hw/arm/apple-silicon/modern-el0-trap.h',
           'scripts/test-apple-modern-el0-trap.c',
           'scripts/test-apple-modern-el0-trap.py']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_and_run(root, temp, mode, flags, extra_defines=()):
    binary = Path(temp) / mode
    command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-DAPPLE_MODERN_LAYOUT_STANDALONE', *extra_defines,
               '-I' + str(root / 'include'),
               *flags,
               str(root / 'hw/arm/apple-silicon/modern-el0-trap.c'),
               str(root / 'scripts/test-apple-modern-el0-trap.c'),
               '-o', str(binary)]
    built = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if built.returncode:
        raise SystemExit(built.stdout + built.stderr)
    run = subprocess.run([str(binary)], capture_output=True, text=True,
                         timeout=120,
                         env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
    return {'mode': mode, 'exit': run.returncode, 'stdout': run.stdout,
            'stderr': run.stderr[-2000:]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    before = {name: digest(root / name) for name in SOURCES}
    runs = []
    oracle = None
    with tempfile.TemporaryDirectory(prefix='modern-el0-trap-core-') as temp:
        for mode, flags in [('sanitizers', ['-fsanitize=address,undefined',
                                            '-fno-omit-frame-pointer', '-g']),
                            ('production-ndebug', ['-DNDEBUG', '-O2'])]:
            result = build_and_run(root, temp, mode, flags)
            runs.append(result)
            if result['exit']:
                raise SystemExit(result['stdout'] + result['stderr'])
        # Negative oracle: build the same checks with one deliberately wrong
        # expectation (BRK #1 asserted to be a ptrauth failure) and require the
        # binary to fail.
        oracle = build_and_run(root, temp, 'oracle-wrong-expectation',
                               ['-DNDEBUG', '-O2'],
                               extra_defines=['-DORACLE_WRONG_EXPECTATION'])
    if oracle['exit'] == 0:
        raise SystemExit('negative oracle did not fail: ' + oracle['stdout'])
    after = {name: digest(root / name) for name in SOURCES}
    if before != after:
        raise SystemExit('Inputs changed during qualification')
    report = {
        'passed': True,
        'source_sha256': before,
        'runs': runs,
        'negative_oracle': {
            'what': 'the same checks built with -DORACLE_WRONG_EXPECTATION '
                    'assert that BRK #1 is a ptrauth failure; the binary must '
                    'exit non-zero',
            'exit': oracle['exit'],
            'stdout': oracle['stdout'],
            'stderr_tail': oracle['stderr'][-400:],
        },
        'firmware_executed': False,
        'guest_executed': False,
        'scope': 'EL0 BRK immediate classification and trace-line formatting; '
                 'immediates attested from published LLVM llvmorg-21.1.0',
    }
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
