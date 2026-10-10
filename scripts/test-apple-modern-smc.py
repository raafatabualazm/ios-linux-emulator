#!/usr/bin/env python3
"""Qualify modern SMC geometry and refusals against matched served/stock ADTs.

Runs ASan+UBSan and production NDEBUG builds. Confirms all four physical
windows, unique IRQs, stock compatibility prerequisite, lengths, role and
timers index. Mutated properties, overlaps, malformed inputs and absence
are refused without changing output. This is host geometry, not input or
modern SMC firmware/key-ABI qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

SOURCES = ['hw/arm/apple-silicon/modern-boot-layout.c',
           'hw/arm/apple-silicon/modern-boot-metadata.c',
           'hw/arm/apple-silicon/modern-smc.c',
           'include/hw/arm/apple-silicon/modern-smc.h',
           'scripts/test-apple-modern-smc.c',
           'scripts/test-apple-modern-smc.py']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dtree', type=Path, required=True,
                        help='served Darwin-derived T8140 ADT')
    parser.add_argument('--stock', type=Path, required=True,
                        help='the stock T8140 ADT it was derived from')
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    trees = [args.dtree.resolve(), args.stock.resolve()]
    before = {name: digest(root / name) for name in SOURCES}
    tree_hashes = {str(tree): digest(tree) for tree in trees}
    runs = []
    with tempfile.TemporaryDirectory(prefix='modern-smc-core-') as temp:
        for mode, flags in [('sanitizers', ['-fsanitize=address,undefined',
                                            '-fno-sanitize-recover=all',
                                            '-fno-omit-frame-pointer', '-g']),
                            ('production-ndebug', ['-DNDEBUG', '-O2'])]:
            binary = Path(temp) / mode
            command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                       '-DAPPLE_MODERN_LAYOUT_STANDALONE',
                       '-I' + str(root / 'include'), *flags,
                       *(str(root / name) for name in SOURCES
                         if name.endswith('.c')), '-o', str(binary)]
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=300)
            if built.returncode:
                raise SystemExit(built.stdout + built.stderr)
            executed = subprocess.run(
                [str(binary), str(trees[0]), str(trees[1])],
                capture_output=True, text=True, timeout=300,
                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1',
                         UBSAN_OPTIONS='halt_on_error=1'))
            runs.append({'mode': mode, 'flags': flags,
                         'exit': executed.returncode, 'stdout': executed.stdout,
                         'stderr': executed.stderr})
            if executed.returncode:
                raise SystemExit(executed.stdout + executed.stderr)
    results = [json.loads(run['stdout']) for run in runs]
    require(all(r['passed'] and not r['firmware_executed'] and
                not r['guest_executed'] for r in results), 'both builds pass')
    require(len({r['checks'] for r in results}) == 1,
            'both builds run the same number of checks')
    require(before == {name: digest(root / name) for name in SOURCES} and
            tree_hashes == {str(tree): digest(tree) for tree in trees},
            'inputs changed during qualification')
    report = {'passed': True, 'checks_per_run': results[0]['checks'],
              'source_root': str(root), 'source_sha256': before,
              'dtrees': tree_hashes, 'runs': runs,
              'firmware_executed': False, 'guest_executed': False,
              'not_covered': ['modern SMC firmware/key ABI, timers, input acceptance']}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps({k: report[k] for k in
                      ('passed', 'checks_per_run')},
                     indent=2))


if __name__ == '__main__':
    main()
