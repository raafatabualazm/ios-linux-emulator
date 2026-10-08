#!/usr/bin/env python3
"""Run sparse MCC DRAMCFG core/layout gates on owned data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dtree', type=Path, required=True)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sources = ['hw/arm/apple-silicon/modern-boot-layout.c',
               'hw/arm/apple-silicon/modern-boot-metadata.c',
               'hw/arm/apple-silicon/modern-mcc-dramcfg.c',
               'include/hw/arm/apple-silicon/modern-mcc-dramcfg.h',
               'scripts/test-apple-modern-mcc-dramcfg.c',
               'scripts/test-apple-modern-mcc-dramcfg.py']
    before = {name: digest(root / name) for name in sources}
    dtree_before = digest(args.dtree) if args.dtree else None
    runs = []
    with tempfile.TemporaryDirectory(prefix='modern-pmgr-core-') as temp:
        for mode, flags in [('sanitizers', ['-fsanitize=address,undefined',
                                          '-fno-omit-frame-pointer', '-g']),
                            ('production-ndebug', ['-DNDEBUG', '-O2'])]:
            binary = Path(temp) / mode
            command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                       '-DAPPLE_MODERN_LAYOUT_STANDALONE', '-I' + str(root / 'include'),
                       *flags, *(str(root / name) for name in sources
                                 if name.endswith('.c')), '-o', str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if built.returncode:
                raise SystemExit(built.stdout + built.stderr)
            executed = subprocess.run([str(binary), *([str(args.dtree.resolve())]
                                      if args.dtree else [])], capture_output=True,
                                     text=True, timeout=30,
                                     env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
            runs.append({'mode': mode, 'exit': executed.returncode,
                         'stdout': executed.stdout, 'stderr': executed.stderr})
            if executed.returncode:
                raise SystemExit(executed.stdout + executed.stderr)
    if before != {name: digest(root / name) for name in sources} or (
            args.dtree and dtree_before != digest(args.dtree)):
        raise SystemExit('Inputs changed during qualification')
    report = {'passed': True, 'source_sha256': before, 'runs': runs,
              'dtree': str(args.dtree) if args.dtree else None,
              'dtree_sha256': dtree_before, 'firmware_executed': False,
              'qemu_mmio_wrapper_exercised': False,
              'scope': 'Sparse stateful DCS DRAM configuration words and matched layout'}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
