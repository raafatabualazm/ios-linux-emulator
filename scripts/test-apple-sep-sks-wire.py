#!/usr/bin/env python3
"""Exercise the production SKS parser under ASan/UBSan and NDEBUG."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    paths = [root / p for p in (
        'hw/arm/apple-silicon/sep-sks-wire.c',
        'include/hw/arm/apple-silicon/sep-sks-wire.h',
        'scripts/test-apple-sep-sks-wire.c', 'scripts/test-apple-sep-sks-wire.py')]
    hashes = lambda: {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in paths}
    before = hashes()
    report = {'passed': False, 'source_sha256': before, 'runs': [],
              'scope': 'Framing/bounds only; no firmware or key service'}
    with tempfile.TemporaryDirectory(prefix='sks-wire-') as name:
        for mode, flags in [('sanitizers', ['-fsanitize=address,undefined', '-g']),
                            ('ndebug', ['-DNDEBUG', '-O2'])]:
            binary = Path(name) / mode
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-DAPPLE_SEP_SKS_STANDALONE', '-I' + str(root / 'include'),
                            *flags, str(paths[0]), str(paths[2]), '-o', str(binary)],
                           check=True, timeout=60)
            r = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20,
                               env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1'))
            report['runs'].append({'mode': mode, 'exit': r.returncode,
                                   'stdout': r.stdout, 'stderr': r.stderr})
    report['inputs_unchanged'] = hashes() == before
    report['passed'] = report['inputs_unchanged'] and all(
        r['exit'] == 0 for r in report['runs'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as f:
        json.dump(report, f, indent=2)
        f.write('\n')
    print(json.dumps(report))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
