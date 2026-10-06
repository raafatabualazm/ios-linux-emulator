#!/usr/bin/env python3
"""Build production console input core with ASan/UBSan; no guest execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    paths = ['hw/arm/apple-silicon/modern-boot-input.c',
             'include/hw/arm/apple-silicon/modern-boot-input.h',
             'scripts/test-apple-modern-boot-input.c',
             'scripts/test-apple-modern-boot-input.py']
    before = {p: digest(root / p) for p in paths}
    with tempfile.TemporaryDirectory(prefix='modern-console-input-') as temp:
        binary = Path(temp) / 'console-input'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-g',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-I' + str(root / 'include'),
                        str(root / paths[2]), '-o', str(binary)],
                       check=True, capture_output=True, text=True)
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    if run.returncode:
        raise RuntimeError(f'exit={run.returncode}\n{run.stdout}{run.stderr}')
    assert before == {p: digest(root / p) for p in paths}
    report = {'passed': True, 'scope': __doc__, 'source_sha256': before,
              'sanitizers': ['ASan', 'UBSan'], 'exit_code': run.returncode,
              'semantic_checks': int(re.search(r'PASS (\d+)', run.stdout).group(1)),
              'qemu_binding_claim': False, 'guest_execution': False}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=False)
        (args.evidence / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        (args.evidence / 'tests.log').write_text(run.stdout + run.stderr)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
