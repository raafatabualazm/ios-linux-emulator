#!/usr/bin/env python3
"""Run every Apple UART gate in one command and summarize.

The UART model has two opt-in properties, `ucon-store` and `drain-refresh`, both off by
default and off on every shipped board. Nothing else runs the opt-in modes (they are
reached only by `-global`), so without this runner they would be untested. It runs:

  * the owned-ROM hardware-input gate in all four property combinations (each pins the
    values of its combination in both directions: the default pins the HISTORICAL
    values, so a default that drifts fails);
  * the storm gate with both properties on (asserts the contained behaviour);
  * the storm gate in legacy mode (pins the default to the observations recorded from
    the pinned v10 binary).

Usage: test-apple-uart-gates.py --binary B --components C --output-dir NEW_DIR
Exit 0 only if every run passed. Firmware is never executed.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
HW = str(HERE / 'test-apple-modern-aic-hardware-input-qemu.py')
STORM = str(HERE / 'test-apple-uart-ucon-storm-qemu.py')

RUNS = [
    ('hw-default', HW, []),
    ('hw-drain-refresh', HW, ['--uart-drain-refresh', 'on']),
    ('hw-ucon-store', HW, ['--uart-ucon-store', 'on']),
    ('hw-both', HW, ['--uart-drain-refresh', 'on', '--uart-ucon-store', 'on']),
    ('storm-both-on', STORM, ['--mode', 'on']),
    ('storm-legacy-pin', STORM, ['--mode', 'legacy']),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    summary = {}
    for name, script, extra in RUNS:
        process = subprocess.run(
            [sys.executable, script, '--binary', str(args.binary), '--components',
             str(args.components), '--output-dir', str(args.output_dir / name), *extra],
            capture_output=True, text=True)
        try:
            line = json.loads(process.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            line = {'passed': False, 'error': (process.stdout + process.stderr)[-300:]}
        summary[name] = {'passed': bool(line.get('passed')) and process.returncode == 0,
                         'failed_checks': line.get('failed_checks', []),
                         'error': line.get('error')}
    summary['passed'] = all(item['passed'] for item in summary.values())
    (args.output_dir / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
