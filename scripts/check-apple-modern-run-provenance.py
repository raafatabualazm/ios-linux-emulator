#!/usr/bin/env python3
"""Audit that every recorded boot has its machine string stored beside it.

A serial log without the QEMU argv that produced it cannot be attributed to a
binary, a device tree or a machine option, so later work cannot tell which
configuration an observation belongs to. That is not hypothetical: settling the
AIC acknowledge offset left one irreducible gap, because 33 of 34 directories
holding an AppleInterruptControllerV3 start line never recorded which device
tree was passed, and the conclusion had to rest on inference instead of a
measurement.

The observers already do the right thing -- observe-apple-modern-sptm.py and
observe-apple-modern-display.py both put 'argv' in a report.json written beside
serial.log, and the iOS 14 runtime session writes argv.json -- so this only
reports where that was bypassed by an ad-hoc invocation.

This script reads evidence; it never launches an emulator and never writes to
the trees it audits.
"""
import argparse
import json
import pathlib
import sys

# Any of these, beside a serial log, counts as recorded provenance.
REPORTS = ('report.json', 'argv.json', 'run.json', 'start.json')


def machine_string(directory):
    """Return the -M value recorded beside a log, or None."""
    for name in REPORTS:
        path = directory / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        argv = data.get('argv') if isinstance(data, dict) else None
        if isinstance(data, list):
            argv = data
        if isinstance(data, dict) and argv is None:
            argv = data.get('command')
        if not isinstance(argv, list):
            continue
        argv = [str(item) for item in argv]
        for index, item in enumerate(argv):
            if item in ('-M', '-machine') and index + 1 < len(argv):
                return argv[index + 1]
    return None


def audit(roots):
    recorded, missing = [], []
    for root in roots:
        for log in sorted(pathlib.Path(root).rglob('serial.log')):
            directory = log.parent
            machine = machine_string(directory)
            entry = {'directory': str(directory), 'bytes': log.stat().st_size}
            if machine is None:
                missing.append(entry)
            else:
                entry['machine'] = machine
                recorded.append(entry)
    return recorded, missing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roots', nargs='*', type=pathlib.Path,
                        default=[pathlib.Path(
                            '/home/kali/Desktop/Inferno-and-Darwin-VM/'
                            'modern-emulator/evidence')])
    parser.add_argument('--strict', action='store_true',
                        help='exit non-zero when any serial log lacks a '
                             'recorded machine string')
    parser.add_argument('--max-missing', type=int, default=None,
                        help='exit non-zero when more logs lack provenance '
                             'than this known baseline, so new omissions fail '
                             'while the existing backlog does not')
    args = parser.parse_args()

    recorded, missing = audit(args.roots)
    report = {
        'serial_logs': len(recorded) + len(missing),
        'with_machine_string': len(recorded),
        'without_machine_string': len(missing),
        'missing': missing,
        'recorded': recorded,
        'provenance_is_complete': not missing,
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    if args.strict and missing:
        print('%d serial log(s) have no recorded machine string'
              % len(missing), file=sys.stderr)
        return 1
    if args.max_missing is not None and len(missing) > args.max_missing:
        print('serial logs without a machine string rose from %d to %d'
              % (args.max_missing, len(missing)), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
