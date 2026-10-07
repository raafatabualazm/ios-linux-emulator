#!/usr/bin/env python3
"""Audit that every recorded boot can be attributed to a configuration.

A serial log without the QEMU argv that produced it cannot be attributed to a
binary, a device tree or a machine option, so later work cannot tell which
configuration an observation belongs to. That is not hypothetical: settling the
AIC acknowledge offset left one irreducible gap, because 33 of 34 directories
holding an AppleInterruptControllerV3 start line never recorded which device
tree was passed, and the conclusion had to rest on inference instead of a
measurement.

The observers already do the right thing -- observe-apple-modern-sptm.py and
observe-apple-modern-display.py both put 'argv' in a report.json written beside
serial.log, and the iOS 14 runtime session writes argv.json -- so this reports
where that was bypassed by an ad-hoc invocation.

Every serial.log falls into exactly one of three disjoint categories:

  recorded       an argv with a -M machine string sits beside the log
                 (report.json, argv.json, run.json or start.json). The run
                 wrote it itself, so it is the strongest evidence.
  reconstructed  no argv beside the log, but a reconstruction manifest has an
                 entry for the directory whose confidence is documented,
                 measured-from-log or inferred. The configuration was rebuilt
                 afterwards from other evidence. This is WEAKER than recorded,
                 and the confidence is reported with it so that it is never
                 mistaken for a recorded run.
  unattributed   neither. This includes a manifest entry whose confidence is
                 'unrecoverable' (the reconstruction looked and could not
                 establish the configuration), which is also listed separately
                 as unrecoverable.

provenance_is_complete means no log is unattributed. --strict fails on any
unattributed or unrecoverable log. A reconstructed log never makes the audit
fail, but it is never counted as recorded either; use --no-manifest to ask the
old question (does every log have its own recorded argv).

The manifest is a JSON object whose values are per-directory entries (see
organization-record/provenance-20261007/README.md). Non-dict top-level values
(schema, about, evidence_root) are metadata. If the manifest names an
evidence_root, entry keys are resolved against it, so a log in some other tree
is never attributed by a coincidentally equal relative path; without an
evidence_root the keys are taken relative to each scanned root.

This script reads evidence; it never launches an emulator and never writes to
the trees it audits.
"""
import argparse
import json
import pathlib
import sys

# Any of these, beside a serial log, counts as recorded provenance.
REPORTS = ('report.json', 'argv.json', 'run.json', 'start.json')

# Confidences a manifest entry may carry. The first three mean the
# configuration was reconstructed; the last means it could not be.
RECONSTRUCTED = ('documented', 'measured-from-log', 'inferred')
UNRECOVERABLE = 'unrecoverable'

DEFAULT_ROOT = pathlib.Path('/home/kali/Desktop/Inferno-and-Darwin-VM/'
                            'modern-emulator/evidence')
DEFAULT_MANIFEST = pathlib.Path('/home/kali/Desktop/Inferno-and-Darwin-VM/'
                                'organization-record/provenance-20261007/'
                                'reconstructed.json')


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


def load_manifest(path):
    """Return (entries, evidence_root, info). Never raises on a bad file.

    entries maps the manifest key to its entry dict. An unreadable or
    malformed manifest yields no entries, so every log it would have covered
    stays unattributed rather than silently passing.
    """
    info = {'path': str(path) if path else None, 'loaded': False,
            'entries': 0, 'error': None}
    if path is None:
        return {}, None, info
    try:
        data = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError) as err:
        info['error'] = str(err)
        return {}, None, info
    if not isinstance(data, dict):
        info['error'] = 'manifest is not a JSON object'
        return {}, None, info
    root = data.get('evidence_root')
    root = pathlib.Path(root) if isinstance(root, str) and root else None
    # An entry is a dict. One that says reconstructed: false is explicitly not
    # a reconstruction and is ignored; metadata keys are not dicts.
    entries = {key: value for key, value in data.items()
               if isinstance(value, dict) and value.get('reconstructed') is not False}
    info['loaded'] = True
    info['entries'] = len(entries)
    return entries, root, info


def lookup(entries, evidence_root, directory, scan_root):
    """Find the manifest key for a log directory, or None."""
    if evidence_root is not None:
        resolved = directory.resolve()
        for key in entries:
            if (evidence_root / key).resolve() == resolved:
                return key
        return None
    try:
        key = str(directory.relative_to(scan_root))
    except ValueError:
        return None
    return key if key in entries else None


def classify(entry):
    """Return ('reconstructed'|'unrecoverable'|'invalid', confidence)."""
    confidence = entry.get('confidence')
    if confidence in RECONSTRUCTED:
        return 'reconstructed', confidence
    if confidence == UNRECOVERABLE:
        return 'unrecoverable', confidence
    return 'invalid', confidence


def audit(roots, manifest_path=None):
    entries, evidence_root, info = load_manifest(manifest_path)
    recorded, reconstructed, unattributed, unrecoverable = [], [], [], []
    used = set()
    for root in roots:
        root = pathlib.Path(root)
        for log in sorted(root.rglob('serial.log')):
            directory = log.parent
            item = {'directory': str(directory), 'bytes': log.stat().st_size}
            machine = machine_string(directory)
            key = lookup(entries, evidence_root, directory, root) if entries else None
            if machine is not None:
                item['machine'] = machine
                if key is not None:
                    # Both exist: the run's own argv wins, the manifest entry
                    # is redundant and is reported so it can be retired.
                    item['also_in_manifest'] = key
                    used.add(key)
                recorded.append(item)
                continue
            if key is None:
                item['category'] = 'unattributed'
                item['reason'] = 'no argv beside the log and no manifest entry'
                unattributed.append(item)
                continue
            used.add(key)
            entry = entries[key]
            kind, confidence = classify(entry)
            item['manifest_key'] = key
            item['confidence'] = confidence
            if kind == 'reconstructed':
                item['category'] = 'reconstructed'
                item['has_sources'] = bool(entry.get('sources'))
                identity = (entry.get('binary') or {}).get('identity') \
                    if isinstance(entry.get('binary'), dict) else None
                if identity:
                    item['binary_identity'] = identity
                reconstructed.append(item)
            elif kind == 'unrecoverable':
                item['category'] = 'unattributed'
                item['reason'] = 'manifest marks the configuration unrecoverable'
                unattributed.append(item)
                unrecoverable.append(item)
            else:
                item['category'] = 'unattributed'
                item['reason'] = ('manifest entry has no valid confidence '
                                  '(need one of %s or %s)'
                                  % (', '.join(RECONSTRUCTED), UNRECOVERABLE))
                unattributed.append(item)
    orphans = sorted(set(entries) - used)
    return recorded, reconstructed, unattributed, unrecoverable, orphans, info


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('roots', nargs='*', type=pathlib.Path,
                        default=[DEFAULT_ROOT])
    parser.add_argument('--manifest', type=pathlib.Path, default=None,
                        help='reconstruction manifest (JSON). Default: %s when '
                             'it exists' % DEFAULT_MANIFEST)
    parser.add_argument('--no-manifest', action='store_true',
                        help='ignore any manifest, so only recorded argv counts '
                             '(the pre-manifest behaviour)')
    parser.add_argument('--strict', action='store_true',
                        help='exit non-zero when any serial log is unattributed '
                             '(no recorded argv and no usable manifest entry) '
                             'or marked unrecoverable')
    parser.add_argument('--max-missing', type=int, default=None,
                        help='exit non-zero when more logs are unattributed '
                             '(neither recorded nor reconstructed) than this '
                             'known baseline, so new omissions fail while an '
                             'existing backlog does not')
    args = parser.parse_args()

    if args.no_manifest:
        manifest_path = None
    elif args.manifest is not None:
        manifest_path = args.manifest
    else:
        manifest_path = DEFAULT_MANIFEST if DEFAULT_MANIFEST.is_file() else None

    recorded, reconstructed, unattributed, unrecoverable, orphans, info = \
        audit(args.roots, manifest_path)
    if info['error']:
        # An unreadable manifest attributes nothing; say so instead of letting
        # the unattributed count look like an ordinary backlog.
        print('warning: manifest %s not used: %s' % (info['path'], info['error']),
              file=sys.stderr)

    by_confidence = {}
    for item in reconstructed:
        by_confidence[item['confidence']] = by_confidence.get(item['confidence'], 0) + 1
    total = len(recorded) + len(reconstructed) + len(unattributed)
    report = {
        'serial_logs': total,
        'counts': {
            'recorded': len(recorded),
            'reconstructed': len(reconstructed),
            'reconstructed_by_confidence': by_confidence,
            'reconstructed_without_sources': sum(1 for i in reconstructed
                                                 if not i.get('has_sources')),
            'unattributed': len(unattributed),
            'unrecoverable': len(unrecoverable),
        },
        'recorded': recorded,
        'reconstructed': reconstructed,
        'unattributed': unattributed,
        'unrecoverable': unrecoverable,
        'manifest': dict(info, unmatched_entries=orphans),
        # Names kept from the pre-manifest report. They still mean "has no
        # recorded argv of its own", which includes the reconstructed logs.
        'with_machine_string': len(recorded),
        'without_machine_string': len(reconstructed) + len(unattributed),
        'missing': reconstructed + unattributed,
        'provenance_is_complete': not unattributed,
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    status = 0
    if args.strict and unattributed:
        print('%d serial log(s) are unattributed (%d of them marked '
              'unrecoverable)' % (len(unattributed), len(unrecoverable)),
              file=sys.stderr)
        status = 1
    if args.max_missing is not None and len(unattributed) > args.max_missing:
        print('unattributed serial logs rose from %d to %d'
              % (args.max_missing, len(unattributed)), file=sys.stderr)
        status = 1
    return status


if __name__ == '__main__':
    sys.exit(main())
