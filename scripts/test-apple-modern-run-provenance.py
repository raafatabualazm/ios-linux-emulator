#!/usr/bin/env python3
"""Regression test for check-apple-modern-run-provenance.py.

Builds throwaway evidence trees in a temporary directory (never under the real
evidence directories) and checks that

  * a log with neither an argv nor a manifest entry still fails --strict;
  * a reconstructed log does not fail --strict, but is reported as
    reconstructed with its confidence and never as recorded;
  * an unrecoverable manifest entry fails --strict and is listed separately;
  * a manifest cannot attribute a log in a tree it does not describe, an
    invalid confidence does not count, and a missing or corrupt manifest
    attributes nothing;
  * --max-missing keeps its baseline meaning.

It runs the checker as a subprocess, exactly as a user would, and never
launches an emulator.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CHECKER = HERE / 'check-apple-modern-run-provenance.py'
ARGV = ['qemu-system-aarch64', '-M', 'apple-modern,prepare-only=false']


def run(*args):
    proc = subprocess.run([sys.executable, str(CHECKER), *map(str, args)],
                          capture_output=True, text=True)
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        raise AssertionError('checker printed no JSON: %r %r'
                             % (proc.stdout, proc.stderr))
    return proc.returncode, report, proc.stderr


def log(root, name, argv=False):
    directory = root / name
    directory.mkdir(parents=True)
    (directory / 'serial.log').write_text('iBoot version: test\n')
    if argv:
        (directory / 'report.json').write_text(json.dumps({'argv': ARGV}))
    return directory


def write_manifest(path, entries, **meta):
    data = {'schema': 1, 'about': 'test'}
    data.update(meta)
    data.update(entries)
    path.write_text(json.dumps(data))
    return path


def entry(confidence, **extra):
    value = {'reconstructed': True, 'confidence': confidence,
             'sources': ['test'], 'binary': {'identity': 'test'}}
    value.update(extra)
    return value


def names(items, root):
    return sorted(pathlib.Path(i['directory']).relative_to(root).as_posix()
                  for i in items)


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print('ok  ' + message)


def main():
    with tempfile.TemporaryDirectory(prefix='provenance-test-') as tmp:
        base = pathlib.Path(tmp)

        # ---- tree 1: one of every category -------------------------------
        t1 = base / 'tree1'
        for name, argv in (('recorded', True), ('doc', False), ('inf', False),
                           ('meas', False), ('lost', False), ('bare', False)):
            log(t1, name, argv)
        m1 = write_manifest(base / 'm1.json', {
            'doc': entry('documented'),
            'inf': entry('inferred'),
            'meas': entry('measured-from-log'),
            'lost': entry('unrecoverable'),
            'stale': entry('documented'),
        })
        code, rep, err = run(t1, '--manifest', m1)
        check(names(rep['recorded'], t1) == ['recorded'], 'argv beside the log is recorded')
        check(names(rep['reconstructed'], t1) == ['doc', 'inf', 'meas'],
              'manifest entries with documented/inferred/measured-from-log are reconstructed')
        got = {pathlib.Path(i['directory']).name: i['confidence'] for i in rep['reconstructed']}
        check(got == {'doc': 'documented', 'inf': 'inferred', 'meas': 'measured-from-log'},
              'reconstructed logs carry their confidence')
        check(names(rep['unattributed'], t1) == ['bare', 'lost'],
              'no argv and no entry, or an unrecoverable entry, is unattributed')
        check(names(rep['unrecoverable'], t1) == ['lost'],
              'an unrecoverable entry is also reported separately')
        check(rep['counts']['recorded'] + rep['counts']['reconstructed'] + rep['counts']['unattributed']
              == rep['serial_logs'] == 6, 'the three categories are disjoint and cover every log')
        check(rep['provenance_is_complete'] is False, 'provenance is not complete with unattributed logs')
        check(rep['manifest']['unmatched_entries'] == ['stale'], 'a manifest entry with no log is reported')
        check(code == 0, 'without --strict the audit only reports')
        code, rep, err = run(t1, '--manifest', m1, '--strict')
        check(code == 1, '--strict fails on unattributed and unrecoverable logs')

        # ---- the load-bearing proof: bare log still fails, reconstructed does not
        t2 = base / 'tree2'
        log(t2, 'recorded', True)
        log(t2, 'reconstructed')
        m2 = write_manifest(base / 'm2.json', {'reconstructed': entry('inferred')})
        code, rep, err = run(t2, '--manifest', m2, '--strict')
        check(code == 0 and rep['provenance_is_complete'] is True,
              'a reconstructed log does not fail --strict')
        check(rep['counts']['recorded'] == 1 and rep['counts']['reconstructed'] == 1,
              'a reconstructed log is never counted as recorded')
        code, rep, err = run(t2, '--no-manifest', '--strict')
        check(code == 1 and rep['counts']['unattributed'] == 1,
              '--no-manifest restores the recorded-only question')

        log(t2, 'bare')
        code, rep, err = run(t2, '--manifest', m2, '--strict')
        check(code == 1 and names(rep['unattributed'], t2) == ['bare'],
              'a log with neither argv nor a manifest entry fails --strict')
        code, rep, err = run(t2, '--manifest', m2, '--max-missing', '1')
        check(code == 0, '--max-missing accepts the known baseline')
        code, rep, err = run(t2, '--manifest', m2, '--max-missing', '0')
        check(code == 1, '--max-missing fails when unattributed logs exceed the baseline')

        # ---- a manifest must not be bypassed or spoofed ------------------
        t3 = base / 'tree3'
        log(t3, 'a')
        log(t3, 'b')
        log(t3, 'c')
        log(t3, 'd')
        m3 = write_manifest(base / 'm3.json', {
            'a': entry('guess'),                 # not a valid confidence
            'b': {'confidence': 'documented', 'reconstructed': False},
            'c': {'sources': ['x']},             # no confidence at all
            'd': 'documented',                   # not an entry
        })
        code, rep, err = run(t3, '--manifest', m3, '--strict')
        check(code == 1 and names(rep['unattributed'], t3) == ['a', 'b', 'c', 'd'],
              'invalid, disowned or missing confidence does not count as reconstructed')

        # an evidence_root pins entries to one tree: the same relative key in
        # another tree is not attributed
        t4 = base / 'tree4'
        log(t4, 'x')
        elsewhere = base / 'elsewhere'
        m4 = write_manifest(base / 'm4.json', {'x': entry('documented')}, evidence_root=str(elsewhere))
        code, rep, err = run(t4, '--manifest', m4, '--strict')
        check(code == 1 and names(rep['unattributed'], t4) == ['x'],
              'an entry for another evidence_root does not attribute this tree')
        m5 = write_manifest(base / 'm5.json', {'x': entry('documented')}, evidence_root=str(t4))
        code, rep, err = run(t4, '--manifest', m5, '--strict')
        check(code == 0 and names(rep['reconstructed'], t4) == ['x'],
              'an entry for the matching evidence_root attributes it')

        # missing and corrupt manifests attribute nothing and say so
        code, rep, err = run(t4, '--manifest', base / 'absent.json', '--strict')
        check(code == 1 and 'not used' in err, 'a missing manifest attributes nothing and warns')
        (base / 'bad.json').write_text('{not json')
        code, rep, err = run(t4, '--manifest', base / 'bad.json', '--strict')
        check(code == 1 and 'not used' in err, 'a corrupt manifest attributes nothing and warns')

        # an argv beside the log wins over a manifest entry
        t6 = base / 'tree6'
        log(t6, 'both', True)
        m6 = write_manifest(base / 'm6.json', {'both': entry('inferred')})
        code, rep, err = run(t6, '--manifest', m6, '--strict')
        check(code == 0 and names(rep['recorded'], t6) == ['both']
              and rep['counts']['reconstructed'] == 0
              and rep['recorded'][0].get('also_in_manifest') == 'both',
              'recorded argv takes precedence over a manifest entry')

        # recorded-argv detection itself is unchanged
        t7 = base / 'tree7'
        d = log(t7, 'noM')
        (d / 'report.json').write_text(json.dumps({'argv': ['qemu', '-m', '1G']}))
        code, rep, err = run(t7, '--no-manifest', '--strict')
        check(code == 1, 'an argv without a -M machine string is not recorded provenance')
    print('all provenance checker tests passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
