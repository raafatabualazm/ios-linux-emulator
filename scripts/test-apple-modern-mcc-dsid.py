#!/usr/bin/env python3
"""Run AMCC DSID profile core gates on owned data; no firmware runs.

The standalone core and matched-layout test is compiled twice (ASan+UBSan with
no recovery, and the production -DNDEBUG -O2 profile) and run on each supplied
matched T8140 ADT. It replays the pinned BootKC's enableDsidProfileCounters
store sequence and perf slot 3 counter loads; bit meanings, reset contents and
counting are a declared profile with no connected event producer. v3: plan_build
rejects a present amcc-plane-enable-mask != 0xf (or of any size but 4) and keeps
every view inside the 0x140000 AMCC window. v4: those rejections are matched
exactly ("MCC DSID: MCC <name> has <n> bytes, expected 4" before any value;
"MCC DSID: MCC <name>=<value> is not modelled").
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
           'hw/arm/apple-silicon/modern-mcc-quota.c',
           'hw/arm/apple-silicon/modern-mcc-dsid.c',
           'include/hw/arm/apple-silicon/modern-mcc-quota.h',
           'include/hw/arm/apple-silicon/modern-mcc-dsid.h',
           'include/hw/arm/apple-silicon/modern-board-regions.h',
           'scripts/test-apple-modern-mcc-dsid.c',
           'scripts/test-apple-modern-mcc-optional-props.h',
           'scripts/test-apple-modern-mcc-dsid.py']
PIN = 'modern-emulator/evidence/features-20261008/mcc-dcs-perf/source-v4'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dtree', type=Path, action='append', required=True,
                        help='matched T8140 ADT; repeat to check several trees')
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    workspace = next(parent for parent in root.parents
                     if (parent / 'modern-emulator').is_dir())
    trees = [tree.resolve() for tree in args.dtree]
    before = {name: digest(root / name) for name in SOURCES}
    tree_hashes = {str(tree): digest(tree) for tree in trees}
    pinned = workspace / PIN
    pin_match = {name: (pinned / Path(name).name).is_file() and
                 digest(pinned / Path(name).name) == before[name]
                 for name in SOURCES if 'dsid' in name and not name.startswith('scripts/')}
    runs = []
    with tempfile.TemporaryDirectory(prefix='modern-mcc-dsid-core-') as temp:
        for mode, flags in [('sanitizers', ['-fsanitize=address,undefined',
                                          '-fno-sanitize-recover=all',
                                          '-fno-omit-frame-pointer', '-g']),
                            ('production-ndebug', ['-DNDEBUG', '-O2'])]:
            binary = Path(temp) / mode
            command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                       '-DAPPLE_MODERN_LAYOUT_STANDALONE', '-I' + str(root / 'include'),
                       *flags, *(str(root / name) for name in SOURCES
                                 if name.endswith('.c')), '-o', str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=120)
            if built.returncode:
                raise SystemExit(built.stdout + built.stderr)
            for tree in trees:
                executed = subprocess.run([str(binary), str(tree)], capture_output=True,
                                          text=True, timeout=120,
                                          env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1',
                                                   UBSAN_OPTIONS='halt_on_error=1'))
                runs.append({'mode': mode, 'flags': flags, 'dtree': str(tree),
                             'exit': executed.returncode, 'stdout': executed.stdout,
                             'stderr': executed.stderr})
                if executed.returncode:
                    raise SystemExit(executed.stdout + executed.stderr)
    results = [json.loads(run['stdout']) for run in runs]
    require(all(result['passed'] and not result['firmware_executed'] for result in results)
            and len({result['checks'] for result in results}) == 1,
            'Both builds pass the same number of checks on every tree')
    if before != {name: digest(root / name) for name in SOURCES} or tree_hashes != {
            str(tree): digest(tree) for tree in trees}:
        raise SystemExit('Inputs changed during qualification')
    require(len({(result['optional_property_accepts'], result['optional_property_rejects'],
                  result['optional_property_size_rejects']) for result in results}) == 1,
            'Same optional-property oracle on every run')
    report = {'passed': True, 'checks_per_run': results[0]['checks'],
              'optional_property_accepts': results[0]['optional_property_accepts'],
              'optional_property_rejects': results[0]['optional_property_rejects'],
              'optional_property_size_rejects': results[0]['optional_property_size_rejects'],
              'source_root': str(root),
              'source_sha256': before, 'sources_match_pinned_source_v4': pin_match,
              'runs': runs, 'dtrees': tree_hashes, 'firmware_executed': False,
              'qemu_mmio_wrapper_exercised': False,
              'scope': ('AMCC DSID profile core: reset, exact enableDsidProfileCounters '
                        'store sequence, full-width independent readback, plane-0 '
                        'bit-0 event gate, rejected widths/offsets/views/counter stores '
                        'leave the core byte-identical, saturating diagnostics, reset, '
                        'the matched sparse 9-view layout inside the 0x140000 AMCC window, '
                        'and the optional amcc-plane-enable-mask guard (exact 0xf, size 4) '
                        'on renamed-property tree copies with the exact v4 wrong-size and '
                        'unmodelled-value messages; max-way-count and '
                        'dcs-channel-enable-mask are not DSID inputs'),
              'declared_not_attested': ['control/interval bit meanings',
                                        'counter virtual reset value',
                                        'plane-0 +0x2a000 bit 0 as the event gate',
                                        'modulo-2^64 accumulation',
                                        'no event producer connected'],
              'unreachable_by_construction': ['plan_build AMCC-window bound: view offsets '
                                              'and spans are compile-time constants (highest '
                                              'end +0xee004 <= 0x140000)']}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps({key: report[key] for key in ('passed', 'checks_per_run',
                                                   'optional_property_accepts',
                                                   'optional_property_rejects',
                                                   'optional_property_size_rejects',
                                                   'sources_match_pinned_source_v4')},
                     indent=2))


if __name__ == '__main__':
    main()
