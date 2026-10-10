#!/usr/bin/env python3
"""Run the adt-compat-restore core gates on owned data; no firmware, no guest.

The standalone core is compiled twice (ASan+UBSan with no recovery, and the
production -DNDEBUG -O2 profile) and run against the matched pair of T8140 ADTs:
the served Darwin-derived tree and the stock tree it was derived from.

What it qualifies:
  * EVERY restored "compatible" in EVERY group is the BYTE-EXACT value of that
    property in the stock tree, and the served tree carries no such property on
    that node - checked row by row with apple_modern_adt_property, so the
    "byte-exact stock bytes" claim is a gate and not a comment;
  * every named node exists unambiguously in BOTH trees;
  * the one declared property any group serves ("dart-id", 4 bytes) is absent
    from both trees, every value is distinct, and none is the 0 or 1 that
    disp0-probe's dcp-chain / dcp-mapper serve;
  * no group names a node that belongs to disp0-probe or to the W-12 endpoint
    continuation (/arm-io/dcp, iop-dcp-nub, /arm-io/disp0, /arm-io/dcp0-expert,
    dart-dcp, dart-disp0 and their mappers) or to the two existing control arms,
    and no (path, name) pair repeats anywhere - so adt-compat-restore and
    disp0-probe can always be used together;
  * the '+' resolver: each group alone, composition in list order after an
    existing caller entry, and ten malformed lists plus NULL arguments and three
    capacity cases, each refused with the caller's count and buffer untouched;
  * a mutation oracle: one byte flipped in a restored value makes the
    stock-comparison the gate performs fail, and restoring it makes it pass;
  * with --components, the END-TO-END check: the PRODUCTION metadata builder is
    run once per group against the real served tree, and every restored
    property is read back out of the tree it would hand a guest and compared
    byte for byte - and eight nodes no group names are confirmed to still carry
    no "compatible", so nothing leaks between groups.

What it does NOT qualify: that restoring any of this makes a guest better. A
driver that newly attaches and then blocks is a regression. That is measured
per group by the whole-machine arms in the evidence README.
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
           'hw/arm/apple-silicon/modern-compat-groups.c',
           'hw/arm/apple-silicon/modern-compat-groups-resolve.c',
           'hw/arm/apple-silicon/modern-disp-trace.c',
           'include/hw/arm/apple-silicon/modern-compat-groups.h',
           'include/hw/arm/apple-silicon/modern-disp-trace.h',
           'include/hw/arm/apple-silicon/modern-boot-metadata.h',
           'include/hw/arm/apple-silicon/modern-board-regions.h',
           'scripts/test-apple-modern-compat-groups.c',
           'scripts/test-apple-modern-compat-groups.py']


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
    parser.add_argument('--components', type=Path,
                        help='directory with the five decoded boot components; with it, the '
                             'PRODUCTION metadata builder is run per group and the tree it would '
                             'serve a guest is checked property by property')
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    trees = [args.dtree.resolve(), args.stock.resolve()]
    before = {name: digest(root / name) for name in SOURCES}
    tree_hashes = {str(tree): digest(tree) for tree in trees}
    runs = []
    with tempfile.TemporaryDirectory(prefix='modern-compat-groups-') as temp:
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
                [str(binary), str(trees[0]), str(trees[1])] +
                ([str(args.components.resolve())] if args.components else []),
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
    report = {
        'passed': True, 'checks_per_run': results[0]['checks'],
        'groups': results[0]['groups'], 'rows': results[0]['rows'],
        'compatible_rows': results[0]['compatible_rows'],
        'builder_checked': results[0]['builder_checked'],
        'source_root': str(root), 'source_sha256': before, 'dtrees': tree_hashes,
        'runs': runs, 'firmware_executed': False, 'guest_executed': False,
        'scope': __doc__,
        'declared_not_attested': [
            'the dart-id VALUES. SPTM requires the property on a restored '
            'dart,t8110 node (attested, measured by w7-disp0) and only '
            'uniqueness is required of it; iBoot\'s own numbering is not '
            'measured. disp0-probe owns 0 and 1, so these start at 2.',
            'that restoring a compatible is desirable. The option only makes '
            'the match POSSIBLE; whether the matched driver then starts, '
            'blocks, or faults on a register this board does not model is '
            'measured per group in the whole-machine arms, not here.',
            'which personality actually binds. IOProviderClass is a runtime '
            'fact that this gate does not simulate, so the match-gap inventory '
            'the groups were chosen from is an UPPER BOUND.',
        ],
        'not_covered': [
            'any guest behaviour whatsoever',
            'whether the restored node\'s registers are modelled by this board',
            'the 181 further lost matches the ten groups do not restore',
        ]}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps({k: report[k] for k in
                      ('passed', 'checks_per_run', 'groups', 'rows',
                       'compatible_rows', 'builder_checked')}, indent=2))


if __name__ == '__main__':
    main()
