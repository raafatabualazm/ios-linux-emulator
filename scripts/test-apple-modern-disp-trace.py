#!/usr/bin/env python3
"""Run the disp0 bind-probe core gates on owned data; no firmware and no guest runs.

The standalone core is compiled twice (ASan+UBSan with no recovery, and the
production -DNDEBUG -O2 profile) and run against a matched pair of T8140 ADTs:
the served Darwin-derived tree and the stock tree it was derived from.

What it qualifies:
  * every "compatible" the probe restores is BYTE-IDENTICAL to the stock tree's
    own value for that node, and is absent from the served tree, so each arm is
    an anchored restoration rather than an invention;
  * the two properties the probe DECLARES ("no-dcp-driver", "dart-id") are
    absent from both trees, so the declared label is correct;
  * the logging-aperture plan is derived from the served tree's own reg
    properties translated through /arm-io ranges, 29 candidate windows of which
    25 map and 4 lie inside disp0's own apertures (all three /arm-io/dcp
    windows are inside disp0 reg[4]);
  * the no-device oracle: an exclusion covering /arm-io, or DRAM placed over
    it, leaves nothing to observe and the build is REFUSED rather than mapping
    over another device;
  * the aperture core never fails an access, answers zero, records each
    (window, offset, direction) once up to its bound, saturates its counters
    and is byte-identical after an ignored access.
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
           'hw/arm/apple-silicon/modern-disp-trace.c',
           'include/hw/arm/apple-silicon/modern-disp-trace.h',
           'include/hw/arm/apple-silicon/modern-boot-metadata.h',
           'include/hw/arm/apple-silicon/modern-board-regions.h',
           'scripts/test-apple-modern-disp-trace.c',
           'scripts/test-apple-modern-disp-trace.py']


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
    with tempfile.TemporaryDirectory(prefix='modern-disp-trace-core-') as temp:
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
            executed = subprocess.run([str(binary), str(trees[0]), str(trees[1])],
                                      capture_output=True, text=True, timeout=300,
                                      env=dict(os.environ,
                                               ASAN_OPTIONS='detect_leaks=1',
                                               UBSAN_OPTIONS='halt_on_error=1'))
            runs.append({'mode': mode, 'flags': flags, 'exit': executed.returncode,
                         'stdout': executed.stdout, 'stderr': executed.stderr})
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
        'windows': results[0]['windows'], 'mapped': results[0]['mapped'],
        'compat_overrides_anchored_to_stock':
            results[0]['compat_overrides_anchored_to_stock'],
        'declared_properties_absent_from_stock':
            results[0]['declared_properties_absent_from_stock'],
        'source_root': str(root), 'source_sha256': before, 'dtrees': tree_hashes,
        'runs': runs, 'firmware_executed': False, 'guest_executed': False,
        'qemu_mmio_wrapper_exercised': False,
        'scope': ('disp0 bind probe core: the six override profiles (disp0, '
                  'disp0-nodcp, dcp-chain, dcp-mapper, override-control, '
                  'gate-control), '
                  'each restored compatible checked byte-for-byte against the '
                  'stock tree and checked absent from the served tree, the two '
                  'declared properties checked absent from both, the 29-window '
                  'aperture plan with its 4 contained windows and its /arm-io '
                  'ranges translation, the exclusion/DRAM/alias/bad-tree '
                  'refusals including the no-device oracle, and the aperture '
                  'core (zero answers, bounded de-duplicated records, '
                  'saturating counters, ignored accesses leave it byte-equal)'),
        'declared_not_attested': [
            'no-dcp-driver = 1: the property is not in the stock tree; only its '
            'name and the 4-byte read are attested, the value is declared',
            'dart-id 0 and 1 on dart-dcp / dart-disp0: the served tree has no '
            'dart,t8110 node at all, so the numbers are free; iBoot\'s own '
            'numbering is unmeasured',
            'dcp-mapper restores only ATTESTED stock bytes, but the CLAIM that '
            'an IODARTMapper is what AppleA7IOP::start waits for is '
            'declared-inferred until a guest arm shows the wrapper register',
            'the apertures are an observation instrument, not a hardware model: '
            'no disp0 or dcp register has any meaning or side effect',
        ],
        'not_covered': [
            'whether AppleCLCD2 binds in a guest (that is the whole-machine '
            'gate and the arm table, not a core property)',
            'any IOVA, DMA or interrupt behaviour of the display nodes',
        ]}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps({key: report[key] for key in
                      ('passed', 'checks_per_run', 'windows', 'mapped',
                       'compat_overrides_anchored_to_stock',
                       'declared_properties_absent_from_stock')}, indent=2))


if __name__ == '__main__':
    main()
