#!/usr/bin/env python3
"""Run the /arm-io/dcp ASC v6 aperture core gates on owned data; no firmware, no guest.

The standalone core is compiled twice (ASan+UBSan with no recovery, and the
production -DNDEBUG -O2 profile) and run against the matched pair of T8140 ADTs:
the served Darwin-derived tree and the stock tree it was derived from.

What it qualifies:
  * the two trees carry BYTE-IDENTICAL /arm-io/dcp "reg" and /arm-io "ranges",
    and differ only by the stripped "compatible" the disp0-probe arms restore --
    asserted, not assumed, because it is what lets the stock tree stand in for
    the tree the loader actually serves;
  * the window plan is derived from that reg property translated through
    /arm-io ranges, is exactly three windows, and every one of them lies inside
    /arm-io/disp0 reg[4] (which is why the disp0-probe logging apertures must
    skip reg[4] when this model owns these);
  * the attested-size oracle: flipping any one of the three window sizes away
    from the attested 0x88000 / 0x4000 / 0x3c008 makes the build REFUSE, and
    restoring it makes the same build succeed again;
  * the no-device oracle: the served tree has no /arm-io/dcp "compatible", so
    no AppleASCWrapV6 can exist, and the model refuses to map anything;
  * DRAM, exclusion, alias, NULL-output and out-of-range refusals;
  * the core decodes exactly the registers the header claims (the one attested
    predicate at core offset 0 both ways, the declared idle/IDLE_STATUS/CPU_CTRL
    words, both EMPTY mailbox CONTROL words, the 128 dump words), answers zero
    and FLAGS every other offset as unmodelled, never fails an access, bounds
    and de-duplicates its records, saturates its counters, and is byte-identical
    after an ignored access.

What it does NOT qualify: that any of this makes a guest driver proceed. That is
the whole-machine gate and the arm table.
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
           'hw/arm/apple-silicon/modern-dcp-asc.c',
           'hw/arm/apple-silicon/modern-disp-trace.c',
           'include/hw/arm/apple-silicon/modern-dcp-asc.h',
           'include/hw/arm/apple-silicon/modern-disp-trace.h',
           'include/hw/arm/apple-silicon/modern-boot-metadata.h',
           'include/hw/arm/apple-silicon/modern-board-regions.h',
           'scripts/test-apple-modern-dcp-asc.c',
           'scripts/test-apple-modern-dcp-asc.py']


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
    with tempfile.TemporaryDirectory(prefix='modern-dcp-asc-core-') as temp:
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
                [str(binary), str(trees[0]), str(trees[1])],
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
        'candidates': results[0]['candidates'], 'mapped': results[0]['mapped'],
        'source_root': str(root), 'source_sha256': before, 'dtrees': tree_hashes,
        'runs': runs, 'firmware_executed': False, 'guest_executed': False,
        'scope': __doc__,
        'declared_not_attested': [
            'core offset 0 bit 0 = 1 claims iBoot pre-loaded the DCP firmware. '
            'It did not: this loader places no coprocessor firmware and '
            'publishes no /chosen/carveout-memory-map region-id-N or '
            'segment-ranges. Only the PREDICATE (bit 0 clear -> the panic '
            '"ASC firmware must be loaded by iBoot") is attested.',
            'wrapper 0x40 bit 0 = 1 ("idle") and 0x8000 low bits = 3 before a '
            'RUN write: the offsets and the bit tests are attested, the values '
            'are declared.',
            'wrapper 0x48 (CPU_STATUS) reports zero: no source agrees on its '
            'bits and XNU never reads it on a path reachable from start().',
            'the mailbox is EMPTY and has NO peer. No RTKit/RTBuddy endpoint is '
            'published, so no DCPEndpoint24 can appear from this model alone.',
            'every other offset in all three windows answers zero. A zero '
            'answer is not evidence that zero is right; each one is recorded '
            'and the first is exposed as first-unmodelled.',
        ],
        'not_covered': [
            'whether AppleASCWrapV6 or AppleDCPExpert registers in a guest',
            'any DMA, interrupt, firmware-execution or endpoint behaviour',
            'the reg[0] sub-window at +0x2c000 (reg[2], 0x3c008) has no '
            'attested meaning at all; it is answered by the wrapper aperture',
        ]}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps({k: report[k] for k in
                      ('passed', 'checks_per_run', 'candidates', 'mapped')},
                     indent=2))


if __name__ == '__main__':
    main()
