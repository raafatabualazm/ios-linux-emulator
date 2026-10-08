#!/usr/bin/env python3
"""Run AMCC system-level-cache way/flush core gates on owned data; no firmware runs.

The standalone core and matched-layout test is compiled twice (ASan+UBSan with
no recovery, and the production -DNDEBUG -O2 profile) and run on each supplied
matched T8140 ADT. It replays the pinned BootKC's mccEnableCacheMode /
mccWaitForWaysPwrOn and cacheFlush cell sequences; global-to-plane broadcast and
immediate power-up/flush completion are a declared profile. v3: the reset way
request is the 12-way handover state 0x8000000c (status 0x0c000c00) that m1n1
PR #664 read back per plane on t604x/t8140-family Macs (analogy; the machine is
not stated), and plan_build rejects a present amcc-plane-enable-mask != 0xf or
max-way-count > 0x7f (any size but 4 too). v4: view_offset() returns
UINT64_MAX for every invalid view, and the optional-property rejections are
matched exactly ("MCC SLC: MCC <name> has <n> bytes, expected 4" before any
value; "MCC SLC: MCC <name>=<value> is not modelled").
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
           'hw/arm/apple-silicon/modern-mcc-slc.c',
           'include/hw/arm/apple-silicon/modern-mcc-quota.h',
           'include/hw/arm/apple-silicon/modern-mcc-slc.h',
           'include/hw/arm/apple-silicon/modern-board-regions.h',
           'scripts/test-apple-modern-mcc-slc.c',
           'scripts/test-apple-modern-mcc-optional-props.h',
           'scripts/test-apple-modern-mcc-slc.py']
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
                 for name in SOURCES if 'slc' in name and not name.startswith('scripts/')}
    runs = []
    with tempfile.TemporaryDirectory(prefix='modern-mcc-slc-core-') as temp:
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
              'scope': ('AMCC SLC core: 12-way reset (0x8000000c, status 0x0c000c00), '
                        'exact mccEnableCacheMode/mccWaitForWaysPwrOn and cacheFlush '
                        'sequences, 7-bit status fields for stored way counts, write-only '
                        'global (+0x2800/+0x82c/+0x2844) and read-only plane cells, rejected '
                        'widths/offsets/views leave the core byte-identical, saturating '
                        'diagnostics, reset, public view offsets inside the 0x140000 AMCC '
                        'window, the matched sparse 11-view layout including the board '
                        'carve shape of the compatibility AMCC aperture, the optional '
                        'amcc-plane-enable-mask (exact 0xf) / max-way-count (<= 0x7f) '
                        'guards on renamed-property tree copies with the exact v4 wrong-size '
                        'and unmodelled-value messages, and the v4 UINT64_MAX view_offset() '
                        'result for every view >= 11'),
              'declared_not_attested': ['global writes broadcast to every plane',
                                        'requested ways report powered at once',
                                        'flushes complete at once (bit 0 reads 0)',
                                        '12-way handover request 0x8000000c is a per-plane '
                                        'readback on t604x/t8140-family Macs (m1n1 PR #664, '
                                        'machine not stated), analogy for iPhone17,3; bit 31 '
                                        'unexplained',
                                        'no cache, power or timing model'],
              'unreachable_by_construction': ['plan_build AMCC-window bound: every view '
                                              'offset is a compile-time constant <= 0x102844 '
                                              '(+4 <= 0x140000)']}
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
