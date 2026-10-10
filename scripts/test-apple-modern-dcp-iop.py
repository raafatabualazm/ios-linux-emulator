#!/usr/bin/env python3
"""Run the /arm-io/dcp RTKit-peer (dcp-iop) core gates on owned data; no firmware, no guest.

The standalone half of modern-dcp-iop.c is compiled twice (ASan+UBSan with no
recovery, and the production -DNDEBUG -O2 profile) and run against the matched
pair of T8140 ADTs: the served Darwin-derived tree and the stock tree it was
derived from.

What it qualifies:
  * the two trees carry BYTE-IDENTICAL /arm-io/dcp "reg", "role" and
    "interrupts" and /arm-io "ranges", and differ only by the two stripped
    "compatible" values the disp0-probe arms restore;
  * the endpoint arithmetic the whole module turns on: name index = raw - 31,
    so AppleDCPLinkServiceSoC's "DCPEndpoint24" is raw 55 (0x37) and
    user-relative 23; the in-tree SMC precedent (user-relative 0 -> raw 32 ->
    "SMCEndpoint1"), public Asahi's SYSTEM_ENDPOINT 0x20 -> index 1, and
    AppleSPU's AOPEndpoint32 -> raw 63 all check out against the same formula;
  * every RTKit control channel (raw 0..31) is REFUSED a nub name, as are a
    raw endpoint past one byte, an empty/overlong/non-printable role, and an
    output buffer too small to hold the name;
  * the two declared ADT flags: exactly two, on /arm-io/dcp/iop-dcp-nub, named
    "pre-loaded" and "running", value 4-byte LE 1 -- and NEITHER name exists
    in either tree, so they are declared additions and not stock values;
  * the wrapper plan derived from reg[0] translated through /arm-io ranges, the
    attested 0x88000 size, the role "DCP", the four ADT interrupt lines in ADT
    order, and the derived nub name;
  * the attested-size oracle (flip reg[0]'s size -> REFUSE, restore ->
    succeed), the AppleASCWrapV6 oracle (break /arm-io/dcp's compatible ->
    REFUSE), the RTBuddy oracle (break the nub's compatible -> REFUSE), the
    no-device oracle (the served tree -> REFUSE), a bus address outside
    /arm-io, an unterminated role, a zero interrupt line, two identical
    interrupt lines, and the DRAM / exclusion / alias / NULL-output refusals.

What it does NOT qualify: the transport (that is the in-tree a7iop RTKit, used
by five other devices), nor that publishing an endpoint makes any guest driver
proceed. That is the whole-machine gate and the arm table.
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
           'hw/arm/apple-silicon/modern-dcp-iop.c',
           'hw/arm/apple-silicon/modern-disp-trace.c',
           'include/hw/arm/apple-silicon/modern-dcp-iop.h',
           'include/hw/arm/apple-silicon/modern-disp-trace.h',
           'include/hw/arm/apple-silicon/modern-boot-metadata.h',
           'include/hw/arm/apple-silicon/modern-board-regions.h',
           'scripts/test-apple-modern-dcp-iop.c',
           'scripts/test-apple-modern-dcp-iop.py']


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
        'endpoint_raw': results[0]['endpoint_raw'],
        'endpoint_user': results[0]['endpoint_user'],
        'nub_name': results[0]['nub_name'],
        'source_root': str(root), 'source_sha256': before, 'dtrees': tree_hashes,
        'runs': runs, 'firmware_executed': False, 'guest_executed': False,
        'scope': __doc__,
        'declared_not_attested': [
            'the two ADT flags "pre-loaded" = 1 and "running" = 1 on '
            '/arm-io/dcp/iop-dcp-nub. They are NOT in the stock tree and they '
            'claim iBoot already loaded and started the DCP; this loader '
            'places no DCP firmware and publishes no '
            '/chosen/carveout-memory-map region-id-N or segment-ranges. All '
            'five in-tree RTKit devices set the same pair on their own nub, '
            'which is precedent, not attestation.',
            'the raw endpoint 0x37 for IOMFB is ANALOGY from public Asahi '
            '(another SoC generation); what is ATTESTED is the nub-name format '
            '"%sEndpoint%u", that AppleDCPLinkServiceSoC matches '
            '"DCPEndpoint24", and that Apple\'s DCPEndpoint list stops at 24. '
            'The bias of 31 is in-tree precedent (SMC user-relative 0 is '
            'Apple\'s SMCEndpoint1), not a firmware-attested constant.',
            'which a7iop register file /arm-io/dcp wants: sep.c passes V4 for '
            'a node whose compatible says v6, so both are offered and the '
            'question is settled by a guest, not by this test.',
            'the positional ADT-interrupt-to-mailbox-line mapping. It is the '
            'convention t8030 uses for SMC/SIO/ANS; no source states it.',
            'nothing behind the endpoint is implemented. It counts the '
            'messages it receives and replies to none.',
        ],
        'not_covered': [
            'whether RTBuddy publishes any RTBuddyEndpointService nub in a '
            'guest, and whether AppleDCPLinkServiceSoC then matches',
            'the RTKit transport, management protocol and roll-call: that is '
            'the in-tree hw/misc/apple-silicon/a7iop code, unchanged here',
            'any DMA, firmware execution or DCP message semantics',
        ]}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps({k: report[k] for k in
                      ('passed', 'checks_per_run', 'endpoint_raw',
                       'endpoint_user', 'nub_name')},
                     indent=2))


if __name__ == '__main__':
    main()
