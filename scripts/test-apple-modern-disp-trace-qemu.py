#!/usr/bin/env python3
"""Whole-machine gate for the disp0 bind probe, with a no-device oracle.

Boots the unmodified M0 restore-shell recipe four times and runs two refusal
oracles.  Every guest runs one at a time: the CALLER must already hold the
shared QEMU lock, this script never takes it and never starts two guests.

Positive (what the probe is for):
  * disp0-probe=dcp-chain makes AppleT8110DART bind to BOTH /arm-io/dart-dcp
    and /arm-io/dart-disp0 - a driver that is absent from the registry without
    the probe - which proves the restored "compatible" reaches the
    AppleARMIODevice nub and makes IONameMatch succeed.
  * disp0-probe=disp0 maps 25 of 29 display register windows as logging
    apertures and the boot still reaches bash-5.3# with no panic.

No-device oracle:
  * with the option off the aperture device does not exist (no disp-trace line
    on stderr) and AppleT8110DART is absent, while the same boot still reaches
    bash-5.3#.  So every positive above is attributable to the option.

Measured and asserted, not assumed: AppleCLCD2 never appears in ANY arm, and
no AP access to any of the 25 mapped windows is ever recorded.  If a future
change makes AppleCLCD2 bind, THIS GATE FAILS and must be updated with the new
measurement - that is deliberate.

Refusal oracles: an unknown arm name, and dcp-chain combined with
adt-dart-ids=on (the profile serves its own declared dart-id).
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

PROMPT = 'bash-5.3#'
BOOT_ARGS = 'rd=md0 serial=3 io=0x3f -v -noprogress wdt=-1 wlan-olyhal-abort'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise SystemExit('GATE FAILED: ' + message)


def machine(components, extra):
    parts = ['apple-modern']
    for key, value in components.items():
        parts.append('%s=%s' % (key, value))
    parts.append('prepare-only=off')
    parts.append('img4-ignition-compat=on')
    parts.append('pauth-compat=on')
    parts.extend(extra)
    parts.append('boot-command-line=' + BOOT_ARGS)
    return ','.join(parts)


def boot(binary, components, extra, seconds, workdir, name):
    out = Path(workdir) / name
    out.mkdir(parents=True, exist_ok=True)
    argv = machine(components, extra)
    (out / 'argv.txt').write_text(binary + '\n' + argv + '\n')
    serial = out / 'serial.log'
    serial.touch()
    with (out / 'qemu.out').open('wb') as sink:
        child = subprocess.Popen(
            [binary, '-M', argv, '-m', '8G', '-smp', '1', '-nodefaults',
             '-display', 'none', '-monitor', 'none',
             '-serial', 'file:' + str(serial)], stdout=sink, stderr=sink)
        deadline = time.time() + seconds
        try:
            while time.time() < deadline:
                if child.poll() is not None:
                    break
                text = serial.read_bytes()
                if PROMPT.encode() in text or b'panic(' in text:
                    break
                time.sleep(1.0)
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)
    return {'name': name, 'argv': argv, 'exit': child.returncode,
            'serial': serial.read_bytes().decode('utf-8', 'replace'),
            'stderr': (out / 'qemu.out').read_text(errors='replace')}


def refuse(binary, components, extra, workdir, name):
    out = Path(workdir) / name
    out.mkdir(parents=True, exist_ok=True)
    argv = machine(components, extra)
    done = subprocess.run([binary, '-M', argv, '-m', '8G', '-smp', '1',
                           '-nodefaults', '-display', 'none', '-monitor', 'none',
                           '-serial', 'none'],
                          capture_output=True, text=True, timeout=300)
    (out / 'argv.txt').write_text(binary + '\n' + argv + '\n')
    (out / 'refusal.txt').write_text(done.stdout + done.stderr)
    return {'name': name, 'argv': argv, 'exit': done.returncode,
            'text': done.stdout + done.stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--bootkc', required=True)
    parser.add_argument('--sptm', required=True)
    parser.add_argument('--txm', required=True)
    parser.add_argument('--dtree', required=True)
    parser.add_argument('--tc', required=True)
    parser.add_argument('--ramdisk', required=True)
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    components = {'bootkc': args.bootkc, 'sptm': args.sptm, 'txm': args.txm,
                  'dtree': args.dtree, 'tc': args.tc, 'ramdisk': args.ramdisk}
    inputs = {name: digest(path) for name, path in
              [('binary', args.binary)] + list(components.items())}
    checks = 0
    runs = []
    with tempfile.TemporaryDirectory(prefix='disp-trace-gate-') as temp:
        work = Path(args.evidence) / 'runs' if args.evidence else Path(temp)
        work.mkdir(parents=True, exist_ok=True)
        off = boot(args.binary, components, [], args.seconds, work, 'oracle-off')
        chain = boot(args.binary, components, ['disp0-probe=dcp-chain'],
                     args.seconds, work, 'dcp-chain')
        plain = boot(args.binary, components, ['disp0-probe=disp0'],
                     args.seconds, work, 'disp0')
        nodcp = boot(args.binary, components, ['disp0-probe=disp0-nodcp'],
                     args.seconds, work, 'disp0-nodcp')
        runs = [off, chain, plain, nodcp]
        bad = refuse(args.binary, components, ['disp0-probe=nonsense'], work,
                     'refuse-unknown-arm')
        clash = refuse(args.binary, components,
                       ['disp0-probe=dcp-chain', 'adt-dart-ids=on'], work,
                       'refuse-dart-id-clash')

    # ---- every arm still boots ------------------------------------------
    for run in runs:
        require(PROMPT in run['serial'], '%s reaches the restore shell' % run['name'])
        require('panic(' not in run['serial'], '%s panics' % run['name'])
        checks += 2

    # ---- no-device oracle ------------------------------------------------
    require('disp-trace' not in off['stderr'],
            'the aperture device must not exist with the option off')
    require('AppleT8110DART' not in off['serial'],
            'AppleT8110DART must be absent with the option off')
    require('AppleCLCD' not in off['serial'], 'no AppleCLCD with the option off')
    checks += 3

    # ---- positive: the restored compatible binds a real driver ----------
    for nub in ('dart-dcp@2340000/AppleT8110DART',
                'dart-disp0@2300000/AppleT8110DART'):
        require(nub in chain['serial'],
                'dcp-chain must bind AppleT8110DART on %s' % nub)
        checks += 1

    # ---- the apertures are built and are what the plan says -------------
    for run in (chain, plain, nodcp):
        require('25 of 29 display register windows mapped as LOGGING APERTURES'
                in run['stderr'], '%s maps 25 of 29 windows' % run['name'])
        skipped = run['stderr'].count('skipped: inside an earlier window')
        require(skipped == 4, '%s skips exactly 4 contained windows, saw %d'
                % (run['name'], skipped))
        for window in ('0x410000000+0xafc000', '0x412800000+0x800000',
                       '0x302800000+0xbc000', '0x3082b8044+0xc'):
            require(window in run['stderr'],
                    '%s reports window %s' % (run['name'], window))
            checks += 1
        checks += 2

    # ---- measured negative result, asserted so a change is noticed ------
    for run in (chain, plain, nodcp):
        for absent in ('AppleCLCD', 'IOMobileFramebuffer', 'UPPipe',
                       'DCPPowerManager', 'AppleDCPExpert'):
            require(absent not in run['serial'],
                    'MEASURED-NEGATIVE CHANGED: %s now appears in %s; re-measure '
                    'the arm table and update this gate' % (absent, run['name']))
            checks += 1
        require('disp-trace #' not in run['stderr'],
                'MEASURED-NEGATIVE CHANGED: %s recorded an AP access to a '
                'display window; re-measure the arm table' % run['name'])
        checks += 1
        require('disp0@0' in run['serial'],
                '%s still publishes the disp0 nub' % run['name'])
        checks += 1

    # ---- the known-good observability control ---------------------------
    for run in runs:
        require('aic@F1000000/AppleInterruptControllerV3' in run['serial'],
                'the IOKit registration instrument must report the known-good '
                'control (AppleInterruptControllerV3 on aic) in ' + run['name'])
        checks += 1

    # ---- refusal oracles -------------------------------------------------
    require(bad['exit'] != 0 and 'unknown disp0-probe arm' in bad['text'],
            'an unknown arm name must be refused')
    require(clash['exit'] != 0 and 'cannot be combined with' in clash['text'],
            'dcp-chain with adt-dart-ids=on must be refused')
    checks += 2

    require(inputs == {name: digest(path) for name, path in
                       [('binary', args.binary)] + list(components.items())},
            'inputs changed during the gate')
    report = {'passed': True, 'checks': checks, 'inputs_sha256': inputs,
              'boot_args': BOOT_ARGS,
              'arms': {run['name']: {
                  'reached_prompt': PROMPT in run['serial'],
                  'panics': run['serial'].count('panic('),
                  'registering_lines': run['serial'].count('Registering: '),
                  'apple_clcd2': run['serial'].count('AppleCLCD'),
                  'apple_t8110dart': run['serial'].count('AppleT8110DART'),
                  'aperture_records': run['stderr'].count('disp-trace #'),
                  'windows_mapped': len(re.findall(r'disp-trace /arm-io/\S+ reg\[\d+\] \S+ mapped',
                                                   run['stderr'])),
              } for run in runs},
              'refusals': {bad['name']: bad['exit'], clash['name']: clash['exit']},
              'measured_negative': (
                  'AppleCLCD2 does not bind in any arm and no AP access to any '
                  'mapped display window is ever recorded; the gate asserts '
                  'this so that a future change which does bind it fails here '
                  'and forces a re-measurement'),
              'not_claimed': [
                  'no pixel, framebuffer, IOSurface or swap behaviour',
                  'no model of any disp0 or dcp register',
                  'nothing about why AppleCLCD2 does not bind (the README '
                  'states that as a measured correlation plus a '
                  'declared-inferred cause)']}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'gate-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps({key: report[key] for key in
                      ('passed', 'checks', 'arms', 'refusals')}, indent=2))


if __name__ == '__main__':
    main()
