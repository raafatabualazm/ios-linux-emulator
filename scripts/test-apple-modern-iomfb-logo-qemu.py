#!/usr/bin/env python3
"""Gate: Apple's own `restored_external` draws the Apple logo on the board's scanout
through an IOMobileFramebuffer user client.

This is the first *pixel* acceptance test for the modern board. Everything the guest
runs is Apple's own code out of the user's retained iOS 27.0/24A437 restore ramdisk:
`restored_external` is a complete, GPU-free IOMobileFramebuffer client (it composites
with `IOSurfaceCreate` + CPU writes and links nothing from Metal, QuartzCore or
CoreGraphics), so this proves pixels without SpringBoard, without a GPU, without
storage, without a restored root filesystem and without SEP.

What it proves when it passes: the kernel published an `IOMobileFramebuffer` service,
a userspace client opened it, submitted a swap, and the artwork Apple ships in
`usr/share/progressui` ended up in the scanout the host can read.

What it does NOT prove: anything about a real display controller or DCP firmware, about
CoreAnimation (restored_external never touches it), or about compressed surfaces. The
guest filesystem is a hand-built ramdisk and the run uses the project's declared opt-in
compatibility settings (`img4-ignition-compat`, `pauth-compat`) plus a generated v1
trust cache, so Apple's code-signing *origin* requirement is bypassed by declaration.

Structure, and why it can fail honestly:

  1. DETECTOR SELF-CHECK, host only, no guest. The logo detector is shown to accept a
     synthetic frame that has the artwork composited into it and to reject a frame of
     XNU console text, a black frame, a white frame and a plain white rectangle of the
     same size as the artwork. Those five results are measured every run and the gate
     refuses to judge any guest frame unless all five hold.
  2. CLIENT ARM. Boot the logo ramdisk, wait for the shell, capture the scanout
     *before* starting the client (the logo must be absent), then type `sh /logo`
     through the board's console keyboard and sample the scanout until the logo
     appears or the window closes.
  3. NO-CLIENT ORACLE. Byte-identical image, binary, tree and boot arguments; the only
     difference is that nothing is typed, so `restored_external` never runs. The logo
     must NOT appear. This is the same oracle shape the M0 typed-command gate uses.
  4. Optional IOKIT-LOG diagnostic arm: the same boot with XNU's `io=` IOKit debug
     flags, recorded but never part of the verdict.

The gate passes only if every self-check holds, the client arm shows the logo and the
oracle arm does not.
"""
import argparse
import importlib.util
import json
import os
import resource
import signal
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

import numpy as np

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import apple_modern_tga as tga                                       # noqa: E402
from apple_modern_logo import IOU_PASS, LogoDetector, composite      # noqa: E402


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


board = module('board_preparation_gate', 'test-apple-modern-machine.py')

WORKSPACE = Path('/home/kali/Desktop/Inferno-and-Darwin-VM/modern-emulator')
PROMPT = b'bash-5.3#'
DEVICE = 'modern-boot-display'
# The M0 restore-shell boot arguments, unchanged. serial=3 keeps the UART as the
# console so the client's own stdout/stderr (StandardOutPath /dev/console in Apple's
# own plist) is captured, and boot-display=on provides the console keyboard.
BOOT_ARGS = 'rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort'
MAX_WALL = 420
PROMPT_WINDOW = 240
LOGO_WINDOW = 120
SHIFTED = {'$': '4', '(': '9', ')': '0', '*': '8'}
KEYS = {' ': 'spc', '/': 'slash', '.': 'dot', '-': 'minus'}
# Lines worth quoting verbatim from the UART, whichever way the run goes.
INTERESTING = [
    'W6LOGO_START', 'W6LOGO_EXIT', 'W6SVC_START', 'W6SVC_DONE',
    'found applelogo at', 'unable to find a suitable applelogo',
    'unable to get display list', 'unable to get framebuffer',
    'ramrod_display', 'set_progress', 'enable_usb', 'IONVRAM',
    'IOMobileFramebuffer', 'IOMFB', 'AppleCLCD', 'DCPPowerManager', 'DCPLink',
    'display-subsystem', 'SwapBegin', 'SwapEnd', 'restored_external',
    'main-screen', 'Can\'t blit image', 'showprogress',
    'dyld[', 'Library not loaded', 'Symbol not found', 'code signature',
    'AMFI', 'Killed', 'Trace/BPT', 'Abort trap', 'Segmentation fault',
]
# The client's own ordered restore state machine; the display step is 0x0406.
CHECKPOINT = 'CHECKPOINT'
DISPLAY_STEP = '[0x0406] set_progress_0'
NO_DISPLAY_LIST = 'unable to get display list'
NO_FRAMEBUFFER = 'unable to get framebuffer'


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (1200, 1200))


def key_event(code, down):
    return {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': code}}}


def typed(text, enter=True):
    events = []
    for ch in text:
        if ch in SHIFTED:
            events += [key_event('shift', True), key_event(SHIFTED[ch], True),
                       key_event(SHIFTED[ch], False), key_event('shift', False)]
        else:
            code = KEYS.get(ch, ch)
            events += [key_event(code, True), key_event(code, False)]
    if enter:
        events += [key_event('ret', True), key_event('ret', False)]
    return events


# --------------------------------------------------------------------------- artwork
def load_artwork(directory):
    """Boolean alpha masks of every applelogo*.tga the guest image carries."""
    out = {}
    for path in sorted(Path(directory).glob('applelogo*.tga')):
        out[path.name] = tga.mask(str(path))
    if not out:
        sys.exit('no applelogo*.tga under %s' % directory)
    return out


# ----------------------------------------------------------------- detector self-check
def self_check(detector, artwork, console, out):
    """Five measured results the detector must produce before any guest frame counts."""
    height, width = 768, 1024
    lines = ['bash-5.3# sh /logo', 'W6LOGO_START',
             'ACMTRM: waitForSEPEndpoint: timed out waiting for AppleSEPManager (timeoutMs=5000).'] * 16
    text = console.render(lines[:48], columns=width // 8, rows=height // 16)
    text = text[:height, :width]
    name = max(artwork, key=lambda n: artwork[n].size)
    smallest = min(artwork, key=lambda n: artwork[n].size)
    cases = {}

    black = np.zeros((height, width), dtype=bool)
    white = np.ones((height, width), dtype=bool)
    rect = np.zeros((height, width), dtype=bool)
    rh, rw = artwork[smallest].shape
    rect[(height - rh) // 2:(height - rh) // 2 + rh,
         (width - rw) // 2:(width - rw) // 2 + rw] = True
    over_text, at = composite(text, artwork[smallest])
    over_black, _ = composite(black, artwork[name])

    # A real swap can lose anti-aliased edge pixels to the luminance threshold and can
    # pick up stray lit pixels, so the detector is also required to accept an eroded,
    # speckled copy. Fixed seed: the self-check must be reproducible.
    rng = np.random.default_rng(0x10465040)
    degraded = artwork[smallest].copy()
    fg = np.flatnonzero(degraded.ravel())
    degraded.ravel()[rng.choice(fg, size=int(0.08 * fg.size), replace=False)] = False
    bg = np.flatnonzero(~degraded.ravel())
    degraded.ravel()[rng.choice(bg, size=int(0.005 * bg.size), replace=False)] = True
    over_black_degraded, _ = composite(black, degraded)

    for label, mask, want in (('console_text_only', text, False),
                              ('black_frame', black, False),
                              ('white_frame', white, False),
                              ('white_rectangle_logo_sized', rect, False),
                              ('logo_over_console_text', over_text, True),
                              ('logo_on_black', over_black, True),
                              ('logo_eroded_8pct_speckled', over_black_degraded, True)):
        got = detector.inspect_mask(mask)
        cases[label] = {'expected_logo_present': want,
                        'logo_present': got['logo_present'],
                        'best': got['best'], 'best_iou': got['best_iou'],
                        'at': got['at'], 'ok': got['logo_present'] == want}
    (out / 'self-check.json').write_text(json.dumps(
        {'threshold': IOU_PASS, 'composited_at': at, 'cases': cases}, indent=2) + '\n')
    return all(c['ok'] for c in cases.values()), cases


# ------------------------------------------------------------------------------- arms
def boot_arm(arm, args, detector, out, extra_boot_args=''):
    """One guest boot. arm = 'client' | 'no-client' | 'iokit-log'."""
    out.mkdir(parents=True, exist_ok=True)
    serial = out / 'serial.log'
    comp = args.components
    machine = ('apple-modern'
               f',bootkc={comp / "bootkc"},sptm={comp / "sptm"},txm={comp / "txm"}'
               f',dtree={args.dtree},tc={args.trustcache},ramdisk={args.ramdisk}'
               ',prepare-only=off,img4-ignition-compat=on,pauth-compat=on,boot-display=on'
               f',boot-command-line={BOOT_ARGS}{extra_boot_args}')
    argv = [str(args.binary), '-M', machine, '-m', args.memory, '-smp', '1', '-nodefaults',
            '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(serial),
            '-S', '-qmp', 'stdio']
    (out / 'argv.json').write_text(json.dumps({'argv': argv, 'arm': arm}, indent=2) + '\n')
    assets = {'bootkc': comp / 'bootkc', 'sptm': comp / 'sptm', 'txm': comp / 'txm',
              'dtree': args.dtree, 'tc': args.trustcache, 'ramdisk': args.ramdisk,
              'binary': args.binary}
    before = {name: board.digest(path) for name, path in assets.items()}

    report = {'arm': arm, 'checks': {}, 'detail': {}, 'frames': []}
    checks, detail = report['checks'], report['detail']
    started = time.monotonic()
    process = qmp = watchdog = None
    try:
        with (out / 'emulator.log').open('wb') as stderr:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=stderr, bufsize=0, preexec_fn=child_limits,
                                       start_new_session=True)
            watchdog = threading.Timer(MAX_WALL + 30,
                                       lambda: os.killpg(process.pid, signal.SIGKILL))
            watchdog.daemon = True
            watchdog.start()

            def guard():
                remaining = MAX_WALL + 30 - (time.monotonic() - started)
                if remaining <= 0:
                    raise RuntimeError('boot wall-clock bound exceeded')
                return remaining

            qmp = board.QMP(None, guard, process)

            def uart(cap=32 << 20):
                """Last `cap` bytes of the UART log. Capped because the optional
                iokit-log arm can make XNU extremely chatty and the host is shared."""
                if not serial.exists():
                    return b''
                size = serial.stat().st_size
                with serial.open('rb') as fh:
                    if size > cap:
                        fh.seek(size - cap)
                    return fh.read()

            shot = [0]

            def snap(label):
                shot[0] += 1
                png = out / ('frame-%02d-%s.png' % (shot[0], label))
                qmp.request('screendump', {'filename': str(png), 'format': 'png'})
                qmp.events.clear()
                verdict = detector.inspect(png)
                verdict['label'] = label
                verdict['t'] = round(time.monotonic() - t0, 1)
                verdict['png'] = png.name
                report['frames'].append(verdict)
                if not verdict['logo_present'] and label.startswith('poll'):
                    png.unlink(missing_ok=True)      # keep the evidence dir small
                    verdict['png'] = None
                return verdict

            qmp.request('cont')
            t0 = time.monotonic()

            prompt_at = None
            while time.monotonic() - t0 < PROMPT_WINDOW:
                if process.poll() is not None:
                    raise RuntimeError('emulator exited before the shell prompt')
                if PROMPT in uart():
                    prompt_at = time.monotonic() - t0
                    break
                time.sleep(1.0)
            checks['shell_prompt_reached'] = prompt_at is not None
            detail['prompt_seconds'] = None if prompt_at is None else round(prompt_at, 1)
            if prompt_at is None:
                return report, before, assets

            time.sleep(3)
            baseline = snap('baseline-before-client')
            checks['logo_absent_before_client'] = not baseline['logo_present']

            if arm == 'client':
                # `sh /logo` runs Apple's binary; the script is run through the
                # interpreter because Darwin refuses to exec an unsigned script.
                qmp.request('input-send-event', {'device': DEVICE, 'head': 0,
                                                 'events': typed('sh /svc')})
                time.sleep(4)
                qmp.request('input-send-event', {'device': DEVICE, 'head': 0,
                                                 'events': typed('sh /logo')})
                detail['typed'] = ['sh /svc', 'sh /logo']
            else:
                detail['typed'] = []

            found = None
            deadline = time.monotonic() + LOGO_WINDOW
            samples = 0
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    detail['emulator_exited_early'] = True
                    break
                verdict = snap('poll')
                samples += 1
                if verdict['logo_present']:
                    found = verdict
                    break
                time.sleep(1.5)
            detail['frames_sampled'] = samples
            final = snap('final')
            if found is None and final['logo_present']:
                found = final
            checks['logo_drawn'] = found is not None
            detail['best_iou_seen'] = max([f['best_iou'] for f in report['frames']] or [0.0])
            detail['best_frame'] = max(report['frames'], key=lambda f: f['best_iou'],
                                       default=None)

            text = uart().decode('utf-8', 'replace')
            (out / 'uart.txt').write_text(text)
            hits = {}
            for needle in INTERESTING:
                lines = [l.strip() for l in text.splitlines() if needle in l]
                if lines:
                    hits[needle] = lines[:12]
            detail['uart_lines'] = hits
            detail['uart_bytes'] = len(text)
            detail['checkpoints'] = [l.strip() for l in text.splitlines()
                                     if CHECKPOINT in l][:80]
            started = 'W6LOGO_START' in text
            checks['client_started'] = started if arm == 'client' else not started
            if arm == 'client':
                # Diagnostics that say WHERE it stopped, so a failing run is a handoff
                # rather than a mystery.
                checks['client_reached_display_step'] = DISPLAY_STEP in text
                checks['display_enumerated'] = (DISPLAY_STEP in text
                                                and NO_DISPLAY_LIST not in text
                                                and NO_FRAMEBUFFER not in text)
                detail['display_step_failure'] = [
                    l.strip() for l in text.splitlines()
                    if NO_DISPLAY_LIST in l or NO_FRAMEBUFFER in l][:4]
                detail['last_checkpoint'] = (detail['checkpoints'][-1]
                                             if detail['checkpoints'] else None)
    except BaseException as error:                                    # noqa: BLE001
        report['error'] = '%s: %s' % (type(error).__name__, error)
        report['traceback'] = traceback.format_exc()
    finally:
        if watchdog:
            watchdog.cancel()
        try:
            if qmp:
                qmp.request('quit')
        except Exception:                                             # noqa: BLE001
            pass
        if process is not None:
            try:
                process.wait(timeout=10)
            except Exception:                                         # noqa: BLE001
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except Exception:                                     # noqa: BLE001
                    pass
                process.wait()
            report['exit_code'] = process.returncode
        if qmp:
            qmp.close()
    return report, before, assets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--components', type=Path,
                    default=WORKSPACE / 'evidence/firmware-20261002/boot-components/derived')
    ap.add_argument('--dtree', type=Path, default=WORKSPACE / 'runtime/darwin-reference-27/dtree')
    ap.add_argument('--ramdisk', type=Path, required=True)
    ap.add_argument('--trustcache', type=Path, required=True)
    ap.add_argument('--artwork', type=Path, required=True,
                    help='the usr/share/progressui directory of the staged image')
    ap.add_argument('--bootkc-glyphs', type=Path, default=None,
                    help='boot kernel collection for the console glyph table '
                         '(defaults to --components/bootkc)')
    ap.add_argument('--memory', default='8G')
    ap.add_argument('--arms', default='client,no-client',
                    help='comma separated: client, no-client, iokit-log')
    ap.add_argument('--iokit-flags', default='0x3e',
                    help='XNU io= IOKit debug flags for the iokit-log arm')
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    from apple_modern_console import Console
    console = Console(args.bootkc_glyphs or (args.components / 'bootkc'))
    artwork = load_artwork(args.artwork)
    detector = LogoDetector(artwork)

    summary = {'threshold': IOU_PASS,
               'artwork': {n: [int(m.shape[1]), int(m.shape[0]), int(m.sum())]
                           for n, m in artwork.items()},
               'arms': {}}
    ok, cases = self_check(detector, artwork, console, args.out)
    summary['self_check_passed'] = ok
    summary['self_check'] = cases
    if not ok:
        summary['verdict'] = 'FAIL (detector self-check)'
        (args.out / 'report.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary, indent=2))
        return 2

    for arm in [a.strip() for a in args.arms.split(',') if a.strip()]:
        extra = ' io=%s' % args.iokit_flags if arm == 'iokit-log' else ''
        report, before, assets = boot_arm(arm, args, detector, args.out / arm, extra)
        after = {name: board.digest(path) for name, path in assets.items()}
        report['inputs_unchanged'] = before == after
        report['inputs'] = before
        (args.out / arm / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        summary['arms'][arm] = {'checks': report['checks'],
                                'prompt_seconds': report['detail'].get('prompt_seconds'),
                                'best_iou_seen': report['detail'].get('best_iou_seen'),
                                'last_checkpoint': report['detail'].get('last_checkpoint'),
                                'display_step_failure':
                                    report['detail'].get('display_step_failure'),
                                'uart_lines': report['detail'].get('uart_lines'),
                                'inputs_unchanged': report['inputs_unchanged'],
                                'error': report.get('error')}

    client = summary['arms'].get('client', {}).get('checks', {})
    oracle = summary['arms'].get('no-client', {}).get('checks', {})
    passed = (ok and client.get('shell_prompt_reached') and client.get('client_started')
              and client.get('logo_absent_before_client') and client.get('logo_drawn')
              and oracle.get('shell_prompt_reached') and oracle.get('logo_drawn') is False
              and all(a.get('inputs_unchanged') for a in summary['arms'].values()))
    summary['verdict'] = 'PASS' if passed else 'FAIL'
    (args.out / 'report.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'self_check'}, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
