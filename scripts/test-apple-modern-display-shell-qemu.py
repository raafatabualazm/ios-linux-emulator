#!/usr/bin/env python3
"""Gate: a command typed on the host runs in the iOS 27 guest and its answer is
drawn on the framebuffer.

What this proves, and what it does not. The restore shell boots with the console
routed to the framebuffer (serial=2, so the UART stays silent). A per-run random
command is typed through the board's console keyboard that asks the GUEST to compute an
answer the host never typed (`echo <token>$((a*b))`); the decoded framebuffer must show
`<token><a*b>`, which only an executed command can print, followed by a fresh prompt. Frames are
decoded with the glyph table XNU itself carries, so the check reads real guest output
rather than matching pixels, and a single cursor cell can no longer satisfy it (the
older observer treated "any non-black pixel" as a visible console).

It does NOT exercise a display controller, a GPU, Apple's HID path or any graphical
UI. The keyboard is a console convenience that injects UART receive bytes. The guest
draws only its text console. The restore shell is a Linux-built minimal ramdisk, and
the run uses the project's declared opt-in compatibility settings.

Negative checks inside every pass: the legacy key paths (HMP sendkey, QMP send-key)
deliver nothing to this board, and input-send-event without a device is refused.
`--oracle legacy-keys` and `--oracle no-keys` deliberately break the typing step; the
gate must FAIL under each, which shows the token check cannot pass on its own.

Measured on the first run: the prompt is on screen about 40 s after the guest starts.
Timing varies with host load and is not a property of the board.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
from apple_modern_console import Console  # noqa: E402


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


board = module('board_preparation_gate', 'test-apple-modern-machine.py')

WORKSPACE = Path('/home/kali/Desktop/Inferno-and-Darwin-VM/modern-emulator')
PROMPT = 'bash-5.3#'
DEVICE = 'modern-boot-display'
BOOT_ARGS = 'rd=md0 serial=2 -v -noprogress wdt=-1 wlan-olyhal-abort'
MAX_WALL = 330                      # per boot, seconds
KEYS = {' ': 'spc'}
UART_BASE = 0x385200000             # ADT /arm-io/uart0 reg[0], translated through /arm-io ranges


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
    resource.setrlimit(resource.RLIMIT_AS, (24 << 30, 24 << 30))


def key_event(code, down):
    return {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': code}}}


SHIFTED = {'$': '4', '(': '9', ')': '0', '*': '8'}


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


def token(prefix):
    """Random, letters and digits only, so every character is one key press."""
    return prefix + os.urandom(4).hex()


def self_check(console):
    """The decoder must round-trip text drawn with the kernel's own glyphs."""
    from PIL import Image
    lines = ['bash-5.3# echo g0123abcd', 'g0123abcd', 'ACMTRM: waitForSEPEndpoint: timed out.']
    with tempfile.TemporaryDirectory(prefix='console-selfcheck-') as scratch:
        path = Path(scratch) / 'frame.png'
        Image.fromarray((console.render(lines) * 255).astype('uint8')).save(path)
        rows, unknown, _ = console.decode(path)
    return rows[:3] == lines and unknown == 0


def boot_once(index, args, console, out, oracle):
    tag = f'pass{index}'
    out.mkdir(parents=True, exist_ok=True)
    serial = out / f'{tag}-serial.log'
    emulator_log = out / f'{tag}-emulator.log'
    comp = args.components
    machine = ('apple-modern'
               f',bootkc={comp / "bootkc"},sptm={comp / "sptm"},txm={comp / "txm"},dtree={args.dtree}'
               f',tc={args.trustcache},ramdisk={args.ramdisk}'
               ',prepare-only=off,img4-ignition-compat=on,pauth-compat=on,boot-display=on'
               f',boot-command-line={BOOT_ARGS}')
    argv = [str(args.binary), '-M', machine, '-m', '8G', '-smp', '1', '-nodefaults',
            '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(serial),
            '-S', '-qmp', 'stdio']
    (out / f'{tag}-argv.json').write_text(json.dumps({'argv': argv, 'oracle': oracle}, indent=2) + '\n')
    assets = {name: comp / name for name in ('bootkc', 'sptm', 'txm')}
    assets.update({'dtree': args.dtree, 'tc': args.trustcache, 'ramdisk': args.ramdisk})
    before = {name: board.digest(path) for name, path in assets.items()}
    before['binary'] = board.digest(args.binary)

    report = {'tag': tag, 'oracle': oracle, 'checks': {}, 'detail': {}, 'frames': []}
    checks, detail = report['checks'], report['detail']
    started = time.monotonic()
    process = qmp = watchdog = None

    try:
        with emulator_log.open('xb') as stderr:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=stderr, bufsize=0, preexec_fn=child_limits,
                                       start_new_session=True)
            watchdog = threading.Timer(MAX_WALL + 30, lambda: os.killpg(process.pid, signal.SIGKILL))
            watchdog.daemon = True
            watchdog.start()

            def guard():
                remaining = MAX_WALL + 30 - (time.monotonic() - started)
                if remaining <= 0:
                    raise RuntimeError('boot wall-clock bound exceeded')
                return remaining

            qmp = board.QMP(None, guard, process)

            def uart_bytes():
                return serial.stat().st_size if serial.exists() else 0

            def snap(label):
                """Capture and decode; retry a few times if a half-drawn cell shows up."""
                png = out / f'{tag}-{label}.png'
                for _ in range(4):
                    qmp.request('screendump', {'filename': str(png), 'format': 'png'})
                    rows, unknown, text = console.decode(png)
                    if unknown == 0:
                        break
                    time.sleep(0.4)
                (out / f'{tag}-{label}.txt').write_text('\n'.join(rows) + '\n')
                report['frames'].append({'label': label, 't': round(time.monotonic() - t0, 1),
                                         'unknown_cells': unknown, 'text_cells': text})
                qmp.events.clear()
                return rows, unknown, text

            qmp.request('cont')
            t0 = time.monotonic()

            # 1. Wait for the prompt to appear ON SCREEN (serial=2: the UART is silent).
            prompt_at = None
            while time.monotonic() - t0 < 200:
                if process.poll() is not None:
                    raise RuntimeError('emulator exited before the prompt')
                poll = out / 'poll.png'
                qmp.request('screendump', {'filename': str(poll), 'format': 'png'})
                rows, _, _ = console.decode(poll)
                if any(PROMPT in row for row in rows):
                    prompt_at = time.monotonic() - t0
                    break
                time.sleep(2.0)
            (out / 'poll.png').unlink(missing_ok=True)
            checks['prompt_reached_on_screen'] = prompt_at is not None
            detail['prompt_seconds'] = None if prompt_at is None else round(prompt_at, 1)
            if prompt_at is None:
                return report

            time.sleep(3)
            rows, unknown, text = snap('before-keys')
            checks['console_text_visible'] = text >= 100
            detail['text_cells_before_keys'] = text
            checks['uart_silent_before_keys'] = uart_bytes() == 0

            # 2. Legacy key paths must deliver nothing to this board.
            control = token('n')
            for ch in control:
                qmp.request('send-key', {'keys': [{'type': 'qcode', 'data': ch}]})
            for ch in control[:4]:
                qmp.request('human-monitor-command', {'command-line': f'sendkey {ch}'})
            time.sleep(6)
            rows, _, _ = snap('after-legacy-keys')
            screen = '\n'.join(rows)
            checks['legacy_key_paths_deliver_nothing'] = (control[:5] not in screen and
                                                          uart_bytes() == 0)

            # 3. input-send-event without a device must be refused.
            refusal = None
            try:
                qmp.request('input-send-event', {'events': typed('z', enter=False)})
            except RuntimeError as error:
                refusal = str(error)
            detail['no_device_refusal'] = refusal
            checks['no_device_input_refused'] = bool(refusal) and 'Input handler not found' in refusal

            # 4. The real typing step (or a deliberately broken one for the oracles).
            #
            # The command asks the GUEST to compute an answer the host never typed:
            #     echo <token>$((<a>*<b>))
            # The echo of the typed line shows the literal "$((a*b))"; only an executed command
            # prints "<token><a*b>". That makes the proof independent of how long the line stays
            # on screen. It has to be, because after about 40 s the guest's kernel logs one
            # AppleSEPManager timeout line over and over, the screen becomes 45+ of 48 rows of it,
            # and the typed line scrolls away within seconds. The first version of this gate looked
            # for the token twice in one frame and failed in about half of the boots.
            #
            # Measured: boots are bimodal. In most the answer is on screen within a second; in the
            # others the echo appears but the answer does not for a long time (tens of seconds in
            # the probe runs). So sample continuously, accept any command's answer, and record the
            # latency instead of assuming it.
            expected, attempts = {}, []
            answer_frame = None
            window_end = time.monotonic() + 90
            poll = out / 'poll.png'
            samples = 0
            for attempt in range(3):
                word = token('g')
                a, b = 100 + int.from_bytes(os.urandom(2), 'big') % 900, \
                    100 + int.from_bytes(os.urandom(2), 'big') % 900
                command = f'echo {word}$(({a}*{b}))'
                answer = f'{word}{a * b}'
                expected[answer] = {'command': command, 'typed_at': time.monotonic()}
                if oracle == 'no-keys':
                    pass
                elif oracle == 'legacy-keys':
                    for ch in command:
                        keys = ([{'type': 'qcode', 'data': 'shift'},
                                 {'type': 'qcode', 'data': SHIFTED[ch]}] if ch in SHIFTED
                                else [{'type': 'qcode', 'data': KEYS.get(ch, ch)}])
                        qmp.request('send-key', {'keys': keys})
                    qmp.request('send-key', {'keys': [{'type': 'qcode', 'data': 'ret'}]})
                else:
                    qmp.request('input-send-event', {'device': DEVICE, 'head': 0,
                                                     'events': typed(command)})
                attempt_end = min(window_end, time.monotonic() + (45 if attempt < 2 else 90))
                while time.monotonic() < attempt_end:
                    qmp.request('screendump', {'filename': str(poll), 'format': 'png'})
                    qmp.events.clear()
                    rows, unknown, _ = console.decode(poll)
                    samples += 1
                    screen = '\n'.join(rows)
                    hit = next((ans for ans in expected if ans in screen), None)
                    if hit and unknown == 0:
                        answer_frame = (hit, rows)
                        proof = out / f'{tag}-proof-answer.png'
                        poll.replace(proof)
                        (out / f'{tag}-proof-answer.txt').write_text(screen + '\n')
                        report['frames'].append({'label': 'proof-answer', 'unknown_cells': unknown,
                                                 't': round(time.monotonic() - t0, 1)})
                        break
                    time.sleep(0.05)
                # Whether the typed line was also echoed is deliberately NOT recorded: kernel log
                # lines interleave with the echo and split it across rows, so it says nothing.
                attempts.append({'command': command, 'expected_answer': answer})
                if answer_frame:
                    break
                if time.monotonic() >= window_end:
                    break
            poll.unlink(missing_ok=True)
            detail['typing_attempts'] = attempts
            detail['frames_sampled_after_typing'] = samples
            seen = answer_frame is not None
            checks['command_executed_in_guest'] = seen
            if seen:
                hit, rows = answer_frame
                detail['answer_latency_s'] = round(time.monotonic() - expected[hit]['typed_at'], 2)
                detail['answered_attempt'] = list(expected).index(hit)
                # the shell must have printed a fresh prompt below the answer
                last = max(i for i, row in enumerate(rows) if hit in row)
                prompt_after = any(PROMPT in row for row in rows[last + 1:])
                for _ in range(40):                    # the prompt can lag the answer by a moment
                    if prompt_after:
                        break
                    time.sleep(0.1)
                    qmp.request('screendump', {'filename': str(poll), 'format': 'png'})
                    qmp.events.clear()
                    rows2, _, _ = console.decode(poll)
                    last2 = [i for i, row in enumerate(rows2) if hit in row]
                    prompt_after = bool(last2) and any(PROMPT in row for row in rows2[max(last2) + 1:])
                poll.unlink(missing_ok=True)
                checks['fresh_prompt_after_answer'] = prompt_after
                checks['no_unknown_glyphs_in_proof_frame'] = report['frames'][-1]['unknown_cells'] == 0
            else:
                checks['fresh_prompt_after_answer'] = False
                checks['no_unknown_glyphs_in_proof_frame'] = False
                if oracle == 'real':
                    # Where did the bytes stop? UTRSTAT bit 0 set means received data is waiting in
                    # the UART that the guest has not read; clear means it was consumed. Both reads
                    # are side-effect free (URXH, which pops, is NOT read).
                    diagnostics = {}
                    for name, offset in (('UTRSTAT', 0x10), ('UFSTAT', 0x18), ('UFCON', 0x08)):
                        reply = qmp.request('human-monitor-command',
                                            {'command-line': f'xp /1wx {UART_BASE + offset:#x}'})
                        diagnostics[name] = reply.strip()
                    detail['uart_registers_when_no_answer'] = diagnostics
            checks['uart_silent_at_end'] = uart_bytes() == 0
            detail['uart_bytes_final'] = uart_bytes()
    except BaseException as error:  # noqa: BLE001 - recorded, then the pass is judged
        report['error'] = f'{type(error).__name__}: {error}'
        report['traceback'] = traceback.format_exc()
    finally:
        if watchdog:
            watchdog.cancel()
        try:
            if qmp:
                qmp.request('quit')
        except Exception:  # noqa: BLE001
            pass
        if process is not None:
            try:
                process.wait(timeout=8)
            except Exception:  # noqa: BLE001
                pass
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            report['exit_code'] = process.returncode
        after = {name: board.digest(path) for name, path in assets.items()}
        after['binary'] = board.digest(args.binary)
        checks['inputs_unchanged'] = after == before
        report['elapsed_seconds'] = round(time.monotonic() - started, 1)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path,
                        help='directory holding bootkc, sptm, txm')
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--ramdisk', type=Path, default=WORKSPACE / 'runtime/ios27-restore-shell/min.dmg')
    parser.add_argument('--trustcache', type=Path, default=WORKSPACE / 'runtime/ios27-restore-shell/min.tc')
    parser.add_argument('--dtree', type=Path, default=WORKSPACE / 'runtime/darwin-reference-27/dtree',
                        help="Darwin's fixed-up tree; the stock tree gives no console output at all")
    parser.add_argument('--passes', type=int, default=2)
    parser.add_argument('--oracle', choices=('real', 'legacy-keys', 'no-keys'), default='real',
                        help='break the typing step on purpose; the gate must then fail')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True)

    console = Console(args.components / 'bootkc')
    report = {'scope': 'Typed command runs in the iOS 27 restore shell; answer is read from the framebuffer',
              'binary': str(args.binary), 'binary_sha256': board.digest(args.binary)['sha256'],
              'oracle': args.oracle, 'passes': [], 'passed': False,
              'decoder_self_check': self_check(console),
              'exercises_display_controller': False, 'exercises_apple_hid': False,
              'guest_draws_only_text_console': True, 'firmware_executed': True,
              'uses_declared_compat_options': ['img4-ignition-compat', 'pauth-compat']}
    if not report['decoder_self_check']:
        report['error'] = 'console decoder failed its round-trip self check'
    else:
        for index in range(args.passes):
            report['passes'].append(boot_once(index, args, console, args.output_dir / f'pass{index}',
                                              args.oracle))
        report['passed'] = all(p['checks'] and all(p['checks'].values()) and 'error' not in p
                               for p in report['passes'])
    (args.output_dir / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    failed = {p['tag']: [n for n, ok in p['checks'].items() if not ok] + ([p['error']] if 'error' in p else [])
              for p in report['passes']}
    print(json.dumps({'passed': report['passed'], 'oracle': args.oracle, 'passes': len(report['passes']),
                      'failed_checks': {k: v for k, v in failed.items() if v},
                      'prompt_seconds': [p['detail'].get('prompt_seconds') for p in report['passes']],
                      'binary_sha256': report['binary_sha256']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
