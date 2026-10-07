#!/usr/bin/env python3
"""Bound a modern restore boot and observe guest-rendered boot console pixels.

This launcher records opt-in inherited compatibility settings explicitly. It
does not implement DCP, install apps, or claim a SpringBoard GUI. Inputs remain
read-only; screenshots and serial observations are retained with hashes.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys
import threading
import time
import traceback


sys.path.insert(0, str(Path(__file__).resolve().parent))
from apple_modern_console import Console  # noqa: E402

# A capture counts as a visible console only if it decodes to this many glyph cells. The
# cursor is one solid cell and is not a glyph, so it can never satisfy this by itself.
MIN_TEXT_CELLS = 40

spec = importlib.util.spec_from_file_location(
    'display_observation_board', Path(__file__).with_name('test-apple-modern-machine.py'))
board = importlib.util.module_from_spec(spec)
spec.loader.exec_module(board)
MAX_LOG = 1 << 20
MAX_FILE = 16 << 20
WIDTH, HEIGHT, STRIDE = 1024, 768, 4096


def require(value, description):
    if not value:
        raise RuntimeError(description)


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    resource.setrlimit(resource.RLIMIT_CPU, (75, 75))
    resource.setrlimit(resource.RLIMIT_AS, (16 << 30, 16 << 30))


def run(args, output):
    started = time.monotonic()
    paths = {name: args.components / name for name in board.ASSETS}
    paths['dtree'] = args.dtree
    paths['restore-trustcache'] = args.trustcache
    paths['ramdisk'] = args.ramdisk
    before = {name: board.digest(path) for name, path in paths.items()}
    before['binary'] = board.digest(args.binary)
    blobs = {name: path.read_bytes() for name, path in paths.items()}
    layout = board.expected_layout(blobs)
    reserved_size = (STRIDE * HEIGHT + (2 << 20) - 1) & -(2 << 20)
    address = board.DRAM + board.RAM_SIZE - reserved_size
    report = {'observation_completed': False, 'serial_shell_prompt': False,
              'visible_boot_console': False, 'springboard_gui': False,
              'native_dcp': False, 'ipa_installed': False, 'inputs_before': before,
              'compatibility': {'img4_ignition_private_bootkc_patch': args.img4_ignition_compat,
                                'pauth_sign_auth_noops': args.pauth_compat},
              'framebuffer': {'physical_address': hex(address), 'width': WIDTH,
                              'height': HEIGHT, 'stride': STRIDE},
              'limits': {'execution_seconds': args.seconds, 'overall_seconds': args.seconds + 15,
                         'log_bytes': MAX_LOG, 'file_bytes': MAX_FILE}}
    serial = output / 'serial.log'
    emulator = output / 'emulator.log'
    process = qmp = watchdog = None
    try:
        machine = 'apple-modern,' + ','.join(
            name + '=' + str(paths[asset]) for name, asset in
            zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
        machine += ',ramdisk=' + str(args.ramdisk) + ',prepare-only=off,boot-display=on'
        # serial=2 retains UART input while XNU console output uses BootVideo.
        machine += (',boot-command-line=rd=md0 serial=2 -v -noprogress '
                    'wdt=-1 wlan-olyhal-abort')
        if args.img4_ignition_compat:
            machine += ',img4-ignition-compat=on'
        if args.pauth_compat:
            machine += ',pauth-compat=on'
        argv = [str(args.binary), '-M', machine, '-m', '8G', '-smp', '1',
                '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial',
                'file:' + str(serial), '-S', '-qmp', 'stdio']
        report['argv'] = argv
        with emulator.open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=log, bufsize=0, preexec_fn=child_limits)
            watchdog = threading.Timer(args.seconds + 15, process.kill)
            watchdog.daemon = True
            watchdog.start()

            def guard():
                remaining = args.seconds + 15 - (time.monotonic() - started)
                require(remaining > 0, 'Overall observation deadline')
                for path in (serial, emulator):
                    if path.exists():
                        require(path.stat().st_size <= MAX_LOG, 'Log size bound')
                return remaining

            qmp = board.QMP(None, guard, process)
            regs = qmp.request('human-monitor-command', {'command-line': 'info registers'})
            require(board.parse_registers(regs)['PC'] == layout['entry'], 'Prepared SPTM entry PC')
            require(not qmp.request('query-status')['running'], 'Stopped before firmware execution')
            dump = output / 'bootargs-observation.bin'
            qmp.request('pmemsave', {'val': layout['args'], 'size': 1152, 'filename': str(dump)})
            bootargs = dump.read_bytes()
            dump.unlink()
            require(struct.unpack_from('<6Q', bootargs, 40) ==
                    (address, 0, STRIDE, WIDTH, HEIGHT, 32), 'Prepared BootVideo fields')
            report['prepared_entry'] = hex(layout['entry'])
            qmp.request('cont')
            running = time.monotonic()
            while time.monotonic() - running < args.seconds:
                guard()
                require(process.poll() is None, 'QEMU stayed alive during observation')
                text = serial.read_bytes() if serial.exists() else b''
                if b'bash-5.3#' in text or b'bash-5.3$' in text:
                    report['serial_shell_prompt'] = True
                    break
                if b'panic(cpu ' in text:
                    report['guest_panic_observed'] = True
                    break
                time.sleep(0.1)
            qmp.request('stop')
            report['execution_seconds'] = round(time.monotonic() - running, 3)
            screenshot = output / 'boot-console.png'
            qmp.request('screendump', {'filename': str(screenshot), 'format': 'png'})
            from PIL import Image
            with Image.open(screenshot) as image:
                require(image.size == (WIDTH, HEIGHT), 'Captured console geometry')
                rgb = image.convert('RGB')
                histogram = rgb.getcolors(WIDTH * HEIGHT)
                report['pixel_colors'] = len(histogram) if histogram is not None else None
                report['nonblack_pixels'] = sum(count for count, color in histogram if color != (0, 0, 0))
            # nonblack_pixels is kept for the record but is NOT the criterion: a single cursor
            # cell (128 pixels) satisfies "any non-black pixel" with no text on screen at all,
            # which is exactly what a serial=3 boot shows. Decode the capture with the kernel's
            # own glyph table instead.
            # Known limitation, deliberately not papered over: under serial=2 the UART is silent,
            # so serial_shell_prompt cannot become true, and this single late screenshot usually no
            # longer shows the prompt (the guest's repeating log line scrolls it away within seconds).
            # Use test-apple-modern-display-shell-qemu.py to check for the prompt and for input.
            try:
                rows, unknown, text_cells = Console(args.components / 'bootkc').decode(screenshot)
                report['console_text_cells'] = text_cells
                report['console_unknown_cells'] = unknown
                report['console_text_rows'] = sum(1 for row in rows if row.strip(' \u2588'))
                report['visible_boot_console'] = text_cells >= MIN_TEXT_CELLS
                (output / 'boot-console.txt').write_text('\n'.join(rows) + '\n')
            except ValueError as error:
                # Different kernel collection: refuse to decode rather than guess a glyph table.
                report['console_decode_error'] = str(error)
                report['visible_boot_console'] = None
            report['screenshot'] = board.digest(screenshot)
            (output / 'final-registers.txt').write_text(qmp.request(
                'human-monitor-command', {'command-line': 'info registers'}))
            qmp.request('quit')
            require(process.wait(timeout=5) == 0, 'Clean requested shutdown')
        report['observation_completed'] = True
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        (output / 'error-traceback.txt').write_text(traceback.format_exc())
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if qmp is not None:
            qmp.close()
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            report['exit_code'] = process.returncode
            report['child_reaped'] = process.poll() is not None
        after = {name: board.digest(path) for name, path in paths.items()}
        after['binary'] = board.digest(args.binary)
        report['inputs_unchanged'] = after == before
        report['inputs_after'] = after
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--dtree', type=Path, required=True)
    parser.add_argument('--trustcache', type=Path, required=True)
    parser.add_argument('--ramdisk', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=60, choices=range(10, 61))
    parser.add_argument('--img4-ignition-compat', action='store_true')
    parser.add_argument('--pauth-compat', action='store_true')
    args = parser.parse_args()
    for name in ('binary', 'components', 'dtree', 'trustcache', 'ramdisk'):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    require(os.access(args.binary, os.X_OK), 'Executable required')
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = run(args, output)
    print(json.dumps({key: result.get(key) for key in
                      ('observation_completed', 'serial_shell_prompt',
                       'visible_boot_console', 'console_text_cells', 'nonblack_pixels',
                       'inputs_unchanged', 'error')}))
    raise SystemExit(0 if result['observation_completed'] and result['inputs_unchanged'] else 1)


if __name__ == '__main__':
    main()
