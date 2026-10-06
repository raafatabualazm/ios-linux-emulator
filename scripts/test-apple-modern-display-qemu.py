#!/usr/bin/env python3
"""Check BootVideo scanout using actual CPU stores from an owned A64 ROM.

Decoded assets supply normal board metadata only. The CPU executes the owned
writer, never firmware. Independent screenshot pixels, padding, reservation,
boot_args and reset are checked. No display hardware or iOS GUI claim.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import tempfile
import time
import traceback


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


board = module('display_board', 'test-apple-modern-machine.py')
metadata = module('display_metadata', 'test-apple-modern-boot-metadata.py')
WIDTH, HEIGHT, STRIDE = 37, 23, 176
BASE = (1 << 40) + 0x100000
LIMIT_SECONDS = 45
MAX_LOG = 1 << 20
MAX_FILE = 16 << 20  # QEMU's initial 640x480 display surface uses a memfd.


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    return board.digest(path)


def colors():
    # Distinct channels, high byte and non-power-of-two rows test the ABI.
    return [0xa5000000 | ((x * 7 & 255) << 16) | ((y * 11 & 255) << 8) |
            ((x + y * 3) & 255) for y in range(HEIGHT) for x in range(WIDTH)]


def writer(address, uart=None):
    words = []

    def mov(register, value):
        for half in range(4):
            words.append((0xd2800000 if half == 0 else 0xf2800000) |
                         (half << 21) | (((value >> (half * 16)) & 0xffff) << 5) |
                         register)

    mov(10, address)
    pixels = colors()
    memory = bytearray(STRIDE * HEIGHT)
    for y in range(HEIGHT):
        for x in range(STRIDE // 4):
            color = pixels[y * WIDTH + x] if x < WIDTH else 0x00ff00ff
            mov(11, color)
            offset = y * STRIDE + x * 4
            require(offset % 4 == 0 and offset // 4 < 4096, 'Owned STR bounds')
            words.append(0xb9000000 | ((offset // 4) << 10) | (10 << 5) | 11)
            struct.pack_into('<I', memory, offset, color)
    words.append(0xd5033f9f)  # dsb sy
    if uart is not None:
        mov(12, uart)
        mov(13, BASE + 0x10000)
        mov(14, 8)
        words.append(0xf9000000 | (13 << 5) | 31)  # clear eight captured bytes
        poll = len(words)
        words.append(0xb9400000 | (0x10 // 4 << 10) | (12 << 5))  # UTRSTAT
        words.append(0x36000000 | (((poll - len(words)) & 0x3fff) << 5))  # tbz w0,#0,poll
        words.append(0xb9400000 | (0x24 // 4 << 10) | (12 << 5))  # URXH
        words.append(0x39000000 | (13 << 5))  # strb w0,[x13]
        words.append(0x91000400 | (13 << 5) | 13)  # add x13,x13,#1
        words.append(0xf1000400 | (14 << 5) | 14)  # subs x14,x14,#1
        words.append(0x54000001 | (((poll - len(words)) & 0x7ffff) << 5))  # b.ne poll
    terminal = BASE + len(words) * 4
    words.append(0x14000000)  # b .
    return struct.pack('<' + 'I' * len(words), *words), terminal, bytes(memory)


def ppm(path):
    with path.open('rb') as stream:
        def line():
            value = stream.readline(4096)
            while value.startswith(b'#'):
                value = stream.readline(4096)
            return value.strip()
        require(line() == b'P6', 'QMP screenshot uses binary PPM')
        size = [int(v) for v in line().split()]
        require(size == [WIDTH, HEIGHT] and line() == b'255', 'Screenshot geometry/depth')
        body = stream.read(WIDTH * HEIGHT * 3 + 1)
        require(len(body) == WIDTH * HEIGHT * 3, 'Exact screenshot byte count')
        return body


def child_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    resource.setrlimit(resource.RLIMIT_AS, (16 << 30, 16 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(binary, components, output, keyboard=False):
    started = time.monotonic()
    paths = {name: components / name for name in board.ASSETS}
    before = {name: digest(path) for name, path in paths.items()}
    blobs = {name: path.read_bytes() for name, path in paths.items()}
    layout = board.expected_layout(blobs)
    alignment = 2 << 20
    reserved_size = (STRIDE * HEIGHT + alignment - 1) & -alignment
    address = board.DRAM + board.RAM_SIZE - reserved_size
    require(address % alignment == 0, 'Framebuffer occupies aligned DRAM tail')
    uart = None
    if keyboard:
        nodes, _ = metadata.parse_adt(blobs['dtree'])
        relative, uart_size = struct.unpack_from('<QQ', nodes['/arm-io/uart0']['reg']['value'])
        ranges = nodes['/arm-io']['ranges']['value']
        for index in range(0, len(ranges), 24):
            child, parent, length = struct.unpack_from('<QQQ', ranges, index)
            if child <= relative and relative + uart_size <= child + length:
                uart = parent + relative - child
                break
        require(uart is not None, 'Owned UART address derived from stock ADT ranges')
    rom, terminal, expected_ram = writer(address, uart)
    require(all(not (BASE < start + size and start < BASE + len(rom))
                for start, size in layout['regions'].values()), 'ROM avoids firmware reservations')
    rom_path = output / 'pixel-writer.rom'
    rom_path.write_bytes(rom)
    report = {'passed': False, 'scope': __doc__, 'firmware_executed': False,
              'ios_gui_claim': False, 'native_dcp_claim': False,
              'binary': str(binary), 'binary_sha256': digest(binary)['sha256'],
              'keyboard_gate': keyboard,
              'component_hashes_before': before, 'passes': [],
              'limits': {'wall_seconds': LIMIT_SECONDS, 'cpu_seconds': 30,
                         'log_bytes': MAX_LOG, 'file_bytes': MAX_FILE,
                         'virtual_memory_bytes': 16 << 30},
              'framebuffer': {'address': hex(address), 'size': reserved_size,
                              'width': WIDTH, 'height': HEIGHT, 'stride': STRIDE}}
    process = qmp = None
    log_path = output / 'emulator.log'
    try:
        with tempfile.TemporaryDirectory(prefix='modern-display-gate-') as temporary:
            scratch = Path(temporary)
            machine = 'apple-modern,' + ','.join(
                name + '=' + str(paths[asset]) for name, asset in
                zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
            machine += (f',prepare-only=on,boot-display=on,boot-display-width={WIDTH},'
                        f'boot-display-height={HEIGHT},boot-display-stride={STRIDE}')
            argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
                    '-nodefaults', '-display', 'none', '-serial',
                    'null' if keyboard else 'none', '-monitor', 'none',
                    '-S', '-qmp', 'stdio', '-device',
                    f'loader,file={rom_path},addr={BASE},cpu-num=0,force-raw=on']
            report['argv'] = argv
            with log_path.open('xb') as log:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=log, bufsize=0, preexec_fn=child_limits)

                def guard():
                    remaining = LIMIT_SECONDS - (time.monotonic() - started)
                    require(remaining > 0 and log_path.stat().st_size <= MAX_LOG,
                            'Display gate wall/log bound')
                    return remaining

                qmp = board.QMP(None, guard, process)

                def memory(at, size):
                    path = scratch / 'ram.bin'
                    qmp.request('pmemsave', {'val': at, 'size': size, 'filename': str(path)})
                    data = path.read_bytes()
                    path.unlink()
                    require(len(data) == size, 'Exact observed memory size')
                    return data

                expected_pixels = b''.join(bytes((p >> 16 & 255, p >> 8 & 255, p & 255))
                                           for p in colors())
                for iteration in range(2):
                    if iteration:
                        qmp.request('system_reset')
                    deadline = time.monotonic() + 3
                    while True:
                        regs = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                        if board.parse_registers(regs)['PC'] == BASE:
                            break
                        require(time.monotonic() < deadline, 'Owned reset PC before any cont')
                        time.sleep(0.01)
                    require(not qmp.request('query-status')['running'], 'CPU stopped')
                    require(memory(BASE, len(rom)) == rom, 'Owned bytes verified before execution')
                    args = memory(layout['args'], 1152)
                    require(struct.unpack_from('<6Q', args, 40) ==
                            (address, 0, STRIDE, WIDTH, HEIGHT, 32), 'All BootVideo ABI fields')
                    require(struct.unpack_from('<Q', args, 32)[0] == layout['top'],
                            'topOfKernelData keeps original boot blob boundary')
                    require(struct.unpack_from('<Q', args, 24)[0] == board.RAM_SIZE - reserved_size,
                            'memSize excludes the framebuffer from managed RAM')
                    require(struct.unpack_from('<Q', args, 1144)[0] == board.RAM_SIZE,
                            'memSizeActual retains physical DRAM size')
                    tree = memory(layout['tree'], struct.unpack_from('<I', args, 104)[0])
                    nodes, _ = metadata.parse_adt(tree)
                    require(struct.unpack('<QQ', nodes['/chosen/memory-map']['PurpleGfxMem']['value']) ==
                            (address, reserved_size), 'Bootloader graphics ADT reservation')
                    if '/vram' in nodes:
                        require(struct.unpack('<QQ', nodes['/vram']['reg']['value']) ==
                                (address, reserved_size), 'VRAM physical extent')
                    require(not any(memory(address, reserved_size)), 'Entire reservation zero after reset')
                    blank_path = output / f'blank-{iteration}.ppm'
                    qmp.request('screendump', {'filename': str(blank_path), 'format': 'ppm'})
                    require(not any(ppm(blank_path)), 'Scanout observes cleared guest RAM')
                    qmp.request('cont')
                    expected_keys = None
                    if keyboard:
                        def key(code, down):
                            return {'type': 'key', 'data': {'down': down,
                                     'key': {'type': 'qcode', 'data': code}}}

                        def tap(code):
                            return [key(code, True), key(code, False)]

                        shifted = [key('shift', True), *tap('a'), key('shift', False)]
                        events = (shifted + tap('a') if not iteration else tap('a') + shifted)
                        events += [key('ctrl', True), *tap('b'), key('ctrl', False)]
                        events += tap('left') + tap('spc') + tap('ret')
                        expected_keys = (b'Aa' if not iteration else b'aA') + b'\x02\x1b[D \r'
                        qmp.request('input-send-event', {'device': 'modern-boot-display',
                                                        'head': 0, 'events': events})
                    deadline = time.monotonic() + 5
                    while True:
                        regs = qmp.request('human-monitor-command', {'command-line': 'info registers'})
                        pc = board.parse_registers(regs)['PC']
                        require(BASE <= pc < BASE + len(rom), 'Observed PC belongs to owned ROM')
                        if pc == terminal:
                            break
                        require(time.monotonic() < deadline, 'Owned CPU pixel writer completes')
                        time.sleep(0.01)
                    qmp.request('stop')
                    if keyboard:
                        require(memory(BASE + 0x10000, 8) == expected_keys,
                                'Actual CPU UART reads match console events with modifiers/VT100')
                    require(memory(address, len(expected_ram)) == expected_ram,
                            'Actual CPU stores and row padding match independent oracle')
                    screenshot = output / f'pixels-{iteration}.ppm'
                    qmp.request('screendump', {'filename': str(screenshot), 'format': 'ppm'})
                    require(ppm(screenshot) == expected_pixels,
                            'Every visible RGB pixel matches; high byte/padding excluded')
                    report['passes'].append({'after_reset': bool(iteration), 'cpu_writer_completed': True,
                                             'pixels_checked': WIDTH * HEIGHT,
                                             'uart_input_hex': expected_keys.hex() if keyboard else None,
                                             'screenshot_sha256': digest(screenshot)['sha256']})
                    if keyboard and not iteration:
                        # Leave a held modifier and pending/unread character before reset.
                        qmp.request('cont')
                        qmp.request('input-send-event', {'device': 'modern-boot-display', 'head': 0,
                            'events': [key('shift', True), *tap('z')]})
                        qmp.request('stop')
                qmp.request('quit')
                require(process.wait(timeout=5) == 0, 'Requested clean shutdown')
        report['passed'] = True
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        (output / 'error-traceback.txt').write_text(traceback.format_exc())
    finally:
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
        after = {name: digest(path) for name, path in paths.items()}
        report['components_unchanged'] = after == before
        report['binary_unchanged'] = digest(binary)['sha256'] == report['binary_sha256']
        report['passed'] &= report['components_unchanged'] and report['binary_unchanged']
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--check-keyboard', action='store_true')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = run(args.binary.resolve(strict=True), args.components.resolve(strict=True), output,
                 args.check_keyboard)
    print(json.dumps({'passed': report['passed'], 'cpu_display_passes': len(report['passes']),
                      'error': report.get('error'), 'binary_sha256': report['binary_sha256']}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
