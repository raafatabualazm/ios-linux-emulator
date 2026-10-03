#!/usr/bin/env python3
"""Prepare and run isolated, persistent Inferno state; control its real touch input."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
import uuid

DISKS = ('root', 'firmware', 'syscfg', 'ctrl_bits', 'nvram',
         'effaceable', 'panic_log', 'sep_nvram', 'sep_ssc')
BOOT_FILES = {'trustcache': '038-44135-124.dmg.trustcache',
              'ticket': 'root_ticket.der', 'sep-fw': 'sep-firmware.n104.RELEASE.new.img4',
              'sep-rom': 'AppleSEPROM-Cebu-B1', 'kernel': 'kernelcache.research.iphone12b',
              'dtb': 'DeviceTree.n104ap.im4p'}


class SessionError(Exception):
    pass


class RunSignals:
    """Defer termination until the owned child has been stopped and reaped."""
    def __init__(self):
        self.received = None
        self.previous = {}

    def receive(self, number, frame):
        if self.received is None:
            self.received = number

    def __enter__(self):
        # Python only permits installing process handlers from the main thread.
        if threading.current_thread() is threading.main_thread():
            try:
                for number in (signal.SIGTERM, signal.SIGINT):
                    self.previous[number] = signal.getsignal(number)
                    signal.signal(number, self.receive)
            except BaseException:
                self.__exit__(None, None, None)
                raise
        return self

    def __exit__(self, *unused):
        for number, handler in self.previous.items():
            signal.signal(number, handler)

    def annotate(self, record):
        if self.received is not None:
            name = signal.Signals(self.received).name
            record.update(stop_reason=f'runner interrupted by {name}', status='interrupted',
                          interruption_signal=name, interruption_signal_number=self.received)


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def file_identity(path):
    st = Path(path).stat()
    if not stat.S_ISREG(st.st_mode):
        raise SessionError(f'Expected a regular file: {path}')
    return {'device': st.st_dev, 'inode': st.st_ino, 'size': st.st_size,
            'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns}


def checked_path(path):
    result = Path(path).expanduser().resolve()
    if any(char in str(result) for char in (',', '\n', '\r')):
        raise SessionError('QEMU paths cannot contain commas or line breaks')
    return result


def write_json(path, value):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def reject_open_writers(paths):
    """Existing launchers do not share a lock; require source stores to be stopped."""
    wanted = {(p.stat().st_dev, p.stat().st_ino) for p in paths}
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal() or process.name == str(os.getpid()):
            continue
        try:
            descriptors = list((process / 'fd').iterdir())
        except (FileNotFoundError, PermissionError):
            continue
        for fd in descriptors:
            matched = False
            try:
                info = fd.stat()
                if (info.st_dev, info.st_ino) not in wanted:
                    continue
                matched = True
                fields = (process / 'fdinfo' / fd.name).read_text().splitlines()
                flags = next(int(line.split()[1], 8) for line in fields if line.startswith('flags:'))
                if flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                    raise SessionError(f'Source store has an open writer in PID {process.name}')
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError as error:
                if matched:
                    raise SessionError('Cannot verify a matched source store writer') from error
                # procfs can expose directory entries while restricting unrelated
                # process descriptors. The metadata check also requires a stopped
                # source generation; this scan covers accessible descriptors.
                continue


def prepare(bundle, destination, binary=None):
    bundle, destination = checked_path(bundle), checked_path(destination)
    binary = checked_path(binary or bundle / 'bin/qemu-system-aarch64')
    if destination == bundle or bundle in destination.parents:
        raise SessionError('Place isolated state outside the source bundle')
    if destination.exists() or destination.is_symlink():
        raise SessionError('Destination must be new; existing state is never replaced')
    if not os.access(binary, os.X_OK):
        raise SessionError('QEMU is not executable')
    assets = {name: checked_path(bundle / 'boot-files' / filename)
              for name, filename in BOOT_FILES.items()}
    stores = [bundle / name for name in DISKS]
    for path in [binary, *assets.values(), *stores]:
        file_identity(path)
    reject_open_writers(stores)
    before = {name: file_identity(bundle / name) for name in DISKS}
    small_bytes = sum(before[name]['size'] for name in DISKS if name != 'root')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(destination.parent).free < small_bytes + (128 << 20):
        raise SessionError('Less than 128 MiB of working space remains after state copies')
    destination.mkdir(mode=0o700)
    for name in DISKS:
        if name == 'root':
            subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'raw',
                            '-b', str(bundle / name), str(destination / name)],
                           check=True, timeout=30)
        else:
            shutil.copyfile(bundle / name, destination / name)
        (destination / name).chmod(0o600)
    if before != {name: file_identity(bundle / name) for name in DISKS}:
        raise SessionError('Source store changed during the copy; discard incomplete new state')
    manifest = {'schema': 1, 'profile': 'inferno-ios14-gui',
                'guest': {'product': 'iPhone12,1', 'version': '14.0', 'build': '18A5351d'},
                'bundle': str(bundle), 'binary': {'path': str(binary), 'sha256': sha256(binary)},
                'assets': {name: {'path': str(path), 'sha256': sha256(path)}
                           for name, path in assets.items()},
                'original_stores': before,
                'source_root': str(bundle / 'root'),
                'original_small_hashes': {name: sha256(bundle / name) for name in DISKS if name != 'root'},
                'renderer': 'existing software-rendered guest profile; no native AGX claim',
                'guest_changes': 'inherited dyld-cache patch and launchd_unsecure_cache=1',
                'state_policy': 'persistent root overlay and all ancillary/SEP copies as one bundle',
                'gui_complete': False, 'ipa_qualified': False}
    write_json(destination / 'manifest.json', manifest)
    return manifest


def validate_state(state, manifest):
    """Refuse writable aliases and a substituted overlay before starting QEMU."""
    originals = [Path(manifest['bundle']) / name for name in DISKS]
    protected = {(item['device'], item['inode'])
                 for item in manifest['original_stores'].values()}
    for path in [*originals, Path(manifest['source_root']),
                 Path(manifest['binary']['path']),
                 *(Path(item['path']) for item in manifest['assets'].values())]:
        identity = file_identity(path)
        protected.add((identity['device'], identity['inode']))
    seen = set()
    for name in DISKS:
        path = state / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise SessionError(f'Isolated writable store must be a regular file, without symlinks: {name}')
        inode = (info.st_dev, info.st_ino)
        if inode in protected:
            raise SessionError(f'Writable store aliases an original store or boot artifact: {name}')
        if inode in seen:
            raise SessionError(f'Writable stores share an inode: {name}')
        seen.add(inode)
    # Each file is private to this state; even an unrelated hardlink would let
    # guest writes escape the selected bundle.
    if any((state / name).stat().st_nlink != 1 for name in DISKS):
        raise SessionError('Isolated writable stores must not have other hardlinks')
    info = json.loads(subprocess.run(
        ['qemu-img', 'info', '--output=json', str(state / 'root')],
        check=True, capture_output=True, text=True, timeout=30).stdout)
    backing = info.get('full-backing-filename')
    details = info.get('format-specific', {}).get('data', {})
    if (info.get('format') != 'qcow2' or info.get('backing-filename-format') != 'raw'
            or not backing or checked_path(backing) != checked_path(manifest['source_root'])
            or details.get('data-file') or details.get('corrupt')):
        raise SessionError('Root must be an intact qcow2 overlay of the pinned raw original, without an external data file')
    reject_open_writers([*originals, *(state / name for name in DISKS)])


def recover_dead_session(state):
    """Called under the state lock after pin/store validation; preserve stale markers."""
    live_path, endpoint = state / 'live.json', state / 'qmp.sock'
    if not live_path.exists() and not live_path.is_symlink():
        if endpoint.exists() or endpoint.is_symlink():
            raise SessionError('QMP socket has no recorded session; inspect it before recovery')
        return None
    info = live_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
        raise SessionError('Invalid stale live marker; recovery refused')
    with live_path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise SessionError('Stale live marker exceeds size bound')
    live = json.loads(raw)
    if not isinstance(live, dict) or type(live.get('pid')) is not int or live['pid'] <= 0:
        raise SessionError('Invalid stale PID; recovery refused')
    if (Path('/proc') / str(live['pid'])).exists():
        raise SessionError('Recorded guest PID exists (possibly reused); recovery refused')
    previous_run = Path(live.get('run', ''))
    if (previous_run.parent != state / 'runs' or not re.fullmatch('[0-9a-f]{32}', previous_run.name)
            or previous_run.is_symlink() or not previous_run.is_dir()
            or live.get('qmp') != str(endpoint)):
        raise SessionError('Stale markers do not identify this state; recovery refused')
    endpoint_info = None
    if endpoint.exists() or endpoint.is_symlink():
        endpoint_info = endpoint.lstat()
        if not stat.S_ISSOCK(endpoint_info.st_mode):
            raise SessionError('Stale QMP endpoint is not a socket; recovery refused')
    retained = previous_run / ('recovery-' + uuid.uuid4().hex + '.json')
    write_json(retained, {'recovered_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                         'live': live, 'live_sha256': hashlib.sha256(raw).hexdigest(),
                         'recorded_pid_absent': True, 'stores_validated_before_recovery': True,
                         'endpoint': None if endpoint_info is None else {
                             'device': endpoint_info.st_dev, 'inode': endpoint_info.st_ino}})
    # A recreated/replaced marker must never be removed using the earlier proof.
    def identity(value):
        # Reading the marker may update atime under relatime; that is not replacement.
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if identity(live_path.lstat()) != identity(info) or (Path('/proc') / str(live['pid'])).exists():
        raise SessionError('Stale session changed during recovery')
    if endpoint_info is not None and identity(endpoint.lstat()) != identity(endpoint_info):
        raise SessionError('Stale endpoint changed during recovery')
    live_path.unlink()
    if endpoint_info is not None:
        endpoint.unlink()
    return str(retained)


class QMP:
    def __init__(self, path, timeout=8):
        self.socket = socket.socket(socket.AF_UNIX)
        self.stream = None
        self.identifier = 0
        try:
            self.socket.settimeout(timeout)
            self.socket.connect(str(path))
            self.stream = self.socket.makefile('rwb')
            if 'QMP' not in self.read():
                raise SessionError('Missing QMP greeting')
            self.request('qmp_capabilities')
        except BaseException:
            self.close()
            raise

    def read(self):
        line = self.stream.readline((1 << 20) + 1)
        if not line:
            raise SessionError('QMP connection closed before reply')
        if len(line) > 1 << 20 or not line.endswith(b'\n'):
            raise SessionError('QMP message exceeds the framing bound')
        value = json.loads(line)
        if not isinstance(value, dict):
            raise SessionError('Invalid QMP object')
        return value

    def request(self, command, arguments=None):
        self.identifier += 1
        message = {'execute': command, 'id': self.identifier}
        if arguments is not None:
            message['arguments'] = arguments
        self.stream.write((json.dumps(message) + '\n').encode())
        self.stream.flush()
        for _ in range(256):
            reply = self.read()
            if 'event' in reply:
                continue
            if reply.get('id') != self.identifier:
                raise SessionError('QMP reply ID does not match the request')
            if 'error' in reply:
                raise SessionError(str(reply['error']))
            if 'return' not in reply:
                raise SessionError('QMP response lacks a result')
            return reply['return']
        raise SessionError('QMP event stream exceeded its response budget')

    def close(self):
        try:
            if self.stream is not None:
                self.stream.close()
        finally:
            self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def pointer(x, y, width, height):
    if any(type(v) is not int for v in (x, y, width, height)):
        raise SessionError('Touch positions and dimensions must be integers')
    if width < 2 or height < 2 or not (0 <= x < width and 0 <= y < height):
        raise SessionError('Touch coordinates fall outside the display')
    # Top-left screenshot coordinates; the device model performs its own Y flip.
    return [{'type': 'abs', 'data': {'axis': 'x', 'value': round(x * 32767 / (width - 1))}},
            {'type': 'abs', 'data': {'axis': 'y', 'value': round(y * 32767 / (height - 1))}}]


def gesture(qmp, start, end, width=828, height=1792, duration=0.2):
    if not math.isfinite(duration) or not 0.02 <= duration <= 5:
        raise SessionError('Gesture duration must be between 0.02 and 5 seconds')
    initial = pointer(*start, width, height)
    pointer(*end, width, height)  # Validate before pressing the finger.
    qmp.request('input-send-event', {'events': initial + [
        {'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
    try:
        steps = 1 if start == end else max(2, round(duration * 20))
        for step in range(1, steps + 1):
            time.sleep(duration / steps)
            x = round(start[0] + (end[0] - start[0]) * step / steps)
            y = round(start[1] + (end[1] - start[1]) * step / steps)
            qmp.request('input-send-event', {'events': pointer(x, y, width, height)})
    finally:
        qmp.request('input-send-event', {'events': [
            {'type': 'btn', 'data': {'button': 'left', 'down': False}}]})
    time.sleep(0.15)  # Device's end timer emits OUT_OF_RANGE after 100 ms.


def checked_vnc(value):
    """One explicit local RFB endpoint, with no QEMU option passthrough."""
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r'127\.0\.0\.1:(0|[1-9][0-9]?)', value):
        raise SessionError('VNC endpoint must be 127.0.0.1:DISPLAY with DISPLAY from 0 to 99')
    return value


def checked_qemu_data(value=None):
    directory = checked_path(value or Path(__file__).resolve().parents[4] / 'pc-bios')
    if not directory.is_dir():
        raise SessionError('QEMU data directory is missing')
    file_identity(directory / 'keymaps/en-us')
    return directory


def argv_for(state, manifest, display, run_dir, vnc=None, qemu_data=None):
    vnc = checked_vnc(vnc)
    assets = {name: item['path'] for name, item in manifest['assets'].items()}
    machine = 't8030,' + ','.join(f'{name}={assets[name]}'
                                 for name in ('trustcache', 'ticket', 'sep-fw', 'sep-rom'))
    machine += ',kaslr-off=true'
    args = [manifest['binary']['path'], '-M', machine, '-kernel', assets['kernel'],
            '-dtb', assets['dtb'], '-append',
            'tlto_us=-1 mtxspin=-1 agm-genuine=1 agm-authentic=1 agm-trusted=1 '
            'serial=3 launchd_unsecure_cache=1 wdt=-1 -vm_compressor_wk_sw',
            '-smp', '7', '-m', '4G', '-display', display, '-monitor', 'none',
            '-qmp', f'unix:{state / "qmp.sock"},server=on,wait=off',
            '-serial', f'file:{run_dir / "serial.log"}']
    for name in DISKS[-2:]:
        args += ['-drive', f'file={state / name},if=pflash,format=raw']
    for nsid, (name, nstype) in enumerate(zip(DISKS[:7], (1, 2, 3, 4, 5, 6, 8)), 1):
        dev = 'apple-nvram' if name == 'nvram' else 'nvme-ns'
        extra = ',id=nvram' if name == 'nvram' else ''
        fmt = 'qcow2' if name == 'root' else 'raw'
        args += ['-drive', f'file={state / name},if=none,format={fmt},id={name}',
                 '-device', f'{dev},drive={name},bus=nvme-bus.0,nsid={nsid},nstype={nstype}'
                 f'{extra},logical_block_size=4096,physical_block_size=4096']
    if vnc is not None:
        args += ['-L', str(checked_qemu_data(qemu_data)), '-vnc', vnc]
    return args


def run(state, seconds=900, display='none', vnc=None, qemu_data=None):
    vnc = checked_vnc(vnc)
    if qemu_data is not None and vnc is None:
        raise SessionError('The QEMU data directory option requires VNC')
    resources = None
    if vnc is not None:
        qemu_data = checked_qemu_data(qemu_data)
        resources = {'directory': str(qemu_data), 'keymap_en_us_sha256': sha256(qemu_data / 'keymaps/en-us')}
    state = checked_path(state)
    if not 30 <= seconds <= 3600 or len(os.fsencode(state / 'qmp.sock')) > 100:
        raise SessionError('Use a short state path and a 30–3600 second time bound')
    manifest = json.loads((state / 'manifest.json').read_text())
    if manifest.get('schema') != 1 or manifest.get('profile') != 'inferno-ios14-gui':
        raise SessionError('Unknown runtime manifest')
    for item in [manifest['binary'], *manifest['assets'].values()]:
        if sha256(item['path']) != item['sha256']:
            raise SessionError('Pinned executable/boot artifact changed')
    if file_identity(manifest['source_root']) != manifest['original_stores']['root']:
        raise SessionError('Original backing root changed; do not reuse this state generation')
    with (state / 'session.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SessionError('This state already has an active runner') from error
        validate_state(state, manifest)
        if file_identity(manifest['source_root']) != manifest['original_stores']['root'] or any(
                sha256(Path(manifest['bundle']) / name) != value
                for name, value in manifest['original_small_hashes'].items()):
            raise SessionError('Original stores changed; do not launch or recover this state')
        if shutil.disk_usage(state).free < 64 << 20:
            raise SessionError('Less than 64 MiB of working space remains; launch refused')
        socket_path = state / 'qmp.sock'
        recovery = recover_dead_session(state)
        run_dir = state / 'runs' / uuid.uuid4().hex
        run_dir.mkdir(parents=True)
        args = (argv_for(state, manifest, display, run_dir) if vnc is None
                else argv_for(state, manifest, display, run_dir, vnc, qemu_data))
        write_json(run_dir / 'argv.json', args)
        started = time.monotonic()
        record = {'run_id': run_dir.name, 'start_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  'seconds_limit': seconds, 'vnc_endpoint': vnc, 'vnc_resources': resources,
                  'stale_session_recovery': recovery,
                  'ipa_result': 'not attempted', 'gui_result': 'requires visual/semantic evidence'}
        with RunSignals() as interruptions, (run_dir / 'emulator.log').open('wb') as output:
            process = subprocess.Popen(args, cwd=manifest['bundle'], stdout=output, stderr=subprocess.STDOUT)
            try:
                write_json(state / 'live.json', {'pid': process.pid, 'run': str(run_dir), 'qmp': str(socket_path)})
                print(json.dumps({'pid': process.pid, 'run': str(run_dir), 'qmp': str(socket_path)}), flush=True)
                while process.poll() is None:
                    if interruptions.received is not None:
                        interruptions.annotate(record)
                        break
                    if time.monotonic() - started >= seconds:
                        record['stop_reason'] = 'time limit'
                        break
                    if shutil.disk_usage(state).free < 64 << 20:
                        record['stop_reason'] = 'disk space limit'
                        break
                    if any(p.stat().st_size > 24 << 20 for p in run_dir.glob('*.log')):
                        record['stop_reason'] = 'log size limit'
                        break
                    time.sleep(1)
                if process.poll() is not None and 'stop_reason' not in record:
                    marker = state / 'stop-request.json'
                    requested = json.loads(marker.read_text()) if marker.exists() else {}
                    record['stop_reason'] = ('explicit stop request'
                                             if requested.get('run_id') == run_dir.name
                                             else 'unexpected emulator exit')
            except BaseException:
                record['stop_reason'] = 'runner interrupted'
                raise
            finally:
                try:
                    if process.poll() is None:
                        try:
                            with QMP(socket_path) as qmp:
                                qmp.request('quit')
                        except (OSError, ValueError, SessionError) as error:
                            record['quit_error'] = str(error)
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait()
                    else:
                        process.wait()
                    record['exit_code'] = process.returncode
                    reason = record.get('stop_reason')
                    record['status'] = ('unexpected-exit' if reason == 'unexpected emulator exit'
                                        else 'runner-error' if reason == 'runner interrupted' else 'stopped')
                    interruptions.annotate(record)
                    record['elapsed_seconds'] = round(time.monotonic() - started, 2)
                    record['original_root_metadata_unchanged'] = file_identity(manifest['source_root']) == manifest['original_stores']['root']
                    record['original_small_hashes_unchanged'] = all(
                        sha256(Path(manifest['bundle']) / name) == value
                        for name, value in manifest['original_small_hashes'].items())
                    write_json(run_dir / 'result.json', record)
                    print(json.dumps(record), flush=True)
                finally:
                    try:
                        (state / 'live.json').unlink(missing_ok=True)
                    finally:
                        # Only this runner's stopped QMP endpoint is removed.
                        socket_path.unlink(missing_ok=True)
        return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--bundle', type=Path, required=True)
    prep.add_argument('--state', type=Path, required=True)
    prep.add_argument('--binary', type=Path)
    launch = sub.add_parser('run')
    launch.add_argument('--state', type=Path, required=True)
    launch.add_argument('--seconds', type=int, default=900)
    launch.add_argument('--display', choices=('none', 'gtk,zoom-to-fit=on,show-cursor=on'), default='none')
    launch.add_argument('--vnc', help='local VNC endpoint 127.0.0.1:DISPLAY (0–99); TCP port is 5900 + DISPLAY')
    launch.add_argument('--qemu-data', type=Path, help='QEMU data directory for VNC keymaps; defaults to integration pc-bios')
    ctl = sub.add_parser('control')
    ctl.add_argument('--state', type=Path, required=True)
    ctl.add_argument('action', choices=('status', 'side', 'home', 'screenshot', 'tap', 'swipe', 'quit'))
    ctl.add_argument('--output', type=Path)
    ctl.add_argument('--width', type=int, default=828)
    ctl.add_argument('--height', type=int, default=1792)
    ctl.add_argument('--x', type=int)
    ctl.add_argument('--y', type=int)
    ctl.add_argument('--to-x', type=int)
    ctl.add_argument('--to-y', type=int)
    ctl.add_argument('--duration', type=float, default=0.2)
    args = parser.parse_args()
    try:
        if args.command == 'prepare':
            result = prepare(args.bundle, args.state, args.binary)
            print(json.dumps({'profile': result['profile'], 'state': str(args.state.resolve())}))
        elif args.command == 'run':
            result = run(args.state, args.seconds, args.display, args.vnc, args.qemu_data)
            if result['status'] == 'interrupted':
                parser.exit(128 + result['interruption_signal_number'],
                            f'Runner interrupted by {result["interruption_signal"]}; guest reaped.\n')
            if result['exit_code'] != 0 or result['status'] == 'unexpected-exit':
                raise SessionError(f'Emulator exited unexpectedly: {result["exit_code"]}')
        else:
            with QMP(args.state.resolve() / 'qmp.sock') as qmp:
                if args.action == 'status':
                    result = qmp.request('query-status')
                elif args.action in ('side', 'home'):
                    key = 'f5' if args.action == 'side' else 'f6'
                    result = qmp.request('human-monitor-command', {'command-line': f'sendkey {key}'})
                elif args.action == 'screenshot':
                    if args.output is None:
                        raise SessionError('Screenshot needs --output')
                    output = args.output.resolve()
                    if output.exists():
                        raise SessionError('Screenshot destination must be new')
                    result = qmp.request('screendump', {'filename': str(output)})
                elif args.action in ('tap', 'swipe'):
                    end = (args.to_x, args.to_y) if args.action == 'swipe' else (args.x, args.y)
                    gesture(qmp, (args.x, args.y), end, args.width, args.height, args.duration)
                    result = {'sent': args.action, 'gui_effect': 'requires semantic verification'}
                else:
                    state = args.state.resolve()
                    live = json.loads((state / 'live.json').read_text())
                    write_json(state / 'stop-request.json', {'run_id': Path(live['run']).name})
                    result = qmp.request('quit')
                print(json.dumps(result))
    except (SessionError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Session error: {error}\n')


if __name__ == '__main__':
    main()
