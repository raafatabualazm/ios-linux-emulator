#!/usr/bin/env python3
"""Prepare and bound an isolated x86 USB companion; never restore/install apps."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import selectors
import shutil
import socket
import stat
import subprocess
import time
import uuid

_spec = importlib.util.spec_from_file_location(
    'companion_session_helpers', Path(__file__).with_name('session.py'))
session = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(session)
CompanionError = session.SessionError

RESOURCES = ('bios-256k.bin', 'kvmvapic.bin')
HARDWARE_PROFILES = {
    'isolated': RESOURCES,
    'historical': (*RESOURCES, 'vgabios-stdvga.bin', 'efi-virtio.rom'),
}
MAX_IMAGE_BYTES = 512 << 20
MAX_LOG_BYTES = 8 << 20
MIN_FREE_BYTES = 128 << 20
MIN_SECONDS = 30
MAX_SECONDS = 1800


def resources_for(profile):
    try:
        return HARDWARE_PROFILES[profile]
    except (KeyError, TypeError):
        raise CompanionError('Unknown companion hardware profile') from None


def private_directory(path):
    path = session.checked_path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise CompanionError('Companion state must be an owned private directory (0700)')
    return path


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CompanionError('Private companion files must be regular and unaliased')
    return session.file_identity(path)


def image_info(tool, path):
    result = subprocess.run([str(tool), 'info', '--output=json', str(path)],
                            check=True, capture_output=True, text=True, timeout=10)
    if len(result.stdout) > 65536:
        raise CompanionError('Image metadata exceeds its bound')
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise CompanionError('Invalid image metadata')
    size = value.get('virtual-size')
    if type(size) is not int or not 0 < size <= 1 << 40:
        raise CompanionError('Invalid companion virtual disk size')
    if value.get('format') not in ('raw', 'qcow2'):
        raise CompanionError('Companion backing must be raw or qcow2')
    def external(item):
        if isinstance(item, dict):
            return any((key in ('data-file', 'data_file', 'corrupt') and bool(v))
                       or external(v) for key, v in item.items())
        if isinstance(item, list):
            return any(external(v) for v in item)
        return False
    if external(value) or value.get('dirty-flag'):
        raise CompanionError('External data files, corruption and dirty images are refused')
    return value


def pin(path, digest=True):
    value = {'path': str(path), 'identity': session.file_identity(path)}
    if digest:
        value['sha256'] = session.sha256(path)
    return value


def copy_expected(source, destination, expected_size):
    with source.open('rb') as stream:
        data = stream.read(expected_size + 1)
    if len(data) != expected_size:
        raise CompanionError('A companion source size changed during copying')
    with destination.open('xb') as stream:
        stream.write(data)


def verify_pins(manifest):
    for value in manifest['originals'].values():
        path = Path(value['path'])
        if session.file_identity(path) != value['identity']:
            raise CompanionError('An original companion asset changed')
        if 'sha256' in value and session.sha256(path) != value['sha256']:
            raise CompanionError('An original companion asset hash changed')


def prepare(disk, seed, binary, qemu_data, state, qemu_img='/usr/bin/qemu-img',
            hardware_profile='isolated'):
    resources = resources_for(hardware_profile)
    disk, seed, binary, qemu_data, state, qemu_img = map(
        session.checked_path, (disk, seed, binary, qemu_data, state, qemu_img))
    if state.exists() or state.is_symlink():
        raise CompanionError('Companion destination must be new')
    if not os.access(binary, os.X_OK) or not os.access(qemu_img, os.X_OK):
        raise CompanionError('QEMU and qemu-img must be executable')
    assets = {'disk': disk, 'seed': seed, 'binary': binary, 'qemu_img': qemu_img,
              **{name: qemu_data / name for name in resources}}
    session.reject_open_writers(list(assets.values()))
    originals = {role: pin(path, role != 'disk') for role, path in assets.items()}
    info = image_info(qemu_img, disk)
    if info.get('backing-filename') or info.get('full-backing-filename'):
        raise CompanionError('The original companion must have no backing chain')
    if originals['seed']['identity']['size'] > 4 << 20:
        raise CompanionError('Cloud seed exceeds 4 MiB')
    if any(originals[name]['identity']['size'] > 1 << 20 for name in resources):
        raise CompanionError('BIOS resource exceeds 1 MiB')
    if shutil.disk_usage(state.parent).free < MIN_FREE_BYTES:
        raise CompanionError('Insufficient free space for companion preparation')
    state.mkdir(mode=0o700)
    try:
        subprocess.run([str(qemu_img), 'create', '-q', '-f', 'qcow2', '-F',
                        info['format'], '-b', str(disk), str(state / 'disk.qcow2')],
                       check=True, capture_output=True, timeout=10)
        copy_expected(seed, state / 'seed.iso', originals['seed']['identity']['size'])
        (state / 'resources').mkdir(mode=0o700)
        for name in resources:
            copy_expected(qemu_data / name, state / 'resources' / name,
                          originals[name]['identity']['size'])
        private = {'seed.iso': session.sha256(state / 'seed.iso'),
                   **{f'resources/{name}': session.sha256(state / 'resources' / name)
                      for name in resources}}
        manifest = {'schema': 1, 'state': str(state), 'originals': originals,
                    'hardware_profile': hardware_profile,
                    'backing_format': info['format'], 'virtual_size': info['virtual-size'],
                    'private_hashes': private, 'disk_preservation': 'metadata; no new full disk hash',
                    'network': 'restrict=on; optional loopback-only SSH forward',
                    'credentials_recorded': False}
        verify_pins(manifest)
        session.write_json(state / 'manifest.json', manifest)
        (state / 'runs').mkdir(mode=0o700)
        return manifest
    except BaseException:
        # This path was created by this invocation and contains only generated files.
        shutil.rmtree(state)
        raise


def load(state):
    state = private_directory(state)
    regular(state / 'manifest.json')
    with (state / 'manifest.json').open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise CompanionError('Companion manifest exceeds its bound')
    manifest = json.loads(raw)
    if manifest.get('schema') != 1 or manifest.get('state') != str(state):
        raise CompanionError('Companion manifest does not match this state')
    resources = resources_for(manifest.get('hardware_profile', 'isolated'))
    if set(manifest['originals']) != {'disk', 'seed', 'binary', 'qemu_img', *resources}:
        raise CompanionError('Unexpected original companion resource set')
    if set(manifest['private_hashes']) != {'seed.iso', *('resources/' + n for n in resources)}:
        raise CompanionError('Unexpected private companion resource set')
    verify_pins(manifest)
    for relative, digest in manifest['private_hashes'].items():
        path = state / relative
        regular(path)
        if session.sha256(path) != digest:
            raise CompanionError('A private companion resource changed')
    overlay = state / 'disk.qcow2'
    identity = regular(overlay)
    originals = [Path(v['path']) for v in manifest['originals'].values()]
    if any((identity['device'], identity['inode']) ==
           (p.stat().st_dev, p.stat().st_ino) for p in originals):
        raise CompanionError('Companion overlay aliases an original')
    info = image_info(Path(manifest['originals']['qemu_img']['path']), overlay)
    backing = info.get('full-backing-filename', info.get('backing-filename'))
    if (info['format'] != 'qcow2' or info['virtual-size'] != manifest['virtual_size'] or
            backing != manifest['originals']['disk']['path'] or
            info.get('backing-filename-format') != manifest['backing_format']):
        raise CompanionError('Companion overlay backing was substituted')
    session.reject_open_writers([*originals, overlay, state / 'seed.iso'])
    return state, manifest


def argv_for(state, manifest, usb, run_dir, ssh_port=32222):
    if type(ssh_port) is not int or not 0 <= ssh_port <= 65535:
        raise CompanionError('SSH port must be 0 (disabled) or 1..65535')
    network = 'user,id=isolated,restrict=on'
    if ssh_port:
        network += f',hostfwd=tcp:127.0.0.1:{ssh_port}-:22'
    profile = manifest.get('hardware_profile', 'isolated')
    resources_for(profile)
    historical = profile == 'historical'
    # run-companion.sh's q35 defaults are qemu64 and standard VGA in this
    # source generation. Retain its integrated USB and four-core/3G profile
    # as an explicit comparison; default isolated states keep their old argv.
    hardware = (['-usb'] if historical else ['-nodefaults'])
    drive = f'file={state / "disk.qcow2"},if=virtio,format=qcow2'
    if historical:
        drive += ',cache=unsafe'
    nic = 'virtio-net-pci,netdev=isolated' + ('' if historical else ',romfile=')
    return [manifest['originals']['binary']['path'], '-L', str(state / 'resources'),
            '-M', 'q35', '-m', '3G' if historical else '2G', '-smp', '4' if historical else '2',
            '-accel', 'tcg,thread=multi', '-cpu', 'qemu64' if historical else 'max',
            *hardware, '-display', 'none', '-monitor', 'none',
            '-serial', 'stdio', '-qmp', f'unix:{state / "qmp.sock"},server=on,wait=off',
            '-drive', drive,
            '-drive', f'file={state / "seed.iso"},if=virtio,format=raw,readonly=on',
            '-netdev', network, '-device', nic,
            '-device', 'usb-ehci,id=ehci', '-device',
            f'usb-tcp-remote,bus=ehci.0,conn-type=unix,conn-addr={usb}']


def limit_child():
    # Caps each writable regular file (the only guest disk is the overlay).
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_IMAGE_BYTES, MAX_IMAGE_BYTES))
    os.umask(0o077)


class CleanupQMP(session.QMP):
    """One deadline covers greeting, capabilities, event frames and quit."""
    def __init__(self, path):
        self.deadline = time.monotonic() + 2
        super().__init__(path, timeout=2)

    def read(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Companion QMP cleanup deadline reached')
        self.socket.settimeout(remaining)
        return super().read()


def drain_output(outputs, budget):
    """Reaped child pipes only; bounded nonblocking reads retain final errors."""
    total = 0
    for stream, output in outputs.items():
        for _ in range(130):
            try:
                chunk = os.read(stream.fileno(), min(65536, budget - total + 1))
            except BlockingIOError:
                break
            if not chunk:
                break
            remaining = budget - total
            output.write(chunk[:remaining])
            total += min(len(chunk), remaining)
            if len(chunk) > remaining:
                return total, True
    return total, False


def run(state, usb, seconds=600, ssh_port=32222):
    if not math.isfinite(seconds) or not MIN_SECONDS <= seconds <= MAX_SECONDS:
        raise CompanionError('Companion duration must be 30..1800 seconds')
    state = private_directory(state)
    lock_path = state / '.lock'
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state, manifest = load(state)
        for name in ('live.json', 'qmp.sock'):
            if (state / name).exists() or (state / name).is_symlink():
                raise CompanionError('Companion live marker/endpoint exists; inspect before reuse')
        usb = session.checked_path(usb)
        if usb.name != 'usb.sock':
            raise CompanionError('Use the exact phone USB waiting-state endpoint')
        endpoint = session.USBEndpoint(usb.parent)
        if shutil.disk_usage(state).free < MIN_FREE_BYTES:
            raise CompanionError('Insufficient free space to start the companion')
        if (state / 'disk.qcow2').stat().st_size >= MAX_IMAGE_BYTES:
            raise CompanionError('Companion overlay already meets the disk limit')
        run_dir = state / 'runs' / uuid.uuid4().hex
        run_dir.mkdir(mode=0o700)
        command = argv_for(state, manifest, usb, run_dir, ssh_port)
        record = {'command': command, 'run': str(run_dir), 'seconds_limit': seconds,
                  'hardware_profile': manifest.get('hardware_profile', 'isolated'),
                  'usb_endpoint': str(usb), 'ssh_loopback_port': ssh_port,
                  'usb_listener_ready': False, 'usb_enumerated': False,
                  'installed_apps': False, 'status': 'starting',
                  'max_image_bytes': MAX_IMAGE_BYTES, 'max_log_bytes': MAX_LOG_BYTES}
        session.write_json(run_dir / 'start.json', record)
        process = None
        qmp_identity = None
        selector = selectors.DefaultSelector()
        log_stack = contextlib.ExitStack()
        outputs = {}
        started = time.monotonic()
        total_log = 0
        try:
            with session.RunSignals() as interruptions:
                try:
                    console = log_stack.enter_context((run_dir / 'console.log').open('xb'))
                    errors = log_stack.enter_context((run_dir / 'stderr.log').open('xb'))
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               preexec_fn=limit_child)
                    record['pid'] = process.pid
                    session.write_json(state / 'live.json', {'pid': process.pid, 'run': str(run_dir)})
                    for stream, output in ((process.stdout, console), (process.stderr, errors)):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, output)
                        outputs[stream] = output
                    while process.poll() is None:
                        if interruptions.received is not None:
                            record['stop_reason'] = 'runner interrupted'
                            break
                        if time.monotonic() - started >= seconds:
                            record['stop_reason'] = 'time limit'
                            break
                        if shutil.disk_usage(state).free < MIN_FREE_BYTES:
                            record['stop_reason'] = 'free-space limit'
                            break
                        if (state / 'disk.qcow2').stat().st_size >= MAX_IMAGE_BYTES:
                            record['stop_reason'] = 'overlay size limit'
                            break
                        qmp = state / 'qmp.sock'
                        if qmp_identity is None and qmp.exists():
                            qi = qmp.lstat()
                            if not stat.S_ISSOCK(qi.st_mode) or qi.st_uid != os.getuid():
                                raise CompanionError('Companion QMP endpoint is not an owned socket')
                            qmp_identity = (qi.st_dev, qi.st_ino)
                        if not record['usb_listener_ready'] and endpoint._capture():
                            entries = endpoint._entries()
                            # The phone may connect before this runner's first
                            # poll. Linux then lists the listener and its
                            # accepted stream with the same pathname. Preserve
                            # the one-listener check without mistaking that
                            # ordinary accepted stream for startup failure.
                            listeners = [item for item in entries if item[0] & 0x10000]
                            if (len(listeners) == 1 and
                                    all(item[1] == socket.SOCK_STREAM for item in entries)):
                                endpoint._capture()
                                record['usb_listener_ready'] = True
                                session.write_json(run_dir / 'usb-ready.json',
                                                   {'pid': process.pid, 'endpoint': str(usb),
                                                    'identity': endpoint.identity,
                                                    'enumeration_proven': False})
                        if not record['usb_listener_ready'] and time.monotonic() - started > 10:
                            record['stop_reason'] = 'USB listener startup timeout'
                            break
                        for key, _ in selector.select(timeout=0.05):
                            chunk = os.read(key.fd, min(65536, MAX_LOG_BYTES - total_log + 1))
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            remaining = MAX_LOG_BYTES - total_log
                            key.data.write(chunk[:remaining])
                            total_log += min(len(chunk), remaining)
                            if len(chunk) > remaining:
                                record['stop_reason'] = 'log size limit'
                                break
                        if record.get('stop_reason') == 'log size limit':
                            break
                except BaseException as error:
                    record.update(status='error', error=type(error).__name__)
                    raise
                finally:
                    if process is not None:
                        # An interruption can occur between child startup and
                        # the first polling iteration. Capture any observed
                        # endpoints before stopping the child, retaining the
                        # same identity checks used during ordinary polling.
                        try:
                            endpoint._capture()
                        except (CompanionError, OSError):
                            record['usb_capture_error'] = True
                        if qmp_identity is None:
                            try:
                                qi = (state / 'qmp.sock').lstat()
                                if stat.S_ISSOCK(qi.st_mode) and qi.st_uid == os.getuid():
                                    qmp_identity = (qi.st_dev, qi.st_ino)
                            except OSError:
                                record['qmp_capture_error'] = True
                        if process.poll() is None:
                            try:
                                with CleanupQMP(state / 'qmp.sock') as qmp:
                                    qmp.request('quit')
                                process.wait(timeout=3)
                            except Exception:
                                if process.poll() is None:
                                    process.terminate()
                                try:
                                    process.wait(timeout=3)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    process.wait(timeout=3)
                        else:
                            process.wait()
                        record['exit_code'] = process.returncode
                        try:
                            added, truncated = drain_output(outputs, MAX_LOG_BYTES - total_log)
                            total_log += added
                            if truncated:
                                record['stop_reason'] = 'log size limit'
                        except OSError:
                            record.update(status='error', log_drain_error=True)
                        finally:
                            for stream in (process.stdout, process.stderr):
                                stream.close()
                    try:
                        log_stack.close()
                    except OSError:
                        record.update(status='error', log_flush_error=True)
                    selector.close()
                    record.update(elapsed_seconds=round(time.monotonic() - started, 3),
                                  log_bytes=total_log)
                    if process is not None and record['status'] != 'error':
                        record['status'] = 'stopped' if record.get('stop_reason') and process.returncode == 0 else 'unexpected-exit'
                    interruptions.annotate(record)
                    try:
                        verify_pins(manifest)
                        record['originals_unchanged'] = True
                    except Exception:
                        record['originals_unchanged'] = False
                        record['status'] = 'error'
                    if process is None or process.poll() is not None:
                        try:
                            record['usb_cleanup'] = endpoint.cleanup(child_reaped=True)
                        except (CompanionError, OSError):
                            record.update(status='error', usb_cleanup='metadata unavailable; preserved')
                        if qmp_identity is not None:
                            try:
                                qi = (state / 'qmp.sock').lstat()
                                if stat.S_ISSOCK(qi.st_mode) and (qi.st_dev, qi.st_ino) == qmp_identity:
                                    (state / 'qmp.sock').unlink()
                                    record['qmp_cleanup'] = 'removed captured socket'
                            except FileNotFoundError:
                                # Real QEMU removes its own Unix listener on
                                # clean exit. The reaped child and absent path
                                # already satisfy this cleanup step.
                                record['qmp_cleanup'] = 'already absent'
                            except OSError:
                                record.update(status='error', qmp_cleanup='metadata unavailable; preserved')
                        (state / 'live.json').unlink(missing_ok=True)
                    session.write_json(run_dir / 'result.json', record)
        finally:
            selector.close()
            log_stack.close()
        return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    prep = modes.add_parser('prepare')
    for name in ('disk', 'seed', 'binary', 'qemu-data', 'state'):
        prep.add_argument('--' + name, required=True, type=Path)
    prep.add_argument('--qemu-img', type=Path, default=Path('/usr/bin/qemu-img'))
    prep.add_argument('--hardware-profile', choices=tuple(HARDWARE_PROFILES),
                      default='isolated', help='pin hardware/resources; historical matches the retained local launcher')
    runner = modes.add_parser('run')
    runner.add_argument('--state', required=True, type=Path)
    runner.add_argument('--usb-socket', required=True, type=Path)
    runner.add_argument('--seconds', type=float, default=600)
    runner.add_argument('--ssh-port', type=int, default=32222)
    args = parser.parse_args()
    try:
        if args.mode == 'prepare':
            result = prepare(args.disk, args.seed, args.binary, args.qemu_data, args.state,
                             args.qemu_img, args.hardware_profile)
            print(json.dumps({'prepared': result['state'], 'backing_format': result['backing_format']}))
            return 0
        result = run(args.state, args.usb_socket, args.seconds, args.ssh_port)
        print(json.dumps({key: result.get(key) for key in
                          ('run', 'status', 'stop_reason', 'exit_code', 'usb_listener_ready', 'originals_unchanged')}))
        if result.get('interruption_signal_number'):
            return 128 + result['interruption_signal_number']
        return 0 if result['status'] == 'stopped' and result.get('originals_unchanged') else 1
    except (CompanionError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Companion refused: {type(error).__name__}: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
