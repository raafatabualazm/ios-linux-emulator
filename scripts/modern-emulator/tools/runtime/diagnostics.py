#!/usr/bin/env python3
"""Bounded private GUI/control evidence and guest-exit diagnostics."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import time

spec = importlib.util.spec_from_file_location('_diagnostic_session', Path(__file__).with_name('session.py'))
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)

MIB = 1 << 20
MAX_LOG = 4 * MIB
MAX_SCREEN = 8 * MIB
MAX_SCREEN_TOTAL = 64 * MIB
MAX_EVENTS = 256
MAX_EVENT_LOG = 256 * 1024


class DiagnosticError(Exception):
    pass


def load_json(path, limit=65536):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise DiagnosticError('JSON evidence exceeds size bound')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise DiagnosticError('Expected a JSON object')
    return value


def write_new(path, value):
    raw = (json.dumps(value, indent=2) + '\n').encode()
    if len(raw) > MAX_EVENT_LOG:
        raise DiagnosticError('Evidence report exceeds bound')
    with Path(path).open('xb') as stream:
        stream.write(raw)


def originals(state):
    manifest = load_json(Path(state) / 'manifest.json')
    bundle = Path(manifest['bundle'])
    metadata = {name: session.file_identity(bundle / name) for name in session.DISKS}
    hashes = {name: session.sha256(bundle / name) for name in session.DISKS if name != 'root'}
    return {'root_metadata_matches': metadata['root'] == manifest['original_stores']['root'],
            'small_store_hashes_match': hashes == manifest['original_small_hashes'],
            'store_metadata': metadata, 'small_store_sha256': hashes,
            'root_hash_recomputed': False}


def recognized_fds(state):
    state = Path(state).resolve()
    manifest = load_json(state / 'manifest.json')
    live = load_json(state / 'live.json')
    pid = live['pid']
    if type(pid) is not int or pid <= 0:
        raise DiagnosticError('Invalid guest PID')
    known = {}
    for kind, base in [('original', Path(manifest['bundle'])), ('isolated', state)]:
        for name in session.DISKS:
            info = (base / name).stat()
            known[(info.st_dev, info.st_ino)] = (kind, name)
    rows = []
    for fd in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            info = fd.stat()
            item = known.get((info.st_dev, info.st_ino))
            if item is None:
                continue
            flags = next(int(x.split()[1], 8) for x in
                         (fd.parent.parent / 'fdinfo' / fd.name).read_text().splitlines()
                         if x.startswith('flags:'))
            rows.append({'fd': int(fd.name), 'kind': item[0], 'store': item[1],
                         'writable': (flags & os.O_ACCMODE) != os.O_RDONLY})
        except FileNotFoundError:
            continue
    original = [x for x in rows if x['kind'] == 'original']
    isolated = {x['store'] for x in rows if x['kind'] == 'isolated' and x['writable']}
    return {'pid': pid, 'stores': rows,
            'original_root_open_read_only': any(x['store'] == 'root' and not x['writable'] for x in original),
            'original_writers': [x for x in original if x['writable']],
            'all_isolated_stores_open_writable': isolated == set(session.DISKS)}


def png_dimensions(path):
    with Path(path).open('rb') as stream:
        header = stream.read(33)
    if len(header) != 33 or header[:8] != b'\x89PNG\r\n\x1a\n' or header[12:16] != b'IHDR':
        raise DiagnosticError('Expected a PNG screenshot')
    width, height = struct.unpack_from('>II', header, 16)
    if not 2 <= width <= 4096 or not 2 <= height <= 4096:
        raise DiagnosticError('Screenshot dimensions exceed bound')
    return width, height


class Recorder:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.context = load_json(self.directory / 'context.json')
        self.state = Path(self.context['state'])
        if session.sha256(self.state / 'manifest.json') != self.context['manifest_sha256']:
            raise DiagnosticError('State manifest changed after recorder initialization')

    @classmethod
    def create(cls, state, directory):
        state, directory = Path(state).resolve(), Path(directory)
        if directory.exists() or directory.is_symlink():
            raise DiagnosticError('Recorder directory must be new')
        manifest = load_json(state / 'manifest.json')
        live = load_json(state / 'live.json')
        directory.mkdir(parents=True, mode=0o700)
        write_new(directory / 'context.json', {'schema': 1, 'state': str(state),
                  'manifest_sha256': session.sha256(state / 'manifest.json'),
                  'binary': manifest['binary'], 'guest': manifest['guest'],
                  'run': live['run'], 'pid': live['pid'],
                  'display': {'width': 828, 'height': 1792},
                  'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})
        recorder = cls(directory)
        recorder.check_live()
        recorder.append({'kind': 'originals-before', 'verification': originals(state)})
        recorder.append({'kind': 'recognized-fds', 'verification': recognized_fds(state)})
        return recorder

    def check_live(self):
        """Bind live operations to the run recorded in this evidence directory."""
        live = load_json(self.state / 'live.json')
        pid = self.context.get('pid')
        if type(pid) is not int or pid <= 0 or live.get('pid') != pid or \
                live.get('run') != self.context.get('run'):
            raise DiagnosticError('Recorder belongs to a different or stale guest run')
        try:
            os.kill(pid, 0)
        except ProcessLookupError as error:
            raise DiagnosticError('Recorded guest process is no longer alive') from error

    def append(self, event):
        value = {'time_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **event}
        raw = (json.dumps(value, separators=(',', ':')) + '\n').encode()
        if len(raw) > 8192:
            raise DiagnosticError('Event exceeds size bound')
        path = self.directory / 'events.jsonl'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'r+b') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            previous = stream.read(MAX_EVENT_LOG + 1)
            if len(previous) + len(raw) > MAX_EVENT_LOG or previous.count(b'\n') >= MAX_EVENTS:
                raise DiagnosticError('Recorder event budget exhausted')
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return value

    def capture(self, label):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', label):
            raise DiagnosticError('Use a short lowercase screenshot label')
        screens = list(self.directory.glob('*.png'))
        if len(screens) >= 64 or sum(x.stat().st_size for x in screens) > MAX_SCREEN_TOTAL - MAX_SCREEN:
            raise DiagnosticError('Recorder screenshot budget exhausted')
        path = self.directory / f'{len(screens):03d}-{label}.png'
        if path.exists() or path.is_symlink():
            raise DiagnosticError('Screenshot destination already exists')
        self.check_live()
        try:
            with session.QMP(self.state / 'qmp.sock') as qmp:
                self.check_live()
                status = qmp.request('query-status')
                qmp.request('screendump', {'filename': str(path), 'format': 'png'})
            if path.stat().st_size > MAX_SCREEN:
                raise DiagnosticError('Screenshot exceeds size bound')
            size = png_dimensions(path)
            if size != (828, 1792):
                raise DiagnosticError(f'Expected 828x1792 screenshot, got {size}')
            return self.append({'kind': 'screen', 'label': label, 'path': str(path),
                               'sha256': session.sha256(path), 'bytes': path.stat().st_size,
                               'width': size[0], 'height': size[1], 'guest_status': status,
                               'semantic_result': 'requires visual observation'})
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def control(self, action, start=None, end=None, duration=0.2):
        if action not in ('home', 'side', 'tap', 'swipe'):
            raise DiagnosticError('Unsupported recorder control')
        if action in ('tap', 'swipe'):
            if not math.isfinite(duration) or not 0.02 <= duration <= 5:
                raise DiagnosticError('Gesture duration must be between 0.02 and 5 seconds')
            if not isinstance(start, (tuple, list)) or len(start) != 2:
                raise DiagnosticError('Control requires a start coordinate')
            end = start if action == 'tap' else end
            if not isinstance(end, (tuple, list)) or len(end) != 2:
                raise DiagnosticError('Swipe requires an end coordinate')
            session.pointer(*start, 828, 1792)
            session.pointer(*end, 828, 1792)
        else:
            start = end = duration = None
        self.check_live()
        # Persist intent before touching the guest, including at the event limit.
        self.append({'kind': 'control-intent', 'action': action, 'start': start,
                     'end': end, 'duration': duration, 'semantic_result': 'input requested'})
        with session.QMP(self.state / 'qmp.sock') as qmp:
            self.check_live()
            if action in ('home', 'side'):
                qmp.request('human-monitor-command', {'command-line': 'sendkey ' + ('f6' if action == 'home' else 'f5')})
            else:
                session.gesture(qmp, start, end, 828, 1792, duration)
        return self.append({'kind': 'control', 'action': action, 'start': start, 'end': end,
                            'duration': duration, 'semantic_result': 'event sent only'})

    def observe(self, screen, description):
        if len(description) > 1000 or not description.strip():
            raise DiagnosticError('Observation must be 1–1000 characters')
        path = self.directory / screen
        if path.parent != self.directory or path.is_symlink() or not path.is_file() or path.suffix != '.png':
            raise DiagnosticError('Observation must refer to a recorder screenshot')
        return self.append({'kind': 'visual-observation', 'screen': screen,
                            'sha256': session.sha256(path), 'description': description})

    def snapshot(self):
        self.check_live()
        with session.QMP(self.state / 'qmp.sock') as qmp:
            self.check_live()
            status = qmp.request('query-status')
            network = qmp.request('human-monitor-command', {'command-line': 'info network'})
        if not isinstance(network, str) or len(network.encode()) > 4096:
            raise DiagnosticError('Network diagnostic exceeds text bound')
        return self.append({'kind': 'runtime-snapshot', 'guest_status': status,
                            'qemu_network_info': network,
                            'recognized_fds': recognized_fds(self.state),
                            'guest_connectivity_verified': False})


def classify(run):
    run = Path(run)
    result = load_json(run / 'result.json') if (run / 'result.json').is_file() else {}
    patterns = {'guest-sep-panic': re.compile(r'^panic\(cpu\b.*SEP Panic:', re.I),
                'guest-kernel-panic': re.compile(r'^panic\(cpu\b', re.I),
                'host-assertion': re.compile(r'(?:Assertion .* failed|Assertion failed|Segmentation fault)')}
    matches, scans, kinds = [], [], set()
    for name in ('serial.log', 'emulator.log'):
        path = run / name
        if not path.is_file():
            continue
        total = path.stat().st_size
        offset = max(0, total - MAX_LOG)
        with path.open('rb') as stream:
            stream.seek(offset)
            raw = stream.read(MAX_LOG + 1)
        if len(raw) > MAX_LOG:
            raise DiagnosticError('Log changed beyond classifier bound')
        scans.append({'path': str(path), 'total_bytes': total, 'offset': offset,
                      'scanned_bytes': len(raw), 'truncated': offset > 0})
        for line in raw.decode('utf-8', 'replace').splitlines():
            for kind, expression in patterns.items():
                if expression.search(line):
                    kinds.add(kind)
                    # Do not preserve key/ticket-bearing log lines as excerpts.
                    text = '[sensitive line omitted]' if re.search(r'keybag|ivkey|ticket|password', line, re.I) else line[:256]
                    if len(matches) < 32:
                        matches.append({'kind': kind, 'log': name, 'text': text})
                    break
    exit_code = result.get('exit_code')
    if 'guest-sep-panic' in kinds:
        outcome = 'guest-sep-panic'
    elif 'guest-kernel-panic' in kinds:
        outcome = 'guest-kernel-panic'
    elif 'host-assertion' in kinds:
        outcome = 'host-crash'
    elif result.get('status') == 'interrupted':
        outcome = 'runner-interrupted'
    elif type(exit_code) is int and exit_code < 0:
        outcome = 'host-crash'
    elif result.get('status') == 'unexpected-exit' or result.get('stop_reason') == 'unexpected emulator exit':
        outcome = 'unexpected-exit'
    elif result.get('status') == 'stopped':
        outcome = 'controlled-stop'
    else:
        outcome = 'undetermined'
    return {'schema': 1, 'run': str(run), 'classification': outcome,
            'exit_code': exit_code, 'stop_reason': result.get('stop_reason'),
            'positive_guest_success': False, 'observed_categories': sorted(kinds),
            'matches': matches, 'log_scans': scans,
            'method': 'bounded terminal-log patterns; no screen or app inference'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('init');create.add_argument('--state', required=True);create.add_argument('--evidence', required=True)
    capture = sub.add_parser('capture');capture.add_argument('--evidence', required=True);capture.add_argument('--label', required=True)
    control = sub.add_parser('control');control.add_argument('--evidence', required=True);control.add_argument('action', choices=('home','side','tap','swipe'))
    for name in ('x','y','to-x','to-y'):control.add_argument('--'+name, type=int)
    control.add_argument('--duration', type=float, default=0.2)
    observe = sub.add_parser('observe');observe.add_argument('--evidence', required=True);observe.add_argument('--screen', required=True);observe.add_argument('--description', required=True)
    snapshot = sub.add_parser('snapshot');snapshot.add_argument('--evidence', required=True)
    outcome = sub.add_parser('classify');outcome.add_argument('--run', required=True);outcome.add_argument('--output', required=True)
    check = sub.add_parser('originals');check.add_argument('--state', required=True);check.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'init':
            r = Recorder.create(args.state, args.evidence);value = {'evidence': str(r.directory)}
        elif args.command == 'capture':value = Recorder(args.evidence).capture(args.label)
        elif args.command == 'control':
            end = (args.to_x,args.to_y) if args.action == 'swipe' else None
            value = Recorder(args.evidence).control(args.action,(args.x,args.y),end,args.duration)
        elif args.command == 'observe':value = Recorder(args.evidence).observe(args.screen,args.description)
        elif args.command == 'snapshot':value = Recorder(args.evidence).snapshot()
        elif args.command == 'classify':value = classify(args.run);write_new(args.output,value)
        else:value = originals(args.state);write_new(args.output,value)
    except (DiagnosticError, session.SessionError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f'Diagnostic error: {error}\n')
    print(json.dumps(value))


if __name__ == '__main__':main()
