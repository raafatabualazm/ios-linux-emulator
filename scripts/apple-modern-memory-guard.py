#!/usr/bin/env python3
"""Per-run guest lock/live memory guard with scoped descendant cleanup.

Track PID/starttime identities, including children that create new sessions.
A process-local Linux subreaper adopts those children if their parent exits.
No address-space cap; no discovery/termination by command name or global grep.
"""
import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import time

LOCK = '/tmp/claude-1000/-home-kali-Desktop-Inferno-and-Darwin-VM/8f2976bd-ed3f-4fa4-9688-9809d9a486be/scratchpad/qemu.lock'

def available():
    return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                    if line.startswith('MemAvailable:')))

def identity(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        return {'pid': pid, 'starttime': int(fields[19]),
                'parent': int(fields[1]), 'state': fields[0]}
    except (FileNotFoundError, ProcessLookupError):
        return None

def children(pid):
    try:
        return [int(value) for value in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
    except (FileNotFoundError, ProcessLookupError):
        return []

def matches(record):
    current = identity(record['pid'])
    return current if current and current['starttime'] == record['starttime'] else None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--max-seconds', type=float, default=150)
    parser.add_argument('--lock', type=Path, default=Path(LOCK))
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    assert args.command and args.command[0] == '--' and args.command[1:]
    assert args.max_seconds > 0 and not args.report.exists()
    command = args.command[1:]
    # Scoped only to this guard; adopted descendants remain attributable to the
    # one process tree this guard launches. No other subprocess is created here.
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(36, 1, 0, 0, 0) == 0, 'Cannot become child subreaper'
    with args.lock.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        start_available = available()
        assert start_available >= 7000000
        minimum = start_available
        started = time.monotonic()
        process = subprocess.Popen(command, start_new_session=True)
        root = identity(process.pid)
        assert root is not None
        tracked = {root['pid']: root}
        reason = 'completed'
        signaled = []
        reaped = []

        def discover():
            # Direct adopted children are also owned: this guard creates only
            # the one root child and otherwise gains children via subreaping.
            todo = [process.pid, *children(os.getpid())]
            seen = set()
            while todo:
                pid = todo.pop()
                if pid in seen:
                    continue
                seen.add(pid)
                current = identity(pid)
                previous = tracked.get(pid)
                if not current or (previous and previous['starttime'] != current['starttime']):
                    continue
                tracked.setdefault(pid, current)
                todo.extend(children(pid))

        def live_descendants():
            return [record for pid, record in tracked.items()
                    if pid != process.pid and (current := matches(record))
                    and current['state'] != 'Z']

        def send(record, sig):
            if matches(record):
                try:
                    os.kill(record['pid'], sig)
                    signaled.append({'pid': record['pid'], 'starttime': record['starttime'],
                                     'signal': int(sig)})
                except ProcessLookupError:
                    pass

        def reap():
            # Only tracked descendants; subprocess owns/reaps the root PID.
            for pid, record in tracked.items():
                if pid == process.pid or not matches(record):
                    continue
                try:
                    waited, _ = os.waitpid(pid, os.WNOHANG)
                    if waited:
                        reaped.append(pid)
                except ChildProcessError:
                    pass

        try:
            while process.poll() is None:
                discover()
                current = available()
                minimum = min(minimum, current)
                if current < 900000:
                    reason = 'memory-floor'
                    break
                if time.monotonic() - started > args.max_seconds:
                    reason = 'timeout'
                    break
                time.sleep(.1)
            discover()
            if reason == 'completed' and live_descendants():
                reason = 'descendants-left'
        except BaseException:
            reason = 'guard-interrupted'
            raise
        finally:
            # Discover while root still lives, then terminate descendants before
            # its group. Detached/new-session children receive explicit signals.
            discover()
            remaining = live_descendants()
            if reason != 'completed' or remaining:
                for record in reversed(remaining):
                    send(record, signal.SIGTERM)
                if matches(root) and process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    process.poll()
                    discover()
                    reap()
                    if process.poll() is not None and not live_descendants():
                        break
                    time.sleep(.05)
                for record in live_descendants():
                    send(record, signal.SIGKILL)
                if matches(root) and process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                discover()
                reap()
                survivors = [record for pid, record in tracked.items()
                             if pid != process.pid and matches(record)]
                if not survivors:
                    break
                time.sleep(.05)
            report = {'command': command, 'exit': process.returncode, 'reason': reason,
                      'mem_available_start_kb': start_available,
                      'mem_available_min_kb': minimum,
                      'seconds': time.monotonic() - started,
                      'tracked': list(tracked.values()), 'signaled': signaled,
                      'adopted_reaped': reaped, 'survivors': survivors,
                      'cleanup_verified': not survivors}
            args.report.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps({key: report[key] for key in
                             ['exit', 'reason', 'seconds', 'cleanup_verified']}))
            if survivors:
                raise RuntimeError('Owned descendants did not disappear/reap')
        return process.returncode if reason == 'completed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
