#!/usr/bin/env python3
"""Record when an observer first sees launchd milestones; never control the guest."""
import argparse
import datetime
import importlib.util
import json
import pathlib
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--pid', type=int, required=True)
p.add_argument('--log', type=pathlib.Path, required=True)
p.add_argument('--out', type=pathlib.Path, required=True)
p.add_argument('--reader', type=pathlib.Path,
               default=pathlib.Path(__file__).with_name('analyse-apple-launchd-witnesses.py'))
p.add_argument('--max-seconds', type=int, default=3600)
p.add_argument('--interval', type=int, default=30)
p.add_argument('--job', action='append', default=[], help='additional exact launchd label')
a = p.parse_args()
if a.pid <= 0 or a.max_seconds <= 0 or not 1 <= a.interval <= 60:
    p.error('positive pid/budget and interval 1..60 required')
log = a.log.resolve()
proc = pathlib.Path('/proc') / str(a.pid)
identity = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
argv = (proc / 'cmdline').read_bytes().split(b'\0')
if not argv or 'qemu-system' not in pathlib.Path(argv[0].decode()).name or \
        ('file:' + str(log)).encode() not in argv:
    raise SystemExit('PID must own the exact QEMU serial log')
a.out.mkdir(parents=True, exist_ok=False)
spec = importlib.util.spec_from_file_location('reader', a.reader)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
start, previous = time.monotonic(), None
selected = ('com.apple.codex.root-remount', 'com.apple.UserEventAgent-System',
            'com.apple.centaurid', 'com.apple.SpringBoard', 'com.apple.backboardd', 'com.apple.logd',
            'com.apple.runningboardd', 'com.apple.codex.spindump', 'com.apple.codex.stackshot') + tuple(a.job)

def alive():
    try:
        return (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] == identity
    except FileNotFoundError:
        return False

def save(name, value):
    temporary = a.out / (name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(a.out / name)

while True:
    live = alive()
    if log.exists():
        d = reader.read(log)
        summary = {'domain_milestones': d['domain_milestones'],
                   'unique_running_jobs': d['unique_running_jobs'],
                   'jobs': {n: d['jobs'][n] for n in selected if n in d['jobs']}}
        if summary != previous:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            summary.update(observed_utc=now, observed_elapsed_seconds=round(time.monotonic()-start, 1),
                           source_log_sha256=d['sha256'], qemu_pid=a.pid, process_still_present=live,
                           qualification='first observer receipt, not exact guest wall timestamp or UID proof')
            with (a.out / 'changes.jsonl').open('a') as f:
                f.write(json.dumps(summary) + '\n')
            save('latest.json', summary)
            save('witnesses.json', d)
            previous = {k: v for k, v in summary.items() if k in ('domain_milestones', 'unique_running_jobs', 'jobs')}
    if not live or time.monotonic()-start >= a.max_seconds:
        save('observer-result.json', {'qemu_pid': a.pid, 'elapsed_seconds': round(time.monotonic()-start,1),
              'stop': 'process-exited' if not live else 'observer-budget', 'guest_control_performed': False})
        break
    time.sleep(a.interval)
