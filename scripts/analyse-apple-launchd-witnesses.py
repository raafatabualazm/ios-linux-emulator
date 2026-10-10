#!/usr/bin/env python3
"""Read launchd witnesses without promoting a proxy PID or failed INIT to running."""
import argparse
import hashlib
import json
import pathlib
import re

LINE = re.compile(r'com\.apple\.xpc\.launchd\|(?P<time>\S+ \S+) '
                  r'\((?P<domain>(?:system|user/\d+)/)?(?P<label>[\w.-]+)'
                  r'(?: \[(?P<pid>\d+)\])?\) <[^>]+>: (?P<message>.*)')
SPAWN = re.compile(r'(xpcproxy|launchd\(proxyless\)) spawned with pid (\d+)')
EVENT = re.compile(r'internal event: ([A-Z_]+), code = (-?\d+)')


def read(path):
    jobs, boot_args, launchd_lines, panics = {}, [], 0, 0
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for raw in f:
            digest.update(raw)
            line = raw.decode('utf-8', 'replace').replace('\r', '').rstrip('\n')
            panics += 'panic(' in line
            if 'boot-args = ' in line:
                boot_args.append(line.split('boot-args = ', 1)[1])
            match = LINE.search(line)
            if not match:
                continue
            launchd_lines += 1
            label, message, time = match['label'], match['message'], match['time']
            job = jobs.setdefault(label, dict(first_guest_time=time, last_guest_time=time,
                states=[], events=[], spawns=[], elision_disabled_by_boot_arg=False,
                elide_intent=False, running_witnesses=[], init_witnesses=[], diagnostics=[]))
            job['last_guest_time'] = time
            job['elision_disabled_by_boot_arg'] |= 'elision was disabled by boot-arg' in message
            job['elide_intent'] |= 'service will attempt to elide xpcproxy' in message
            pid = int(match['pid']) if match['pid'] else None
            if message.startswith('service state: '):
                state = message.split(': ', 1)[1]
                if state not in job['states']:
                    job['states'].append(state)
                if state == 'running':
                    job['running_witnesses'].append(dict(time=time, pid=pid, message=message))
            spawn = SPAWN.search(message)
            if spawn:
                job['spawns'].append(dict(time=time, proxy=spawn[1], pid=int(spawn[2])))
            event = EVENT.search(message)
            if event:
                row = dict(time=time, pid=pid, event=event[1], code=int(event[2]))
                job['events'].append(row)
                if event[1] == 'INIT':
                    job['init_witnesses'].append(row)
            if any(word in message for word in ('failed', 'Failed', 'error =', 'could not initialize',
                                                'tried to claim home screen', 'exited due to')):
                if len(job['diagnostics']) < 20:
                    job['diagnostics'].append(dict(time=time, pid=pid, message=message))
    return dict(log=str(path), sha256=digest.hexdigest(), launchd_lines=launchd_lines,
                panics=panics, boot_args=boot_args, jobs=jobs,
                proxy_pid_is_not_execution=True, absent_witness_is_not_failure=True,
                unique_running_jobs=sum(bool(j['running_witnesses']) for j in jobs.values()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=pathlib.Path)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = read(args.log)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    for label in ('com.apple.SpringBoard', 'com.apple.backboardd', 'com.apple.logd'):
        print(label, json.dumps(result['jobs'].get(label, {'seen': False})))
    print(json.dumps({key: value for key, value in result.items() if key != 'jobs'}))
