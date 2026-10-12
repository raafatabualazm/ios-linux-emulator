#!/usr/bin/env python3
"""Retain bounded console marker receipts for an already qualified owned run.

Markers are candidates for human review, not proof that sampling succeeded.
This observer has no QMP connection and never signals the guest.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import time


ERRORS = (
    b"Stackshot failed:", b"Failed to start sampling",
    b"Unable to create SPSampledProcess", b"No target process to monitor for exiting",
    b"bad stackshot data length", b"ERROR trying to create sample store",
    b"spindump-stuck:",
)
SAMPLING = (
    b"Sampling completed, generating report...", b"Started sampling with ",
    b"Created shared SPStackshotProvider",
    b"Sampling all processes for ",
)
HEADERS = (b"Date/Time:", b"Report Version:", b"Process:", b"Command:", b"Duration:", b"Steps:")


def identity(pid):
    p = Path('/proc') / str(pid)
    stat = (p / 'stat').read_text()
    tail = stat[stat.rfind(')') + 2:].split()
    if tail[0] == 'Z' or p.stat().st_uid != os.getuid():
        raise ValueError('not a live same-owner process')
    return tail[19], (p / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')


def marker(line):
    for group, strings in (('error_candidate', ERRORS), ('sampling_candidate', SAMPLING)):
        for value in strings:
            if value in line:
                return group, value.decode()
    # Only standalone console headers, not quoted launchd messages or usage text.
    clean = line.strip()
    for value in HEADERS:
        if clean.startswith(value):
            return 'report_header_candidate', value.decode()
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binding', required=True, type=Path)
    ap.add_argument('--serial', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--seconds', type=int, default=4200)
    args = ap.parse_args()
    if not 1 <= args.seconds <= 14400:
        ap.error('seconds must be 1..14400')
    bound = json.loads(args.binding.read_text())
    pid = bound['pid']
    birth, argv = identity(pid)
    expected_serial = ('file:' + str(args.serial.resolve())).encode()
    actual_serial = [argv[i + 1] for i, value in enumerate(argv[:-1]) if value == b'-serial']
    if birth != bound['start_ticks'] or actual_serial != [expected_serial]:
        raise ValueError('binding birth or exact serial argv differs')
    args.out.mkdir(exist_ok=False)
    started = time.monotonic()
    offset = 0
    pending = b''
    previous = []
    receipts = []
    reason = 'budget-expired'
    with (args.out / 'candidates.jsonl').open('w') as output:
        while time.monotonic() - started < args.seconds:
            exited = False
            try:
                current_birth, _ = identity(pid)
                if current_birth != birth:
                    reason = 'birth-changed'
                    break
            except (FileNotFoundError, ProcessLookupError, ValueError):
                reason = 'process-exited'
                exited = True
            with args.serial.open('rb') as source:
                if source.seek(0, 2) > 64 * 1024 * 1024:
                    raise ValueError('serial exceeds 64 MiB analysis budget')
                source.seek(offset + len(pending))
                chunk = source.read()
            data = pending + chunk
            lines = data.splitlines(keepends=True)
            pending = b''
            if lines and not lines[-1].endswith((b'\r', b'\n')):
                pending = lines.pop()
            for line in lines:
                found = marker(line)
                if found:
                    if len(receipts) >= 512:
                        raise ValueError('console marker budget exhausted')
                    item = {
                        'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'observed_elapsed_seconds': round(time.monotonic() - started, 3),
                        'byte_offset': offset, 'byte_length': len(line),
                        'raw_sha256': hashlib.sha256(line).hexdigest(),
                        'kind': found[0], 'marker': found[1],
                        'line': line.decode(errors='replace').rstrip('\r\n'),
                        'preceding_lines': previous[-3:],
                        'qualification': 'candidate receipt only; not sampling success or exact wall execution time',
                    }
                    output.write(json.dumps(item) + '\n')
                    output.flush()
                    receipts.append(item)
                previous.append(line.decode(errors='replace').rstrip('\r\n'))
                previous = previous[-3:]
                offset += len(line)
            if exited:
                break
            time.sleep(10)
    result = {
        'qemu_pid': pid, 'start_ticks': birth, 'stop_reason': reason,
        'elapsed_seconds': round(time.monotonic() - started, 3),
        'candidate_count': len(receipts), 'bytes_scanned': offset,
        'source_serial': str(args.serial.resolve()),
        'guest_control_performed': False,
        'qualification': 'bounded marker receipts; absence or header alone does not prove outcome',
    }
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
