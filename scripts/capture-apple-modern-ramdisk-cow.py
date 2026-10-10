#!/usr/bin/env python3
"""Pause an owned QEMU and save only changed private ramdisk pages through QMP."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import socket
import struct
import time


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


class QMP:
    def __init__(self, path, pid):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(30)
        self.socket.connect(str(path))
        peer = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer[0] != pid or peer[1] != os.getuid():
            raise ValueError(f'QMP peer does not match owned PID/UID: {peer}')
        self.file = self.socket.makefile('rwb', buffering=0)
        greeting = json.loads(self.file.readline())
        if 'QMP' not in greeting:
            raise ValueError('missing QMP greeting')
        self.index = 0
        self.command('qmp_capabilities')

    def command(self, execute, arguments=None):
        self.index += 1
        request = dict(execute=execute, id=self.index)
        if arguments:
            request['arguments'] = arguments
        self.file.write(json.dumps(request).encode() + b'\n')
        while True:
            reply = json.loads(self.file.readline())
            if reply.get('id') != self.index:
                continue
            if 'error' in reply:
                raise RuntimeError(reply['error'])
            return reply['return']


def mapping(pid, image):
    stat = image.stat()
    found = []
    for line in pathlib.Path(f'/proc/{pid}/maps').read_text().splitlines():
        parts = line.split(None, 5)
        if len(parts) != 6:
            continue
        start, end = map(lambda x: int(x, 16), parts[0].split('-'))
        major, minor = map(lambda x: int(x, 16), parts[3].split(':'))
        if (int(parts[4]) == stat.st_ino and os.makedev(major, minor) == stat.st_dev
                and int(parts[2], 16) == 0 and parts[1] == 'rw-p'):
            found.append(dict(start=start, end=end, source=line))
    if len(found) != 1 or found[0]['end'] - found[0]['start'] != stat.st_size:
        raise ValueError(f'need one complete private image mapping: {found}')
    return found[0]


def cow_ranges(pid, address, size, page):
    """Bit61 marks file/shared-anon; present or swapped private non-file pages are candidates."""
    if address % page or size % page:
        raise ValueError('capture currently requires page-aligned image and mapping')
    ranges, start, end, candidates = [], None, None, 0
    with pathlib.Path(f'/proc/{pid}/pagemap').open('rb', buffering=0) as f:
        f.seek(address // page * 8)
        total = size // page
        index = 0
        while index < total:
            count = min(65536, total - index)
            raw = f.read(count * 8)
            if len(raw) != count * 8:
                raise ValueError('short pagemap read')
            for (flags,) in struct.iter_unpack('<Q', raw):
                offset = index * page
                is_cow = bool(flags & ((1 << 63) | (1 << 62))) and not flags & (1 << 61)
                if is_cow:
                    candidates += 1
                    if start is None:
                        start = offset
                    end = offset + page
                elif start is not None:
                    ranges.append((start, end - start)); start = None
                index += 1
        if start is not None:
            ranges.append((start, end - start))
    return ranges, candidates


def capture(args):
    image = args.image.resolve(strict=True)
    out = args.out.resolve()
    if out.exists():
        raise ValueError('output exists; refusing to overwrite evidence')
    cmdline = pathlib.Path(f'/proc/{args.pid}/cmdline').read_bytes().split(b'\0')
    if not cmdline or 'qemu-system-' not in pathlib.Path(os.fsdecode(cmdline[0])).name:
        raise ValueError('PID is not an owned QEMU system process')
    # QMP peer credentials independently bind the socket to this PID and current UID.
    qmp = QMP(args.qmp, args.pid)
    initial_status = qmp.command('query-status')
    qmp.command('stop')
    if qmp.command('query-status')['running']:
        raise ValueError('QEMU did not stop')
    source_stat = image.stat()
    host_mapping = mapping(args.pid, image)
    mtree = qmp.command('human-monitor-command', {'command-line': 'info mtree'})
    physical = set()
    for line in mtree.splitlines():
        match = re.search(r'([0-9a-f]+)-([0-9a-f]+) \(prio \d+, ram\): '
                          + re.escape(args.region) + r'$', line.strip())
        if match:
            physical.add((int(match[1], 16), int(match[2], 16) + 1))
    if len(physical) != 1:
        raise ValueError(f'expected one physical RAM region named {args.region}: {physical}')
    physical_start, physical_end = physical.pop()
    # modern-machine.c rounds only its physical MemoryRegion to the 16KiB
    # guest page size. The source file mapping stays exact; padding is not
    # part of the APFS image and is deliberately excluded from the delta.
    expected_region_size = source_stat.st_size
    if args.region == 'apple-modern.large-ramdisk':
        expected_region_size = (expected_region_size + 16383) & ~16383
    if physical_end - physical_start != expected_region_size:
        raise ValueError('physical region length differs from declared image rounding')
    page = os.sysconf('SC_PAGE_SIZE')
    ranges, candidates = cow_ranges(args.pid, host_mapping['start'], source_stat.st_size, page)
    if candidates * page > args.max_bytes:
        raise ValueError(f'COW candidates exceed capture budget: {candidates * page}')
    out.mkdir()
    (out / 'mtree.txt').write_text(mtree)
    source_hash = sha256(image)
    changed, saved = [], 0
    delta = out / 'delta.bin'
    with image.open('rb') as base, delta.open('xb') as dst:
        for start, size in ranges:
            for offset in range(start, start + size, 64 << 10):
                length = min(64 << 10, start + size - offset)
                temporary = out / 'qmp-range.bin'
                qmp.command('pmemsave', {'val': physical_start + offset,
                            'size': length, 'filename': str(temporary)})
                data = temporary.read_bytes(); temporary.unlink()
                if len(data) != length:
                    raise ValueError('short QMP memory save')
                base.seek(offset); original = base.read(length)
                if len(original) != length:
                    raise ValueError('short source read')
                for pos in range(0, length, page):
                    chunk = data[pos:pos + page]
                    if chunk != original[pos:pos + page]:
                        changed.append(dict(offset=offset + pos, size=len(chunk),
                            delta_offset=saved, sha256=hashlib.sha256(chunk).hexdigest()))
                        dst.write(chunk); saved += len(chunk)
    after = image.stat()
    if ((source_stat.st_ino, source_stat.st_size, source_stat.st_mtime_ns, source_stat.st_ctime_ns)
            != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or sha256(image) != source_hash):
        raise ValueError('source changed during capture')
    if qmp.command('query-status')['running']:
        raise ValueError('guest unexpectedly resumed during capture')
    result = dict(format='apple-modern-cow-delta-v1', source=str(image), source_sha256=source_hash,
        source_size=source_stat.st_size, pid=args.pid, host_mapping=host_mapping,
        physical_start=physical_start, physical_region_size=expected_region_size,
        excluded_padding_bytes=expected_region_size-source_stat.st_size,
        page_size=page, cow_candidate_pages=candidates,
        changed_pages=len(changed), saved_bytes=saved, delta_sha256=sha256(delta), blocks=changed,
        initial_status=initial_status, paused=True, filesystem_consistency='crash-consistent; not fsck-clean',
        captured_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    (out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    if args.resume and initial_status['running']:
        qmp.command('cont')
    print(json.dumps({key: value for key, value in result.items() if key not in ('blocks', 'host_mapping')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--qmp', type=pathlib.Path, required=True)
    parser.add_argument('--image', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--region', default='apple-modern.large-ramdisk')
    parser.add_argument('--max-bytes', type=int, default=512 << 20)
    parser.add_argument('--resume', action='store_true')
    capture(parser.parse_args())
