#!/usr/bin/env python3
"""Apply Inferno's GUI patch to an offline iOS 14 raw APFS image.

Keep originals, forward/reverse diffs and hashes in a new work directory.
Prepare recovery data before touching the image and verify complete files.
Requires Python 3.11+, Linux procfs and the supplied external executables.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

DSC = '/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'
CHUNK = 1024 * 1024


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_file(path):
    with path.open('rb') as stream:
        os.fsync(stream.fileno())


def atomic_save_manifest(work, manifest):
    """Keep the previous valid manifest until its replacement is durable."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         dir=work, prefix='.manifest-', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(manifest, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, work / 'manifest.json')
        temporary = None
        sync_directory(work)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def make_diffs(original, patched, forward, reverse):
    """Bound preparation memory to two chunks and preserve same-size edits."""
    if original.stat().st_size != patched.stat().st_size:
        raise ValueError('File length changed; extent patching cannot resize files')
    records = changed = 0
    with original.open('rb') as a, patched.open('rb') as b, \
            forward.open('wb') as f, reverse.open('wb') as r:
        offset = 0
        while True:
            old, new = a.read(CHUNK), b.read(CHUNK)
            if len(old) != len(new):
                raise ValueError('File length changed during diff preparation')
            if not old:
                break
            if old != new:
                i = 0
                while i < len(old):
                    if old[i] == new[i]:
                        i += 1
                        continue
                    end = i + 1
                    while end < len(old) and old[end] != new[end]:
                        end += 1
                    header = struct.pack('<QI', offset+i, end-i)
                    f.write(header + new[i:end])
                    r.write(header + old[i:end])
                    records += 1
                    changed += end-i
                    i = end
            offset += len(old)
        for stream in (f, r):
            stream.flush()
            os.fsync(stream.fileno())
    return {'records': records, 'changed_bytes': changed}


def require_offline(image):
    """Detect QEMU using this inode. This is a check, not an exclusive lock."""
    identity = (image.stat().st_dev, image.stat().st_ino)
    proc = Path('/proc')
    if not proc.is_dir():
        raise RuntimeError('The offline process check requires Linux procfs')
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if not (entry / 'comm').read_text().startswith('qemu-system'):
                continue
            for fd in (entry / 'fd').iterdir():
                try:
                    stat = fd.stat()
                    if (stat.st_dev, stat.st_ino) == identity:
                        raise RuntimeError(f'Image is open by QEMU PID {entry.name}; stop that VM first')
                except FileNotFoundError:
                    pass
        except (FileNotFoundError, ProcessLookupError):
            pass
        except PermissionError as exc:
            raise RuntimeError('Cannot inspect a QEMU process; sufficient permissions are required') from exc


def verify_file(ep, work, item, expected_hash, suffix):
    check = work / (item['name'] + suffix)
    run(*ep, '-extract', item['path'] + '=' + str(check))
    if check.stat().st_size != item['size'] or digest(check) != expected_hash:
        raise RuntimeError('Full-file verification failed: ' + item['path'])
    check.unlink()


def save_recovery_status(work, manifest):
    """Journal failures must never prevent undo or mask the original error."""
    try:
        atomic_save_manifest(work, manifest)
    except BaseException as exc:
        print(f'Could not save recovery status {manifest["status"]}: {exc}', file=sys.stderr)


def apply_patches(ep, work, manifest):
    # Reject an image changed since extraction before any patch is attempted.
    for item in manifest['files']:
        verify_file(ep, work, item, item['before_sha256'], '.preflight')
    manifest['status'] = 'applying'
    atomic_save_manifest(work, manifest)
    attempted = []
    try:
        for item in manifest['files']:
            if not item['records']:
                continue
            attempted.append(item)  # The child may fail after a partial write.
            run(*ep, '-patch', item['path'] + '=' + str(work / (item['name'] + '.diff')))
        for item in manifest['files']:
            verify_file(ep, work, item, item['after_sha256'], '.verified')
        manifest['status'] = 'verified'
        atomic_save_manifest(work, manifest)
    except BaseException:
        manifest['status'] = 'rollback-required'
        save_recovery_status(work, manifest)
        rollback_ok = True
        for item in reversed(attempted):
            try:
                run(*ep, '-patch', item['path'] + '=' + str(work / (item['name'] + '.undo')))
                verify_file(ep, work, item, item['before_sha256'], '.restored')
            except BaseException as exc:
                rollback_ok = False
                print(f'Rollback failed for {item["path"]}: {exc}', file=sys.stderr)
        manifest['status'] = 'rolled-back' if rollback_ok else 'rollback-required'
        save_recovery_status(work, manifest)
        raise


def prepare_and_apply(args, image):
    args.workdir.mkdir(mode=0o700, parents=True, exist_ok=False)
    work = args.workdir.resolve()
    sync_directory(work.parent)
    ep = [str(args.extent_probe.resolve()), '-img', str(image), '-base', str(args.base), '-vol', args.volume]
    manifest = {'image': str(image), 'base': args.base, 'volume': args.volume,
                'status': 'preparing', 'files': []}
    atomic_save_manifest(work, manifest)
    name = Path(DSC).name
    original, patched = work / (name + '.original'), work / name
    run(*ep, '-extract', DSC + '=' + str(original))
    shutil.copy2(original, patched)
    flags = ['--unredact-logs'] if args.unredact_logs else []
    # Bare invocation preserves the tested patcher's default rendering fixes.
    run(args.patcher.resolve(), *flags, patched)
    stats = make_diffs(original, patched, work / (name + '.diff'), work / (name + '.undo'))
    for artifact in (original, patched, work / (name + '.diff'), work / (name + '.undo')):
        sync_file(artifact)
    sync_directory(work)
    manifest['files'].append({'path': DSC, 'name': name, 'size': original.stat().st_size,
                              'before_sha256': digest(original), 'after_sha256': digest(patched), **stats})
    manifest['status'] = 'prepared'
    atomic_save_manifest(work, manifest)
    run(*ep, DSC)
    require_offline(image)
    apply_patches(ep, work, manifest)
    print('Dyld filesystem patch verified. Originals and rollback data: ' + str(work))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--extent-probe', required=True, type=Path)
    parser.add_argument('--patcher', required=True, type=Path)
    parser.add_argument('--workdir', required=True, type=Path, help='New directory for originals and rollback data')
    parser.add_argument('--base', type=int, default=24576)
    parser.add_argument('--volume', default='role:system')
    parser.add_argument('--unredact-logs', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('This helper requires Linux and procfs')
    if args.base < 0:
        parser.error('--base must be nonnegative')
    image = args.image.resolve(strict=True)
    if not image.is_file() or args.base > image.stat().st_size - 4096:
        raise ValueError('Expected a regular raw image and a valid APFS container offset')
    for tool in (args.extent_probe, args.patcher):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise ValueError(f'Executable missing: {tool}')
    # Serialize cooperating helpers. QEMU and other writers still must be stopped.
    import fcntl
    with image.open('r+b') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        require_offline(image)
        lock.seek(args.base + 32)
        if lock.read(4) != b'NXSB' or struct.unpack('<I', lock.read(4))[0] != 4096:
            raise ValueError(f'4096-byte-block APFS container absent at offset {args.base}')
        prepare_and_apply(args, image)


if __name__ == '__main__':
    main()
