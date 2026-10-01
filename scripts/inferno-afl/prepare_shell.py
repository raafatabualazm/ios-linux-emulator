#!/usr/bin/env python3
"""Make a separate Bash ramdisk from the pinned iOS 14 HFS+ lab image."""
import argparse
import hashlib
import mmap
from pathlib import Path
import plistlib
import subprocess

STOCK_SHA256 = 'dfda491c79438ddd87b519747bbdc697d29c3d706b046ae9c57930178dcd7ab5'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True,
                        help='pinned ios_scfuzzer.img ramdisk')
    parser.add_argument('--output', type=Path, required=True,
                        help='new separate shell image')
    args = parser.parse_args()
    source = args.source.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if output.exists():
        parser.error(f'Output already exists: {output}; keep the prepared image')
    if digest(source) != STOCK_SHA256:
        parser.error('Source is not the validated iOS 14 HFS+ lab image')
    with source.open('rb') as stream, mmap.mmap(stream.fileno(), 0,
                                              access=mmap.ACCESS_READ) as image:
        needle = b'<string>/bin/sysc_fuzz</string>'
        at = image.find(needle)
        if at < 0 or image.find(needle, at + 1) >= 0:
            parser.error('Expected one contiguous fuzzer launch plist')
        start = image.rfind(b'<?xml', max(0, at - 4096), at)
        end = image.find(b'</plist>', at, at + 4096)
        if start < 0 or end < 0:
            parser.error('Launch plist is not a contiguous XML file')
        end += len(b'</plist>')
        if image[end:end+1] == b'\n':
            end += 1
        original = image[start:end]
    document = plistlib.loads(original)
    if document.get('Label') != 'com.apple.bash' or document.get('ProgramArguments') != ['/bin/sysc_fuzz']:
        parser.error('Unexpected launch job')
    document['ProgramArguments'] = ['/bin/bash', '--noprofile', '--norc', '-i']
    patched = plistlib.dumps(document, sort_keys=False)
    if len(patched) > len(original):
        parser.error('Shell plist does not fit the existing HFS+ file')
    patched = patched.replace(b'</plist>',
                              b' ' * (len(original)-len(patched)) + b'</plist>')
    assert len(patched) == len(original) and plistlib.loads(patched) == document
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['cp', '--reflink=auto', '--sparse=always', '--',
                    str(source), str(output)], check=True)
    with output.open('r+b') as stream, mmap.mmap(stream.fileno(), 0) as image:
        assert image[start:end] == original
        image[start:end] = patched
        image.flush()
        assert image[start:end] == patched
    print(f'Shell image: {output}')
    print(f'Changed only {len(original)} launch-plist bytes at offset {start}; file length preserved')
    print('SHA256:', digest(output))


if __name__ == '__main__':
    main()
