#!/usr/bin/env python3
"""Derive a guarded checkpoint-v3 from pinned checkpoint-v2 plus one preference edit.

Reads the pinned warm image and checkpoint-v2, applies exactly the declared page
edits in memory, and writes a NEW checkpoint file plus a receipt. The pinned
image, the pinned checkpoint and the 0-byte patch list are never modified.

One variant per invocation: each produced checkpoint changes a single guest
preference domain, so a boot using it has one independent variable.
"""
import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

IMAGE = ROOT / 'warm-fixture-v1/image.dmg'
IMAGE_SHA = '97e99ce7a509279a3f09a86788d301e4c8cee33e09ef6d687e0a100e9579effd'
IMAGE_SIZE = 17179869184

CHECKPOINT = ROOT / 'warm-fixture-v2/checkpoint.bin'
CHECKPOINT_SHA = '1c89ce23fd2d4424ef8eb8a69e40cddad3b6b89346a9e541a164fda50334341d'
CHECKPOINT_SIZE = 267967360

MAGIC = b'IMCOW001'
HDR = 56
REC = 4136          # u64 image offset + sha256(32) + 4096 payload
PAGE = 4096
COUNT = 64789

# Each variant edits one data page (the plist) and one FS-tree leaf page (the
# inode's j_dstream length fields). Offsets, indices and hashes below were each
# verified read-only against the pinned inputs before this script was written.
VARIANTS = {
    'setup-watchdog': {
        'domain': 'com.apple.springboard',
        'candidate': HERE / 'candidates/com.apple.springboard.plist',
        'original_sha': 'fdf4ad5ea57830e0db4381f38f868a62e6de255df25084e9787202609705f188',
        'old_len': 144,
        'data': {
            'op': 'add',                      # not present in checkpoint-v2
            'offset': 0x37bf29000,
            'insert_index': 4153,
        },
        'node': {
            'index': 64168,
            'offset': 0x3f0cac000,
            'payload_sha': '560a80c28e03e6d8479538c3bb9446bce681d5b54ae05d94b535e138f3e2d10a',
            'cksum': '4a7abe24bbcfae6b',
            'size_fields': (0xb9b, 0xbb3),
        },
    },
    'setup-completion': {
        'domain': 'com.apple.purplebuddy',
        'candidate': HERE / 'candidates/com.apple.purplebuddy.plist',
        'original_sha': '1967bf14b6ac307f7762180013c511463d32dd60147664eb9f9c9c17b183334a',
        'old_len': 90,
        'data': {
            'op': 'replace',
            'offset': 0x37c5dc000,
            'index': 4694,
            'payload_sha': 'd791b1154da8e6c98d713afa10f9f03c235dfa15c1421f0d927b2a7462f38526',
        },
        'node': {
            'index': 63304,
            'offset': 0x3f084e000,
            'payload_sha': '955d4d6f18547c8e5a13e5113b4901222125fe3da0597f49deb0fb1173cb924c',
            'cksum': '9d5cffa1d3f95d41',
            'size_fields': (0x7de, 0x7f6),
        },
    },
}


def sha256_file(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def fletcher64(block):
    """APFS obj_phys checksum over block[8:], as used by repair-inline-patch-checksums.py."""
    assert len(block) == PAGE
    a = b = 0
    for word in struct.unpack('<1022I', block[8:]):
        a = (a + word) % 0xffffffff
        b = (b + a) % 0xffffffff
    x = 0xffffffff - ((a + b) % 0xffffffff)
    y = 0xffffffff - ((a + x) % 0xffffffff)
    return struct.pack('<II', x, y)


def read_records(path):
    raw = path.read_bytes()
    assert len(raw) == CHECKPOINT_SIZE, f'checkpoint size {len(raw)}'
    header = raw[:HDR]
    assert header[:8] == MAGIC, 'bad magic'
    src_size, = struct.unpack_from('<Q', header, 8)
    src_sha = header[16:48].hex()
    count, = struct.unpack_from('<Q', header, 48)
    assert src_size == IMAGE_SIZE, f'header source size {src_size}'
    assert src_sha == IMAGE_SHA, f'header source sha {src_sha}'
    assert count == COUNT, f'header count {count}'
    assert HDR + count * REC == len(raw), 'length does not match record count'
    records = []
    for i in range(count):
        base = HDR + i * REC
        offset, = struct.unpack_from('<Q', raw, base)
        digest = raw[base + 8:base + 40]
        payload = raw[base + 40:base + REC]
        assert hashlib.sha256(payload).digest() == digest, f'record {i} digest'
        records.append([offset, payload])
    return header, records


def check_order(records):
    prev = -1
    for i, (offset, payload) in enumerate(records):
        assert offset % PAGE == 0, f'record {i} unaligned 0x{offset:x}'
        assert offset > prev, f'record {i} not ascending'
        assert 0 <= offset and offset + PAGE <= IMAGE_SIZE, f'record {i} out of range'
        assert len(payload) == PAGE, f'record {i} payload length'
        prev = offset


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--variant', choices=sorted(VARIANTS), required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()

    out = args.output
    receipt_path = out.with_name(out.name + '.receipt.json')
    if out.exists():
        ap.error(f'output already exists: {out}')
    if receipt_path.exists():
        ap.error(f'receipt already exists: {receipt_path}')

    spec = VARIANTS[args.variant]

    # --- input pins -------------------------------------------------------
    image_sha = sha256_file(IMAGE)
    assert image_sha == IMAGE_SHA, f'image sha {image_sha}'
    assert IMAGE.stat().st_size == IMAGE_SIZE, 'image size'
    checkpoint_sha = sha256_file(CHECKPOINT)
    assert checkpoint_sha == CHECKPOINT_SHA, f'checkpoint sha {checkpoint_sha}'

    new_plist = spec['candidate'].read_bytes()
    new_len = len(new_plist)
    assert 0 < new_len <= PAGE, 'candidate does not fit one page'
    candidate_sha = hashlib.sha256(new_plist).hexdigest()

    header, records = read_records(CHECKPOINT)
    check_order(records)
    offsets = [r[0] for r in records]

    changes = []

    # --- data page: the plist itself --------------------------------------
    data = spec['data']
    if data['op'] == 'replace':
        idx = data['index']
        offset, payload = records[idx]
        assert offset == data['offset'], f'data offset 0x{offset:x}'
        assert hashlib.sha256(payload).hexdigest() == data['payload_sha'], 'data payload sha'
        old_blob = payload[:spec['old_len']]
        assert payload[spec['old_len']:] == b'\0' * (PAGE - spec['old_len']), 'data tail not zero'
    else:
        offset = data['offset']
        idx = data['insert_index']
        assert offset not in offsets, 'data page unexpectedly already in checkpoint'
        assert offsets[idx - 1] < offset < offsets[idx], 'insert index does not preserve order'
        with IMAGE.open('rb') as f:
            f.seek(offset)
            payload = f.read(PAGE)
        old_blob = payload[:spec['old_len']]
        assert payload[spec['old_len']:] == b'\0' * (PAGE - spec['old_len']), 'base tail not zero'
    assert hashlib.sha256(old_blob).hexdigest() == spec['original_sha'], 'original plist sha'

    new_payload = new_plist + b'\0' * (PAGE - new_len)
    assert len(new_payload) == PAGE
    if data['op'] == 'replace':
        records[idx][1] = new_payload
    else:
        records.insert(idx, [offset, new_payload])
    changes.append({
        'what': 'data page (preference plist)', 'op': data['op'], 'index': idx,
        'image_offset': hex(offset),
        'old_payload_sha256': hashlib.sha256(payload).hexdigest(),
        'new_payload_sha256': hashlib.sha256(new_payload).hexdigest(),
        'old_file_bytes': spec['old_len'], 'new_file_bytes': new_len,
        'old_file_sha256': spec['original_sha'], 'new_file_sha256': candidate_sha,
    })

    # --- FS-tree leaf: the inode's j_dstream lengths -----------------------
    node = spec['node']
    nidx = node['index'] + (1 if data['op'] == 'add' and node['index'] >= idx else 0)
    noffset, npayload = records[nidx]
    assert noffset == node['offset'], f'node offset 0x{noffset:x}'
    assert hashlib.sha256(npayload).hexdigest() == node['payload_sha'], 'node payload sha'
    assert npayload[:8].hex() == node['cksum'], 'stored node checksum'
    assert fletcher64(npayload) == npayload[:8], 'node checksum invalid before edit'

    edited = bytearray(npayload)
    for site in node['size_fields']:
        current, = struct.unpack_from('<Q', edited, site)
        assert current == spec['old_len'], f'size field at 0x{site:x} is {current}'
        struct.pack_into('<Q', edited, site, new_len)
    edited[0:8] = fletcher64(bytes(edited))
    edited = bytes(edited)
    assert fletcher64(edited) == edited[:8], 'node checksum invalid after edit'

    differing = [i for i in range(PAGE) if edited[i] != npayload[i]]
    allowed = set(range(0, 8))
    for site in node['size_fields']:
        allowed |= set(range(site, site + 8))
    assert set(differing) <= allowed, f'unexpected node bytes changed: {differing}'

    records[nidx] = [noffset, edited]
    changes.append({
        'what': 'FS-tree leaf (j_dstream size and total_bytes_written)',
        'op': 'replace', 'index': nidx, 'image_offset': hex(noffset),
        'size_fields': [hex(s) for s in node['size_fields']],
        'old_value': spec['old_len'], 'new_value': new_len,
        'old_payload_sha256': node['payload_sha'],
        'new_payload_sha256': hashlib.sha256(edited).hexdigest(),
        'old_checksum': node['cksum'], 'new_checksum': edited[:8].hex(),
        'bytes_changed': len(differing),
    })

    # --- re-validate the whole record set ---------------------------------
    check_order(records)
    new_count = len(records)
    assert new_count == COUNT + (1 if data['op'] == 'add' else 0), 'record count'

    untouched_ok = 0
    base_header, base_records = read_records(CHECKPOINT)
    base_map = {o: p for o, p in base_records}
    for offset_i, payload_i in records:
        if offset_i in (data['offset'], node['offset']):
            continue
        assert base_map[offset_i] == payload_i, f'untouched record 0x{offset_i:x} changed'
        untouched_ok += 1
    assert untouched_ok == COUNT - (1 if data['op'] == 'replace' else 0) - 1, 'untouched count'

    # --- emit --------------------------------------------------------------
    new_header = bytearray(base_header)
    struct.pack_into('<Q', new_header, 48, new_count)

    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(bytes(new_header))
        for offset_i, payload_i in records:
            f.write(struct.pack('<Q', offset_i))
            f.write(hashlib.sha256(payload_i).digest())
            f.write(payload_i)
        f.flush()
        os.fsync(f.fileno())

    expected_size = HDR + new_count * REC
    assert out.stat().st_size == expected_size, 'output size'
    out_sha = sha256_file(out)

    # read the file back with the same reader used on v2
    verify_raw = out.read_bytes()
    assert verify_raw[:8] == MAGIC
    vcount, = struct.unpack_from('<Q', verify_raw, 48)
    assert vcount == new_count
    vprev = -1
    for i in range(vcount):
        base = HDR + i * REC
        o, = struct.unpack_from('<Q', verify_raw, base)
        d = verify_raw[base + 8:base + 40]
        p = verify_raw[base + 40:base + REC]
        assert hashlib.sha256(p).digest() == d, f'readback record {i} digest'
        assert o > vprev and o % PAGE == 0, f'readback record {i} order'
        vprev = o

    # inputs unchanged
    assert sha256_file(IMAGE) == IMAGE_SHA, 'image changed during build'
    assert sha256_file(CHECKPOINT) == CHECKPOINT_SHA, 'checkpoint changed during build'

    receipt = {
        'status': 'built and read-back verified; NOT boot-qualified',
        'variant': args.variant,
        'domain': spec['domain'],
        'single_variable': f"only {spec['domain']} preferences differ from checkpoint-v2",
        'inputs': {
            'image': {'path': str(IMAGE), 'sha256': IMAGE_SHA, 'size': IMAGE_SIZE},
            'checkpoint_v2': {'path': str(CHECKPOINT), 'sha256': CHECKPOINT_SHA,
                              'size': CHECKPOINT_SIZE, 'records': COUNT},
            'candidate_plist': {'path': str(spec['candidate']), 'sha256': candidate_sha,
                                'bytes': new_len},
        },
        'changes': changes,
        'records_untouched_verified': untouched_ok,
        'output': {'path': str(out.resolve()), 'sha256': out_sha,
                   'size': expected_size, 'records': new_count},
    }
    rfd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(rfd, 'w') as f:
        json.dump(receipt, f, indent=2)
        f.write('\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
