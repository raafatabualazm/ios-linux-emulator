#!/usr/bin/env python3
"""Independently qualify a checkpoint-v3 against pinned checkpoint-v2.

Written as a fresh reader: it re-derives every structure from the files rather
than importing anything from build-checkpoint-v3.py, and it compares the two
COMPOSED states (image + checkpoint) rather than the checkpoint files. Nothing
is modified; no image copy is created.
"""
import argparse
import hashlib
import json
import plistlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = ROOT / 'warm-fixture-v1/image.dmg'
V2 = ROOT / 'warm-fixture-v2/checkpoint.bin'
IMAGE_SHA = '97e99ce7a509279a3f09a86788d301e4c8cee33e09ef6d687e0a100e9579effd'
V2_SHA = '1c89ce23fd2d4424ef8eb8a69e40cddad3b6b89346a9e541a164fda50334341d'
PAGE, HDR, REC = 4096, 56, 4136


def fletcher64(block):
    a = b = 0
    for word in struct.unpack('<1022I', block[8:]):
        a = (a + word) % 0xffffffff
        b = (b + a) % 0xffffffff
    x = 0xffffffff - ((a + b) % 0xffffffff)
    y = 0xffffffff - ((a + x) % 0xffffffff)
    return struct.pack('<II', x, y)


def load(path):
    raw = path.read_bytes()
    assert raw[:8] == b'IMCOW001', f'{path}: magic'
    src_size, = struct.unpack_from('<Q', raw, 8)
    src_sha = raw[16:48].hex()
    count, = struct.unpack_from('<Q', raw, 48)
    assert HDR + count * REC == len(raw), f'{path}: length'
    pages, prev = {}, -1
    for i in range(count):
        base = HDR + i * REC
        offset, = struct.unpack_from('<Q', raw, base)
        digest = raw[base + 8:base + 40]
        payload = raw[base + 40:base + REC]
        assert hashlib.sha256(payload).digest() == digest, f'{path}: record {i} digest'
        assert offset % PAGE == 0 and offset > prev, f'{path}: record {i} order'
        assert offset + PAGE <= src_size, f'{path}: record {i} range'
        prev = offset
        pages[offset] = payload
    return {'src_size': src_size, 'src_sha': src_sha, 'count': count, 'pages': pages}


def composed_page(cp, offset):
    """Read one page of the composed image without materialising it."""
    if offset in cp['pages']:
        return cp['pages'][offset]
    with IMAGE.open('rb') as f:
        f.seek(offset)
        return f.read(PAGE)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--checkpoint', type=Path, required=True)
    ap.add_argument('--expect-domain', required=True)
    ap.add_argument('--expect-keys', nargs='+', required=True,
                    help='keys that MUST be present in the resulting plist')
    ap.add_argument('--expect-plist-sha', required=True)
    ap.add_argument('--data-offset', required=True)
    ap.add_argument('--node-offset', required=True)
    args = ap.parse_args()

    data_off = int(args.data_offset, 0)
    node_off = int(args.node_offset, 0)
    report = {'checkpoint': str(args.checkpoint.resolve()), 'checks': []}

    def ok(name, detail=''):
        report['checks'].append({'check': name, 'result': 'pass', 'detail': detail})
        print(f'PASS  {name}  {detail}')

    with IMAGE.open('rb') as f:
        assert hashlib.file_digest(f, 'sha256').hexdigest() == IMAGE_SHA
    with V2.open('rb') as f:
        assert hashlib.file_digest(f, 'sha256').hexdigest() == V2_SHA
    ok('pinned inputs unchanged', 'image 97e99ce7..., checkpoint-v2 1c89ce23...')

    v2 = load(V2)
    v3 = load(args.checkpoint)
    assert v3['src_size'] == v2['src_size'] == IMAGE.stat().st_size
    assert v3['src_sha'] == v2['src_sha'] == IMAGE_SHA
    ok('v3 header pins the same source image', f"size {v3['src_size']}, sha {v3['src_sha'][:16]}...")
    ok('v3 record set structurally valid', f"{v3['count']} records, ascending, aligned, digests verified")

    # --- exactly the declared pages differ in the COMPOSED state ----------
    touched = set(v2['pages']) | set(v3['pages'])
    differing = []
    for off in sorted(touched):
        if composed_page(v2, off) != composed_page(v3, off):
            differing.append(off)
    assert differing == sorted([data_off, node_off]), \
        f'composed pages differ at {[hex(o) for o in differing]}'
    ok('exactly two composed pages differ',
       f'0x{data_off:x} (plist) and 0x{node_off:x} (FS leaf)')

    # --- the plist reads back correctly -----------------------------------
    page = composed_page(v3, data_off)
    trailer_len = None
    for n in range(8, PAGE + 1):
        try:
            if plistlib.loads(page[:n]) is not None:
                trailer_len = n
                break
        except Exception:
            continue
    assert trailer_len is not None, 'no prefix of the page parses as a plist'
    blob = page[:trailer_len]
    got_sha = hashlib.sha256(blob).hexdigest()
    assert got_sha == args.expect_plist_sha, f'plist sha {got_sha}'
    parsed = plistlib.loads(blob)
    missing = [k for k in args.expect_keys if k not in parsed]
    assert not missing, f'missing keys {missing}'
    assert page[trailer_len:] == b'\0' * (PAGE - trailer_len), 'page tail not zero'
    ok(f'{args.expect_domain} plist reads back byte-exact',
       f'{trailer_len} bytes, sha {got_sha[:16]}..., keys {sorted(parsed)}')

    # --- the FS leaf is a valid APFS object and its lengths agree ---------
    node = composed_page(v3, node_off)
    assert fletcher64(node) == node[:8], 'node Fletcher64 invalid'
    ok('FS leaf Fletcher64 valid after edit', f'o_cksum {node[:8].hex()}')

    v2node = composed_page(v2, node_off)
    diffs = [i for i in range(PAGE) if node[i] != v2node[i]]
    assert all(i < 8 or any(s <= i < s + 8 for s in LENGTH_SITES) for i in diffs), \
        f'unexpected node bytes changed: {diffs}'
    sizes = []
    for site in LENGTH_SITES:
        old, = struct.unpack_from('<Q', v2node, site)
        new, = struct.unpack_from('<Q', node, site)
        sizes.append((hex(site), old, new))
    assert all(new == trailer_len for _, _, new in sizes), f'length fields {sizes}'
    # alloced_size sits 8 bytes after j_dstream.size and must stay block-aligned
    alloced, = struct.unpack_from('<Q', node, LENGTH_SITES[0] + 8)
    assert alloced == PAGE, f'alloced_size {alloced} is not {PAGE}'
    ok('j_dstream lengths updated, alloced_size untouched',
       f'{sizes}, alloced_size {alloced}')

    report['verdict'] = 'QUALIFIED (offline); not boot-qualified'
    print()
    print(json.dumps({'verdict': report['verdict'],
                      'checks_passed': len(report['checks'])}, indent=2))


LENGTH_SITES = ()

if __name__ == '__main__':
    import sys
    # length-field offsets within the node page, supplied per variant
    for i, a in enumerate(sys.argv):
        if a == '--length-sites':
            LENGTH_SITES = tuple(int(x, 0) for x in sys.argv[i + 1].split(','))
            del sys.argv[i:i + 2]
            break
    assert LENGTH_SITES, 'pass --length-sites a,b'
    main()
