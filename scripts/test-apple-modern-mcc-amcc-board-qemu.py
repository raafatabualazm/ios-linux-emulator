#!/usr/bin/env python3
"""Board-level gate for the v4 AMCC plan guards and SLC aperture carve; no firmware runs.

Each case is one prepare-only QEMU board (no CPU instruction executes) built
from a private copy of a matched T8140 ADT:

* Optional /arm-io/mcc properties. A copy gets amcc-plane-enable-mask,
  max-way-count or dcs-channel-enable-mask by renaming an existing 4-byte
  /arm-io/mcc property that no plan builder reads (the ADT name is a fixed
  32-byte field, so the rename is in place; wrong sizes rewrite only the
  length field; size 0 drops the 4 data bytes and size 8 renames the 8-byte
  dramcfg-data). With modern-mcc-dsid/-slc/-dcs-perf on, the board must either
  construct the device (default value) or refuse to start with exit status 1.
  v4: the refusal is exactly "<device>: MCC <name> has <n> bytes, expected 4"
  for a wrong size (checked before the value) or "<device>: MCC
  <name>=<value> is not modelled", with <device> "DCS performance",
  "MCC DSID" or "MCC SLC".
* SLC compatibility-aperture carve. A copy of the served tree gets another
  /chosen/lock-regs/amcc aperture-phys-addr/aperture-size. The board must
  map exactly the SLC views inside the aperture at priority 1 and every other
  view plainly (priority 0), the flat view must show the aperture minus
  exactly those views (pieces keep their aperture offsets), every plane
  status cell must read the 12-way reset status 0x0c000c00 through the bus
  (HMP xp), every plane flush cell 0, and aperture cells next to a carved
  view 0 (or, when the neighbour is a bound register, that register's low
  word); the SLC read counter must count exactly the SLC reads. v4: the
  aperture's lock word (+0..+7) and every CTRR bound register [reg, reg+8)
  must lie wholly inside one remaining aperture piece and read its board
  value through the bus (HMP xp /1gx): 0 for the lock word and banks A/B/D,
  and for bank C the ACC_CTRR_C window the board programs at construction
  (DeviceTree first page .. SPTM-rx last page, from the independent layout).
* v4 CTRR/lock-word refusal. A copy of the served tree moves one
  /chosen/lock-regs/amcc/amcc-ctrr-* lower- or upper-limit-reg-offset (and,
  for some cases, the aperture) so the 8-byte bound register overlaps an
  in-aperture SLC view in its lower or upper half. With modern-mcc-slc on the
  board must refuse to start with exactly "MCC SLC view overlaps a
  compatibility AMCC lock or CTRR bound register"; with SLC off the same tree
  must construct. Registers touching a view without overlapping it (the
  nearest 8-aligned offsets on either side) must construct and pass the carve
  checks. The lock-word overlap cannot be expressed in an ADT: the aperture
  base is 0x1000-aligned and every SLC view sits at 0x800/0x804/0x82c/0x844
  mod 0x1000, which the report proves by enumeration.

Every board's emulator log must be exactly the declared-profile warnings of
the devices constructed, in construction order (DCS performance, DSID, SLC),
followed by the refusal line for a refused board, and nothing else.

Run the whole script under `flock <qemu.lock>`: boards are started strictly
one after another and each child is reaped before the next starts.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('amcc_board_helpers',
    Path(__file__).with_name('test-apple-modern-pmgr-qemu.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
mailbox, board = helper.mailbox, helper.board
require = helper.require

AMCC = 0x220000000
PLANE = 0x40000
SLC_VIEWS = ([AMCC + 0x102800, AMCC + 0x10082c, AMCC + 0x102844] +
             [AMCC + p * PLANE + 0x2804 for p in range(4)] +
             [AMCC + p * PLANE + 0x2844 for p in range(4)])
SLC_STATUS = SLC_VIEWS[3:7]
SLC_FLUSH = SLC_VIEWS[7:11]
RESET_STATUS = 0x0c000c00
REGIONS = {'dsid': ('apple-modern.mcc-dsid', 9), 'slc': ('apple-modern.mcc-slc', 11),
           'dcs-perf': ('apple-modern.mcc-dcs-perf', 6)}
QOM = {'dsid': '/machine/mcc-dsid', 'slc': '/machine/mcc-slc',
       'dcs-perf': '/machine/mcc-dcs-perf'}
SLC_ANNOUNCEMENT = ('apple-modern: opt-in AMCC SLC way/flush cells; declared profile: '
                    '12-way handover state (per-plane readback on t604x/t8140-family '
                    'Macs, m1n1 PR #664, analogy)')
# v4 board warnings, each a whole log line (default virtual reset values).
ANNOUNCEMENTS = {
    'dcs-perf': ('warning: apple-modern: opt-in sparse DCS performance block on DCS0-2; '
                 'declared profile: virtual reset 0x0000000000000000 (all counters), clear '
                 'bits complete at once and zero their duration counter, counter stores '
                 'abort; no DRAM event source connected'),
    'dsid': ('warning: apple-modern: opt-in sparse AMCC DSID profile cells; counter virtual '
             'reset 0x0000000000000000; no DSID event source connected'),
    'slc': ('warning: ' + SLC_ANNOUNCEMENT + ', global writes broadcast and requested ways '
            'report powered at once; no cache model'),
}
CONSTRUCTION_ORDER = ('dcs-perf', 'dsid', 'slc')     # modern_init order
PREFIX_DEVICE = {'DCS performance': 'dcs-perf', 'MCC DSID': 'dsid', 'MCC SLC': 'slc'}
OVERLAP_ERROR = 'MCC SLC view overlaps a compatibility AMCC lock or CTRR bound register'
DONORS = ('dsid_mgmt', 'mcw-reg-idx', 'pmp_ptd_db_reg_idx')
WIDE_DONOR = 'dramcfg-data'     # 8 bytes; no plan builder reads it
BANKS = ('amcc-ctrr-a', 'amcc-ctrr-b', 'amcc-ctrr-c', 'amcc-ctrr-d')
MTREE_LINE = re.compile(r'^\s*([0-9a-f]{16})-([0-9a-f]{16}) \(prio (-?\d+), ([a-z/ -]+)\): '
                        r'(\S+)(?: @([0-9a-f]+))?')
XP_LINE = re.compile(r'^([0-9a-f]{16}): 0x([0-9a-f]{8})\s*$')
XP64_LINE = re.compile(r'^([0-9a-f]{16}): 0x([0-9a-f]{16})\s*$')

# (case, devices, base tree, [(property, value, size)], expected rejection or None)
# Sizes 1..4 rewrite a 4-byte donor's length; 0 drops its data; 8 uses dramcfg-data.
OPTIONAL_CASES = [
    ('dsid-plane-mask-0xf', ['dsid'], 'stock', [('amcc-plane-enable-mask', 0xf, 4)], None),
    ('dsid-plane-mask-0x7', ['dsid'], 'stock', [('amcc-plane-enable-mask', 0x7, 4)],
     'MCC DSID: MCC amcc-plane-enable-mask=0x7 is not modelled'),
    ('dsid-plane-mask-0x1f', ['dsid'], 'served', [('amcc-plane-enable-mask', 0x1f, 4)],
     'MCC DSID: MCC amcc-plane-enable-mask=0x1f is not modelled'),
    ('dsid-plane-mask-size-2', ['dsid'], 'stock', [('amcc-plane-enable-mask', 0xf, 2)],
     'MCC DSID: MCC amcc-plane-enable-mask has 2 bytes, expected 4'),
    ('dsid-ignores-slc-and-dcs-masks', ['dsid'], 'stock',
     [('max-way-count', 0x80, 4), ('dcs-channel-enable-mask', 0x7, 4)], None),
    ('slc-plane-mask-0xf', ['slc'], 'served', [('amcc-plane-enable-mask', 0xf, 4)], None),
    ('slc-plane-mask-0xe', ['slc'], 'served', [('amcc-plane-enable-mask', 0xe, 4)],
     'MCC SLC: MCC amcc-plane-enable-mask=0xe is not modelled'),
    ('slc-stock-plane-mask-0x7', ['slc'], 'stock', [('amcc-plane-enable-mask', 0x7, 4)],
     'MCC SLC: MCC amcc-plane-enable-mask=0x7 is not modelled'),
    ('slc-max-way-count-0x7f', ['slc'], 'served', [('max-way-count', 0x7f, 4)], None),
    ('slc-max-way-count-0xc', ['slc'], 'stock', [('max-way-count', 0xc, 4)], None),
    ('slc-max-way-count-0x80', ['slc'], 'served', [('max-way-count', 0x80, 4)],
     'MCC SLC: MCC max-way-count=0x80 is not modelled'),
    ('slc-max-way-count-size-3', ['slc'], 'served', [('max-way-count', 0xc, 3)],
     'MCC SLC: MCC max-way-count has 3 bytes, expected 4'),
    ('slc-ignores-dcs-mask', ['slc'], 'served', [('dcs-channel-enable-mask', 0x7, 4)], None),
    ('dcs-perf-dcs-mask-0xf', ['dcs-perf'], 'stock', [('dcs-channel-enable-mask', 0xf, 4)], None),
    ('dcs-perf-dcs-mask-0x7', ['dcs-perf'], 'stock', [('dcs-channel-enable-mask', 0x7, 4)],
     'DCS performance: MCC dcs-channel-enable-mask=0x7 is not modelled'),
    ('dcs-perf-dcs-mask-size-1', ['dcs-perf'], 'stock', [('dcs-channel-enable-mask', 0xf, 1)],
     'DCS performance: MCC dcs-channel-enable-mask has 1 bytes, expected 4'),
    ('dcs-perf-plane-mask-0x3', ['dcs-perf'], 'served', [('amcc-plane-enable-mask', 0x3, 4)],
     'DCS performance: MCC amcc-plane-enable-mask=0x3 is not modelled'),
    ('dcs-perf-ignores-way-count', ['dcs-perf'], 'stock', [('max-way-count', 0x80, 4)], None),
    ('all-three-defaults', ['dcs-perf', 'dsid', 'slc'], 'served',
     [('amcc-plane-enable-mask', 0xf, 4), ('max-way-count', 0xc, 4),
      ('dcs-channel-enable-mask', 0xf, 4)], None),
    ('all-three-way-count-0x80', ['dcs-perf', 'dsid', 'slc'], 'served',
     [('amcc-plane-enable-mask', 0xf, 4), ('max-way-count', 0x80, 4),
      ('dcs-channel-enable-mask', 0xf, 4)], 'MCC SLC: MCC max-way-count=0x80 is not modelled'),
    # v4: sizes 0 and 8, and a wrong size that also holds an unmodelled value
    # (the size is reported, not the value).
    ('dsid-plane-mask-size-0', ['dsid'], 'served', [('amcc-plane-enable-mask', 0, 0)],
     'MCC DSID: MCC amcc-plane-enable-mask has 0 bytes, expected 4'),
    ('slc-max-way-count-size-8', ['slc'], 'served', [('max-way-count', 0xc, 8)],
     'MCC SLC: MCC max-way-count has 8 bytes, expected 4'),
    ('dcs-perf-plane-mask-size-8', ['dcs-perf'], 'stock', [('amcc-plane-enable-mask', 0xf, 8)],
     'DCS performance: MCC amcc-plane-enable-mask has 8 bytes, expected 4'),
    ('slc-max-way-count-size-2-value-0x80', ['slc'], 'stock', [('max-way-count', 0x80, 2)],
     'MCC SLC: MCC max-way-count has 2 bytes, expected 4'),
    ('all-three-dcs-mask-size-3', ['dcs-perf', 'dsid', 'slc'], 'served',
     [('dcs-channel-enable-mask', 0xf, 3)],
     'DCS performance: MCC dcs-channel-enable-mask has 3 bytes, expected 4'),
    ('all-three-plane-mask-0xe-dcs-first', ['dcs-perf', 'dsid', 'slc'], 'stock',
     [('amcc-plane-enable-mask', 0xe, 4)],
     'DCS performance: MCC amcc-plane-enable-mask=0xe is not modelled'),
    ('dsid-slc-plane-mask-size-2', ['dsid', 'slc'], 'served',
     [('amcc-plane-enable-mask', 0xf, 2)],
     'MCC DSID: MCC amcc-plane-enable-mask has 2 bytes, expected 4'),
]
# (case, aperture base, aperture size); the served tree has 0x220000000/0x4000.
APERTURE_CASES = [
    ('aperture-served', 0x220000000, 0x4000),
    ('aperture-plane-1', 0x220040000, 0x4000),
    ('aperture-1mib-planes-0-3', 0x220000000, 0x100000),
    ('aperture-without-views', 0x220010000, 0x1000),
    ('aperture-global-cells', 0x220100000, 0x4000),
]
SERVED_APERTURE = (AMCC, 0x4000)
GLOBAL_APERTURE = (AMCC + 0x100000, 0x4000)
# v4 (case, devices, aperture, [(bank, 'lower'|'upper', offset)], refused?).
# Served banks: a 0x10/0x20, b 0x110/0x120, c 0x210/0x220, d 0x310/0x320.
CTRR_CASES = [
    # The predecessor's probe tree (v3/findings/ctrr-overlap): register
    # [0x2800, 0x2808) holds plane 0's status view 0x2804 in its upper half.
    ('ctrr-a-lower-0x2800', ['slc'], SERVED_APERTURE, [('amcc-ctrr-a', 'lower', 0x2800)], True),
    ('ctrr-a-lower-0x2800-slc-off', [], SERVED_APERTURE, [('amcc-ctrr-a', 'lower', 0x2800)], False),
    ('ctrr-a-lower-0x2800-dcs-dsid-only', ['dcs-perf', 'dsid'], SERVED_APERTURE,
     [('amcc-ctrr-a', 'lower', 0x2800)], False),
    ('ctrr-a-lower-0x2800-all-three', ['dcs-perf', 'dsid', 'slc'], SERVED_APERTURE,
     [('amcc-ctrr-a', 'lower', 0x2800)], True),
    # Upper register of the last bank; plane 0 flush view 0x2844 in its upper half.
    ('ctrr-d-upper-0x2840', ['slc'], SERVED_APERTURE, [('amcc-ctrr-d', 'upper', 0x2840)], True),
    # Global cells: WAYS 0x102800 in the register's lower half, CTRL_82C 0x10082c in the upper.
    ('ctrr-b-lower-0x2800-global-aperture', ['slc'], GLOBAL_APERTURE,
     [('amcc-ctrr-b', 'lower', 0x2800)], True),
    ('ctrr-c-upper-0x828-global-aperture', ['slc'], GLOBAL_APERTURE,
     [('amcc-ctrr-c', 'upper', 0x828)], True),
    # Other planes: plane 1 flush, plane 3 status.
    ('ctrr-a-upper-0x2840-plane-1-aperture', ['slc'], (AMCC + 0x40000, 0x4000),
     [('amcc-ctrr-a', 'upper', 0x2840)], True),
    ('ctrr-c-lower-0xc2800-1mib-aperture', ['slc'], (AMCC, 0x100000),
     [('amcc-ctrr-c', 'lower', 0xc2800)], True),
    # Touching or nearest-8-aligned registers that do not overlap a view: constructed.
    ('ctrr-a-lower-0x2808-adjacent', ['slc'], SERVED_APERTURE,
     [('amcc-ctrr-a', 'lower', 0x2808)], False),
    ('ctrr-a-lower-0x27f8-below', ['slc'], SERVED_APERTURE,
     [('amcc-ctrr-a', 'lower', 0x27f8)], False),
    ('ctrr-d-upper-0x2848-adjacent', ['slc'], SERVED_APERTURE,
     [('amcc-ctrr-d', 'upper', 0x2848)], False),
    ('ctrr-d-upper-0x2838-below', ['slc'], SERVED_APERTURE,
     [('amcc-ctrr-d', 'upper', 0x2838)], False),
    ('ctrr-b-lower-0x27f8-global-adjacent', ['slc'], GLOBAL_APERTURE,
     [('amcc-ctrr-b', 'lower', 0x27f8)], False),
    ('ctrr-c-upper-0x830-global-adjacent', ['slc'], GLOBAL_APERTURE,
     [('amcc-ctrr-c', 'upper', 0x830)], False),
    ('ctrr-all-banks-adjacent', ['slc'], SERVED_APERTURE,
     [('amcc-ctrr-a', 'lower', 0x27f8), ('amcc-ctrr-a', 'upper', 0x2808),
      ('amcc-ctrr-b', 'lower', 0x2838), ('amcc-ctrr-b', 'upper', 0x2848),
      ('amcc-ctrr-c', 'lower', 0x2800 - 0x10), ('amcc-ctrr-c', 'upper', 0x2850),
      ('amcc-ctrr-d', 'lower', 0x2810), ('amcc-ctrr-d', 'upper', 0x2830)], False),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def adt_headers(blob):
    """{node path: {property: header offset}} for a serialized ADT."""
    cursor, nodes = 0, {}

    def walk(parent, depth):
        nonlocal cursor
        count, children = struct.unpack_from('<II', blob, cursor)
        cursor += 8
        props, name = {}, None
        for _ in range(count):
            raw = blob[cursor:cursor + 32].split(b'\0', 1)[0].decode()
            length = struct.unpack_from('<I', blob, cursor + 32)[0] & 0x7fffffff
            props[raw] = cursor
            if raw == 'name':
                name = blob[cursor + 36:cursor + 36 + length].split(b'\0', 1)[0].decode()
            cursor += 36 + ((length + 3) & ~3)
        path = '/' if depth == 0 else ('/' + name if depth == 1 else parent + '/' + name)
        nodes[path] = props
        for _ in range(children):
            walk(path, depth + 1)

    walk('', 0)
    require(cursor == len(blob), 'ADT walk consumed the whole tree')
    return nodes


def edit_donors(edits):
    """The donor each edit renames: a 4-byte donor in order, dramcfg-data for size 8."""
    narrow = iter(DONORS)
    return [WIDE_DONOR if size == 8 else next(narrow) for _, _, size in edits]


def optional_tree(base, edits):
    """Rename one unvalidated donor per property and store value. Sizes 1..4
    rewrite a 4-byte donor's length (padding unchanged); size 0 also drops its
    4 data bytes; size 8 renames the 8-byte dramcfg-data (value in the low word)."""
    blob = bytearray(base)
    headers = adt_headers(bytes(blob))['/arm-io/mcc']
    removed = None
    for (name, value, size), donor in zip(edits, edit_donors(edits)):
        require(name not in headers and donor in headers, 'Donor present, target absent')
        offset = headers[donor]
        flags = struct.unpack_from('<I', blob, offset + 32)[0]
        if size == 8:
            require(flags & 0x7fffffff == 8, 'Wide donor is an 8-byte property')
            blob[offset:offset + 32] = name.encode().ljust(32, b'\0')
            struct.pack_into('<Q', blob, offset + 36, value)
            continue
        require(flags & 0x7fffffff == 4 and 0 <= size <= 4, 'Donor is a 4-byte property')
        blob[offset:offset + 32] = name.encode().ljust(32, b'\0')
        struct.pack_into('<I', blob, offset + 32, (flags & 0x80000000) | size)
        struct.pack_into('<I', blob, offset + 36, value)
        if size == 0:
            require(removed is None, 'At most one size-0 edit per tree')
            removed = offset + 36
    if removed is not None:
        # Later header offsets shift by 4; drop the bytes after all in-place edits.
        del blob[removed:removed + 4]
    result = bytes(blob)
    adt_headers(result)   # still walks to the exact end
    return result


def amcc_bounds(blob):
    """(aperture base, size, {(bank, 'lower'|'upper'): offset}) as map_amcc reads them."""
    nodes = adt_headers(blob)
    amcc = nodes['/chosen/lock-regs/amcc']
    base = struct.unpack_from('<Q', blob, amcc['aperture-phys-addr'] + 36)[0]
    size = struct.unpack_from('<I', blob, amcc['aperture-size'] + 36)[0]
    regs = {}
    for bank in BANKS:
        props = nodes.get('/chosen/lock-regs/amcc/' + bank, {})
        for which in ('lower', 'upper'):
            key = which + '-limit-reg-offset'
            if key in props:
                regs[(bank, which)] = struct.unpack_from('<I', blob, props[key] + 36)[0]
    return base, size, regs


def ctrr_tree(base, aperture, edits):
    """Served-tree copy with the given aperture and bound-register offsets."""
    blob = bytearray(aperture_tree(base, *aperture))
    nodes = adt_headers(bytes(blob))
    for bank, which, value in edits:
        offset = nodes['/chosen/lock-regs/amcc/' + bank][which + '-limit-reg-offset']
        require(struct.unpack_from('<I', blob, offset + 32)[0] & 0x7fffffff == 4,
                'Bound offset is a 32-bit property')
        struct.pack_into('<I', blob, offset + 36, value)
    return bytes(blob)


def slc_overlaps(aperture, regs):
    """SLC views inside the aperture that overlap its lock word or a bound register,
    by the v4 rule (the oracle the refusal cases are classified with)."""
    base, size = aperture
    hits = []
    for view in SLC_VIEWS:
        if not base <= view < base + size:
            continue
        for label, reg in [('lock-word', 0)] + [(f'{b}:{w}', r) for (b, w), r in
                                               sorted(regs.items()) if r]:
            if view < base + reg + 8 and base + reg < view + 4:
                hits.append((hex(view), label, hex(reg)))
    return hits


def lock_word_unreachable():
    """Enumerate every aperture base map_amcc accepts (0x1000-aligned, size
    0x1000..0x100000) that could contain an SLC view: none puts a view inside
    its lock word [base, base + 8)."""
    low = (min(SLC_VIEWS) - 0x100000) & ~0xfff
    bases = range(low, max(SLC_VIEWS) + 0x1000, 0x1000)
    hits = [hex(b) for b in bases for v in SLC_VIEWS if v < b + 8 and b < v + 4]
    return {'bases_checked': len(bases), 'first_base': hex(bases[0]), 'last_base': hex(bases[-1]),
            'view_offsets_mod_0x1000': sorted({hex(v & 0xfff) for v in SLC_VIEWS}),
            'overlapping_bases': hits, 'unreachable': not hits,
            'reason': ('apple_modern_amcc_init requires a 0x1000-aligned aperture base, so the '
                       'lock word is [0x000, 0x008) mod 0x1000, and every SLC view is 4 bytes at '
                       '0x800, 0x804, 0x82c or 0x844 mod 0x1000; offset 0 is never a bound '
                       'register (0 means the bank has none). The carve\'s lock-word refusal '
                       'therefore cannot be reached from an ADT; only the CTRR-register refusal '
                       'is gated on a board.')}


def aperture_tree(base, address, size):
    blob = bytearray(base)
    headers = adt_headers(bytes(blob))['/chosen/lock-regs/amcc']
    for name, fmt, value in (('aperture-phys-addr', '<Q', address), ('aperture-size', '<I', size)):
        offset = headers[name]
        require(struct.unpack_from('<I', blob, offset + 32)[0] & 0x7fffffff ==
                struct.calcsize(fmt), 'Aperture property width')
        struct.pack_into(fmt, blob, offset + 36, value)
    return bytes(blob)


def verify_tree(original, edited, changed):
    """Only the named /arm-io/mcc, aperture or bound-register properties differ;
    it still parses."""
    before, _ = mailbox.metadata.parse_adt(original)
    after, _ = mailbox.metadata.parse_adt(edited)
    require(list(before) == list(after), 'Same node set and order')
    differences = []
    for path in before:
        names = set(before[path]) | set(after[path])
        for name in sorted(names):
            old = before[path].get(name, {}).get('value')
            new = after[path].get(name, {}).get('value')
            if old != new:
                differences.append(f'{path}:{name}')
    require(sorted(differences) == sorted(changed), 'Exactly the intended edits: ' +
            str(differences))
    return differences


def mtree(qmp, flat):
    text = qmp.request('human-monitor-command',
                       {'command-line': 'info mtree -f' if flat else 'info mtree'})
    lines, entries, inside = text.splitlines(), [], False
    for index, line in enumerate(lines):
        if not inside:
            inside = (line.startswith('FlatView') and any(
                item.strip().startswith('AS "memory"') for item in lines[index + 1:index + 4])
                if flat else line.strip() == 'address-space: memory')
            continue
        if not line.strip():
            break
        match = MTREE_LINE.match(line)
        if match:
            entries.append((int(match.group(1), 16), int(match.group(2), 16),
                            int(match.group(3)), match.group(5),
                            int(match.group(6), 16) if match.group(6) else 0))
    require(inside, 'HMP info mtree lists system memory')
    return entries


def xp32(qmp, address):
    text = qmp.request('human-monitor-command', {'command-line': f'xp /1wx {address:#x}'})
    match = XP_LINE.match(text.strip())
    require(match and int(match.group(1), 16) == address, 'xp output: ' + text.strip())
    return int(match.group(2), 16)


def xp64(qmp, address):
    text = qmp.request('human-monitor-command', {'command-line': f'xp /1gx {address:#x}'})
    match = XP64_LINE.match(text.strip())
    require(match and int(match.group(1), 16) == address, 'xp output: ' + text.strip())
    return int(match.group(2), 16)


def bound_values(blobs, regs):
    """{aperture offset: 64-bit board value} for the lock word and every bound
    register. map_amcc stores only the offsets; construction then programs
    bank C with the ACC_CTRR_C window (DeviceTree first page .. SPTM-rx last
    page), computed here from the independent Python layout."""
    layout = board.expected_layout(blobs)
    tree_region, sptm_rx = layout['regions']['DeviceTree'], layout['regions']['SPTM-rx']
    bank_c = (tree_region[0], sptm_rx[0] + sptm_rx[1] - 0x1000)
    values = {0: 0}
    for (bank, which), reg in regs.items():
        if reg:
            values[reg] = bank_c[which == 'upper'] if bank == 'amcc-ctrr-c' else 0
    return values, bank_c


def check_bound_registers(qmp, aperture, regs, flat, values):
    """v4: the lock word and every bound register stay wholly with the aperture."""
    base, _ = aperture
    pieces = [(s, e, o) for s, e, _, n, o in flat if n == 'apple-modern.amcc']
    out = {}
    for label, reg in [('lock-word', 0)] + [(f'{b}:{w}', r) for (b, w), r in
                                           sorted(regs.items()) if r]:
        start, end = base + reg, base + reg + 7
        holder = [(s, e) for s, e, _ in pieces if s <= start and end <= e]
        require(len(holder) == 1, f'{label} [{start:#x}, {end + 1:#x}) lies in one aperture piece')
        require(not any(s <= end and start <= e for s, e, _, n, _ in flat
                        if n != 'apple-modern.amcc'), f'{label}: nothing else maps over it')
        value = xp64(qmp, start)
        require(value == values[reg], f'{label} reads its board value {values[reg]:#x} '
                f'through the bus (got {value:#x})')
        out[label] = {'offset': hex(reg), 'address': hex(start),
                      'aperture_piece': [hex(holder[0][0]), hex(holder[0][1])],
                      'xp_64': hex(value)}
    return out


def check_slc_carve(qmp, aperture, regs, values):
    base, size = aperture
    end = base + size
    inside = sorted(a for a in SLC_VIEWS if base <= a < end)
    tree, flat = mtree(qmp, False), mtree(qmp, True)
    views = sorted((s, e, p) for s, e, p, n, _ in tree if n == REGIONS['slc'][0])
    expected = sorted((a, a + 3, 1 if a in inside else 0) for a in SLC_VIEWS)
    require(views == expected, 'SLC views: priority 1 exactly inside the aperture: ' +
            str([(hex(s), p) for s, _, p in views]))
    require(sorted((s, e, p) for s, e, p, n, _ in flat if n == REGIONS['slc'][0]) == expected,
            'Every SLC view is visible in the flat view')
    require([(s, e, p) for s, e, p, n, _ in tree if n == 'apple-modern.amcc'] ==
            [(base, end - 1, 0)], 'Compatibility aperture mapped whole at priority 0')
    pieces, cursor = [], base
    for address in inside:
        if address > cursor:
            pieces.append((cursor, address - 1))
        cursor = address + 4
    if cursor < end:
        pieces.append((cursor, end - 1))
    flat_pieces = sorted((s, e) for s, e, _, n, _ in flat if n == 'apple-modern.amcc')
    require(flat_pieces == pieces, 'Flat view: aperture minus exactly the inside views: ' +
            str([(hex(s), hex(e)) for s, e in flat_pieces]))
    require(all(offset == s - base for s, _, _, n, offset in flat if n == 'apple-modern.amcc'),
            'Aperture pieces keep their aperture offsets')
    reads = {}
    for address in SLC_STATUS:
        reads[hex(address)] = xp32(qmp, address)
        require(reads[hex(address)] == RESET_STATUS, f'{address:#x} reads the 12-way status')
    for address in SLC_FLUSH:
        reads[hex(address)] = xp32(qmp, address)
        require(reads[hex(address)] == 0, f'{address:#x} flush status reads 0')
    neighbours = {}
    for address in inside:
        for neighbour in (address - 4, address + 4):
            if base <= neighbour < end and neighbour not in SLC_VIEWS:
                # A 4-byte read matches a bound register only at its start.
                want = values.get(neighbour - base, 0) & 0xffffffff
                neighbours[hex(neighbour)] = xp32(qmp, neighbour)
                require(neighbours[hex(neighbour)] == want,
                        f'Aperture neighbour {neighbour:#x} still reads {want:#x}')
    if not inside:
        neighbours[hex(base)] = xp32(qmp, base)
        require(neighbours[hex(base)] == 0, 'Uncarved aperture still reads 0')
    bound = check_bound_registers(qmp, aperture, regs, flat, values)
    count = qmp.request('qom-get', {'path': QOM['slc'], 'property': 'mmio-read-count'})
    require(count == len(SLC_STATUS) + len(SLC_FLUSH), 'Only the SLC reads reached the SLC')
    return {'aperture': [hex(base), hex(size)], 'views_inside': [hex(a) for a in inside],
            'bound_registers_with_aperture': bound,
            'priority_1_views': [hex(s) for s, _, p in views if p == 1],
            'plainly_mapped_views': [hex(s) for s, _, p in views if p == 0],
            'aperture_flat_pieces': [[hex(s), hex(e)] for s, e in flat_pieces],
            'slc_reads_through_bus': reads, 'aperture_neighbour_reads': neighbours,
            'slc_mmio_read_count': count}


def expected_log(devices, rejection):
    """Warnings of the devices constructed (in construction order) and, for a
    refused board, the refusal line; the refusing device is named by the
    message prefix (the overlap refusal is the SLC's)."""
    failing = None
    if rejection:
        failing = ('slc' if rejection == OVERLAP_ERROR else
                   next(d for p, d in PREFIX_DEVICE.items() if rejection.startswith(p + ': ')))
        require(failing in devices, 'The refusing device is enabled')
    lines = [ANNOUNCEMENTS[d] for d in CONSTRUCTION_ORDER if d in devices and
             (failing is None or CONSTRUCTION_ORDER.index(d) < CONSTRUCTION_ORDER.index(failing))]
    return lines + ([rejection] if rejection else [])


def run_case(binary, components, tree_path, devices, rejection, output, aperture=None,
             regs=None, values=None):
    output.mkdir(parents=True, exist_ok=False)
    assets = {name: (tree_path if name == 'dtree' else components / name)
              for name in board.ASSETS}
    machine = 'apple-modern,' + ','.join(name + '=' + str(assets[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true' + ''.join(f',modern-mcc-{d}=on' for d in devices)
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1', '-nodefaults',
            '-display', 'none', '-serial', 'none', '-monitor', 'none', '-S', '-qmp', 'stdio']
    result = {'argv': argv, 'devices': devices, 'expected_rejection': rejection,
              'passed': False, 'child_reaped': False}
    started = time.monotonic()
    process = qmp = None
    log_path = output / 'emulator.log'
    try:
        with log_path.open('xb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=log, bufsize=0, preexec_fn=mailbox.child_limits)
            if rejection:
                result['child_exit_code'] = process.wait(timeout=30)
                result['child_reaped'] = True
                process = None
                log.flush()
                text = log_path.read_text(errors='replace')
                result['stderr'] = text
                require(result['child_exit_code'] == 1, 'Board refuses to start (exit 1)')
                # error_report() prints the message alone (no program prefix
                # here). v4: the whole log is matched; only warnings of the
                # devices constructed before the refusing one may precede it.
                lines = [line for line in text.splitlines() if line.strip()]
                result['expected_log'] = expected_log(devices, rejection)
                require(lines == result['expected_log'],
                        'Exactly the expected warnings and plan error: ' + repr(lines))
                result['passed'] = True
                return result

            def guard():
                remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                require(remaining > 0 and log_path.stat().st_size < mailbox.MAX_LOG,
                        'Board gate wall/log bound')
                return remaining
            qmp = helper.QMP(None, guard, process)
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'})
                    is True, 'Prepare-only board: no firmware executes')
            require(qmp.request('query-status')['running'] is False, 'CPU stopped')
            tree = mtree(qmp, False)
            result['devices_constructed'] = {}
            for device in REGIONS:
                region, views = REGIONS[device]
                mapped = sum(1 for entry in tree if entry[3] == region)
                require(mapped == (views if device in devices else 0),
                        f'{device}: {mapped} views mapped')
                if device in devices:
                    require(qmp.request('qom-get', {'path': QOM[device],
                            'property': 'mmio-read-count'}) == 0, device + ' constructed')
                result['devices_constructed'][device] = device in devices
            if aperture:
                result['carve'] = check_slc_carve(qmp, aperture, regs, values)
            qmp.request('quit')
            result['child_exit_code'] = process.wait(timeout=10)
            result['child_reaped'] = True
            process = None
            require(result['child_exit_code'] == 0, 'Clean emulator exit')
            log.flush()
            text = log_path.read_text(errors='replace')
            require(('is not modelled' in text) is False, 'No plan error on accepted trees')
            require((SLC_ANNOUNCEMENT in text) == ('slc' in devices),
                    'SLC declared profile announced exactly when mapped')
            result['expected_log'] = expected_log(devices, None)
            require([line for line in text.splitlines() if line.strip()] ==
                    result['expected_log'], 'Log is exactly the constructed devices\' warnings')
            result['passed'] = True
            return result
    except Exception as error:
        result['error'] = str(error)
        return result
    finally:
        if process:
            process.kill()
            result['child_exit_code'] = process.wait(timeout=10)
            result['child_reaped'] = True
        if qmp:
            qmp.close()
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True,
                        help='boot components; <components>/dtree is the stock tree')
    parser.add_argument('--served-dtree', type=Path, required=True,
                        help='served tree with /chosen/lock-regs/amcc')
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary, components = args.binary.resolve(), args.components.resolve()
    bases = {'stock': (components / 'dtree').read_bytes(),
             'served': args.served_dtree.resolve().read_bytes()}
    inputs = {str(binary): sha(binary.read_bytes()),
              str(components / 'dtree'): sha(bases['stock']),
              str(args.served_dtree.resolve()): sha(bases['served'])}
    inputs.update({str(components / name): sha((components / name).read_bytes())
                   for name in board.ASSETS if name != 'dtree'})
    require('aperture-phys-addr' in adt_headers(bases['served'])['/chosen/lock-regs/amcc'] and
            'aperture-phys-addr' not in adt_headers(bases['stock']).get(
                '/chosen/lock-regs/amcc', {}),
            'Served tree has the compatibility aperture; stock does not')
    (output / 'trees').mkdir()
    component_blobs = {name: (components / name).read_bytes() for name in board.ASSETS
                       if name != 'dtree'}
    report = {'script_sha256': sha(Path(__file__).read_bytes()), 'inputs': inputs,
              'firmware_executed': False, 'ios_boot_claim': False,
              'donors': list(DONORS), 'wide_donor': WIDE_DONOR, 'cases': {}}
    for name, devices, base, edits, rejection in OPTIONAL_CASES:
        edited = optional_tree(bases[base], edits)
        changed = verify_tree(bases[base], edited,
                              [f'/arm-io/mcc:{d}' for d in edit_donors(edits)] +
                              [f'/arm-io/mcc:{e[0]}' for e in edits])
        path = output / 'trees' / f'{name}.dtree'
        path.write_bytes(edited)
        result = run_case(binary, components, path, devices, rejection, output / name)
        result.update({'kind': 'optional-property', 'base_tree': base, 'edits':
                       [{'property': p, 'value': hex(v), 'size': s} for p, v, s in edits],
                       'tree_sha256': sha(edited), 'changed_properties': changed})
        report['cases'][name] = result
        print(json.dumps({'case': name, 'passed': result['passed'],
                          'error': result.get('error')}), flush=True)
    for name, address, size in APERTURE_CASES:
        edited = aperture_tree(bases['served'], address, size)
        expected_changes = [f'/chosen/lock-regs/amcc:{p}' for p, v in
                            (('aperture-phys-addr', address != AMCC),
                             ('aperture-size', size != 0x4000)) if v]
        changed = verify_tree(bases['served'], edited, expected_changes)
        path = output / 'trees' / f'{name}.dtree'
        path.write_bytes(edited)
        _, _, regs = amcc_bounds(edited)
        require(not slc_overlaps((address, size), regs), 'Carve cases overlap no bound register')
        values, bank_c = bound_values({**component_blobs, 'dtree': edited}, regs)
        result = run_case(binary, components, path, ['slc'], None, output / name,
                          aperture=(address, size), regs=regs, values=values)
        result.update({'kind': 'aperture-carve', 'base_tree': 'served',
                       'bank_c_board_bounds': [hex(v) for v in bank_c],
                       'tree_sha256': sha(edited), 'changed_properties': changed})
        report['cases'][name] = result
        print(json.dumps({'case': name, 'passed': result['passed'],
                          'error': result.get('error')}), flush=True)
    served_regs = amcc_bounds(bases['served'])[2]
    for name, devices, aperture, edits, refused in CTRR_CASES:
        edited = ctrr_tree(bases['served'], aperture, edits)
        base_now, size_now, regs = amcc_bounds(edited)
        require((base_now, size_now) == aperture, 'Edited aperture reads back')
        overlaps = slc_overlaps(aperture, regs)
        # The case table must agree with the v4 rule applied independently:
        # refused exactly when SLC is on and an in-aperture view overlaps.
        require(refused == (bool(overlaps) and 'slc' in devices),
                'Case table agrees with the overlap rule: ' + str(overlaps))
        rejection = OVERLAP_ERROR if refused else None
        expected_changes = sorted(
            [f'/chosen/lock-regs/amcc:{p}' for p, v in
             (('aperture-phys-addr', aperture[0] != AMCC),
              ('aperture-size', aperture[1] != 0x4000)) if v] +
            [f'/chosen/lock-regs/amcc/{b}:{w}-limit-reg-offset' for b, w, value in edits
             if served_regs[(b, w)] != value])
        changed = verify_tree(bases['served'], edited, expected_changes)
        path = output / 'trees' / f'{name}.dtree'
        path.write_bytes(edited)
        carve = aperture if 'slc' in devices and not refused else None
        values, bank_c = bound_values({**component_blobs, 'dtree': edited}, regs)
        result = run_case(binary, components, path, devices, rejection, output / name,
                          aperture=carve, regs=regs, values=values)
        result.update({'kind': 'ctrr-overlap', 'base_tree': 'served',
                       'bank_c_board_bounds': [hex(v) for v in bank_c],
                       'aperture': [hex(aperture[0]), hex(aperture[1])],
                       'edits': [{'bank': b, 'register': w, 'offset': hex(v)} for b, w, v in edits],
                       'bound_registers': {f'{b}:{w}': hex(r) for (b, w), r in sorted(regs.items())},
                       'overlaps_by_v4_rule': overlaps,
                       'tree_sha256': sha(edited), 'changed_properties': changed})
        report['cases'][name] = result
        print(json.dumps({'case': name, 'passed': result['passed'],
                          'error': result.get('error')}), flush=True)
    report['lock_word_overlap'] = lock_word_unreachable()
    require(report['lock_word_overlap']['unreachable'], 'Lock-word overlap proof')
    report['inputs_unchanged'] = inputs == {
        **{str(binary): sha(binary.read_bytes()),
           str(components / 'dtree'): sha((components / 'dtree').read_bytes()),
           str(args.served_dtree.resolve()): sha(args.served_dtree.resolve().read_bytes())},
        **{str(components / n): sha((components / n).read_bytes())
           for n in board.ASSETS if n != 'dtree'}}
    report['straddle_unreachable'] = (
        'apple_modern_amcc_init requires a 0x1000-aligned aperture base and size; every SLC '
        'view is 4 bytes at an address = 0x800, 0x804, 0x82c or 0x844 mod 0x1000, so no '
        'aperture edge can split a view and carve_amcc_aperture\'s straddle error cannot be '
        'reached from an ADT')
    report['all_children_reaped'] = all(c.get('child_reaped') for c in report['cases'].values())
    report['passed'] = (all(c['passed'] for c in report['cases'].values()) and
                        report['inputs_unchanged'] and report['all_children_reaped'] and
                        report['lock_word_overlap']['unreachable'])
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'cases': len(report['cases']),
                      'failed': [k for k, v in report['cases'].items() if not v['passed']]}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
