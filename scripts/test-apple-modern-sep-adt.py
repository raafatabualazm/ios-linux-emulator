#!/usr/bin/env python3
"""Pin every Apple Device Tree fact an emulated SEP ASC mailbox would key on.

This is a pure-measurement gate. It reads four read-only ADT blobs, parses them
with a self-contained strict parser, and asserts the geometry a device would
derive at runtime. Nothing is built, no guest runs, no device code is touched,
and no blob is opened for writing.

WHAT THIS PROVES
  * The four firmware assets are the exact bytes recorded here (path, size and
    sha256 are in the report), so an asset swap changes the output and fails
    loudly instead of silently moving a device.
  * The ADT parse is exact: every byte of every blob is claimed by the parse
    and there are zero trailing bytes. Both are measured and reported, not
    asserted by a constructor that would have raised first (the parse runs
    non-strict here precisely so a damaged blob produces a named failure and a
    report instead of a traceback). A set of in-memory mutations is rejected
    under the strict parse, so "it parsed" is a real constraint.
  * The /arm-io "ranges" translator is right BEFORE it is trusted about SEP:
    the same unmodified code path that translates the SEP windows reproduces
    the two already-pinned results, AIC 0x301000000 and uart0 0x385200000, and
    a deliberate one-cell decode is shown to get uart0 wrong. Two address cells
    are therefore measured, not assumed. Translation also requires the whole
    window to fit inside the matched ranges triple, not merely its base.
  * /arm-io/sep geometry: both reg windows and their absolute bases, the four
    interrupt numbers, and that interrupt-parent resolves to the unique
    /arm-io/aic node with one interrupt cell. This is identical in all four
    blobs, so it is safe to key a device on.
  * The facts that legitimately DIFFER between the stock tree and the tree
    Darwin actually serves are asserted per blob, never globally. The headline
    one: a device enumerating by a "compatible" containing "ascwrap-v6" finds
    thirteen nodes in the stock tree and NOTHING in the served tree.
  * The tree-wide negative: no node anywhere carries "interrupt-names", checked
    both through the parser and by scanning the raw bytes.

WHAT THIS DOES NOT PROVE
  * Nothing about any register layout. The ADT gives a base and a size. It does
    not describe a single mailbox register, an inbox, an outbox, a doorbell, or
    an event/acknowledge offset. None of that is derivable from these bytes.
  * Nothing about which interrupt is which condition. There is no
    "interrupt-names" property anywhere in any of these trees, so the four SEP
    interrupts are known only by position. Any slot-to-condition map is a
    project choice and must be declared as one, not reported as ADT-derived.
  * Nothing about "v6" semantics, ASC protocol, message format, or what the
    two reg windows are FOR. "win0" below means reg pair index 0; the tree does
    not name it a mailbox aperture, and on eight of the thirteen ascwrap nodes
    reg pair index 1 is not even the last window.
  * Nothing about /arm-io/aic's "aic-iack-offset", which appears only in the
    served trees. Its bytes are recorded; its meaning is not established here
    and it is deliberately NOT folded into any offset this project declares.

CORRECTIONS TO THE PRIOR RECONCILED FACT SET (measured, see report):
  * Translatable /arm-io windows are 343 in the stock trees and 339 in the
    served trees, not "359 identical across all four". The 4-window gap is
    exactly the stock-only /arm-io/dockchannel-uart and /arm-io/sgx.
  * The exact string "iop,ascwrap-v6" occurs on 11 nodes, not 10. Only 11+1+1
    closes against the 13 substring matches.
  * The 13 untranslatable windows span 9 nodes, not 8.
  * "320 nodes differ stock to served" holds only when lenword and padding are
    ignored; comparing the bytes as stored gives 333.

TWO CHECKS THAT ARE REFACTOR GUARDS, NOT INDEPENDENT EVIDENCE
  "child counts close on the node count" and "re-serializes byte-identically"
  cannot fail while the parser is written as it is: the first is forced by one
  append per _node() call, the second by the coverage invariant plus parse
  order. They are kept so a future parser refactor that breaks either is
  caught, and they are named in report["structural_invariants_restated"] so no
  reader counts them as measurement. The coverage and trailing-byte checks are
  NOT in that set: with strict=False they are genuinely falsifiable and a blob
  with one extra byte fails them by name.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

LENGTH_MASK = 0x7FFFFFFF
FLAG_BIT = 0x80000000

# Every check this gate runs on the four real blobs, counting the one that
# asserts this number. Pinned because a pass count alone cannot tell "all
# green" from "a block stopped running": several blocks are conditional
# (measure_ascwrap on the stock profile, the guarded early returns), so a
# future edit that skips one would otherwise leave the gate quietly green.
EXPECTED_CHECKS = 302

# The four read-only assets, with the bytes each one is required to be. A swap
# shows up as a hash mismatch here before any geometry is read.
BLOBS = {
    "stock_evidence": {
        "relative": "modern-emulator/evidence/firmware-20261002/"
                    "boot-components/derived/dtree",
        "sha256": "0a29c3adc1b8621150445e7082630ac221b76a7a168cbff8a3e1f0d5c72992d0",
        "size": 354264, "profile": "stock",
        "role": "stock tree as decoded from the firmware asset",
    },
    "served": {
        "relative": "modern-emulator/runtime/darwin-reference-27/dtree",
        "sha256": "0e7223662172b7f67f96260ad576f887c517ad486d4f1bb239a7dafd752b84dd",
        "size": 341952, "profile": "served",
        "role": "tree Darwin's DT fixup actually serves the guest",
    },
    "served_sep": {
        "relative": "modern-emulator/runtime/darwin-reference-27/dtree-sep",
        "sha256": "bb9d0e153359704e94759a867ee9099052a8a600650c88821e09db6289f0eeda",
        "size": 342056, "profile": "served_sep",
        "role": "declared opt-in variant restoring the SEP compatible strings",
    },
    "stock_runtime": {
        "relative": "modern-emulator/runtime/darwin-reference-27/dtree.stock",
        "sha256": "0a29c3adc1b8621150445e7082630ac221b76a7a168cbff8a3e1f0d5c72992d0",
        "size": 354264, "profile": "stock",
        "role": "runtime copy of the stock tree, expected byte-identical",
    },
}

# Facts identical in all four blobs. A change here means the firmware moved.
SEP_REG_HEX = ("0000607200000000008008000000000000000572000000000000"
               "060000000000")
SEP_INTERRUPTS_HEX = "58010000570100005a01000059010000"
SEP_INTERRUPTS = [344, 343, 346, 345]
SEP_WIN0 = (0x72600000, 0x88000, 0x282600000)   # child offset, size, absolute
SEP_WIN1 = (0x72050000, 0x60000, 0x282050000)
SEP_PHANDLE = 0x62
NUB_PHANDLE = 0x63
NUB_NAME = "iop-sep-nub"
NUB_CHILDREN = ["Sandcat", "xART", "InvalidateHmac"]
AIC_PHANDLE = 0x20
AIC_BASE = 0x301000000          # already pinned by the AIC gate
UART0_BASE = 0x385200000        # already pinned by the AIC gate
ESM_WINDOW = (0x2C267C000, 0x4000, 0x4D267C000)
RANGES_HEX = (
    "00000000000000000000001002000000000000f00200000000000008040000000000"
    "0008040000000000000500000000000000900300000000000090030000000080060700"
    "000000000000b01c000000000000b01c0000000000001000000000000000c00b000000"
    "000000c00b0000000000002000000000000000800b000000000000800b000000000000"
    "4000000000000000980300000000000098030000000080060700000000")
RANGES_ENTRY0 = (0x0, 0x210000000, 0x2F0000000)
RANGES_TRIPLES = 7

# The thirteen stock nodes whose compatible contains "ascwrap-v6", measured.
# Columns: name, reg window count, win0 absolute, win0 size, win1 absolute,
# win1 size, interrupts. "win1" is reg pair index 1, which is NOT the last
# window on the eight nodes whose window count exceeds two.
ASCWRAP_V6 = [
    ("aop",      5,  0x310600000, 0x88000, 0x310050000, 0x4000,
     [391, 390, 393, 392]),
    ("aop2",     3,  0x311600000, 0x88000, 0x311050000, 0x4000,
     [399, 398, 401, 400]),
    ("pmp",      4,  0x300E00000, 0x88000, 0x300850000, 0x4000,
     [824, 823, 826, 825]),
    ("sep",      2,  0x282600000, 0x88000, 0x282050000, 0x60000,
     [344, 343, 346, 345]),
    ("sio",      2,  0x385E00000, 0x88000, 0x385850000, 0x4000,
     [1125, 1124, 1127, 1126]),
    ("ans",      13, 0x389600000, 0x88000, 0x389050000, 0x4000,
     [1008, 1007, 1010, 1009, 1039]),
    ("smc",      3,  0x30C600000, 0x88000, 0x30C050000, 0x4000,
     [582, 581, 584, 583]),
    ("mtp",      2,  0x314600000, 0x88000, 0x314050000, 0x4000,
     [1153, 1152, 1155, 1154]),
    ("dcp",      3,  0x412E00000, 0x88000, 0x412850000, 0x4000,
     [680, 679, 682, 681]),
    ("dcpext",   3,  0x416E00000, 0x88000, 0x416850000, 0x4000,
     [752, 751, 754, 753]),
    ("ispRtb",   6,  0x321600000, 0x88000, 0x321050000, 0x50000,
     [308, 307, 310, 309, 323, 324, 325, 326, 336]),
    ("gfx-asc",  2,  0x482600000, 0x88000, 0x482050000, 0x8,
     [994, 993, 996, 995]),
    ("gfx1-asc", 2,  0x482E00000, 0x88000, 0x482850000, 0x8,
     [998, 997, 1000, 999]),
]
ASCWRAP_WIN0_SIZE = 0x88000
ASCWRAP_WIN1_DELTA = 0x5B0000

# The exact compatible payloads behind those thirteen substring matches. The
# set is not one string: an exact-match probe on "iop,ascwrap-v6" finds 11, and
# /arm-io/ispRtb carries two NUL-separated strings, so a single-string reader
# mis-handles it.
ASCWRAP_COMPATIBLE_CENSUS = {
    "iop,ascwrap-v6\x00": 11,
    "iop-sep,ascwrap-v6\x00": 1,
    "iop-isp,ascwrap-v6\x00isp,s5l8960x\x00": 1,
}

# Traps a naive "for each reg under /arm-io" loop walks into. Measured on all
# four blobs; the lists are identical across them.
ANS_ZERO_WINDOWS = [2, 7, 8]
UNTRANSLATABLE = [
    ("aop-exclave-mailbox", 0, 0x35067C000, 0x4000),
    ("aop2-exclave-mailbox", 0, 0x35167C000, 0x4000),
    ("dcp-exclave-mailbox", 0, 0x452E7C000, 0x4000),
    ("isp-exclave-s-proxy", 0, 0x361800000, 0x480000),
    ("isp-exclave-s-proxy", 1, 0x3628AC000, 0x4000),
    ("isp-exclave-s-proxy", 2, 0x362780000, 0x10000),
    ("admac-base-s-proxy", 0, 0x353700000, 0x34000),
    ("admac-speaker-tx-ec-proxy", 0, 0x353700000, 0x34000),
    ("admac-receiver-tx-ec-proxy", 0, 0x353700000, 0x34000),
    ("siri-exclave-timebase", 0, 0x3482A8000, 0x4000),
    ("exdisplaypipe-s-proxy", 0, 0x450000000, 0xAFC000),
    ("exdisplaypipe-s-proxy", 1, 0x451000000, 0xAFC000),
    ("exdisplaypipe-s-proxy", 2, 0x4523B0000, 0x8000),
]
BLUETOOTH_REG_HEX = "0f00000000000000"
EXCLAVE_MAILBOX_SIBLINGS = ["aop-exclave-mailbox", "aop2-exclave-mailbox",
                            "dcp-exclave-mailbox"]
MAPPER_SEP_EXCLAVE_REG_HEX = "02000000"

# Facts that legitimately differ. Asserting one value for all four is wrong.
PROFILES = {
    "stock": {
        "nodes": 452, "properties": 5414, "sep_properties": 22,
        "sep_compatible": "iop-sep,ascwrap-v6\x00", "sep_compatible_index": 12,
        "nub_compatible": "iop-nub,sep\x00",
        "compatible_total": 291, "ascwrap_nodes": 13, "flagged_properties": 98,
        "nonzero_pad_properties": 5, "memory_map_properties": 19,
        "aic_iack_offset_hex": None, "translatable_windows": 343,
        "irq_behavior_map": (0x00000002, "0000", "2104"),
        "has_dockchannel_uart_and_sgx": True, "has_rtc": False,
        "has_secure_root_prefix": True,
    },
    "served": {
        "nodes": 451, "properties": 5206, "sep_properties": 21,
        "sep_compatible": None, "sep_compatible_index": None,
        "nub_compatible": None,
        "compatible_total": 4, "ascwrap_nodes": 0, "flagged_properties": 0,
        "nonzero_pad_properties": 0, "memory_map_properties": 53,
        "aic_iack_offset_hex": "0010000000000000", "translatable_windows": 339,
        "irq_behavior_map": (0x00000004, "00002104", ""),
        "has_dockchannel_uart_and_sgx": False, "has_rtc": True,
        "has_secure_root_prefix": False,
    },
    "served_sep": {
        "nodes": 451, "properties": 5208, "sep_properties": 22,
        "sep_compatible": "iop-sep,ascwrap-v6\x00", "sep_compatible_index": 21,
        "nub_compatible": "iop-nub,sep\x00",
        "compatible_total": 6, "ascwrap_nodes": 1, "flagged_properties": 0,
        "nonzero_pad_properties": 0, "memory_map_properties": 53,
        "aic_iack_offset_hex": "0010000000000000", "translatable_windows": 339,
        "irq_behavior_map": (0x00000004, "00002104", ""),
        "has_dockchannel_uart_and_sgx": False, "has_rtc": True,
        "has_secure_root_prefix": False,
    },
}

# Stock to served, measured. The arithmetic closes: 291 stock compatible =
# 285 lost on common nodes + 2 on stock-only nodes + 4 surviving in served.
FIXUP = {
    "common_nodes": 450,
    "nodes_losing_compatible": 285,
    "stock_only_nodes": ["/arm-io/dockchannel-uart", "/arm-io/sgx"],
    "served_only_nodes": ["/rtc"],
    "non_compatible_removals": [("/", "secure-root-prefix")],
    "nodes_differing_by_payload": 320,
    "nodes_differing_by_stored_bytes": 333,
}
# served to served_sep is exactly two restored properties and nothing else.
SEP_VARIANT_DELTA = [
    ("/arm-io/sep", "compatible", "iop-sep,ascwrap-v6\x00"),
    ("/arm-io/sep/iop-sep-nub", "compatible", "iop-nub,sep\x00"),
]
SEP_VARIANT_BYTES = 104


def require(value, message):
    if not value:
        raise RuntimeError(message)


class Property:
    """One ADT property, kept with enough detail to re-serialize exactly."""

    __slots__ = ("name", "raw_name", "lenword", "payload", "pad", "offset")


class Node:
    __slots__ = ("path", "name", "prop_count", "child_count", "props",
                 "children", "offset")


class ADT:
    """Strict Apple DeviceTree parser. Not an FDT parser.

    Node     := u32 prop_count, u32 child_count, properties, child nodes
    Property := char name[32], u32 length_and_flags, payload, pad to 4 bytes

    Every byte read is marked in a coverage bitmap, so a gap, an overlap or a
    trailing byte is an error rather than something the parse quietly tolerates.
    That strictness is what makes the geometry below worth anything.

    strict=True (the negative oracle) raises on a coverage gap or a trailing
    byte. strict=False (the per-blob measurement) records self.gaps and
    self.trailing instead, so those two facts are measured and reported by
    name rather than restating something the constructor already enforced.
    Double consumption and reads past the end always raise: the parse state
    after either is meaningless, so there is nothing honest left to measure.
    """

    MAX_DEPTH = 32          # matches walk() in modern-boot-metadata.c

    def __init__(self, data, strict=True):
        self.data = data
        self.size = len(data)
        self.pos = 0
        self.covered = bytearray(self.size)
        self.nodes = []
        self.by_path = {}
        self.max_depth = 0
        self.root = self._node(None, 0)
        self.trailing = self.size - self.pos
        self.gaps = self.covered.count(0)
        if strict:
            require(not self.gaps, "ADT coverage gap: %d byte(s), first at %#x"
                    % (self.gaps,
                       self.covered.index(0) if self.gaps else 0))
            require(self.trailing == 0,
                    "ADT does not consume the file exactly: %d trailing byte(s)"
                    % self.trailing)

    def _claim(self, offset, count):
        require(offset >= 0 and offset + count <= self.size,
                "ADT read past end of file at %#x (want %d, have %d)"
                % (offset, count, self.size - offset))
        for index in range(offset, offset + count):
            require(not self.covered[index],
                    "ADT byte at %#x consumed twice" % index)
            self.covered[index] = 1

    def _u32(self):
        self._claim(self.pos, 4)
        value = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def _property(self):
        prop = Property()
        prop.offset = self.pos
        self._claim(self.pos, 32)
        prop.raw_name = bytes(self.data[self.pos:self.pos + 32])
        self.pos += 32
        prop.lenword = self._u32()
        length = prop.lenword & LENGTH_MASK
        padded = (length + 3) & ~3
        # Bound-check the PADDED extent: the pad bytes belong to this property
        # and must be claimed, or the final property can run off the end.
        self._claim(self.pos, padded)
        prop.payload = bytes(self.data[self.pos:self.pos + length])
        prop.pad = bytes(self.data[self.pos + length:self.pos + padded])
        self.pos += padded
        terminator = prop.raw_name.find(b"\0")
        prop.name = (prop.raw_name if terminator < 0
                     else prop.raw_name[:terminator]).decode("ascii", "replace")
        return prop

    def _node(self, parent, depth):
        require(depth <= self.MAX_DEPTH,
                "ADT nesting deeper than %d at %#x; the house parsers "
                "(modern-boot-metadata.c walk(), parse_adt) stop here too"
                % (self.MAX_DEPTH, self.pos))
        self.max_depth = max(self.max_depth, depth)
        node = Node()
        node.offset = self.pos
        node.prop_count = self._u32()
        node.child_count = self._u32()
        require(node.prop_count <= 4096 and node.child_count <= 4096,
                "Implausible ADT node counts at %#x: %d properties, %d children"
                % (node.offset, node.prop_count, node.child_count))
        node.props = [self._property() for _ in range(node.prop_count)]
        seen = set()
        for prop in node.props:
            require(prop.name not in seen,
                    "Duplicate ADT property name %r in the node at %#x; "
                    "prop() would read the first and flatten() the last"
                    % (prop.name, node.offset))
            seen.add(prop.name)
        named = [p for p in node.props if p.name == "name"]
        node.name = (named[0].payload.rstrip(b"\0").decode("ascii", "replace")
                     if named else "<unnamed@%#x>" % node.offset)
        node.path = "/" if parent is None else (
            parent.path.rstrip("/") + "/" + node.name)
        require(node.path not in self.by_path,
                "Duplicate ADT node path %s" % node.path)
        self.by_path[node.path] = node
        self.nodes.append(node)
        node.children = [self._node(node, depth + 1)
                         for _ in range(node.child_count)]
        return node

    def serialize(self):
        """Positive oracle: rebuild the file, pad bytes and all."""
        out = bytearray()

        def emit(node):
            out.extend(struct.pack("<II", node.prop_count, node.child_count))
            for prop in node.props:
                out.extend(prop.raw_name)
                out.extend(struct.pack("<I", prop.lenword))
                out.extend(prop.payload)
                out.extend(prop.pad)
            for child in node.children:
                emit(child)

        emit(self.root)
        return bytes(out)

    def prop(self, path, name):
        node = self.by_path.get(path)
        if node is None:
            return None
        for candidate in node.props:
            if candidate.name == name:
                return candidate
        return None

    def u32(self, path, name):
        """One u32 cell. Absent is None; present but not 4 bytes is an error.

        Slicing [:4] would silently truncate a wider payload and raise a bare
        struct.error on a narrower one. Every property read this way
        (#address-cells, #interrupt-cells, interrupt-parent, AAPL,phandle)
        feeds geometry, so a width change must be named, not absorbed.
        """
        prop = self.prop(path, name)
        if prop is None:
            return None
        require(len(prop.payload) == 4,
                "%s %s payload is %d bytes, not one u32 cell"
                % (path, name, len(prop.payload)))
        return struct.unpack("<I", prop.payload)[0]

    def string(self, path, name):
        prop = self.prop(path, name)
        return None if prop is None else prop.payload.decode("ascii", "replace")

    def properties(self):
        for node in self.nodes:
            for prop in node.props:
                yield node, prop


def cellspan(buffer, offset, cells):
    """Little-endian u32 cells, least significant first."""
    value = 0
    for index in range(cells):
        value |= struct.unpack_from("<I", buffer, offset + 4 * index)[0] << (32 * index)
    return value


class Translator:
    """/arm-io child offset to absolute address, via the "ranges" triples.

    One instance serves AIC, uart0 and SEP alike. The self-check below runs the
    two already-pinned results through THIS object before anything reads a SEP
    address out of it.
    """

    def __init__(self, adt):
        self.root_address_cells = adt.u32("/", "#address-cells")
        self.root_size_cells = adt.u32("/", "#size-cells")
        self.address_cells = adt.u32("/arm-io", "#address-cells")
        self.size_cells = adt.u32("/arm-io", "#size-cells")
        self.ranges = adt.prop("/arm-io", "ranges")
        require(self.ranges is not None, "/arm-io has no ranges property")
        self.stride = (self.address_cells + self.root_address_cells
                       + self.size_cells) * 4
        require(len(self.ranges.payload) % self.stride == 0,
                "/arm-io ranges payload %d bytes is not a multiple of the "
                "%d-byte triple stride" % (len(self.ranges.payload), self.stride))
        self.triples = []
        for base in range(0, len(self.ranges.payload), self.stride):
            child = cellspan(self.ranges.payload, base, self.address_cells)
            parent = cellspan(self.ranges.payload,
                              base + self.address_cells * 4,
                              self.root_address_cells)
            length = cellspan(self.ranges.payload,
                              base + (self.address_cells
                                      + self.root_address_cells) * 4,
                              self.size_cells)
            self.triples.append((child, parent, length))

    def translate(self, offset, size=0):
        """Return (absolute, matching triple count, contained).

        absolute is None when no triple's child window contains the base.
        contained is False when the base matches but offset + size runs past
        the end of that triple: such a window is NOT cleanly translatable and
        matching on the base alone would report a wrong address for its tail.
        With size 0 (a base-only query) contained is True by definition.
        """
        hits = [t for t in self.triples if t[0] <= offset < t[0] + t[2]]
        if not hits:
            return None, 0, False
        child, parent, length = hits[0]
        return (parent + (offset - child), len(hits),
                offset + size <= child + length)

    def windows(self, adt, path):
        """Reg pairs of a node. Returns None if absent, "ragged" if misaligned."""
        prop = adt.prop(path, "reg")
        if prop is None:
            return None
        stride = (self.address_cells + self.size_cells) * 4
        if len(prop.payload) % stride:
            return "ragged"
        out = []
        for base in range(0, len(prop.payload), stride):
            offset = cellspan(prop.payload, base, self.address_cells)
            size = cellspan(prop.payload, base + self.address_cells * 4,
                            self.size_cells)
            out.append((offset, size))
        return out


def first_window(translator, adt, path):
    """(offset, size) of reg pair 0, or None if there is no usable pair 0.

    windows() returns None for an absent reg and the sentinel "ragged" for a
    payload that is not a whole number of (address, size) pairs; an empty reg
    yields []. All three must stop a caller rather than be indexed.
    """
    windows = translator.windows(adt, path)
    if not isinstance(windows, list) or not windows:
        return None
    return windows[0]


def describe_windows(translator, adt, path):
    """Human-readable state of a node's reg, for a failure message."""
    windows = translator.windows(adt, path)
    if windows is None:
        return "absent" if path in adt.by_path else "absent (no such node)"
    if windows == "ragged":
        return ("ragged: %s" % adt.prop(path, "reg").payload.hex())
    return "%d window(s)" % len(windows)


def interrupts(adt, path):
    prop = adt.prop(path, "interrupts")
    if prop is None:
        return None
    require(len(prop.payload) % 4 == 0,
            "%s interrupts payload is %d bytes, not a whole number of cells"
            % (path, len(prop.payload)))
    return [struct.unpack_from("<I", prop.payload, i)[0]
            for i in range(0, len(prop.payload), 4)]


def digest(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def negative_oracle(name, data, adt):
    """Prove the parser is strict, by mutating copies in memory only.

    If a damaged tree still parsed, "it consumes the file exactly" would say
    nothing about the real one. Each mutation is located through the parse, not
    by scanning for a byte pattern, so it lands on a real structural field. The
    source blob is never touched; every mutation is a copy in memory.
    """
    results = []

    def rejected(label, mutated):
        try:
            ADT(mutated)
        except (RuntimeError, struct.error, IndexError, ValueError) as error:
            results.append({"mutation": label, "rejected": True,
                            "reason": str(error)[:140]})
            return
        results.append({"mutation": label, "rejected": False, "reason": ""})

    def patch(offset, value):
        return data[:offset] + struct.pack("<I", value) + data[offset + 4:]

    def length_word(prop):
        return prop.offset + 32

    rejected("one trailing byte appended", data + b"\0")
    rejected("one byte truncated", data[:-1])
    rejected("root property count incremented",
             patch(0, struct.unpack_from("<I", data)[0] + 1))
    rejected("root property count decremented",
             patch(0, struct.unpack_from("<I", data)[0] - 1))
    rejected("root child count incremented",
             patch(4, struct.unpack_from("<I", data, 4)[0] + 1))
    rejected("root child count decremented",
             patch(4, struct.unpack_from("<I", data, 4)[0] - 1))

    # Bit 31 read as length rather than as a flag. Only the stock trees carry
    # flagged properties, so this one is conditional on the blob.
    flagged = [p for _, p in adt.properties() if p.lenword & FLAG_BIT]
    if flagged:
        prop = flagged[0]
        rejected("flag bit of a flagged property folded into its length",
                 patch(length_word(prop), prop.lenword | 0x40000000))

    # Growing a 4-aligned payload by one byte adds four bytes of padding and
    # shifts every later node; shrinking a payload whose length is 1 mod 4
    # removes four. Either must break the exact-consumption invariant.
    grow = [p for _, p in adt.properties()
            if (p.lenword & LENGTH_MASK) and (p.lenword & LENGTH_MASK) % 4 == 0]
    shrink = [p for _, p in adt.properties()
              if (p.lenword & LENGTH_MASK) % 4 == 1]
    require(grow and shrink,
            "%s: negative oracle found no property to grow or shrink" % name)
    rejected("one property length grown past its padding",
             patch(length_word(grow[0]), grow[0].lenword + 1))
    rejected("one property length shrunk out of its padding",
             patch(length_word(shrink[0]), shrink[0].lenword - 1))

    accepted = [entry["mutation"] for entry in results if not entry["rejected"]]
    require(not accepted,
            "%s: negative oracle -- the parser accepted a mutated tree: %s"
            % (name, ", ".join(accepted)))
    return results


def measure(name, spec, path, checks):
    """Everything this gate measures from one blob."""
    data = path.read_bytes()
    record = digest(path)
    record["role"] = spec["role"]
    record["profile"] = spec["profile"]
    # Populated as each value is computed. A guarded early return leaves the
    # fields it never reached ABSENT rather than filled with an expectation.
    measured = {}
    record["measured"] = measured
    checks.add("%s: sha256 matches the recorded asset" % name,
               record["sha256"] == spec["sha256"],
               "%s sha256 is %s, recorded %s -- the firmware asset moved"
               % (path, record["sha256"], spec["sha256"]))
    checks.add("%s: size matches the recorded asset" % name,
               record["bytes"] == spec["size"],
               "%s is %d bytes, recorded %d -- the firmware asset moved"
               % (path, record["bytes"], spec["size"]))

    # Non-strict: a trailing byte or a coverage gap becomes a named failure in
    # this report rather than a RuntimeError with no report at all. The strict
    # parse is what the negative oracle exercises.
    adt = ADT(data, strict=False)
    profile = PROFILES[spec["profile"]]
    translator = Translator(adt)

    # ---- parse invariants ------------------------------------------------
    checks.add("%s: consumes the file exactly" % name, adt.trailing == 0,
               "%s left %d trailing byte(s)" % (name, adt.trailing))
    checks.add("%s: no coverage gap; every byte is claimed by the parse" % name,
               adt.gaps == 0,
               "%s left %d unclaimed byte(s); double consumption cannot reach "
               "here because _claim() raises on it" % (name, adt.gaps))
    round_trip = adt.serialize() == data
    checks.add("%s: re-serializes byte-identically" % name, round_trip,
               "%s does not round-trip; the parse loses information" % name)
    measured["trailing_bytes"] = adt.trailing
    measured["unclaimed_bytes"] = adt.gaps
    measured["round_trip_identical"] = round_trip
    measured["max_node_depth"] = adt.max_depth
    measured["nodes"] = len(adt.nodes)
    checks.add("%s: node count" % name, len(adt.nodes) == profile["nodes"],
               "%s has %d nodes, expected %d"
               % (name, len(adt.nodes), profile["nodes"]))
    total_properties = sum(node.prop_count for node in adt.nodes)
    measured["properties"] = total_properties
    checks.add("%s: property count" % name,
               total_properties == profile["properties"],
               "%s has %d properties, expected %d"
               % (name, total_properties, profile["properties"]))
    closure = sum(node.child_count for node in adt.nodes) + 1
    checks.add("%s: child counts close on the node count" % name,
               closure == len(adt.nodes),
               "%s child counts sum to %d, node count is %d"
               % (name, closure, len(adt.nodes)))

    # ---- address translation, checked before it is trusted ---------------
    checks.add("%s: / address and size cells are both 2" % name,
               (translator.root_address_cells, translator.root_size_cells) == (2, 2),
               "%s / cells are %r, expected (2, 2)"
               % (name, (translator.root_address_cells, translator.root_size_cells)))
    checks.add("%s: /arm-io address and size cells are both 2" % name,
               (translator.address_cells, translator.size_cells) == (2, 2),
               "%s /arm-io cells are %r, expected (2, 2)"
               % (name, (translator.address_cells, translator.size_cells)))
    checks.add("%s: /arm-io ranges payload is verbatim" % name,
               translator.ranges.payload.hex() == RANGES_HEX,
               "%s /arm-io ranges payload changed to %s"
               % (name, translator.ranges.payload.hex()))
    checks.add("%s: /arm-io ranges has %d triples" % (name, RANGES_TRIPLES),
               len(translator.triples) == RANGES_TRIPLES,
               "%s /arm-io ranges has %d triples, expected %d"
               % (name, len(translator.triples), RANGES_TRIPLES))
    checks.add("%s: ranges entry 0 is the /arm-io aperture" % name,
               translator.triples[0] == RANGES_ENTRY0,
               "%s ranges entry 0 is %r, expected %r"
               % (name, tuple(hex(v) for v in translator.triples[0]),
                  tuple(hex(v) for v in RANGES_ENTRY0)))
    identity = all(child == parent for child, parent, _ in translator.triples[1:])
    checks.add("%s: ranges triples 1-6 are identity mappings" % name, identity,
               "%s has a non-identity ranges triple past entry 0" % name)
    overlap = [(a, b) for index, a in enumerate(translator.triples)
               for b in translator.triples[index + 1:]
               if a[0] < b[0] + b[2] and b[0] < a[0] + a[2]]
    checks.add("%s: ranges child windows do not overlap" % name, not overlap,
               "%s ranges triples overlap, so first-match translation would "
               "depend on order: %r" % (name, overlap))

    # THE translation self-check. If these two are wrong, nothing this gate
    # says about a SEP address is worth reading, so it is a guarded early
    # return: a damaged translator must not go on to print SEP addresses.
    aic = first_window(translator, adt, "/arm-io/aic")
    uart0 = first_window(translator, adt, "/arm-io/uart0")
    checks.add("%s: /arm-io/aic has a usable first reg window" % name,
               aic is not None,
               "%s /arm-io/aic reg is %s; the translator self-check cannot run"
               % (name, describe_windows(translator, adt, "/arm-io/aic")))
    checks.add("%s: /arm-io/uart0 has a usable first reg window" % name,
               uart0 is not None,
               "%s /arm-io/uart0 reg is %s; the translator self-check cannot "
               "run" % (name, describe_windows(translator, adt, "/arm-io/uart0")))
    if aic is None or uart0 is None:
        return adt, record
    aic_base, aic_hits, aic_fits = translator.translate(*aic)
    uart0_base, uart0_hits, uart0_fits = translator.translate(*uart0)
    measured["aic_base"] = None if aic_base is None else hex(aic_base)
    measured["uart0_base"] = None if uart0_base is None else hex(uart0_base)
    self_check = (aic_base == AIC_BASE and aic_hits == 1 and aic_fits
                  and uart0_base == UART0_BASE and uart0_hits == 1
                  and uart0_fits)
    checks.add("%s: translator reproduces the pinned AIC base" % name,
               aic_base == AIC_BASE and aic_hits == 1 and aic_fits,
               "%s translates /arm-io/aic reg 0 to %s (size %#x, %d matching "
               "triple(s), fits inside its triple: %r), the pinned base is %#x "
               "-- the translator is wrong, so do not trust its SEP result"
               % (name, "unmapped" if aic_base is None else hex(aic_base),
                  aic[1], aic_hits, aic_fits, AIC_BASE))
    checks.add("%s: translator reproduces the pinned uart0 base" % name,
               uart0_base == UART0_BASE and uart0_hits == 1 and uart0_fits,
               "%s translates /arm-io/uart0 reg 0 to %s (size %#x, %d matching "
               "triple(s), fits inside its triple: %r), the pinned base is %#x "
               "-- the translator is wrong, so do not trust its SEP result"
               % (name, "unmapped" if uart0_base is None else hex(uart0_base),
                  uart0[1], uart0_hits, uart0_fits, UART0_BASE))
    # Negative control on the cell width: one cell gets uart0 wrong, so two
    # address cells are measured rather than assumed.
    uart0_reg = adt.prop("/arm-io/uart0", "reg")
    one_cell = cellspan(uart0_reg.payload, 0, 1)
    one_cell_base, _, _ = translator.translate(one_cell)
    checks.add("%s: a one-cell decode gets uart0 wrong" % name,
               one_cell_base != UART0_BASE,
               "%s decodes uart0 identically with one address cell, so this "
               "gate does not actually prove the cell width" % name)
    if not self_check:
        # Everything below reads an address out of this object. Stop here
        # rather than publish SEP numbers from a translator known to be wrong.
        return adt, record

    # ---- SEP geometry, identical in all four blobs ------------------------
    sep = adt.by_path.get("/arm-io/sep")
    checks.add("%s: /arm-io/sep exists" % name, sep is not None,
               "%s has no /arm-io/sep node" % name)
    if sep is None:
        return adt, record
    sep_reg = adt.prop("/arm-io/sep", "reg")
    checks.add("%s: /arm-io/sep has a reg property" % name, sep_reg is not None,
               "%s /arm-io/sep has no reg property" % name)
    if sep_reg is None:
        return adt, record
    measured["sep_reg_bytes"] = sep_reg.payload.hex()
    checks.add("%s: /arm-io/sep reg payload is verbatim" % name,
               sep_reg.payload.hex() == SEP_REG_HEX,
               "%s /arm-io/sep reg changed to %s"
               % (name, sep_reg.payload.hex()))
    sep_windows = translator.windows(adt, "/arm-io/sep")
    checks.add("%s: /arm-io/sep has exactly two reg windows" % name,
               isinstance(sep_windows, list) and len(sep_windows) == 2,
               "%s /arm-io/sep reg is %s, expected exactly 2 windows"
               % (name, describe_windows(translator, adt, "/arm-io/sep")))
    if not isinstance(sep_windows, list) or len(sep_windows) != 2:
        return adt, record
    sep_absolute = []
    for index, expected in enumerate((SEP_WIN0, SEP_WIN1)):
        offset, size = sep_windows[index]
        absolute, hits, fits = translator.translate(offset, size)
        sep_absolute.append(absolute)
        checks.add("%s: /arm-io/sep window %d" % (name, index),
                   (offset, size, absolute) == expected and hits == 1 and fits,
                   "%s /arm-io/sep window %d is child %#x size %#x -> %s "
                   "(%d matching ranges triple(s), fits inside its triple: %r),"
                   " expected child %#x size %#x -> %#x via exactly one triple"
                   % (name, index, offset, size,
                      "unmapped" if absolute is None else hex(absolute), hits,
                      fits, expected[0], expected[1], expected[2]))
    measured["sep_window0_absolute"] = (None if sep_absolute[0] is None
                                        else hex(sep_absolute[0]))
    measured["sep_window0_size"] = hex(sep_windows[0][1])
    measured["sep_window1_absolute"] = (None if sep_absolute[1] is None
                                        else hex(sep_absolute[1]))
    measured["sep_window1_size"] = hex(sep_windows[1][1])
    sep_interrupts_prop = adt.prop("/arm-io/sep", "interrupts")
    checks.add("%s: /arm-io/sep has an interrupts property" % name,
               sep_interrupts_prop is not None,
               "%s /arm-io/sep has no interrupts property" % name)
    if sep_interrupts_prop is None:
        return adt, record
    sep_interrupts = interrupts(adt, "/arm-io/sep")
    measured["sep_interrupts"] = sep_interrupts
    measured["sep_interrupts_bytes"] = sep_interrupts_prop.payload.hex()
    checks.add("%s: /arm-io/sep interrupts payload is verbatim" % name,
               sep_interrupts_prop.payload.hex() == SEP_INTERRUPTS_HEX,
               "%s /arm-io/sep interrupts changed to %s"
               % (name, sep_interrupts_prop.payload.hex()))
    checks.add("%s: /arm-io/sep interrupt numbers" % name,
               sep_interrupts == SEP_INTERRUPTS,
               "%s /arm-io/sep interrupts are %r, expected %r"
               % (name, sep_interrupts, SEP_INTERRUPTS))
    parent = adt.u32("/arm-io/sep", "interrupt-parent")
    measured["sep_interrupt_parent"] = None if parent is None else hex(parent)
    checks.add("%s: /arm-io/sep interrupt-parent phandle" % name,
               parent == AIC_PHANDLE,
               "%s /arm-io/sep interrupt-parent is %s, expected %#x"
               % (name, "absent" if parent is None else hex(parent), AIC_PHANDLE))
    phandles = [(node, prop) for node, prop in adt.properties()
                if prop.name == "AAPL,phandle"]
    odd = [(node.path, len(prop.payload)) for node, prop in phandles
           if len(prop.payload) != 4]
    checks.add("%s: every AAPL,phandle payload is one u32 cell" % name, not odd,
               "%s has AAPL,phandle properties that are not 4 bytes: %r; a "
               "[:4] read would silently truncate them" % (name, odd))
    owners = [node.path for node, prop in phandles
              if len(prop.payload) == 4
              and struct.unpack("<I", prop.payload)[0] == AIC_PHANDLE]
    checks.add("%s: phandle %#x resolves uniquely to /arm-io/aic"
               % (name, AIC_PHANDLE),
               owners == ["/arm-io/aic"],
               "%s resolves interrupt-parent %#x to %r, expected exactly "
               "['/arm-io/aic']" % (name, AIC_PHANDLE, owners))
    checks.add("%s: /arm-io/aic has one interrupt cell" % name,
               adt.u32("/arm-io/aic", "#interrupt-cells") == 1,
               "%s /arm-io/aic #interrupt-cells is %r, expected 1; with one "
               "cell the 16-byte SEP interrupts payload is 4 IRQs"
               % (name, adt.u32("/arm-io/aic", "#interrupt-cells")))
    checks.add("%s: /arm-io/aic compatible is aic,3" % name,
               adt.string("/arm-io/aic", "compatible") == "aic,3\x00",
               "%s /arm-io/aic compatible is %r, expected 'aic,3'"
               % (name, adt.string("/arm-io/aic", "compatible")))
    checks.add("%s: /arm-io/sep AAPL,phandle" % name,
               adt.u32("/arm-io/sep", "AAPL,phandle") == SEP_PHANDLE,
               "%s /arm-io/sep AAPL,phandle is %r, expected %#x"
               % (name, adt.u32("/arm-io/sep", "AAPL,phandle"), SEP_PHANDLE))
    nub = adt.by_path.get("/arm-io/sep/" + NUB_NAME)
    checks.add("%s: /arm-io/sep has exactly one child" % name,
               sep.child_count == 1 and nub is not None
               and sep.children[0].name == NUB_NAME,
               "%s /arm-io/sep has %d child/children (%r), expected one named %s"
               % (name, sep.child_count, [c.name for c in sep.children], NUB_NAME))
    if nub is None:
        return adt, record
    checks.add("%s: nub AAPL,phandle" % name,
               adt.u32(nub.path, "AAPL,phandle") == NUB_PHANDLE,
               "%s %s AAPL,phandle is %r, expected %#x"
               % (name, nub.path, adt.u32(nub.path, "AAPL,phandle"), NUB_PHANDLE))
    checks.add("%s: nub children" % name,
               [c.name for c in nub.children] == NUB_CHILDREN,
               "%s %s children are %r, expected %r"
               % (name, nub.path, [c.name for c in nub.children], NUB_CHILDREN))
    # The nub's own compatible is part of the declared SEP opt-in surface: it
    # is the SECOND property the dtree-sep variant restores, and it is not an
    # ascwrap string. Pin it per blob so a change has a named reason, not just
    # a hash mismatch.
    nub_compatible = adt.string(nub.path, "compatible")
    measured["nub_compatible"] = nub_compatible
    checks.add("%s: nub compatible" % name,
               nub_compatible == profile["nub_compatible"],
               "%s %s compatible is %r, expected %r for a %s tree"
               % (name, nub.path, nub_compatible, profile["nub_compatible"],
                  spec["profile"]))

    # ---- tree-wide negative: nothing names an interrupt -------------------
    named = [node.path for node, prop in adt.properties()
             if prop.name == "interrupt-names"]
    measured["interrupt_names_properties"] = len(named)
    measured["interrupt_names_nodes"] = named
    measured["interrupt_names_raw_string_occurrences"] = \
        data.count(b"interrupt-names")
    checks.add("%s: no interrupt-names property anywhere" % name, not named,
               "%s carries interrupt-names on %r. If Apple now names the SEP "
               "lines, the positional-only caveat in this file is obsolete and "
               "the interrupt map must be re-derived, not guessed." % (name, named))
    checks.add("%s: the raw bytes contain no interrupt-names string" % name,
               data.count(b"interrupt-names") == 0,
               "%s contains the raw string interrupt-names %d time(s) even "
               "though the parser found none -- the parser is missing a property"
               % (name, data.count(b"interrupt-names")))

    # ---- traps for the device code ---------------------------------------
    arm_io = adt.by_path["/arm-io"]
    translatable = 0
    untranslatable = []
    zero_windows = []
    ragged = []
    straddling = []
    for child in arm_io.children:
        windows = translator.windows(adt, child.path)
        if windows is None:
            continue
        if windows == "ragged":
            ragged.append((child.name,
                           adt.prop(child.path, "reg").payload.hex()))
            continue
        for index, (offset, size) in enumerate(windows):
            absolute, _, fits = translator.translate(offset, size)
            if offset == 0 and size == 0:
                zero_windows.append((child.name, index))
            elif absolute is None:
                untranslatable.append((child.name, index, offset, size))
            else:
                translatable += 1
                if not fits:
                    straddling.append((child.name, index, offset, size))
    # A window whose BASE is inside a ranges triple but whose END is past it
    # is not cleanly translatable: matching on the base alone would hand a
    # device a correct start and a wrong tail. Measured zero on all four blobs.
    checks.add("%s: every translatable window fits inside its ranges triple"
               % name, not straddling,
               "%s has /arm-io window(s) whose base translates but whose "
               "extent runs past the end of the matched ranges triple: %r"
               % (name, [(n, i, hex(o), hex(s)) for n, i, o, s in straddling]))
    measured["straddling_arm_io_windows"] = len(straddling)
    checks.add("%s: translatable /arm-io windows" % name,
               translatable == profile["translatable_windows"],
               "%s has %d translatable direct-child /arm-io windows, expected "
               "%d" % (name, translatable, profile["translatable_windows"]))
    checks.add("%s: /arm-io/ans zero offset and zero size windows" % name,
               zero_windows == [("ans", i) for i in ANS_ZERO_WINDOWS],
               "%s zero/zero windows are %r, expected ans pairs %r. These "
               "nominally translate to the aperture base; filter on size == 0."
               % (name, zero_windows, ANS_ZERO_WINDOWS))
    checks.add("%s: untranslatable exclave and proxy windows" % name,
               untranslatable == UNTRANSLATABLE,
               "%s untranslatable windows are %r, expected %r"
               % (name, [(n, i, hex(o), hex(s)) for n, i, o, s in untranslatable],
                  [(n, i, hex(o), hex(s)) for n, i, o, s in UNTRANSLATABLE]))
    checks.add("%s: /arm-io/bluetooth is the only ragged reg" % name,
               ragged == [("bluetooth", BLUETOOTH_REG_HEX)],
               "%s ragged reg nodes are %r, expected only bluetooth with %s. A "
               "naive 16-byte-stride loop over /arm-io throws here."
               % (name, ragged, BLUETOOTH_REG_HEX))
    siblings = [c.name for c in arm_io.children if c.name.endswith("-exclave-mailbox")]
    checks.add("%s: SEP has no exclave-mailbox sibling" % name,
               siblings == EXCLAVE_MAILBOX_SIBLINGS,
               "%s exclave mailbox nodes are %r, expected %r. A sep one "
               "appearing would change the brokering story."
               % (name, siblings, EXCLAVE_MAILBOX_SIBLINGS))
    mapper = adt.prop("/arm-io/dart-sep/mapper-sep-exclave", "reg")
    checks.add("%s: mapper-sep-exclave reg is a 4-byte index, not MMIO" % name,
               mapper is not None
               and mapper.payload.hex() == MAPPER_SEP_EXCLAVE_REG_HEX,
               "%s /arm-io/dart-sep/mapper-sep-exclave reg is %r, expected %s"
               % (name, None if mapper is None else mapper.payload.hex(),
                  MAPPER_SEP_EXCLAVE_REG_HEX))
    esm = first_window(translator, adt, "/arm-io/esm")
    esm_absolute, _, esm_fits = (translator.translate(*esm) if esm is not None
                                 else (None, 0, False))
    checks.add("%s: /arm-io/esm window" % name,
               esm is not None and esm_fits
               and (esm[0], esm[1], esm_absolute) == ESM_WINDOW,
               "%s /arm-io/esm window 0 is %r, expected child %#x size %#x -> %#x"
               % (name,
                  describe_windows(translator, adt, "/arm-io/esm")
                  if esm is None
                  else (hex(esm[0]), hex(esm[1]),
                        None if esm_absolute is None else hex(esm_absolute),
                        "fits" if esm_fits else "straddles its ranges triple"),
                  ESM_WINDOW[0], ESM_WINDOW[1], ESM_WINDOW[2]))

    # ---- per-blob facts: these legitimately differ ------------------------
    checks.add("%s: /arm-io/sep property count" % name,
               sep.prop_count == profile["sep_properties"],
               "%s /arm-io/sep has %d properties, expected %d for a %s tree"
               % (name, sep.prop_count, profile["sep_properties"], spec["profile"]))
    sep_names = [p.name for p in sep.props]
    sep_compatible = adt.string("/arm-io/sep", "compatible")
    checks.add("%s: /arm-io/sep compatible" % name,
               sep_compatible == profile["sep_compatible"],
               "%s /arm-io/sep compatible is %r, expected %r for a %s tree"
               % (name, sep_compatible, profile["sep_compatible"], spec["profile"]))
    index = sep_names.index("compatible") if "compatible" in sep_names else None
    checks.add("%s: /arm-io/sep compatible position" % name,
               index == profile["sep_compatible_index"],
               "%s /arm-io/sep compatible is at index %r, expected %r"
               % (name, index, profile["sep_compatible_index"]))
    compatible_total = sum(1 for _, p in adt.properties() if p.name == "compatible")
    checks.add("%s: tree-wide compatible count" % name,
               compatible_total == profile["compatible_total"],
               "%s has %d compatible properties, expected %d for a %s tree"
               % (name, compatible_total, profile["compatible_total"],
                  spec["profile"]))
    ascwrap = [(node.path, prop.payload.decode("ascii", "replace"))
               for node, prop in adt.properties()
               if prop.name == "compatible" and b"ascwrap-v6" in prop.payload]
    checks.add("%s: nodes whose compatible contains ascwrap-v6" % name,
               len(ascwrap) == profile["ascwrap_nodes"],
               "%s matches ascwrap-v6 on %d node(s), expected %d for a %s tree. "
               "A device enumerating by this string finds nothing in the tree "
               "Darwin serves." % (name, len(ascwrap), profile["ascwrap_nodes"],
                                   spec["profile"]))
    flagged = sum(1 for _, p in adt.properties() if p.lenword & FLAG_BIT)
    checks.add("%s: properties with bit 31 set in the length word" % name,
               flagged == profile["flagged_properties"],
               "%s has %d flagged properties, expected %d for a %s tree"
               % (name, flagged, profile["flagged_properties"], spec["profile"]))
    padded = [(node.path, p.name, p.pad.hex())
              for node, p in adt.properties() if p.pad and any(p.pad)]
    checks.add("%s: properties with non-zero padding" % name,
               len(padded) == profile["nonzero_pad_properties"],
               "%s has %d properties with non-zero padding, expected %d for a "
               "%s tree. Never scan a payload to a zero fill."
               % (name, len(padded), profile["nonzero_pad_properties"],
                  spec["profile"]))
    behavior = [(p.lenword, p.payload.hex(), p.pad.hex())
                for _, p in adt.properties() if p.name == "irq-behavior-map"]
    checks.add("%s: irq-behavior-map shape" % name,
               len(behavior) == 5
               and set(behavior) == {profile["irq_behavior_map"]},
               "%s irq-behavior-map properties are %r, expected five copies of "
               "%r. The stock tree under-declares a 4-byte value by 2, so what "
               "looks like non-zero padding is the value's own tail."
               % (name, behavior, profile["irq_behavior_map"]))
    memory_map = adt.by_path.get("/chosen/memory-map")
    checks.add("%s: /chosen/memory-map property count" % name,
               memory_map is not None
               and memory_map.prop_count == profile["memory_map_properties"],
               "%s /chosen/memory-map has %r properties, expected %d for a %s tree"
               % (name, None if memory_map is None else memory_map.prop_count,
                  profile["memory_map_properties"], spec["profile"]))
    iack = adt.prop("/arm-io/aic", "aic-iack-offset")
    iack_hex = None if iack is None else iack.payload.hex()
    checks.add("%s: /arm-io/aic aic-iack-offset" % name,
               iack_hex == profile["aic_iack_offset_hex"],
               "%s /arm-io/aic aic-iack-offset is %r, expected %r for a %s tree"
               % (name, iack_hex, profile["aic_iack_offset_hex"], spec["profile"]))
    checks.add("%s: aic-iack-offset raw string occurrences agree with the parse"
               % name,
               data.count(b"aic-iack-offset") == (0 if iack is None else 1),
               "%s contains the raw string aic-iack-offset %d time(s) but the "
               "parser found %s" % (name, data.count(b"aic-iack-offset"),
                                    "none" if iack is None else "one"))
    present = ("/arm-io/dockchannel-uart" in adt.by_path,
               "/arm-io/sgx" in adt.by_path)
    checks.add("%s: stock-only dockchannel-uart and sgx" % name,
               present == (profile["has_dockchannel_uart_and_sgx"],) * 2,
               "%s dockchannel-uart/sgx presence is %r, expected %r for a %s tree"
               % (name, present, (profile["has_dockchannel_uart_and_sgx"],) * 2,
                  spec["profile"]))
    checks.add("%s: /rtc and / no-rtc" % name,
               ("/rtc" in adt.by_path) == profile["has_rtc"]
               and (adt.prop("/", "no-rtc") is not None) == profile["has_rtc"],
               "%s /rtc present %r and no-rtc present %r, expected both %r for "
               "a %s tree" % (name, "/rtc" in adt.by_path,
                              adt.prop("/", "no-rtc") is not None,
                              profile["has_rtc"], spec["profile"]))
    checks.add("%s: / secure-root-prefix" % name,
               (adt.prop("/", "secure-root-prefix") is not None)
               == profile["has_secure_root_prefix"],
               "%s / secure-root-prefix present %r, expected %r for a %s tree"
               % (name, adt.prop("/", "secure-root-prefix") is not None,
                  profile["has_secure_root_prefix"], spec["profile"]))

    measured.update({
        "sep_properties": sep.prop_count,
        "sep_compatible": sep_compatible,
        "compatible_total": compatible_total,
        "ascwrap_v6_nodes": len(ascwrap),
        "flagged_properties": flagged,
        "nonzero_pad_properties": len(padded),
        "memory_map_properties": (None if memory_map is None
                                  else memory_map.prop_count),
        "aic_iack_offset_bytes": iack_hex,
        "translatable_arm_io_windows": translatable,
        "untranslatable_arm_io_windows": len(untranslatable),
        "untranslatable_node_count": len({n for n, _, _, _ in untranslatable}),
    })

    # ---- the thirteen ascwrap-v6 nodes, stock only ------------------------
    if spec["profile"] == "stock":
        measure_ascwrap(name, adt, translator, ascwrap, checks)
    return adt, record


def measure_ascwrap(name, adt, translator, ascwrap, checks):
    """The thirteen stock ascwrap-v6 nodes and their regularity."""
    checks.add("%s: ascwrap-v6 nodes are all direct /arm-io children" % name,
               all(path.count("/") == 2 and path.startswith("/arm-io/")
                   for path, _ in ascwrap),
               "%s has an ascwrap-v6 node that is not a direct /arm-io child: %r"
               % (name, [p for p, _ in ascwrap if p.count("/") != 2]))
    census = {}
    for _, payload in ascwrap:
        census[payload] = census.get(payload, 0) + 1
    checks.add("%s: the thirteen do not share one compatible string" % name,
               census == ASCWRAP_COMPATIBLE_CENSUS,
               "%s ascwrap-v6 compatible census is %r, expected %r. An "
               "exact-match probe on 'iop,ascwrap-v6' finds 11, not 13, and "
               "ispRtb holds two NUL-separated strings."
               % (name, census, ASCWRAP_COMPATIBLE_CENSUS))
    shallow = [path for path, _ in ascwrap
               if not isinstance(translator.windows(adt, path), list)
               or len(translator.windows(adt, path)) < 2]
    checks.add("%s: every ascwrap-v6 node has at least two reg windows" % name,
               not shallow,
               "%s has ascwrap-v6 node(s) the table cannot be built from: %r"
               % (name, [(p, describe_windows(translator, adt, p))
                         for p in shallow]))
    if shallow:
        return
    observed = []
    for path, _ in ascwrap:
        node_name = path.rsplit("/", 1)[1]
        windows = translator.windows(adt, path)
        first, _, _ = translator.translate(windows[0][0], windows[0][1])
        second, _, _ = translator.translate(windows[1][0], windows[1][1])
        observed.append((node_name, len(windows), first, windows[0][1],
                         second, windows[1][1], interrupts(adt, path)))
    checks.add("%s: the ascwrap-v6 table" % name, observed == ASCWRAP_V6,
               "%s ascwrap-v6 geometry changed.\n  measured %r\n  expected %r"
               % (name, observed, ASCWRAP_V6))
    checks.add("%s: win0 size is %#x on all thirteen" % (name, ASCWRAP_WIN0_SIZE),
               all(row[3] == ASCWRAP_WIN0_SIZE for row in observed),
               "%s has an ascwrap-v6 node whose win0 size is not %#x: %r"
               % (name, ASCWRAP_WIN0_SIZE,
                  [(r[0], hex(r[3])) for r in observed if r[3] != ASCWRAP_WIN0_SIZE]))
    checks.add("%s: win1 is win0 minus %#x on all thirteen"
               % (name, ASCWRAP_WIN1_DELTA),
               all(row[2] - row[4] == ASCWRAP_WIN1_DELTA for row in observed),
               "%s has an ascwrap-v6 node whose win1 delta is not %#x: %r"
               % (name, ASCWRAP_WIN1_DELTA,
                  [(r[0], hex(r[2] - r[4])) for r in observed
                   if r[2] - r[4] != ASCWRAP_WIN1_DELTA]))
    checks.add("%s: interrupt shape is base+1, base, base+3, base+2" % name,
               all(row[6][:4] == [row[6][1] + 1, row[6][1], row[6][1] + 3,
                                  row[6][1] + 2] for row in observed),
               "%s has an ascwrap-v6 node whose first four interrupts do not "
               "follow the shape: %r"
               % (name, [(r[0], r[6][:4]) for r in observed
                         if r[6][:4] != [r[6][1] + 1, r[6][1], r[6][1] + 3,
                                         r[6][1] + 2]]))
    checks.add("%s: every ascwrap-v6 node parents to the AIC" % name,
               all(adt.u32(path, "interrupt-parent") == AIC_PHANDLE
                   for path, _ in ascwrap),
               "%s has an ascwrap-v6 node whose interrupt-parent is not %#x"
               % (name, AIC_PHANDLE))
    # Sizing a SEP window from the majority would be wrong by 24x, and only
    # five of the thirteen even have exactly two windows.
    pairs = sum(1 for row in observed if row[1] == 2)
    checks.add("%s: only five of the thirteen have exactly two windows" % name,
               pairs == 5,
               "%s has %d ascwrap-v6 nodes with exactly two reg windows, "
               "expected 5" % (name, pairs))
    sep_rows = [row for row in observed if row[0] == "sep"]
    checks.add("%s: sep is one of the ascwrap-v6 nodes" % name,
               len(sep_rows) == 1,
               "%s finds %d ascwrap-v6 row(s) named sep among %r; the SEP "
               "window-size comparison below cannot be made"
               % (name, len(sep_rows), [row[0] for row in observed]))
    if len(sep_rows) != 1:
        return
    sep_win1 = sep_rows[0][5]
    majority = max({row[5] for row in observed},
                   key=lambda size: sum(1 for r in observed if r[5] == size))
    checks.add("%s: the SEP win1 size is not the majority size" % name,
               sep_win1 != majority and sep_win1 == SEP_WIN1[1],
               "%s SEP win1 is %#x and the majority win1 is %#x; sizing SEP "
               "from the majority would be wrong"
               % (name, sep_win1, majority))


def compare(stock, served, served_sep, measured_translatable, checks):
    """Cross-blob deltas: what the fixup removes, and what the variant adds.

    measured_translatable is {blob name: translatable window count} as the
    per-blob measurement actually counted them, so the arithmetic below is
    measured against measured and not against two module constants.
    """
    def flatten(adt, strict):
        out = {}
        for node in adt.nodes:
            out[node.path] = {
                p.name: ((p.lenword, p.payload, p.pad) if strict else p.payload)
                for p in node.props}
        return out

    strict_stock, strict_served = flatten(stock, True), flatten(served, True)
    loose_stock, loose_served = flatten(stock, False), flatten(served, False)
    common = [path for path in strict_stock if path in strict_served]
    checks.add("fixup: common node count", len(common) == FIXUP["common_nodes"],
               "stock and served share %d nodes, expected %d"
               % (len(common), FIXUP["common_nodes"]))
    stock_only = sorted(set(strict_stock) - set(strict_served))
    served_only = sorted(set(strict_served) - set(strict_stock))
    checks.add("fixup: stock-only nodes", stock_only == FIXUP["stock_only_nodes"],
               "stock-only nodes are %r, expected %r"
               % (stock_only, FIXUP["stock_only_nodes"]))
    checks.add("fixup: served-only nodes", served_only == FIXUP["served_only_nodes"],
               "served-only nodes are %r, expected %r"
               % (served_only, FIXUP["served_only_nodes"]))
    lost = sum(1 for path in common
               if "compatible" in strict_stock[path]
               and "compatible" not in strict_served[path])
    checks.add("fixup: nodes losing compatible",
               lost == FIXUP["nodes_losing_compatible"],
               "%d common nodes lose compatible, expected %d"
               % (lost, FIXUP["nodes_losing_compatible"]))
    removals = sorted((path, name) for path in common
                      for name in strict_stock[path].keys()
                      - strict_served[path].keys() if name != "compatible")
    checks.add("fixup: the only non-compatible removal",
               removals == FIXUP["non_compatible_removals"],
               "non-compatible removals are %r, expected %r"
               % (removals, FIXUP["non_compatible_removals"]))
    by_payload = sum(1 for path in common
                     if loose_stock[path] != loose_served[path])
    by_bytes = sum(1 for path in common
                   if strict_stock[path] != strict_served[path])
    checks.add("fixup: nodes differing by payload",
               by_payload == FIXUP["nodes_differing_by_payload"],
               "%d common nodes differ by payload, expected %d"
               % (by_payload, FIXUP["nodes_differing_by_payload"]))
    checks.add("fixup: nodes differing by stored bytes",
               by_bytes == FIXUP["nodes_differing_by_stored_bytes"],
               "%d common nodes differ once lenword and padding count, "
               "expected %d" % (by_bytes, FIXUP["nodes_differing_by_stored_bytes"]))
    # 291 stock compatible = 285 lost + 2 on stock-only nodes + 4 surviving.
    stock_compatible = sum(1 for _, p in stock.properties()
                           if p.name == "compatible")
    on_stock_only = sum(1 for path in stock_only
                        if "compatible" in strict_stock[path])
    surviving = sum(1 for _, p in served.properties() if p.name == "compatible")
    checks.add("fixup: the compatible arithmetic closes",
               stock_compatible == lost + on_stock_only + surviving,
               "stock has %d compatible properties but %d lost + %d on "
               "stock-only nodes + %d surviving = %d"
               % (stock_compatible, lost, on_stock_only, surviving,
                  lost + on_stock_only + surviving))
    # Translatable-window arithmetic: the served tree is short exactly the
    # windows of the two stock-only nodes. Both sides are measured -- the two
    # counts come from the per-blob sweep, and `dropped` is counted by
    # translating the stock-only nodes' windows through the same Translator,
    # not by dividing a payload length by 16 and assuming each lands.
    stock_translator = Translator(stock)
    dropped = 0
    dropped_detail = []
    for path in stock_only:
        windows = stock_translator.windows(stock, path)
        if not isinstance(windows, list):
            continue
        for index, (offset, size) in enumerate(windows):
            absolute, _, fits = stock_translator.translate(offset, size)
            if (offset, size) == (0, 0) or absolute is None or not fits:
                continue
            dropped += 1
            dropped_detail.append((path, index, hex(absolute)))
    stock_measured = measured_translatable.get("stock_evidence")
    served_measured = measured_translatable.get("served")
    checks.add("fixup: the translatable-window arithmetic closes",
               stock_measured is not None and served_measured is not None
               and stock_measured - dropped == served_measured,
               "the measured stock %r translatable windows minus the %d "
               "translatable windows of the stock-only nodes (%r) is not the "
               "measured served %r"
               % (stock_measured, dropped, dropped_detail, served_measured))

    strict_variant = flatten(served_sep, True)
    added = sorted((path, name, strict_variant[path][name][1]
                    .decode("ascii", "replace"))
                   for path in strict_variant
                   for name in strict_variant[path].keys()
                   - strict_served.get(path, {}).keys())
    gone = sorted((path, name) for path in strict_served
                  for name in strict_served[path].keys()
                  - strict_variant.get(path, {}).keys())
    changed = sorted((path, name) for path in strict_served
                     for name in strict_served[path].keys()
                     & strict_variant.get(path, {}).keys()
                     if strict_served[path][name] != strict_variant[path][name])
    checks.add("variant: served to dtree-sep adds exactly two compatible "
               "properties", added == SEP_VARIANT_DELTA,
               "the opt-in variant adds %r, expected %r" % (added, SEP_VARIANT_DELTA))
    checks.add("variant: served to dtree-sep removes nothing", not gone,
               "the opt-in variant removes %r" % (gone,))
    checks.add("variant: served to dtree-sep changes nothing", not changed,
               "the opt-in variant changes %r" % (changed,))
    checks.add("variant: served to dtree-sep is %d bytes" % SEP_VARIANT_BYTES,
               served_sep.size - served.size == SEP_VARIANT_BYTES,
               "the opt-in variant is %d bytes larger than the served tree, "
               "expected %d" % (served_sep.size - served.size, SEP_VARIANT_BYTES))
    return {"common_nodes": len(common), "stock_only_nodes": stock_only,
            "served_only_nodes": served_only, "nodes_losing_compatible": lost,
            "non_compatible_removals": [list(r) for r in removals],
            "nodes_differing_by_payload": by_payload,
            "nodes_differing_by_stored_bytes": by_bytes,
            "variant_added_properties": [list(a) for a in added],
            "variant_byte_delta": served_sep.size - served.size}


class Checks:
    def __init__(self):
        self.passed = 0
        self.attempted = 0
        self.failures = []

    def add(self, label, value, message):
        self.attempted += 1
        if value:
            self.passed += 1
        else:
            self.failures.append({"check": label, "detail": message})


def run(root, overrides, output):
    checks = Checks()
    paths = {}
    for name, spec in BLOBS.items():
        paths[name] = (overrides.get(name) or (root / spec["relative"])).resolve()
        checks.add("%s: the blob path is a readable regular file" % name,
                   paths[name].is_file(),
                   "%s is not a regular file at %s" % (name, paths[name]))
    # Four distinct files, or "the two stock copies are byte-identical" can be
    # satisfied by naming one file twice.
    checks.add("the four blob paths are four distinct files",
               len(set(paths.values())) == len(BLOBS),
               "the four resolved blob paths are %r; a repeated path makes the "
               "two-stock-copies check vacuous"
               % {name: str(path) for name, path in paths.items()})

    report = {
        "scope": "ADT geometry measurement only; no build, no guest, no device "
                 "code, no blob written",
        "workspace_root": str(root),
        "blobs": {},
        "checks_passed": 0,
        "failures": [],
    }

    # Hashed before anything parses, so "unchanged" compares a before to an
    # after even for a blob whose measurement raised and left no record.
    before = {name: (digest(path)["sha256"] if path.is_file() else None)
              for name, path in paths.items()}

    parsed = {}
    for name, spec in BLOBS.items():
        try:
            adt, record = measure(name, spec, paths[name], checks)
            parsed[name] = adt
            checks.add("%s: measures without raising" % name, True, "")
        except Exception as error:               # noqa: BLE001 - reported
            record = {"path": str(paths[name]), "role": spec["role"],
                      "profile": spec["profile"],
                      "error": "%s: %s" % (type(error).__name__, error)}
            checks.add("%s: measures without raising" % name, False,
                       "%s raised %s: %s -- the other blobs were still "
                       "measured and this report is complete for them"
                       % (name, type(error).__name__, error))
        report["blobs"][name] = record

    checks.add("the two stock copies are byte-identical",
               paths["stock_evidence"].is_file()
               and paths["stock_runtime"].is_file()
               and paths["stock_evidence"].read_bytes()
               == paths["stock_runtime"].read_bytes(),
               "%s and %s are no longer byte-identical (or one is unreadable)"
               % (paths["stock_evidence"], paths["stock_runtime"]))

    # Run the oracle on one stock and one served tree: only the stock trees
    # carry bit-31 flagged properties, so only they exercise that mutation.
    report["negative_oracle"] = {}
    for name in ("stock_evidence", "served"):
        if name not in parsed:
            checks.add("%s: the negative oracle ran" % name, False,
                       "%s did not parse, so the negative oracle could not "
                       "run on it" % name)
            continue
        try:
            report["negative_oracle"][name] = negative_oracle(
                name, paths[name].read_bytes(), parsed[name])
            checks.add("%s: the negative oracle ran" % name, True, "")
        except Exception as error:               # noqa: BLE001 - reported
            checks.add("%s: the negative oracle ran" % name, False,
                       "%s: %s" % (type(error).__name__, error))

    cross_inputs = ("stock_evidence", "served", "served_sep")
    if all(name in parsed for name in cross_inputs):
        try:
            report["cross_blob"] = compare(
                parsed["stock_evidence"], parsed["served"],
                parsed["served_sep"],
                {name: report["blobs"][name].get("measured", {})
                       .get("translatable_arm_io_windows")
                 for name in cross_inputs}, checks)
            checks.add("the cross-blob comparison ran", True, "")
        except Exception as error:               # noqa: BLE001 - reported
            checks.add("the cross-blob comparison ran", False,
                       "the cross-blob comparison raised %s: %s"
                       % (type(error).__name__, error))
    else:
        checks.add("the cross-blob comparison ran", False,
                   "the cross-blob comparison needs %r to parse; %r did not"
                   % (list(cross_inputs),
                      [n for n in cross_inputs if n not in parsed]))

    # Honesty fields, in the AIC gate's spirit. Everything above is in the
    # bytes; everything here is a statement about what the bytes do NOT say.
    # Nothing here is a measurement: facts that ARE measured, such as whether
    # an interrupt-names property exists, live in each blob's "measured" block.
    report["honesty"] = {
        "interrupt_condition_mapping_is_apple_documented": False,
        "sep_interrupts_are_known_by_position_only": True,
        "win0_is_named_a_mailbox_aperture_by_the_adt": False,
        "mailbox_register_layout_derived_from_adt": False,
        "event_or_ack_offset_derived_from_adt": False,
        "aic_iack_offset_meaning_established": False,
        "ascwrap_v6_semantics_established": False,
        "untranslatable_windows_proven_absolute": False,
        "bit31_flag_meaning_established": False,
        "irq_behavior_map_producer_intent_established": False,
        "device_code_exercised": False,
        "guest_execution": False,
        "qemu_built_or_run": False,
        "blobs_modified": False,
    }
    # Named so no reader counts them as measurement: see the file header.
    report["structural_invariants_restated"] = [
        "<blob>: child counts close on the node count",
        "<blob>: re-serializes byte-identically",
    ]

    after = {name: (digest(path)["sha256"] if path.is_file() else None)
             for name, path in paths.items()}
    unchanged = after == before
    checks.add("blobs are unchanged after measurement", unchanged,
               "a blob changed during the run: before %r, after %r"
               % (before, after))
    report["blobs_unchanged"] = unchanged

    # Last, and counting itself: a measurement oracle that silently runs fewer
    # checks after an edit is the failure mode that matters most here.
    checks.add("the expected number of checks ran",
               checks.attempted + 1 == EXPECTED_CHECKS,
               "%d checks ran, expected %d. A block was skipped or added; the "
               "pass count alone would not have shown it"
               % (checks.attempted + 1, EXPECTED_CHECKS))

    report["checks_attempted"] = checks.attempted
    report["checks_passed"] = checks.passed
    report["failures"] = list(checks.failures)
    report["passed"] = not checks.failures

    if output is not None:
        # "x": an evidence gate must never silently destroy a prior run's
        # report.json. Matches the sibling gates. A refused write is reported
        # as a failure, and the measurement itself is still printed.
        output.mkdir(parents=True, exist_ok=True)
        try:
            with (output / "report.json").open("x") as destination:
                json.dump(report, destination, indent=2, sort_keys=True)
                destination.write("\n")
        except FileExistsError:
            report["failures"].append({
                "check": "the report was written to --output-dir",
                "detail": "%s already exists; refusing to overwrite a prior "
                          "run's evidence. The measurement is on stdout."
                          % (output / "report.json")})
            report["passed"] = False

    print(json.dumps(report, indent=2, sort_keys=True))
    if report["failures"]:
        for failure in report["failures"]:
            print("FAIL %s: %s" % (failure["check"], failure["detail"]),
                  file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", type=Path,
                        help="Workspace root holding modern-emulator "
                             "(default: four levels above this script)")
    parser.add_argument("--output-dir", type=Path,
                        help="Write report.json here as well as to stdout")
    for name in BLOBS:
        parser.add_argument("--" + name.replace("_", "-"), type=Path,
                            help="Override the %s blob path" % name)
    args = parser.parse_args()
    root = (args.workspace or Path(__file__).resolve().parents[3]).resolve()
    overrides = {name: getattr(args, name) for name in BLOBS}
    try:
        return run(root, overrides, args.output_dir)
    except Exception as error:                   # noqa: BLE001 - reported
        # The house shape is "print a JSON report, exit non-zero". Even a
        # failure the run could not absorb gets a report, not a bare traceback.
        print(json.dumps({
            "scope": "ADT geometry measurement only; no build, no guest, no "
                     "device code, no blob written",
            "workspace_root": str(root),
            "passed": False,
            "checks_passed": 0,
            "failures": [{"check": "the gate completed",
                          "detail": "%s: %s" % (type(error).__name__, error)}],
        }, indent=2, sort_keys=True))
        print("FAIL the gate completed: %s: %s"
              % (type(error).__name__, error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
