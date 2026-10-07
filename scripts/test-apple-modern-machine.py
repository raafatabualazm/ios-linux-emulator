#!/usr/bin/env python3
"""Audit apple-modern's stopped RAM preparation with decoded local components.

The CPU stays stopped throughout: this checks normal loading, metadata and
system_reset only. It does not qualify SPTM execution, iOS boot, GUI or IPAs.
An optional decoded restore ramdisk is checked without mounting its filesystem.
Firmware RAM dumps are transient; retained reports contain hashes and counts.
QMP can use bounded child pipes with --qmp-stdio. The optional register reset
pattern gate uses only owned loader devices and compatibility register RAM.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback


DRAM = 1 << 40
RAM_SIZE = 8 << 30
# Declared acknowledge offset the board publishes and the controller decodes.
AIC_IACK_OFFSET = 0x2000
PAGE = 0x4000
INDEX_MASK = (1 << 36) - 1
COMMAND_LINE = "--audit-modern-command-line -v"
ASSETS = ("bootkc", "sptm", "txm", "dtree", "restore-trustcache")
MAX_LOG = 1024 * 1024
MAX_QMP_FRAME = 65536
sys.dont_write_bytecode = True


def require(condition: bool, description: str) -> None:
    if not condition:
        raise RuntimeError(description)


def digest(path: Path) -> dict:
    with path.open("rb") as stream:
        value = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": value}


def page(value: int) -> int:
    return (value + PAGE - 1) & -PAGE


def parse_image(data: bytes) -> dict:
    """Independent, bounded Mach-O load-command reader for the copy oracle."""
    require(len(data) >= 32, "Mach-O header is incomplete")
    magic, cpu, _, kind, count, size = struct.unpack_from("<6I", data)
    require(magic == 0xFEEDFACF and cpu == 0x0100000C and kind in (2, 12),
            "Expected a decoded ARM64 Mach-O component")
    end = 32 + size
    require(0 < count <= 4096 and end <= len(data), "Mach-O command bounds")
    cursor, segments, entry = 32, {}, None
    for _ in range(count):
        require(cursor + 8 <= end, "Mach-O command header bounds")
        command, length = struct.unpack_from("<II", data, cursor)
        require(length >= 8 and length % 8 == 0 and cursor + length <= end,
                "Mach-O command length bounds")
        if command == 0x19:
            require(length >= 72, "Mach-O segment header bounds")
            name = data[cursor + 8:cursor + 24].split(b"\0", 1)[0].decode("ascii")
            virtual, memory, offset, file_size = struct.unpack_from("<4Q", data, cursor + 24)
            require(name not in segments and memory and file_size <= memory and
                    offset + file_size <= len(data), "Mach-O segment extent bounds")
            segments[name] = {"virtual": virtual, "memory": memory,
                              "offset": offset, "file": file_size}
        elif command == 5:
            require(length == 288 and entry is None, "Mach-O thread entry schema")
            entry = struct.unpack_from("<Q", data, cursor + 272)[0]
        cursor += length
    require(cursor == end and segments and entry is not None, "Mach-O image completeness")
    return {"segments": segments, "low": min(s["virtual"] for s in segments.values()),
            "entry": entry}


def expected_layout(blobs: dict[str, bytes]) -> dict:
    """Calculate the documented T8140 group order independently in Python."""
    images = {name: parse_image(blobs[name]) for name in ("bootkc", "sptm", "txm")}
    prefix_groups = [
        ("TXM-ro", "txm", ("__TEXT", "__DATA_CONST")),
        ("TXM-rx", "txm", ("__TEXT_EXEC",)),
        ("TXM-bx", "txm", ("__TEXT_BOOT_EXEC",)),
        ("TrustCache", None, ()),
        ("BootKC-rx", "bootkc", ("__TEXT_EXEC",)),
        ("BootKC-bx", "bootkc", ("__TEXT_BOOT_EXEC",)),
        ("BootKC-ro", "bootkc", ("__TEXT", "__PRELINK_TEXT", "__DATA_CONST")),
        ("BootKC-rs", "bootkc", ("__DATA_SPTM",)),
        ("DeviceTree", None, ()),
    ]
    suffix_groups = [
        ("SPTM-ro", "sptm", ("__TEXT", "__DATA_CONST", "__LATE_CONST")),
        ("SPTM-rx", "sptm", ("__TEXT_EXEC", "__LAST")),
        ("SPTM-rw", "sptm", ("__DATA", "__BOOTDATA")),
        ("SPTM-le", "sptm", ("__LINKEDIT",)),
        ("TXM-rw", "txm", ("__DATA",)),
        ("TXM-le", "txm", ("__LINKEDIT",)),
        ("BootKC-rw", "bootkc", ("__PRELINK_INFO", "__DATA")),
        ("BootKC-le", "bootkc", ("__LINKEDIT",)),
        ("CL4-dummypage", None, ()),
        ("BootArgs", None, ()),
    ]
    capacities = {"TrustCache": page(len(blobs["restore-trustcache"]) + 8),
                  "DeviceTree": PAGE + page(len(blobs["dtree"]) + 65536),
                  "CL4-dummypage": PAGE, "BootArgs": PAGE}

    def group_size(name: str, image: str | None, names: tuple) -> int:
        return (sum(images[image]["segments"][s]["memory"] for s in names)
                if image else capacities[name])

    sptm_base = DRAM + (images["bootkc"]["low"] & INDEX_MASK)
    cursor = sptm_base - sum(group_size(*group) for group in prefix_groups)
    regions, copies = {}, []
    for name, image, names in prefix_groups + suffix_groups:
        begin = cursor
        if image:
            for segment in names:
                source = images[image]["segments"][segment]
                copies.append({"image": image, "segment": segment, "physical": cursor,
                               **source})
                cursor += source["memory"]
        else:
            cursor += capacities[name]
        require(DRAM <= begin < cursor <= DRAM + RAM_SIZE and begin % PAGE == 0,
                "Reference layout fits aligned DRAM")
        regions[name] = (begin, cursor - begin)
    require(regions["SPTM-ro"][0] == sptm_base, "Reference SPTM index placement")
    for copy in copies:
        if copy["image"] == "sptm":
            require(copy["physical"] == sptm_base + copy["virtual"] - images["sptm"]["low"],
                    "SPTM virtual and physical segment orders agree")
    require(len(copies) == 23 and len(regions) == 19, "Reference component schema")
    ramdisk = None
    if blobs.get("ramdisk"):
        size = len(blobs["ramdisk"])
        reserved = page(size)
        require(cursor % PAGE == 0 and cursor + reserved <= DRAM + RAM_SIZE,
                "Reference ramdisk fits aligned DRAM")
        ramdisk = {"physical": cursor, "file": size, "memory": reserved}
        regions["RAMDisk"] = (cursor, reserved)
        cursor += reserved
    return {"images": images, "regions": regions, "copies": copies,
            "entry": sptm_base + images["sptm"]["entry"] - images["sptm"]["low"],
            "args": regions["BootArgs"][0], "tree": regions["DeviceTree"][0] + PAGE,
            "top": cursor, "virtual_base": images["bootkc"]["low"] & ~INDEX_MASK,
            "ramdisk": ramdisk}


class QMP:
    def __init__(self, path: Path | None, guard, process=None):
        self.sock = None
        self.input_stream = self.output_stream = None
        self.buffer = bytearray()
        self.events = []
        self.sequence = 0
        self.guard = guard
        try:
            if process is None:
                require(path is not None, "QMP Unix endpoint supplied")
                self.sock = socket.socket(socket.AF_UNIX)
                self.sock.settimeout(3)
                self.sock.connect(str(path))
                self.read_fd = self.write_fd = self.sock.fileno()
            else:
                require(path is None and process.stdin is not None and
                        process.stdout is not None, "QMP child stdio pipes supplied")
                self.input_stream = process.stdin
                self.output_stream = process.stdout
                self.write_fd = self.input_stream.fileno()
                self.read_fd = self.output_stream.fileno()
            os.set_blocking(self.read_fd, False)
            os.set_blocking(self.write_fd, False)
            require("QMP" in self.receive(time.monotonic() + 15),
                    "Valid QMP greeting")
            self.request("qmp_capabilities")
        except BaseException:
            self.close()
            raise

    def receive(self, deadline: float) -> dict:
        while True:
            self.guard()
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                require(newline + 1 <= MAX_QMP_FRAME, "QMP response frame bound")
                line = bytes(self.buffer[:newline + 1])
                del self.buffer[:newline + 1]
                value = json.loads(line)
                require(isinstance(value, dict), "QMP response object")
                return value
            require(len(self.buffer) < MAX_QMP_FRAME, "QMP incomplete frame bound")
            remaining = min(deadline - time.monotonic(), self.guard())
            require(remaining > 0, "QMP response deadline")
            readable, _, _ = select.select([self.read_fd], [], [], min(0.1, remaining))
            if not readable:
                continue
            try:
                data = os.read(self.read_fd,
                               min(4096, MAX_QMP_FRAME - len(self.buffer)))
            except (BlockingIOError, InterruptedError):
                continue
            require(bool(data), "Complete QMP response before child/endpoint EOF")
            self.buffer.extend(data)

    def send(self, data: bytes, deadline: float) -> None:
        require(0 < len(data) <= MAX_QMP_FRAME, "QMP request frame bound")
        offset = 0
        while offset < len(data):
            remaining = min(deadline - time.monotonic(), self.guard())
            require(remaining > 0, "QMP request write deadline")
            _, writable, _ = select.select([], [self.write_fd], [], min(0.1, remaining))
            if not writable:
                continue
            try:
                written = os.write(self.write_fd, data[offset:])
            except (BlockingIOError, InterruptedError):
                continue
            require(written > 0, "QMP request write completed")
            offset += written

    def request(self, command: str, arguments: dict | None = None):
        self.guard()
        self.sequence += 1
        request = {"execute": command, "id": self.sequence}
        if arguments is not None:
            request["arguments"] = arguments
        deadline = time.monotonic() + 3
        self.send(json.dumps(request).encode() + b"\n", deadline)
        while time.monotonic() < deadline:
            value = self.receive(deadline)
            if "event" in value:
                self.events.append(value["event"])
                require(len(self.events) <= 64, "QMP event count bound")
                continue
            require(value.get("id") == self.sequence, "QMP response ID")
            require("error" not in value, "QMP command failed: " + str(value.get("error")))
            require("return" in value, "QMP command response")
            return value["return"]
        raise RuntimeError("QMP request deadline")

    def close(self):
        if self.sock is not None:
            self.sock.close()
        for stream in (self.input_stream, self.output_stream):
            if stream is not None:
                stream.close()


def parse_registers(text: str) -> dict:
    values = {}
    for name in ("PC", "X00", "PSTATE"):
        match = re.search(r"\b" + name + r"=([0-9a-fA-F]+)", text)
        require(match is not None, "HMP register observation: " + name)
        values[name] = int(match[1], 16)
    return values


def audit(qmp: QMP, scratch: Path, blobs: dict, layout: dict, parse_adt) -> dict:
    reads, total = 0, 0
    ramdisk_size = len(blobs.get("ramdisk", b""))
    inspection_limit = 18 * 1024 * 1024 + ramdisk_size

    def memory(address: int, size: int) -> bytes:
        nonlocal reads, total
        require(0 < size <= 17 * 1024 * 1024 and total + size <= inspection_limit,
                "RAM inspection byte budget")
        path = scratch / "ram-inspection.bin"
        path.unlink(missing_ok=True)
        qmp.request("pmemsave", {"val": address, "size": size, "filename": str(path)})
        require(path.stat().st_size == size, "Complete physical RAM dump")
        data = path.read_bytes()
        path.unlink()
        reads += 1
        total += size
        return data

    args = memory(layout["args"], 1152)
    tree_size = struct.unpack_from("<I", args, 104)[0]
    require(0 < tree_size <= layout["regions"]["DeviceTree"][1] - PAGE,
            "Prepared ADT fits its reservation")
    tree = memory(layout["tree"], tree_size)
    expected_args = bytearray(1152)
    struct.pack_into("<HH", expected_args, 0, 2, 2)
    for offset, value in ((8, layout["virtual_base"]), (16, DRAM), (24, RAM_SIZE),
                          (32, layout["top"]), (96, layout["virtual_base"] + layout["tree"] - DRAM),
                          (1144, RAM_SIZE)):
        struct.pack_into("<Q", expected_args, offset, value)
    struct.pack_into("<I", expected_args, 104, tree_size)
    expected_args[108:108 + len(COMMAND_LINE)] = COMMAND_LINE.encode("ascii")
    require(args == expected_args, "All 1152 boot_args ABI bytes")

    original, original_order = parse_adt(blobs["dtree"])
    prepared, prepared_order = parse_adt(tree)
    require(original_order == prepared_order, "ADT nodes and order preserved")
    normal = {name: struct.pack("<QQ", *extent) for name, extent in layout["regions"].items()}
    for prefix, image in (("BootKC", "bootkc"), ("SPTM", "sptm"), ("TXM", "txm")):
        normal[prefix + "-virt"] = struct.pack("<QQ", layout["images"][image]["low"], 0)
        normal[prefix + "-entry"] = struct.pack("<QQ", layout["images"][image]["entry"], 0)
    normal["slide"] = bytes(16)
    for name in ("SPTM-rm", "CL4-rx", "CL4-ro", "CL4-rw", "CL4-le", "CL4-entry", "CL4-virt"):
        normal[name] = b"\xff" * 16
    if layout["ramdisk"] is None:
        normal["RAMDisk"] = b"\xff" * 16
    # /arm-io/aic "aic-iack-offset" is published by the board because XNU's
    # AppleInterruptControllerV3 reads only that property for the acknowledge
    # register offset, defaults it to zero, and panics at
    # AppleInterruptControllerV3.cpp:214 when it is still zero. The stock tree
    # does not carry it, so the board must add it, and the value must match the
    # offset the controller decodes. Asserting the exact bytes here keeps the
    # served tree and the model from drifting apart.
    generated = {"/chosen": {"dram-base": struct.pack("<Q", DRAM),
                              "dram-size": struct.pack("<Q", RAM_SIZE)},
                 "/chosen/memory-map": normal,
                 "/arm-io/aic": {"aic-iack-offset": struct.pack("<Q", AIC_IACK_OFFSET)}}
    preserved = 0
    for path, props in original.items():
        for name, prop in props.items():
            if name not in generated.get(path, {}):
                require(prepared[path][name]["raw"] == prop["raw"],
                        "Unrelated ADT property bytes preserved")
                preserved += 1
    for path, props in prepared.items():
        for name in props.keys() - original[path].keys():
            require(name in generated.get(path, {}), "Only normal boot properties added")
    for path, props in generated.items():
        for name, value in props.items():
            require(prepared[path][name]["value"] == value, "Normal ADT property value: " + name)
    require("/arm-io/sgx" in prepared, "Original graphics node retained")
    cpu_windows = []
    for property_name in ("cpu-impl-reg", "cpm-impl-reg"):
        value = original["/cpus/cpu0"][property_name]["value"]
        require(len(value) == 16, "One stock CPU register-window tuple")
        address, size = struct.unpack("<QQ", value)
        require(address > 0 and 0 < size <= 1024 * 1024 and
                address + size <= (1 << 64) - 1,
                "Bounded stock CPU register-window span")
        loaded = memory(address, size)
        require(loaded == bytes(size), "Complete zeroed CPU register window: " + property_name)
        cpu_windows.append({"property": property_name, "physical_address": hex(address),
                            "logical_bytes_verified": size,
                            "sha256": hashlib.sha256(loaded).hexdigest(), "all_zero": True})
    wrapped = struct.pack("<II", 1, 8) + blobs["restore-trustcache"]
    tc_address, tc_size = layout["regions"]["TrustCache"]
    require(memory(tc_address, len(wrapped)) == wrapped, "Unchanged stock trustcache with offsets header")
    require(memory(tc_address + len(wrapped), min(64, tc_size - len(wrapped))) ==
            bytes(min(64, tc_size - len(wrapped))), "Trustcache reservation padding is zero")

    segment_samples = bss_samples = 0
    for copy in layout["copies"]:
        size = copy["file"]
        if size:
            length = min(64, size)
            for offset in sorted({0, (size - length) // 2, size - length}):
                actual = memory(copy["physical"] + offset, length)
                start = copy["offset"] + offset
                require(actual == blobs[copy["image"]][start:start + length],
                        "Unchanged loaded segment sample: " + copy["image"] + "/" + copy["segment"])
                segment_samples += 1
        bss_size = copy["memory"] - size
        if bss_size:
            length = min(64, bss_size)
            for offset in sorted({0, (bss_size - length) // 2, bss_size - length}):
                require(memory(copy["physical"] + size + offset, length) == bytes(length),
                        "Zero-filled segment BSS sample: " + copy["image"] + "/" + copy["segment"])
                bss_samples += 1
    dummy, _ = layout["regions"]["CL4-dummypage"]
    require(memory(dummy, PAGE) == bytes(PAGE), "Reserved dummy page is zero")
    require(memory(layout["regions"]["DeviceTree"][0], PAGE) == bytes(PAGE),
            "DeviceTree prefix page is zero")
    ramdisk_observation = None
    if layout["ramdisk"] is not None:
        ramdisk = layout["ramdisk"]
        loaded_hash = hashlib.sha256()
        for offset in range(0, ramdisk["file"], 8 * 1024 * 1024):
            length = min(8 * 1024 * 1024, ramdisk["file"] - offset)
            loaded_hash.update(memory(ramdisk["physical"] + offset, length))
        expected_hash = hashlib.sha256(blobs["ramdisk"]).hexdigest()
        require(loaded_hash.hexdigest() == expected_hash, "Complete unchanged ramdisk RAM copy")
        padding = ramdisk["memory"] - ramdisk["file"]
        if padding:
            require(memory(ramdisk["physical"] + ramdisk["file"], padding) == bytes(padding),
                    "Ramdisk reservation padding is zero")
        require(layout["top"] == ramdisk["physical"] + ramdisk["memory"],
                "Bootargs topOfKernelData includes the complete ramdisk reservation")
        ramdisk_observation = {"physical_address": hex(ramdisk["physical"]),
                               "payload_bytes_verified": ramdisk["file"],
                               "reserved_bytes_verified": ramdisk["memory"],
                               "payload_sha256": loaded_hash.hexdigest(),
                               "zero_padding_bytes_verified": padding,
                               "adt_descriptor_verified": True,
                               "bootargs_reservation_end_verified": True,
                               "filesystem_qualified": False}
    return {"bootargs_bytes_verified": len(args), "bootargs_sha256": hashlib.sha256(args).hexdigest(),
            "prepared_dtree_bytes": len(tree), "prepared_dtree_sha256": hashlib.sha256(tree).hexdigest(),
            "adt_nodes_preserved_in_order": len(original),
            "unrelated_adt_properties_preserved_byte_exactly": preserved,
            "normal_adt_properties_verified": sum(map(len, generated.values())),
            "advertised_regions_verified": len(layout["regions"]), "graphics_node_retained": True,
            "stock_trustcache_bytes_verified": len(wrapped), "segments_sampled": len(layout["copies"]),
            "segment_samples_verified": segment_samples, "zero_bss_samples_verified": bss_samples,
            "physical_memory_reads": reads, "physical_memory_bytes_read": total,
            "physical_memory_byte_limit": inspection_limit,
            "cpu_register_windows": cpu_windows,
            "cpu_register_window_bytes_verified": sum(w["logical_bytes_verified"] for w in cpu_windows),
            "cpu_register_ram_reset_pattern_write_qualified": False,
            "ramdisk": ramdisk_observation}


def audit_register_reset_pattern(qmp: QMP, scratch: Path, windows: list[dict],
                                 guard) -> dict:
    """Use standard loader devices to write only compatibility RAM, never PC/code.

    Startup loaders initially write zero, leaving the normal oracle unchanged.
    Each loader has data/data-len/addr and deliberately no cpu-num or file.
    Standard QOM unrealize/change-data/realize then reset proves the test
    inspected nonzero mapped RAM. Unrealizing every loader and resetting again
    distinguishes actual clearing from RAM only observed zero at construction.
    """
    loaders = []
    expected = {}
    for index, window in enumerate(windows):
        size = window["logical_bytes_verified"]
        require(size >= 16, "CPU register window fits separated test patterns")
        data = bytearray(size)
        for at, offset in enumerate((0, size - 8)):
            name = f"audit-register-pattern-{index}-{at}"
            pattern = 0x0123456789ABCDEF ^ (index << 32) ^ at
            path = "/machine/peripheral/" + name
            require(qmp.request("qom-get", {"path": path, "property": "realized"}) is True,
                    "Owned startup loader is realized")
            qmp.request("qom-set", {"path": path, "property": "realized", "value": False})
            qmp.request("qom-set", {"path": path, "property": "data", "value": pattern})
            qmp.request("qom-set", {"path": path, "property": "realized", "value": True})
            data[offset:offset + 8] = struct.pack("<Q", pattern)
            loaders.append(name)
        expected[window["property"]] = bytes(data)

    def reset() -> None:
        before = len(qmp.events)
        qmp.request("system_reset")
        deadline = time.monotonic() + 5
        while "RESET" not in qmp.events[before:]:
            require(time.monotonic() < deadline, "Register pattern reset completion")
            qmp.request("query-status")
            time.sleep(0.01)
        require(qmp.request("query-status")["running"] is False,
                "Register pattern test keeps every CPU stopped")

    def inspect(window: dict, wanted: bytes) -> dict:
        guard()
        path = scratch / "register-pattern-inspection.bin"
        path.unlink(missing_ok=True)
        qmp.request("pmemsave", {"val": int(window["physical_address"], 16),
                    "size": window["logical_bytes_verified"], "filename": str(path)})
        require(path.stat().st_size == len(wanted), "Complete register pattern RAM dump")
        actual = path.read_bytes()
        path.unlink()
        require(actual == wanted, "Full register RAM pattern/reset bytes: " + window["property"])
        return {"property": window["property"], "bytes_verified": len(actual),
                "sha256": hashlib.sha256(actual).hexdigest()}

    reset()
    loaded = [inspect(w, expected[w["property"]]) for w in windows]
    for name in loaders:
        path = "/machine/peripheral/" + name
        qmp.request("qom-set", {"path": path, "property": "realized", "value": False})
        require(qmp.request("qom-get", {"path": path, "property": "realized"}) is False,
                "Pattern loader unrealized before zero-reset qualification")
    reset()
    cleared = [inspect(w, bytes(w["logical_bytes_verified"])) for w in windows]
    return {"passed": True, "startup_loader_devices_unrealized": len(loaders),
            "loader_cpu_num_or_file_supplied": False, "guest_execution": False,
            "nonzero_pattern_full_window_observations": loaded,
            "zero_after_loader_unrealize_and_reset": cleared}


def run(binary: Path, components: Path, output: Path, ramdisk: Path | None = None,
        qmp_stdio: bool = False, check_register_reset_pattern: bool = False) -> dict:
    asset_paths = {name: components / name for name in ASSETS}
    if ramdisk is not None:
        asset_paths["ramdisk"] = ramdisk
    before = {name: digest(path) for name, path in asset_paths.items()}
    blobs = {name: path.read_bytes() for name, path in asset_paths.items()}
    layout = expected_layout(blobs)
    spec = importlib.util.spec_from_file_location(
        "metadata_oracle", Path(__file__).with_name("test-apple-modern-boot-metadata.py"))
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    report = {"scope": "Whole apple-modern machine: stopped RAM preparation and reset only",
              "binary": str(binary), "binary_sha256": digest(binary)["sha256"],
              "components": str(components), "ramdisk": str(ramdisk) if ramdisk else None,
              "qmp_transport": "stdio" if qmp_stdio else "unix",
              "register_reset_pattern_requested": check_register_reset_pattern,
              "register_reset_pattern": None,
              "cpu_register_ram_reset_pattern_write_qualified": False,
              "component_hashes_before": before,
              "passed": False, "stage": "startup", "observations": [], "modern_guest_boot": False,
              "guest_execution": False, "gui_verified": False, "ipa_executed": False}
    process = qmp = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="modern-machine-") as temporary:
            scratch = Path(temporary)
            endpoint = scratch / "qmp.sock"
            machine = "apple-modern," + ",".join(
                name + "=" + str(components / asset)
                for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"), ASSETS))
            machine += ",boot-command-line=" + COMMAND_LINE
            if ramdisk is not None:
                machine += ",ramdisk=" + str(ramdisk)
            argv = [str(binary), "-M", machine, "-m", "8G", "-smp", "1",
                    "-nodefaults", "-display", "none", "-serial", "none",
                    "-monitor", "none", "-S", "-qmp",
                    "stdio" if qmp_stdio else "unix:" + str(endpoint) + ",server=on,wait=off"]
            if check_register_reset_pattern:
                nodes, _ = oracle.parse_adt(blobs["dtree"])
                for index, name in enumerate(("cpu-impl-reg", "cpm-impl-reg")):
                    value = nodes["/cpus/cpu0"][name]["value"]
                    require(len(value) == 16, "Startup test loader uses one stock register-window tuple")
                    address, size = struct.unpack("<QQ", value)
                    require(address > 0 and 16 <= size <= 1024 * 1024 and
                            address + size <= (1 << 64) - 1,
                            "Startup test loader stays in bounded register RAM")
                    for at, offset in enumerate((0, size - 8)):
                        argv.extend(["-device", "loader,id=audit-register-pattern-" +
                                     f"{index}-{at},addr={address + offset},data=0,data-len=8"])
            report["argv"] = argv
            log_path = output / "emulator.log"
            with log_path.open("xb") as log:
                process = subprocess.Popen(argv,
                    stdin=subprocess.PIPE if qmp_stdio else subprocess.DEVNULL,
                    stdout=subprocess.PIPE if qmp_stdio else log,
                    stderr=log if qmp_stdio else subprocess.STDOUT, bufsize=0)
                def resource_guard() -> float:
                    remaining = 45 - (time.monotonic() - started)
                    require(remaining > 0 and log_path.stat().st_size <= MAX_LOG,
                            "QEMU integration time/log bounds")
                    return remaining

                if qmp_stdio:
                    qmp = QMP(None, resource_guard, process)
                else:
                    deadline = time.monotonic() + 15
                    while qmp is None:
                        require(process.poll() is None, "QEMU startup exited; inspect emulator.log")
                        require(time.monotonic() < deadline and log_path.stat().st_size <= MAX_LOG,
                                "QEMU startup resource bounds")
                        try:
                            qmp = QMP(endpoint, resource_guard)
                        except (FileNotFoundError, ConnectionRefusedError):
                            time.sleep(0.02)
                report["stage"] = "machine-properties"
                require(qmp.request("qom-get", {"path": "/machine", "property": "prepare-only"}) is True,
                        "Machine default is prepare-only")
                require(qmp.request("qom-get", {"path": "/machine", "property": "mte"}) is False,
                        "Default memory accounting has MTE disabled")
                require(qmp.request("qom-get", {"path": "/machine", "property": "timebase-frequency"}) == 24000000,
                        "Configurable experimental timebase default")
                require(qmp.request("qom-get", {"path": "/machine", "property": "boot-command-line"}) == COMMAND_LINE,
                        "Ordinary custom boot command line supplied through machine property")
                cpus = qmp.request("query-cpus-fast")
                require(len(cpus) == 1 and isinstance(cpus[0].get("qom-path"), str),
                        "One CPU with its actual QOM path created")
                cpu_path = cpus[0]["qom-path"]
                for iteration in range(2):
                    report["stage"] = "reset" if iteration else "initial-registers"
                    require(time.monotonic() - started < 45 and log_path.stat().st_size <= MAX_LOG,
                            "QEMU integration resource bounds")
                    if iteration:
                        previous_events = len(qmp.events)
                        qmp.request("system_reset")
                        deadline = time.monotonic() + 5
                        while "RESET" not in qmp.events[previous_events:]:
                            require(time.monotonic() < deadline, "Observed asynchronous system_reset completion")
                            qmp.request("query-status")
                            time.sleep(0.01)
                    status = qmp.request("query-status")
                    require(status["running"] is False, "CPU remains stopped; no guest execution requested")
                    cpu_properties = {}
                    for name in ("apple-modern-gxf", "apple-modern-timers",
                                 "apple-modern-guarded", "apple-modern-sprr"):
                        value = qmp.request("qom-get", {"path": cpu_path, "property": name})
                        require(value is True, "Modern CPU property enabled: " + name)
                        cpu_properties[name] = value
                    registers = qmp.request("human-monitor-command", {"command-line": "info registers"})
                    values = parse_registers(registers)
                    require(values["PC"] == layout["entry"] and values["X00"] == layout["args"] and
                            values["PSTATE"] & 15 == 9, "Prepared SPTM PC/x0/AArch64 EL2h")
                    (output / f"registers-{iteration}.txt").write_text(registers)
                    report["stage"] = f"memory-observation-{iteration}"
                    observation = audit(qmp, scratch, blobs, layout, oracle.parse_adt)
                    observation.update({"after_system_reset": bool(iteration), "running": False,
                                        "entry_physical": hex(values["PC"]),
                                        "bootargs_physical": hex(values["X00"]), "reset_el": "EL2h",
                                        "cpu_qom_path": cpu_path, "cpu_properties": cpu_properties})
                    report["observations"].append(observation)
                require(report["observations"][0]["bootargs_sha256"] == report["observations"][1]["bootargs_sha256"] and
                        report["observations"][0]["prepared_dtree_sha256"] == report["observations"][1]["prepared_dtree_sha256"],
                        "Metadata repeats byte-exactly across system_reset")
                require(report["observations"][0]["ramdisk"] == report["observations"][1]["ramdisk"],
                        "Optional ramdisk copy and descriptor repeat across system_reset")
                require(report["observations"][0]["cpu_register_windows"] ==
                        report["observations"][1]["cpu_register_windows"],
                        "Complete CPU register RAM remains zero across system_reset")
                if check_register_reset_pattern:
                    report["stage"] = "register-reset-pattern"
                    report["register_reset_pattern"] = audit_register_reset_pattern(
                        qmp, scratch, report["observations"][0]["cpu_register_windows"],
                        resource_guard)
                    report["cpu_register_ram_reset_pattern_write_qualified"] = True
                qmp.request("quit")
                require(process.wait(timeout=5) == 0, "Clean requested QEMU shutdown")
            report["passed"] = True
            report["stage"] = "complete"
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        report["passed"] = False
        (output / "error-traceback.txt").write_text(traceback.format_exc())
    finally:
        if qmp is not None:
            try:
                qmp.close()
            except Exception as error:
                report["cleanup_error"] = str(error)
                report["passed"] = False
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            report["exit_code"] = process.returncode
            report["child_reaped"] = process.poll() is not None
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()
        try:
            after = {name: digest(path) for name, path in asset_paths.items()}
            report["component_hashes_after"] = after
            report["components_unchanged"] = before == after
            report["binary_unchanged"] = digest(binary)["sha256"] == report["binary_sha256"]
            require(report["components_unchanged"] and report["binary_unchanged"], "Inputs stayed immutable")
        except Exception as error:
            report["preservation_error"] = str(error)
            report["passed"] = False
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True,
                        help="Directory containing bootkc, sptm, txm, dtree and restore-trustcache")
    parser.add_argument("--ramdisk", type=Path,
                        help="Optional regular decoded ramdisk; checks RAM bytes, not filesystem boot")
    parser.add_argument("--qmp-stdio", action="store_true",
                        help="Use bounded child stdin/stdout pipes for QMP instead of a Unix socket")
    parser.add_argument("--check-register-reset-pattern", action="store_true",
                        help="Also check nonzero CPU register RAM using owned startup loader QOM unrealize/reset")
    parser.add_argument("--output-dir", type=Path,
                        help="New private directory for report and bounded log; RAM dumps are deleted")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    components = args.components.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "Binary is a regular executable file")
    require(components.is_dir() and "," not in str(components), "Component directory without QEMU option separators")
    for name in ASSETS:
        asset = components / name
        require(not asset.is_symlink() and asset.is_file() and 0 < asset.stat().st_size <= 512 * 1024 * 1024,
                "Regular bounded decoded asset: " + name)
    ramdisk = None
    if args.ramdisk is not None:
        require(not args.ramdisk.is_symlink(), "Ramdisk must not be a symlink")
        ramdisk = args.ramdisk.resolve(strict=True)
        require(ramdisk.is_file() and "," not in str(ramdisk) and
                0 < ramdisk.stat().st_size <= 512 * 1024 * 1024,
                "Regular bounded decoded ramdisk without QEMU option separators")
    require(sum((components / name).stat().st_size for name in ASSETS) +
            (ramdisk.stat().st_size if ramdisk else 0) <= 1024 * 1024 * 1024,
            "All decoded inputs fit the machine's 1 GiB budget")
    previous_umask = os.umask(0o077)
    try:
        if args.output_dir:
            output = args.output_dir.resolve()
            output.mkdir(parents=True, exist_ok=False, mode=0o700)
            report = run(binary, components, output, ramdisk, args.qmp_stdio,
                         args.check_register_reset_pattern)
        else:
            with tempfile.TemporaryDirectory(prefix="modern-machine-report-") as directory:
                report = run(binary, components, Path(directory), ramdisk, args.qmp_stdio,
                             args.check_register_reset_pattern)
    finally:
        os.umask(previous_umask)
    print(json.dumps({key: report.get(key) for key in
                      ("passed", "binary_sha256", "components_unchanged", "binary_unchanged", "error")}
                     | {"stopped_preparation_observations": len(report["observations"]),
                        "modern_guest_boot": False, "guest_execution": False}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
