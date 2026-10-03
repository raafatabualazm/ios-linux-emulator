#!/usr/bin/env python3
"""Compile production layout/metadata with sanitizers; optionally audit assets.

No guest launch. Actual firmware stays outside the source checkout. Reports
contain hashes/counts and addresses, never ADT property contents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def digest(path: Path) -> dict:
    sha = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            sha.update(chunk)
    return {"sha256": sha.hexdigest(), "bytes": path.stat().st_size}


def parse_adt(blob: bytes) -> tuple[dict, list[str]]:
    cursor = 0
    nodes: dict = {}
    order: list[str] = []

    def walk(parent: str, depth: int) -> None:
        nonlocal cursor
        assert depth <= 32 and cursor + 8 <= len(blob)
        count, children = struct.unpack_from("<II", blob, cursor)
        cursor += 8
        props = {}
        assert 0 < count <= 4096 and children <= 8192
        for _ in range(count):
            begin = cursor
            assert cursor + 36 <= len(blob)
            raw_name = blob[cursor:cursor + 32]
            assert b"\0" in raw_name
            name = raw_name.split(b"\0", 1)[0].decode("ascii")
            flags = struct.unpack_from("<I", blob, cursor + 32)[0]
            length = flags & 0x7FFFFFFF
            cursor += 36
            assert cursor + length <= len(blob)
            data = blob[cursor:cursor + length]
            cursor += (length + 3) & ~3
            assert cursor <= len(blob) and name and name not in props
            props[name] = {"value": data, "raw": blob[begin:cursor]}
        name = props["name"]["value"].split(b"\0", 1)[0].decode("ascii")
        path = parent + "/" + name if depth else "/"
        if depth == 1:
            path = "/" + name
        assert path not in nodes and len(nodes) < 8192
        nodes[path] = props
        order.append(path)
        for _ in range(children):
            walk(path, depth + 1)

    walk("", 0)
    assert cursor == len(blob)
    return nodes, order


def audit_metadata(components: Path, scratch: Path, layout_log: str) -> dict:
    original_blob = (components / "dtree").read_bytes()
    prepared_blob = (scratch / "prepared-dtree").read_bytes()
    original, original_order = parse_adt(original_blob)
    prepared, prepared_order = parse_adt(prepared_blob)
    assert original_order == prepared_order
    normal_names = {line.split()[1] for line in layout_log.splitlines()
                    if line.startswith("REGION ")}
    normal_names |= {"BootKC-virt", "BootKC-entry", "SPTM-virt", "SPTM-entry",
                     "TXM-virt", "TXM-entry", "slide", "SPTM-rm", "CL4-rx",
                     "CL4-ro", "CL4-rw", "CL4-le", "CL4-entry", "CL4-virt", "RAMDisk"}
    preserved = 0
    for path, props in original.items():
        for name, prop in props.items():
            if (path == "/chosen" and name in {"dram-base", "dram-size"}) or (
                    path == "/chosen/memory-map" and name in normal_names):
                continue
            assert prepared[path][name]["raw"] == prop["raw"]
            preserved += 1
    for path, props in prepared.items():
        for name in props.keys() - original[path].keys():
            assert (path == "/chosen" and name in {"dram-base", "dram-size"}) or (
                path == "/chosen/memory-map" and name in normal_names)
    memory_map = prepared["/chosen/memory-map"]
    region_count = 0
    for line in layout_log.splitlines():
        if line.startswith("REGION "):
            _, name, address, size = line.split()
            assert struct.unpack("<QQ", memory_map[name]["value"]) == (
                int(address, 16), int(size, 16))
            region_count += 1
    args = (scratch / "prepared-bootargs").read_bytes()
    assert len(args) == 1152
    assert struct.unpack_from("<HH", args) == (2, 2)
    phys = struct.unpack_from("<Q", args, 16)[0]
    memory = struct.unpack_from("<Q", args, 24)[0]
    actual_memory = struct.unpack_from("<Q", args, 1144)[0]
    assert phys == 1 << 40 and actual_memory == 8 << 30
    assert memory == actual_memory // 32 * 31
    assert struct.unpack_from("<I", args, 104)[0] == len(prepared_blob)
    assert args[108:108 + 12] == b"-v serial=3\0"
    assert struct.unpack_from("<Q", args, 1136)[0] == 1
    catalog = (components / "restore-trustcache").read_bytes()
    wrapped = (scratch / "prepared-trustcache").read_bytes()
    assert wrapped[:8] == struct.pack("<II", 1, 8) and wrapped[8:] == catalog
    assert "/arm-io/sgx" in prepared
    return {"pass": True, "nodes_preserved_in_original_order": len(original),
            "original_properties_preserved_byte_exactly": preserved,
            "advertised_regions_verified": region_count,
            "prepared_dtree_bytes": len(prepared_blob), "bootargs_bytes": len(args),
            "trustcache_bytes": len(wrapped), "graphics_node_retained": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--components", type=Path,
                        help="Directory with the five decoded matching components")
    parser.add_argument("--evidence", type=Path,
                        help="Save private report/log here, refusing existing files")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sources = ["hw/arm/apple-silicon/modern-boot-layout.c",
               "include/hw/arm/apple-silicon/modern-boot-layout.h",
               "hw/arm/apple-silicon/modern-boot-metadata.c",
               "include/hw/arm/apple-silicon/modern-boot-metadata.h",
               "scripts/test-apple-modern-boot-layout.c",
               "scripts/test-apple-modern-boot-metadata.c"]
    source_hashes = {name: digest(root / name) for name in sources}
    assets = ["bootkc", "sptm", "txm", "dtree", "restore-trustcache"]
    before = ({name: digest(args.components / name) for name in assets}
              if args.components else {})
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "-DAPPLE_MODERN_LAYOUT_STANDALONE", "-I" + str(root / "include")]
    logs = []
    counts = {}
    oracle = None
    with tempfile.TemporaryDirectory(prefix="modern-metadata-audit-") as temp:
        scratch = Path(temp)
        outputs = {}
        for name in ("layout", "metadata"):
            binary = scratch / name
            production = [str(root / "hw/arm/apple-silicon/modern-boot-layout.c")]
            if name == "metadata":
                production.append(str(root / "hw/arm/apple-silicon/modern-boot-metadata.c"))
            command = ["cc", *flags, *production,
                       str(root / f"scripts/test-apple-modern-boot-{name}.c"),
                       "-o", str(binary)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            command = [str(binary)]
            if args.components:
                command.append(str(args.components.resolve()))
                if name == "metadata":
                    command.append(str(scratch))
            run = subprocess.run(command, capture_output=True, text=True, timeout=60)
            logs.append(f"{name} exit={run.returncode}\n" + run.stdout + run.stderr)
            if run.returncode:
                raise RuntimeError(logs[-1])
            outputs[name] = run.stdout
            counts[name] = int(re.search(r"PASS (\d+)", run.stdout).group(1))
        if args.components:
            oracle = audit_metadata(args.components, scratch, outputs["layout"])
    after = ({name: digest(args.components / name) for name in assets}
             if args.components else {})
    assert before == after
    assert source_hashes == {name: digest(root / name) for name in sources}
    report = {"scope": "Production-source standalone preparation; no guest execution",
              "source_hashes": source_hashes, "sanitizers": ["ASan", "UBSan"],
              "semantic_checks": counts, "actual_metadata_oracle": oracle,
              "immutable_components_before": before,
              "immutable_components_after": after,
              "immutable_components_unchanged": before == after,
              "modern_guest_boot": False, "gui_verified": False, "ipa_executed": False}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        report_path = args.evidence / "modern-metadata-review.json"
        log_path = args.evidence / "modern-metadata-tests.log"
        with report_path.open("x") as destination:
            json.dump(report, destination, indent=2)
            destination.write("\n")
        with log_path.open("x") as destination:
            destination.write("\n".join(logs))
    print(json.dumps({"semantic_checks": counts, "actual_metadata_oracle": oracle,
                      "immutable_components_unchanged": before == after}, indent=2))


if __name__ == "__main__":
    main()
