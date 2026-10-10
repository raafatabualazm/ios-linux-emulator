#!/usr/bin/env python3
"""Whole-machine gate for the opt-in second (OS cryptex) trust-cache module.

Every case starts apple-modern with the CPU stopped (`-S`, prepare-only=on),
so no guest code runs and no trust-cache entry is ever consulted. What is
proved, all measured against bytes read back out of guest RAM:

  * default board unchanged: with no cryptex module the published catalog is
    byte-for-byte the historical one -- count 1, offset 8, the module's own
    bytes, then zeros to the end of the reservation;
  * with a cryptex module the catalog is count 2, offset 8 and
    offset 8 + len(first), with both modules' bytes verbatim and nothing else
    changed in the reservation;
  * the served ADT's /chosen/memory-map TrustCache extent covers the whole
    catalog in both cases, and the region grows by exactly what the second
    module costs;
  * negative oracles: a malformed cryptex module is refused by name, a
    cryptex module whose bytes are truncated is refused, and a binary that
    predates the property refuses the property itself.

Run under the shared QEMU lock. Do not wrap it in `ulimit -v`.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
PAGE = 0x4000
COMMAND_LINE = "--audit-modern-command-line -v"


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


machine_gate = load("test-apple-modern-machine")
metadata_oracle = load("test-apple-modern-boot-metadata")
require = machine_gate.require
QMP = machine_gate.QMP


def page_up(value: int) -> int:
    return (value + PAGE - 1) & -PAGE


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def module(version: int, count: int, entry_size: int) -> bytes:
    """A bare, inert trust-cache module: the 24-byte header then `count`
    zero-filled entries. No cdhash is ever read, written or merged by this
    gate; these bytes exist only so the catalog has something to carry."""
    return struct.pack("<I16sI", version, bytes(16), count) + bytes(count * entry_size)


def run_case(binary: Path, components: Path, output: Path, name: str,
             first: Path, cryptex: Path | None, v2: bool,
             expect_refusal: str | None = None) -> dict:
    """Start the machine stopped, read the TrustCache reservation back out of
    guest RAM, and return what was found there."""
    assets = {"bootkc": components / "bootkc", "sptm": components / "sptm",
              "txm": components / "txm", "dtree": components / "dtree",
              "tc": first}
    machine = "apple-modern," + ",".join(f"{k}={v}" for k, v in assets.items())
    machine += ",prepare-only=on"
    if v2:
        machine += ",trustcache-v2=on"
    if cryptex is not None:
        machine += f",cryptex-trustcache={cryptex}"
    machine += ",boot-command-line=" + COMMAND_LINE
    case = output / name
    case.mkdir(parents=True)
    log_path = case / "emulator.log"
    with tempfile.TemporaryDirectory(prefix="cryptex-tc-") as temporary:
        scratch = Path(temporary)
        endpoint = scratch / "qmp.sock"
        argv = [str(binary), "-M", machine, "-m", "8G", "-smp", "1",
                "-nodefaults", "-display", "none", "-serial", "none",
                "-monitor", "none", "-S",
                "-qmp", "unix:" + str(endpoint) + ",server=on,wait=off"]
        (case / "argv.json").write_text(json.dumps(argv, indent=1))
        started = time.monotonic()
        with log_path.open("xb") as log:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                if expect_refusal is not None:
                    process.wait(timeout=30)
                    text = log_path.read_text(errors="replace")
                    require(process.returncode != 0,
                            f"{name}: the machine must refuse this input")
                    require(expect_refusal in text,
                            f"{name}: refusal {text.strip()!r} lacks "
                            f"{expect_refusal!r}")
                    return {"case": name, "refused": True,
                            "message": text.strip()[:400]}

                def guard() -> float:
                    remaining = 45 - (time.monotonic() - started)
                    require(remaining > 0, f"{name}: QMP time bound")
                    return remaining

                qmp = None
                deadline = time.monotonic() + 15
                while qmp is None:
                    require(process.poll() is None,
                            f"{name}: QEMU exited; see emulator.log")
                    require(time.monotonic() < deadline,
                            f"{name}: QMP startup bound")
                    try:
                        qmp = QMP(endpoint, guard)
                    except (FileNotFoundError, ConnectionRefusedError):
                        time.sleep(0.1)
                require(qmp.request("query-status")["running"] is False,
                        f"{name}: the CPU must be stopped")

                def memory(address: int, size: int) -> bytes:
                    require(0 < size <= 8 << 20, f"{name}: read bound")
                    path = scratch / "ram.bin"
                    path.unlink(missing_ok=True)
                    qmp.request("pmemsave", {"val": address, "size": size,
                                             "filename": str(path)})
                    data = path.read_bytes()
                    require(len(data) == size, f"{name}: short RAM dump")
                    path.unlink()
                    return data

                blobs = {n: p.read_bytes() for n, p in assets.items()}
                blobs["restore-trustcache"] = blobs["tc"]
                layout = machine_gate.expected_layout(blobs)
                args = memory(layout["args"], 1152)
                tree_size = struct.unpack_from("<I", args, 104)[0]
                tree = memory(layout["tree"], tree_size)
                nodes, _ = metadata_oracle.parse_adt(tree)
                extent = nodes["/chosen/memory-map"]["TrustCache"]["value"]
                require(len(extent) == 16, f"{name}: TrustCache extent length")
                address, size = struct.unpack("<QQ", extent)
                catalog = memory(address, size)
                qmp.request("quit")
                return {"case": name, "refused": False,
                        "region": {"address": address, "size": size},
                        "catalog": catalog,
                        "tree_sha256": digest(tree),
                        "bootargs_sha256": digest(args)}
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)


def check_catalog(name: str, found: dict, modules: list[bytes]) -> None:
    catalog = found["catalog"]
    header = 4 + 4 * len(modules)
    expected = bytearray(struct.pack("<I", len(modules)))
    offset = header
    for payload in modules:
        expected += struct.pack("<I", offset)
        offset += len(payload)
    for payload in modules:
        expected += payload
    require(len(catalog) >= len(expected),
            f"{name}: reservation {len(catalog)} shorter than the catalog "
            f"{len(expected)}")
    require(catalog[:len(expected)] == bytes(expected),
            f"{name}: catalog bytes differ from the expected layout")
    require(set(catalog[len(expected):]) <= {0},
            f"{name}: the tail of the reservation is not zero")
    require(found["region"]["size"] == page_up(len(expected)),
            f"{name}: reservation is not the page-rounded catalog")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--previous-pin", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = {"scope": "Whole apple-modern machine, CPU stopped: the published "
                       "trust-cache catalog only. No guest execution, no "
                       "trust-cache entry parsed.",
              "binary": str(args.binary), "cases": [], "passed": False}
    scratch = args.output_dir / "modules"
    scratch.mkdir(exist_ok=True)
    first = module(1, 3, 22)
    second = module(1, 5, 22)
    second_v2 = module(2, 7, 24)
    (scratch / "first-v1").write_bytes(first)
    (scratch / "second-v1").write_bytes(second)
    (scratch / "second-v2").write_bytes(second_v2)
    (scratch / "second-bad").write_bytes(second[:-1])

    base = run_case(args.binary, args.components, args.output_dir,
                    "default-one-module", scratch / "first-v1", None, False)
    check_catalog("default-one-module", base, [first])
    report["cases"].append({"case": base["case"],
                            "region": base["region"],
                            "catalog_sha256": digest(base["catalog"])})

    two = run_case(args.binary, args.components, args.output_dir,
                   "two-v1-modules", scratch / "first-v1",
                   scratch / "second-v1", False)
    check_catalog("two-v1-modules", two, [first, second])
    require(two["region"]["address"] == base["region"]["address"],
            "the catalog stays at the same address")
    require(two["tree_sha256"] != base["tree_sha256"] or
            two["region"]["size"] == base["region"]["size"],
            "a changed reservation must show in the served tree")
    report["cases"].append({"case": two["case"], "region": two["region"],
                            "catalog_sha256": digest(two["catalog"])})

    two_v2 = run_case(args.binary, args.components, args.output_dir,
                      "two-modules-v2-cryptex", scratch / "first-v1",
                      scratch / "second-v2", True)
    check_catalog("two-modules-v2-cryptex", two_v2, [first, second_v2])
    report["cases"].append({"case": two_v2["case"], "region": two_v2["region"],
                            "catalog_sha256": digest(two_v2["catalog"])})

    report["cases"].append(run_case(
        args.binary, args.components, args.output_dir, "oracle-v2-without-optin",
        scratch / "first-v1", scratch / "second-v2", False,
        expect_refusal="version-2 trustcache needs trustcache-v2=on"))
    report["cases"].append(run_case(
        args.binary, args.components, args.output_dir, "oracle-truncated-cryptex",
        scratch / "first-v1", scratch / "second-bad", False,
        expect_refusal="missing or malformed cryptex trustcache"))
    if args.previous_pin:
        report["cases"].append(run_case(
            args.previous_pin, args.components, args.output_dir,
            "oracle-previous-pin", scratch / "first-v1", scratch / "second-v1",
            False, expect_refusal="cryptex-trustcache"))

    report["passed"] = True
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=1,
                                                            default=str))
    print(json.dumps({"passed": True, "cases": len(report["cases"])}))


if __name__ == "__main__":
    main()
