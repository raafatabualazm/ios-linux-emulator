#!/usr/bin/env python3
"""Whole-machine gate for the large-ramdisk option and mc->default_ram_id.

Every case starts apple-modern with the CPU stopped, so no guest code runs.
What is proved, all measured:

  * default board unchanged: the option reads off, a small ramdisk is still
    copied into guest RAM, and the DRAM ramblock is still "apple-modern.ram";
  * with the option OFF a ramdisk over 512 MiB is still refused with the
    existing read_asset() message (sparse fixture, refused on st_size);
  * with the option ON the same small ramdisk gives a byte-identical served
    ADT, identical boot_args and identical guest bytes at ramdisk_physical,
    and adds the host mapping as its own ramblock;
  * with the option ON a multi-GiB image (past the old 4 GiB layout cap and
    the 512 MiB asset cap) is accepted and the guest reads the right bytes
    back out of guest RAM at the start, middle and end of the reservation;
  * negative oracles: the option on without a ramdisk asset, a file over the
    opt-in ceiling, a deliberately wrong expected marker, and the previous
    pin, which does not know the property at all;
  * guest RAM can be file-backed: -object memory-backend-file on a sparse
    file plus -machine memory-backend=... with -m 20G.

Peak host RSS and disk use are recorded. Run under the shared QEMU lock, and
do not wrap it in `ulimit -v` (the guest RAM mapping needs the address space).
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
ASSETS = ("bootkc", "sptm", "txm", "dtree", "restore-trustcache")
PROPERTY_NAMES = ("bootkc", "sptm", "txm", "dtree", "tc")


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


machine_gate = load("test-apple-modern-machine")
metadata_oracle = load("test-apple-modern-boot-metadata")
require = machine_gate.require


def page_up(value: int) -> int:
    return (value + PAGE - 1) & -PAGE


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def disk_free() -> int:
    stats = os.statvfs("/home/kali")
    return stats.f_bavail * stats.f_frsize


def mem_available() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("no MemAvailable")


def placement(components: Path, size: int) -> dict:
    """Independent Python copy of the C rule: the RAMDisk region starts at the
    page-aligned cursor that follows BootArgs."""
    blobs = {name: (components / name).read_bytes() for name in ASSETS}
    layout = machine_gate.expected_layout(blobs)
    require(layout["top"] % PAGE == 0, "ramdisk base is page aligned")
    return {"physical": layout["top"], "reserved": page_up(size),
            "args": layout["args"], "tree": layout["tree"]}


def marker(index: int) -> bytes:
    return b"W4-ASSETS-MARK-%04d" % index


def make_marker_image(path: Path, size: int, spots: list) -> dict:
    """A sparse image carrying a distinct marker at each given offset."""
    with path.open("wb") as sink:
        sink.truncate(size)
        for index, offset in enumerate(spots):
            sink.seek(offset)
            sink.write(marker(index))
    require(path.stat().st_size == size, "marker image has the asked size")
    return {"bytes": size, "allocated_kib": path.stat().st_blocks // 2,
            "spots": spots}


def qmp_argv(binary: Path, components: Path, extra: str, ram: str,
             ramdisk: Path | None, backend: Path | None, monitor: bool) -> list:
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(PROPERTY_NAMES, ASSETS))
    if ramdisk is not None:
        machine += ",ramdisk=" + str(ramdisk)
    argv = [str(binary)]
    if backend is not None:
        argv += ["-object", "memory-backend-file,id=apple-modern.ram,size=" +
                 ram + ",mem-path=" + str(backend) + ",share=on"]
        machine += ",memory-backend=apple-modern.ram"
    machine += extra + ",boot-command-line=" + COMMAND_LINE
    argv += ["-M", machine, "-m", ram, "-smp", "1", "-nodefaults",
             "-display", "none", "-serial", "none", "-monitor", "none", "-S"]
    if monitor:
        argv += ["-qmp", "stdio"]
    return argv


def peak_rss(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    except OSError:
        return 0
    return 0


def immutable(qmp) -> dict:
    qmp.sequence += 1
    request = {"execute": "qom-set", "id": qmp.sequence,
               "arguments": {"path": "/machine", "property": "large-ramdisk",
                             "value": True}}
    deadline = time.monotonic() + 5
    qmp.send(json.dumps(request).encode() + b"\n", deadline)
    while time.monotonic() < deadline:
        response = qmp.receive(deadline)
        if "event" in response:
            continue
        require("error" in response and "return" not in response,
                "large-ramdisk is creation-only")
        require(response["error"]["desc"] ==
                "apple-modern properties are fixed after initialization",
                "exact immutability message")
        return response["error"]
    raise RuntimeError("immutability deadline")


def run_case(binary: Path, components: Path, label: str, evidence: Path,
             place: dict, reads: list, extra: str = "", ram: str = "8G",
             ramdisk: Path | None = None,
             backend: Path | None = None) -> dict:
    """Start, inspect guest RAM, quit. `reads` are (offset, length) pairs
    inside the ramdisk reservation."""
    started = time.monotonic()
    argv = qmp_argv(binary, components, extra, ram, ramdisk, backend, True)
    result = {"label": label, "argv": argv, "ram": ram,
              "ramdisk_physical": place["physical"]}
    with tempfile.TemporaryDirectory(prefix="large-ramdisk-qemu-") as temp:
        scratch = Path(temp)
        log = scratch / "emulator.log"
        with log.open("xb") as sink:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=sink,
                                       bufsize=0)

        def guard() -> float:
            remaining = 180 - (time.monotonic() - started)
            require(remaining > 0 and log.stat().st_size < (1 << 20),
                    "gate time/log bounds")
            return remaining

        qmp = machine_gate.QMP(None, guard, process)
        dump = scratch / "dump.bin"
        try:
            require(qmp.request("query-status")["running"] is False,
                    "CPU stopped")
            result["option"] = qmp.request(
                "qom-get", {"path": "/machine", "property": "large-ramdisk"})
            result["ramblocks"] = qmp.request(
                "human-monitor-command", {"command-line": "info ramblock"})
            result["flatview"] = [
                line.strip() for line in qmp.request(
                    "human-monitor-command",
                    {"command-line": "info mtree -f"}).splitlines()
                if "apple-modern.ram" in line or
                "apple-modern.large-ramdisk" in line]
            qmp.request("pmemsave", {"val": place["args"], "size": 1152,
                                     "filename": str(dump)})
            boot_args = dump.read_bytes()
            dump.unlink()
            result["bootargs_mem_size"] = struct.unpack_from("<Q", boot_args,
                                                             24)[0]
            result["bootargs_top"] = struct.unpack_from("<Q", boot_args, 32)[0]
            tree_size = struct.unpack_from("<I", boot_args, 104)[0]
            qmp.request("pmemsave", {"val": place["tree"], "size": tree_size,
                                     "filename": str(dump)})
            tree = dump.read_bytes()
            dump.unlink()
            result["tree_sha256"] = hashlib.sha256(tree).hexdigest()
            nodes, _ = metadata_oracle.parse_adt(tree)
            result["adt_ramdisk"] = nodes["/chosen/memory-map"]["RAMDisk"][
                "value"].hex()
            result["reads"] = []
            for offset, length in reads:
                qmp.request("pmemsave", {"val": place["physical"] + offset,
                                         "size": length,
                                         "filename": str(dump)})
                result["reads"].append({"offset": offset, "length": length,
                                        "bytes": dump.read_bytes().hex()})
                dump.unlink()
            result["peak_rss"] = peak_rss(process.pid)
            result["immutable"] = immutable(qmp)
            qmp.request("quit")
            result["exit_code"] = process.wait(timeout=20)
            process = None
        finally:
            if process is not None:
                process.kill()
                process.wait(timeout=20)
            qmp.close()
        result["log"] = log.read_text(errors="replace")
    (evidence / f"{label}-emulator.log").write_text(result["log"])
    return result


def refusal(binary: Path, components: Path, label: str, evidence: Path,
            extra: str = "", ram: str = "8G",
            ramdisk: Path | None = None) -> dict:
    argv = qmp_argv(binary, components, extra, ram, ramdisk, None, False)
    run = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    (evidence / f"{label}-emulator.log").write_text(run.stdout + run.stderr)
    require(run.returncode != 0, f"{label} exits non-zero")
    return {"label": label, "argv": argv, "exit_code": run.returncode,
            "stderr": run.stderr.strip()[-2000:]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--previous-pin", type=Path, required=True,
                        help="pin without the option, for the no-device oracle")
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--small-ramdisk", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--large-bytes", type=lambda v: int(v, 0),
                        default=6 << 30)
    parser.add_argument("--scratch", type=Path, required=True,
                        help="directory for sparse fixtures (not evidence)")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    args.scratch.mkdir(parents=True, exist_ok=True)

    inputs = {str(args.binary): sha(args.binary),
              str(args.previous_pin): sha(args.previous_pin),
              str(args.small_ramdisk): sha(args.small_ramdisk)}
    for name in ASSETS:
        inputs[str(args.components / name)] = sha(args.components / name)
    report = {"scope": __doc__, "guest_execution": False,
              "inputs_sha256": inputs, "cases": {}, "oracles": {},
              "disk_free_before": disk_free(),
              "mem_available_before": mem_available()}

    small = args.small_ramdisk.stat().st_size
    small_place = placement(args.components, small)
    window = min(0x10000, small)
    small_reads = [(0, window), (page_up(small) - window, window)]
    head = args.small_ramdisk.read_bytes()[:window]

    with tempfile.TemporaryDirectory(prefix="w4-fixtures-",
                                     dir=str(args.scratch)) as temp:
        scratch = Path(temp)

        # --- A: default board, small ramdisk, copying path -----------------
        default_small = run_case(args.binary, args.components, "default-small",
                                 args.evidence, small_place, small_reads,
                                 ramdisk=args.small_ramdisk)
        report["cases"]["default-small"] = default_small
        require(default_small["option"] is False, "option defaults to off")
        require("apple-modern.ram" in default_small["ramblocks"],
                "DRAM ramblock keeps its name")
        require("apple-modern.large-ramdisk" not in
                default_small["ramblocks"],
                "no extra ramblock on the default path")
        require(not [line for line in default_small["flatview"]
                     if "large-ramdisk" in line],
                "no mapped region in the default flat view")
        require(bytes.fromhex(default_small["reads"][0]["bytes"]) == head,
                "the copied ramdisk head is in guest RAM")
        require(default_small["adt_ramdisk"] ==
                struct.pack("<QQ", small_place["physical"],
                            small_place["reserved"]).hex(),
                "ADT RAMDisk region matches the independent placement")

        # --- C: option on, same small ramdisk ------------------------------
        on_small = run_case(args.binary, args.components, "on-small",
                            args.evidence, small_place, small_reads,
                            ramdisk=args.small_ramdisk,
                            extra=",large-ramdisk=on")
        report["cases"]["on-small"] = on_small
        require(on_small["option"] is True, "option reads on")
        mapped = [line for line in on_small["flatview"]
                  if "apple-modern.large-ramdisk" in line]
        require(len(mapped) == 1, "exactly one mapped region in the flat view")
        require(mapped[0].startswith(
            "%016x-%016x (prio 1, ram): apple-modern.large-ramdisk" %
            (small_place["physical"],
             small_place["physical"] + small_place["reserved"] - 1)),
            "the mapping covers exactly the ramdisk reservation at priority 1")
        require("apple-modern.large-ramdisk" not in on_small["ramblocks"],
                "the mapping is a RAM_PREALLOC block with no migration id")
        require(on_small["tree_sha256"] == default_small["tree_sha256"],
                "served ADT byte-identical with and without the option")
        require(on_small["reads"] == default_small["reads"],
                "guest bytes at ramdisk_physical identical, head and tail")
        require(on_small["bootargs_mem_size"] ==
                default_small["bootargs_mem_size"] and
                on_small["bootargs_top"] == default_small["bootargs_top"],
                "boot_args unchanged by the option")

        # --- D: option on, large sparse marker image ------------------------
        big_path = scratch / "large-marker.img"
        spots = [0, args.large_bytes // 2, args.large_bytes - 0x1000]
        report["large_image"] = make_marker_image(big_path, args.large_bytes,
                                                  spots)
        big_place = placement(args.components, args.large_bytes)
        big_reads = [(offset, len(marker(index)))
                     for index, offset in enumerate(spots)]
        on_large = run_case(args.binary, args.components, "on-large",
                            args.evidence, big_place, big_reads, ram="12G",
                            ramdisk=big_path, extra=",large-ramdisk=on")
        report["cases"]["on-large"] = on_large
        mapped = [line for line in on_large["flatview"]
                  if "apple-modern.large-ramdisk" in line]
        require(len(mapped) == 1 and mapped[0].startswith(
            "%016x-%016x (prio 1, ram): apple-modern.large-ramdisk" %
            (big_place["physical"],
             big_place["physical"] + big_place["reserved"] - 1)),
            "the large mapping covers exactly its reservation")
        for index, read in enumerate(on_large["reads"]):
            require(bytes.fromhex(read["bytes"]) == marker(index),
                    f"guest reads marker {index} at offset {spots[index]}")
        require(on_large["adt_ramdisk"] ==
                struct.pack("<QQ", big_place["physical"],
                            big_place["reserved"]).hex(),
                "ADT RAMDisk region for the large image")
        report["oracles"]["wrong-marker"] = {
            "claim": "the read-back comparison can fail",
            "passed": bytes.fromhex(on_large["reads"][0]["bytes"]) !=
                      marker(1)}
        require(report["oracles"]["wrong-marker"]["passed"],
                "mutation oracle: a wrong marker does not compare equal")

        # --- B/E/F: refusals -----------------------------------------------
        oversize = scratch / "oversize.img"
        with oversize.open("wb") as sink:
            sink.truncate(600 << 20)
        off_oversize = refusal(args.binary, args.components, "off-oversize",
                               args.evidence, ramdisk=oversize)
        report["oracles"]["off-oversize"] = off_oversize
        require("modern asset must be a regular nonempty file of at most 512 "
                "MiB within the" in off_oversize["stderr"],
                "option off keeps the existing 512 MiB message")
        oversize.unlink()
        no_ramdisk = refusal(args.binary, args.components, "on-no-ramdisk",
                             args.evidence, extra=",large-ramdisk=on")
        report["oracles"]["on-no-ramdisk"] = no_ramdisk
        require("large-ramdisk needs a ramdisk asset" in no_ramdisk["stderr"],
                "option on without the asset is refused by name")
        over_ceiling = scratch / "over-ceiling.img"
        with over_ceiling.open("wb") as sink:
            sink.truncate((32 << 30) + 1)
        ceiling = refusal(args.binary, args.components, "on-over-ceiling",
                          args.evidence, extra=",large-ramdisk=on",
                          ramdisk=over_ceiling)
        report["oracles"]["on-over-ceiling"] = ceiling
        require("large modern ramdisk must be a regular nonempty file of at "
                "most" in ceiling["stderr"],
                "option on over the ceiling is refused by name")
        over_ceiling.unlink()

        # --- G: no-device oracle on the previous pin -----------------------
        previous = refusal(args.previous_pin, args.components, "previous-pin",
                           args.evidence, extra=",large-ramdisk=on",
                           ramdisk=args.small_ramdisk)
        report["oracles"]["previous-pin"] = previous
        require("large-ramdisk" in previous["stderr"],
                "the previous pin does not know the property")

        # --- H: file-backed guest RAM, -m 20G ------------------------------
        backing = scratch / "guest-ram.img"
        with backing.open("wb") as sink:
            sink.truncate(20 << 30)
        allocated_before = backing.stat().st_blocks // 2
        free_before = disk_free()
        backed = run_case(args.binary, args.components, "file-backed-20g",
                          args.evidence, big_place, big_reads, ram="20G",
                          ramdisk=big_path, extra=",large-ramdisk=on",
                          backend=backing)
        backed["backing_file"] = {
            "declared_bytes": 20 << 30,
            "allocated_kib_before": allocated_before,
            "allocated_kib_after": backing.stat().st_blocks // 2,
            "disk_free_delta_bytes": free_before - disk_free()}
        report["cases"]["file-backed-20g"] = backed
        require(backed["bootargs_mem_size"] == 20 << 30,
                "the guest is told about 20 GiB of DRAM")
        require("apple-modern.ram" in backed["ramblocks"],
                "the file backend takes the board's ramblock name")
        for index, read in enumerate(backed["reads"]):
            require(bytes.fromhex(read["bytes"]) == marker(index),
                    f"file-backed guest reads marker {index}")
        backing.unlink()
        big_path.unlink()

    report["disk_free_after"] = disk_free()
    report["peak_rss_bytes"] = {label: case.get("peak_rss")
                                for label, case in report["cases"].items()}
    for case in report["cases"].values():
        case.pop("log", None)
    report["inputs_unchanged"] = all(
        sha(Path(path)) == value for path, value in inputs.items())
    require(report["inputs_unchanged"], "inputs unchanged")
    report["passed"] = True
    (args.evidence / "report.json").write_text(
        json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True, "cases": list(report["cases"]),
                      "oracles": list(report["oracles"]),
                      "peak_rss_bytes": report["peak_rss_bytes"],
                      "large_image": report["large_image"],
                      "backing_file": report["cases"]["file-backed-20g"][
                          "backing_file"],
                      "disk_free_before": report["disk_free_before"],
                      "disk_free_after": report["disk_free_after"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
