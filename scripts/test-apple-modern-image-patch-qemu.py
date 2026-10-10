#!/usr/bin/env python3
"""Whole-machine gate for the declared image-patch facility (stopped CPU).

Starts apple-modern with prepare-only loading (CPU stopped, -S) and inspects
the decoded BootKC as loaded into guest RAM:

 * default board  -- no image-patches option: the stock log string is present
   in guest RAM, the facility is silent, and applied-image-patches is empty;
 * image-patches=demo -- the single demo patch's replacement is present where
   the stock string was, the announcement is logged with the exact wording,
   and applied-image-patches lists exactly 'demo-log-string';
 * the BootKC read-only region of the two runs differs in EXACTLY the 35-byte
   patch span and nowhere else (default board is otherwise byte-identical);
 * image-patches=nonesuch -- a clean, non-zero startup refusal naming the set.

No guest code runs. The on-disk components are hashed before and after.
Run under the shared QEMU lock.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent

STOCK = b"Warning: arc4random not implemented"
REPL = b"Inferno demo image-patch (harmless)"
BOOTKC_FILE_OFFSET = 0x8E1C29  # measured location of the stock string
ANNOUNCE_SUBSTR = ("applied declared image-patch 'demo-log-string' (set "
                   "'demo'):")


def load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"),
                                                  HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


machine_gate = load("test-apple-modern-machine")
require = machine_gate.require


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def start(binary: Path, components: Path, extra: str, scratch: Path, started: float):
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"),
                               machine_gate.ASSETS))
    machine += ",boot-command-line=" + machine_gate.COMMAND_LINE + extra
    argv = [str(binary), "-M", machine, "-m", "8G", "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S",
            "-qmp", "stdio"]
    log = scratch / "emulator.log"
    with log.open("xb") as sink:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=sink, bufsize=0)

    def guard() -> float:
        remaining = 60 - (time.monotonic() - started)
        require(remaining > 0 and log.stat().st_size < (1 << 20), "gate time/log bounds")
        return remaining

    return process, machine_gate.QMP(None, guard, process), argv, log


def patch_physical(blobs: dict) -> tuple[int, tuple[int, int]]:
    """Guest physical address of the stock string, and the BootKC-ro region."""
    layout = machine_gate.expected_layout(blobs)
    phys = None
    for copy in layout["copies"]:
        if copy["image"] != "bootkc":
            continue
        if copy["offset"] <= BOOTKC_FILE_OFFSET < copy["offset"] + copy["file"]:
            phys = copy["physical"] + (BOOTKC_FILE_OFFSET - copy["offset"])
            break
    require(phys is not None, "stock string sits in a copied BootKC segment")
    region = layout["regions"]["BootKC-ro"]
    require(region[0] <= phys and phys + len(STOCK) <= region[0] + region[1],
            "stock string sits inside the BootKC read-only region")
    return phys, region


def dump(qmp, scratch: Path, address: int, size: int, name: str) -> Path:
    path = scratch / name
    qmp.request("pmemsave", {"val": address, "size": size, "filename": str(path)})
    require(path.stat().st_size == size, "complete pmemsave dump")
    return path


def run_case(binary: Path, components: Path, extra: str, label: str, phys: int,
             region: tuple[int, int], evidence: Path, scratch: Path) -> dict:
    started = time.monotonic()
    work = scratch / label
    work.mkdir()
    process, qmp, argv, log = start(binary, components, extra, work, started)
    out = {"label": label, "argv": argv}
    try:
        require(qmp.request("query-status")["running"] is False, "CPU stopped")
        window = dump(qmp, work, phys, len(STOCK), "window.bin")
        out["window"] = window.read_bytes().hex()
        ro = dump(qmp, work, region[0], region[1], "bootkc-ro.bin")
        out["bootkc_ro_path"] = str(ro)
        out["applied"] = qmp.request("qom-get", {"path": "/machine",
                                     "property": "applied-image-patches"})
        out["image_patches"] = qmp.request("qom-get", {"path": "/machine",
                                           "property": "image-patches"})
        if extra:
            out["immutable"] = immutable(qmp)
        qmp.request("quit")
        out["exit_code"] = process.wait(timeout=10)
        process = None
        out["log"] = log.read_text(errors="replace")
    finally:
        if process:
            process.kill()
            process.wait(timeout=10)
        qmp.close()
    (evidence / f"{label}-emulator.log").write_text(out.get("log", ""))
    return out


def immutable(qmp) -> bool:
    qmp.sequence += 1
    request = {"execute": "qom-set", "id": qmp.sequence,
               "arguments": {"path": "/machine", "property": "image-patches",
                             "value": "demo"}}
    deadline = time.monotonic() + 3
    qmp.send(json.dumps(request).encode() + b"\n", deadline)
    while time.monotonic() < deadline:
        response = qmp.receive(deadline)
        if "event" in response:
            continue
        require("error" in response and "return" not in response,
                "image-patches is creation-only")
        require(response["error"]["desc"] ==
                "apple-modern properties are fixed after initialization",
                "exact immutability message")
        return True
    raise RuntimeError("immutability deadline")


def diff_files(a: Path, b: Path) -> list[int]:
    """Streaming byte-diff; returns the list of differing offsets (bounded)."""
    changed = []
    block = 1 << 20
    with a.open("rb") as fa, b.open("rb") as fb:
        base = 0
        while True:
            ba, bb = fa.read(block), fb.read(block)
            require(len(ba) == len(bb), "equal-length region dumps")
            if not ba:
                break
            if ba != bb:
                for i in range(len(ba)):
                    if ba[i] != bb[i]:
                        changed.append(base + i)
                        require(len(changed) <= 4096, "bounded diff size")
            base += len(ba)
    return changed


def refused(binary: Path, components: Path, evidence: Path) -> dict:
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"),
                               machine_gate.ASSETS))
    machine += ",image-patches=nonesuch"
    argv = [str(binary), "-M", machine, "-m", "8G", "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S"]
    run = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    (evidence / "unknown-set-emulator.log").write_text(run.stdout + run.stderr)
    require(run.returncode != 0, "unknown set exits non-zero")
    require("unknown image-patches set 'nonesuch' (supported: demo)" in run.stderr,
            "unknown set names the supported choice")
    return {"exit_code": run.returncode, "stderr": run.stderr.strip()[-400:]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    assets = {name: args.components / name for name in machine_gate.ASSETS}
    before = {name: sha(path) for name, path in assets.items()}
    blobs = {name: path.read_bytes() for name, path in assets.items()}
    phys, region = patch_physical(blobs)
    report = {"binary": str(args.binary), "binary_sha256": sha(args.binary),
              "patch_physical": hex(phys), "bootkc_ro_region": [hex(region[0]),
              hex(region[1])], "passed": False, "firmware_executed": False,
              "guest_execution": False}
    try:
        with tempfile.TemporaryDirectory(prefix="image-patch-qemu-") as temp:
            scratch = Path(temp)
            default = run_case(args.binary, args.components, "", "default",
                               phys, region, args.output_dir, scratch)
            demo = run_case(args.binary, args.components, ",image-patches=demo",
                            "demo", phys, region, args.output_dir, scratch)

            # Default board: stock string present, facility silent and empty.
            require(bytes.fromhex(default["window"]) == STOCK,
                    "default board keeps the stock BootKC string")
            require(default["applied"] == "", "default applied list is empty")
            require(default["image_patches"] == "",
                    "default image-patches option is unset")
            require("image-patch" not in default["log"],
                    "default board does not mention image-patch")
            # Negative in-memory oracle: the replacement is NOT in the default run.
            require(bytes.fromhex(default["window"]) != REPL,
                    "default board does not contain the replacement")

            # Enabled board: replacement present, announced, listed, immutable.
            require(bytes.fromhex(demo["window"]) == REPL,
                    "enabled board contains the replacement in guest RAM")
            require(demo["applied"] == "demo-log-string",
                    "applied list names exactly the demo patch")
            require(ANNOUNCE_SUBSTR in demo["log"],
                    "announcement is logged with the exact wording")
            require("declared modification, not Apple fidelity" in demo["log"],
                    "announcement declares it is a modification")
            require(demo["immutable"], "image-patches is creation-only")

            # The two runs differ ONLY within the declared 35-byte patch span
            # and nowhere else in the 20 MiB read-only region. (Two of the 35
            # bytes coincide between the stock and replacement strings, so the
            # measured diff is <= 35 bytes; what matters is that none lies
            # outside the span.)
            changed = diff_files(Path(default["bootkc_ro_path"]),
                                 Path(demo["bootkc_ro_path"]))
            span = set(range(phys - region[0], phys - region[0] + len(STOCK)))
            require(0 < len(changed) and set(changed) <= span,
                    "default and enabled BootKC-ro differ only inside the patch span")
            report["changed_byte_count"] = len(changed)
            report["patch_span_bytes"] = len(STOCK)
            report["announcement"] = next(
                (l for l in demo["log"].splitlines() if ANNOUNCE_SUBSTR in l), "")
            report["unknown_set"] = refused(args.binary, args.components,
                                            args.output_dir)
            report["passed"] = True
    except BaseException as error:
        report["error"] = repr(error)
    report["components_unchanged"] = before == {n: sha(p) for n, p in assets.items()}
    report["passed"] = report["passed"] and report["components_unchanged"]
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report.get(k) for k in
                      ("passed", "error", "components_unchanged",
                       "changed_byte_count", "announcement")}, indent=1))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
