#!/usr/bin/env python3
"""Whole-machine gate for pmgr-boot-on (stopped CPU, prepare-only).

Reads all 138 PMGR power-state cells through the guest physical address space
(HMP xp) with the default board and with the 'j700' profile, across a
system_reset. Cell addresses and the expected set are derived independently:
addresses from the stock ADT (ps-groups, devices, ranges), the set from the
retained Asahi T8140 pmgr device tree (apple,always-on labels). Run under the
shared QEMU lock.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent.parent
DTSI = ROOT / ("modern-emulator/evidence/features-20261008/mcc-dcs-perf/research/sources/"
               "linux-asahi-t8140-pmgr.dtsi")


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


machine_gate = load("test-apple-modern-machine")
oracle = load("test-apple-modern-boot-metadata")
require = machine_gate.require


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cell_addresses(nodes):
    """name -> physical address of each hardware power-state cell (stock ADT)."""
    pmgr, arm_io = nodes["/arm-io/pmgr"], nodes["/arm-io"]
    ranges = [struct.unpack_from("<QQQ", arm_io["ranges"]["value"], i)
              for i in range(0, len(arm_io["ranges"]["value"]), 24)]
    regs = [struct.unpack_from("<QQ", pmgr["reg"]["value"], i)
            for i in range(0, len(pmgr["reg"]["value"]), 16)]
    groups = [struct.unpack_from("<III", pmgr["ps-groups"]["value"], i)
              for i in range(0, len(pmgr["ps-groups"]["value"]), 12)]
    devices = pmgr["devices"]["value"]

    def physical(child):
        for c, p, n in ranges:
            if c <= child < c + n:
                return p + child - c
        raise AssertionError("unmapped bus address")

    cells = {}
    for i in range(0, len(devices), 48):
        record = devices[i:i + 48]
        if record[0] & 0x10:
            continue
        name = record[32:48].split(b"\0")[0].decode()
        offset = record[16] | record[17] << 8 | record[18] << 16
        index, base, _ = groups[record[19]]
        child, _ = regs[index]
        require(name not in cells, "unique device names")
        cells[name] = physical(child) + base + offset
    return cells


def always_on_labels():
    text = DTSI.read_text()
    blocks = re.findall(r"ps_\w+: power-controller@[0-9a-f]+ \{(.*?)\n\t\};", text, re.S)
    return sorted(re.search(r'label = "([^"]+)"', b).group(1).upper()
                  for b in blocks if "apple,always-on" in b)


def launch(binary, components, extra, scratch):
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"), machine_gate.ASSETS))
    machine += ",boot-command-line=" + machine_gate.COMMAND_LINE + extra
    argv = [str(binary), "-M", machine, "-m", "8G", "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S", "-qmp", "stdio"]
    log = scratch / "emulator.log"
    started = time.monotonic()
    with log.open("xb") as sink:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=sink, bufsize=0)

    def guard():
        remaining = 45 - (time.monotonic() - started)
        require(remaining > 0 and log.stat().st_size < (1 << 20), "gate time/log bounds")
        return remaining

    return process, machine_gate.QMP(None, guard, process), log


def read_cells(qmp, cells):
    values = {}
    for name, address in cells.items():
        out = qmp.request("human-monitor-command", {"command-line": f"xp /1wx {address:#x}"})
        match = re.search(r":\s+0x([0-9a-f]{8})", out)
        require(match is not None, f"xp output for {name}: {out!r}")
        values[name] = int(match.group(1), 16)
    return values


def case(binary, components, extra, cells, label, evidence):
    with tempfile.TemporaryDirectory(prefix="pmgr-boot-on-") as temp:
        process, qmp, log = launch(binary, components, extra, Path(temp))
        result = {"label": label}
        try:
            result["first"] = read_cells(qmp, cells)
            qmp.request("system_reset")
            result["after_reset"] = read_cells(qmp, cells)
            result["writes"] = qmp.request("qom-get", {"path": "/machine/pmgr",
                                                      "property": "mmio-write-count"})
            qmp.request("quit")
            result["exit_code"] = process.wait(timeout=10)
            process = None
            result["log"] = log.read_text(errors="replace")
        finally:
            if process:
                process.kill()
                process.wait(timeout=10)
            qmp.close()
    (evidence / f"{label}-emulator.log").write_text(result.get("log", ""))
    return result


def expect_refusal(binary, components, extra, needle, label, evidence):
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"), machine_gate.ASSETS))
    run = subprocess.run([str(binary), "-M", machine + extra, "-m", "8G", "-smp", "1",
                          "-nodefaults", "-display", "none", "-serial", "none",
                          "-monitor", "none", "-S"], capture_output=True, text=True, timeout=30)
    (evidence / f"{label}-emulator.log").write_text(run.stdout + run.stderr)
    require(run.returncode != 0 and needle in run.stderr, f"{label}: refused with the expected error")
    return run.stderr.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    assets = {n: args.components / n for n in machine_gate.ASSETS}
    before = {n: sha(p) for n, p in assets.items()}
    nodes, _ = oracle.parse_adt(assets["dtree"].read_bytes())
    cells = cell_addresses(nodes)
    on = always_on_labels()
    report = {"binary": str(args.binary), "binary_sha256": sha(args.binary),
              "dtsi_sha256": sha(DTSI), "cells": len(cells), "always_on_labels": on,
              "passed": False, "guest_execution": False}
    try:
        require(len(cells) == 138 and len(on) == 25 and all(n in cells for n in on),
                "138 hardware cells; 25 always-on labels each name one cell")
        base = ",modern-pmgr=on"
        default = case(args.binary, args.components, base, cells, "default", args.output_dir)
        require(default["first"] == default["after_reset"] == dict.fromkeys(cells, 0),
                "default board: every cell power-gated, before and after reset")
        on_case = case(args.binary, args.components, base + ",pmgr-boot-on=j700", cells,
                       "j700", args.output_dir)
        expected = {n: (0xff if n in on else 0) for n in cells}
        require(on_case["first"] == expected, "j700: exactly the 25 always-on cells read 0xff")
        require(on_case["after_reset"] == expected, "j700: profile restored by system_reset")
        require("25 PMGR domains reset powered on from the 'j700' profile" in on_case["log"] and
                "analogy" in on_case["log"], "board declares the profile as analogy")
        require("pmgr-boot-on" not in default["log"] and "PMGR domains reset powered" not in default["log"],
                "default board is silent about the profile")
        report["unknown_profile"] = expect_refusal(
            args.binary, args.components, base + ",pmgr-boot-on=nonesuch",
            "unknown pmgr-boot-on profile 'nonesuch' (supported: j700)", "unknown", args.output_dir)
        report["without_pmgr"] = expect_refusal(
            args.binary, args.components, ",pmgr-boot-on=j700",
            "pmgr-boot-on needs modern-pmgr=on", "no-pmgr", args.output_dir)
        report["passed"] = True
    except BaseException as error:
        report["error"] = repr(error)
    report["components_unchanged"] = before == {n: sha(p) for n, p in assets.items()}
    report["passed"] = report["passed"] and report["components_unchanged"]
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report.get(k) for k in ("passed", "error", "components_unchanged")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
