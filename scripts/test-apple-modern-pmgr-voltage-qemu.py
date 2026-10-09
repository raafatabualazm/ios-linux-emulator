#!/usr/bin/env python3
"""Whole-machine gate for the pmgr-voltage-states board option (stopped CPU).

Starts apple-modern with prepare-only loading and inspects the served ADT in
guest RAM: default board (stock pmgr tables untouched), the measured 'j700'
profile (exactly the 11 declared properties differ, bytes taken from the
evidence JSON, independent of the generated C), an unknown profile (clean
startup refusal) and creation-only mutability. No guest code runs.
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
ROOT = HERE.parent.parent.parent.parent
PROFILE_JSON = ROOT / ("modern-emulator/evidence/features-20261009/voltage-states/"
                       "derived/taskA-j700-pmgr-voltage-states-exact.json")
NAMES = ["voltage-states0", "voltage-states1", "voltage-states1-sram",
         "voltage-states2", "voltage-states5", "voltage-states5-sram",
         "voltage-states8", "voltage-states9", "voltage-states9-sram",
         "voltage-states10", "voltage-states11"]
STOCK_PMGR_VOLTAGE = {"voltage-states0", "voltage-states2", "voltage-states9"}


def load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


machine_gate = load("test-apple-modern-machine")
oracle = load("test-apple-modern-boot-metadata")
require = machine_gate.require


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def start(binary: Path, components: Path, extra: str, scratch: Path, started: float):
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"), machine_gate.ASSETS))
    machine += ",boot-command-line=" + machine_gate.COMMAND_LINE + extra
    argv = [str(binary), "-M", machine, "-m", "8G", "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S",
            "-qmp", "stdio"]
    log = scratch / "emulator.log"
    with log.open("xb") as sink:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=sink, bufsize=0)

    def guard() -> float:
        remaining = 45 - (time.monotonic() - started)
        require(remaining > 0 and log.stat().st_size < (1 << 20), "gate time/log bounds")
        return remaining

    return process, machine_gate.QMP(None, guard, process), argv, log


def served_tree(qmp, scratch: Path, blobs: dict) -> bytes:
    layout = machine_gate.expected_layout(blobs)
    path = scratch / "dump.bin"
    qmp.request("pmemsave", {"val": layout["args"], "size": 1152, "filename": str(path)})
    args = path.read_bytes()
    tree_size = struct.unpack_from("<I", args, 104)[0]
    require(0 < tree_size <= layout["regions"]["DeviceTree"][1] - machine_gate.PAGE,
            "served ADT fits its reservation")
    path.unlink()
    qmp.request("pmemsave", {"val": layout["tree"], "size": tree_size, "filename": str(path)})
    data = path.read_bytes()
    require(len(data) == tree_size, "complete served ADT")
    return data


def run_case(binary: Path, components: Path, extra: str, blobs: dict, label: str,
             evidence: Path) -> dict:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pmgr-voltage-qemu-") as temp:
        scratch = Path(temp)
        process, qmp, argv, log = start(binary, components, extra, scratch, started)
        result = {"label": label, "argv": argv}
        try:
            require(qmp.request("query-status")["running"] is False, "CPU stopped")
            tree = served_tree(qmp, scratch, blobs)
            nodes, order = oracle.parse_adt(tree)
            result["pmgr"] = {n: p["value"].hex() for n, p in nodes["/arm-io/pmgr"].items()
                              if n.startswith("voltage-states")}
            result["nodes"] = order
            result["tree"] = tree
            if extra:
                result["property_immutable"] = qmp_immutable(qmp)
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


def qmp_immutable(qmp) -> dict:
    qmp.sequence += 1
    request = {"execute": "qom-set", "id": qmp.sequence,
               "arguments": {"path": "/machine", "property": "pmgr-voltage-states",
                             "value": "off"}}
    deadline = time.monotonic() + 3
    qmp.send(json.dumps(request).encode() + b"\n", deadline)
    while time.monotonic() < deadline:
        response = qmp.receive(deadline)
        if "event" in response:
            continue
        require("error" in response and "return" not in response,
                "pmgr-voltage-states is creation-only")
        require(response["error"]["desc"] == "apple-modern properties are fixed after initialization",
                "exact immutability message")
        return response["error"]
    raise RuntimeError("immutability deadline")


def refused(binary: Path, components: Path, evidence: Path) -> dict:
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"), machine_gate.ASSETS))
    machine += ",pmgr-voltage-states=nonesuch"
    argv = [str(binary), "-M", machine, "-m", "8G", "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S"]
    run = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    (evidence / "unknown-profile-emulator.log").write_text(run.stdout + run.stderr)
    require(run.returncode != 0, "unknown profile exits non-zero")
    require("unknown pmgr-voltage-states profile 'nonesuch' (supported: j700)" in run.stderr,
            "unknown profile names the supported choice")
    return {"exit_code": run.returncode, "stderr": run.stderr.strip()}


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
    profile = json.loads(PROFILE_JSON.read_text())["properties"]
    expected = {name: bytes.fromhex(profile[name]["hex"]) for name in NAMES}
    stock_nodes, stock_order = oracle.parse_adt(blobs["dtree"])
    report = {"binary": str(args.binary), "binary_sha256": sha(args.binary),
              "profile_json_sha256": sha(PROFILE_JSON), "passed": False,
              "firmware_executed": False, "guest_execution": False}
    try:
        # Default board: stock pmgr voltage tables, nothing added.
        default = run_case(args.binary, args.components, "", blobs, "default", args.output_dir)
        stock_voltage = {n: p["value"].hex() for n, p in stock_nodes["/arm-io/pmgr"].items()
                         if n.startswith("voltage-states")}
        require(set(stock_voltage) == STOCK_PMGR_VOLTAGE, "stock tree carries only 0, 2 and 9")
        require(default["pmgr"] == stock_voltage, "default board serves the stock voltage tables")
        require("voltage-states" not in default["log"], "default board does not mention the profile")
        # Measured profile.
        j700 = run_case(args.binary, args.components, ",pmgr-voltage-states=j700", blobs,
                        "j700", args.output_dir)
        require(j700["nodes"] == default["nodes"] == stock_order, "node set and order preserved")
        require(j700["pmgr"] == {n: expected[n].hex() for n in NAMES},
                "served pmgr tables equal the measured bytes exactly")
        require("pmgr voltage-states from the measured 'j700' profile" in j700["log"] and
                "analogy" in j700["log"], "board declares the profile as analogy")
        # Everything outside the 11 properties matches the default board's tree.
        d_nodes, _ = oracle.parse_adt(default["tree"])
        j_nodes, _ = oracle.parse_adt(j700["tree"])
        changed = []
        for path, props in d_nodes.items():
            require(set(props) <= set(j_nodes[path]), "no property disappeared")
            for name, prop in props.items():
                if prop["raw"] != j_nodes[path][name]["raw"]:
                    changed.append((path, name))
            for name in j_nodes[path]:
                if name not in props:
                    changed.append((path, name))
        require(sorted(changed) == sorted(("/arm-io/pmgr", n) for n in NAMES),
                "exactly the 11 declared properties differ")
        require(len(j_nodes["/arm-io/pmgr"]) == len(d_nodes["/arm-io/pmgr"]) + 8,
                "three tables replaced, eight added")
        require(j700["property_immutable"], "creation-only option")
        report["unknown_profile"] = refused(args.binary, args.components, args.output_dir)
        report["j700_changed_properties"] = [f"{p}:{n}" for p, n in sorted(changed)]
        report["stock_pmgr_voltage"] = stock_voltage
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
