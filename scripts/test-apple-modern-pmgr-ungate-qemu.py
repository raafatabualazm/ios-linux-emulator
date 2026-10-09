#!/usr/bin/env python3
"""Whole-machine gate for the pmgr-ungate board option (stopped CPU).

Starts apple-modern with prepare-only loading and reads the served ADT out of
guest RAM: default board (no escape hatch anywhere in the tree), pmgr-ungate=on
(exactly /arm-io no-clock-gate and no-power-gate added, one declared nonzero
byte each, nothing else in the tree touched, the two function-*_gate properties
still present), the creation-only refusal, and a no-device oracle built from an
independent ADT parser plus a check that a binary without the option rejects
it. No guest code runs. Run under the shared QEMU lock.
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
HATCHES = ("no-clock-gate", "no-power-gate")
GATE_FUNCTIONS = ("function-clock_gate", "function-power_gate")


def load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"),
                                                  HERE / (name + ".py"))
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
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"),
                               machine_gate.ASSETS))
    machine += ",boot-command-line=" + machine_gate.COMMAND_LINE + extra
    argv = [str(binary), "-M", machine, "-m", "4G", "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S",
            "-qmp", "stdio"]
    log = scratch / "emulator.log"
    with log.open("xb") as sink:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=sink, bufsize=0)

    def guard() -> float:
        remaining = 45 - (time.monotonic() - started)
        require(remaining > 0 and log.stat().st_size < (1 << 20),
                "gate time/log bounds")
        return remaining

    return process, machine_gate.QMP(None, guard, process), argv, log


def served_tree(qmp, scratch: Path, blobs: dict) -> bytes:
    layout = machine_gate.expected_layout(blobs)
    path = scratch / "dump.bin"
    qmp.request("pmemsave", {"val": layout["args"], "size": 1152,
                             "filename": str(path)})
    args = path.read_bytes()
    tree_size = struct.unpack_from("<I", args, 104)[0]
    require(0 < tree_size <= layout["regions"]["DeviceTree"][1] - machine_gate.PAGE,
            "served ADT fits its reservation")
    path.unlink()
    qmp.request("pmemsave", {"val": layout["tree"], "size": tree_size,
                             "filename": str(path)})
    data = path.read_bytes()
    require(len(data) == tree_size, "complete served ADT")
    return data


def immutable(qmp) -> dict:
    qmp.sequence += 1
    request = {"execute": "qom-set", "id": qmp.sequence,
               "arguments": {"path": "/machine", "property": "pmgr-ungate",
                             "value": False}}
    deadline = time.monotonic() + 3
    qmp.send(json.dumps(request).encode() + b"\n", deadline)
    while time.monotonic() < deadline:
        response = qmp.receive(deadline)
        if "event" in response:
            continue
        require("error" in response and "return" not in response,
                "pmgr-ungate is creation-only")
        require(response["error"]["desc"] ==
                "apple-modern properties are fixed after initialization",
                "exact immutability message")
        return response["error"]
    raise RuntimeError("immutability deadline")


def run_case(binary: Path, components: Path, extra: str, blobs: dict, label: str,
             evidence: Path, check_immutable: bool) -> dict:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pmgr-ungate-qemu-") as temp:
        scratch = Path(temp)
        process, qmp, argv, log = start(binary, components, extra, scratch, started)
        result = {"label": label, "argv": argv}
        try:
            require(qmp.request("query-status")["running"] is False, "CPU stopped")
            result["tree"] = served_tree(qmp, scratch, blobs)
            if check_immutable:
                result["property_immutable"] = immutable(qmp)
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


def unknown_binary_rejects(binary: Path, components: Path, evidence: Path) -> dict:
    """A pin that does not know the property must refuse it by name."""
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"),
                               machine_gate.ASSETS))
    machine += ",pmgr-ungate=on"
    argv = [str(binary), "-M", machine, "-m", "4G", "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S"]
    run = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    (evidence / "previous-pin-emulator.log").write_text(run.stdout + run.stderr)
    require(run.returncode != 0, "previous pin exits non-zero")
    require("pmgr-ungate" in run.stderr, "previous pin names the unknown property")
    return {"exit_code": run.returncode, "stderr": run.stderr.strip()[:400]}


def changed_properties(base: dict, other: dict) -> list:
    changed = []
    require(set(other) == set(base), "node set unchanged")
    for path, props in base.items():
        require(set(props) <= set(other[path]), "no property disappeared")
        for name, prop in props.items():
            if prop["raw"] != other[path][name]["raw"]:
                changed.append((path, name))
        changed += [(path, n) for n in other[path] if n not in props]
    return sorted(changed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--previous-pin", type=Path,
                        help="a build without pmgr-ungate, for the no-device oracle")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    assets = {name: args.components / name for name in machine_gate.ASSETS}
    before = {name: sha(path) for name, path in assets.items()}
    blobs = {name: path.read_bytes() for name, path in assets.items()}
    stock_nodes, stock_order = oracle.parse_adt(blobs["dtree"])
    report = {"binary": str(args.binary), "binary_sha256": sha(args.binary),
              "passed": False, "firmware_executed": False,
              "guest_execution": False}
    try:
        # The input tree must not already carry either escape hatch anywhere,
        # otherwise the whole comparison is vacuous.
        for path, props in stock_nodes.items():
            for hatch in HATCHES:
                require(hatch not in props,
                        f"input tree has no {hatch} ({path})")
        report["input_has_gate_functions"] = sorted(
            n for n in stock_nodes["/arm-io"] if n in GATE_FUNCTIONS)

        off = run_case(args.binary, args.components, "", blobs, "default", args.output_dir,
                       False)
        off_nodes, off_order = oracle.parse_adt(off["tree"])
        for hatch in HATCHES:
            require(hatch not in off_nodes["/arm-io"],
                    f"default board serves no {hatch}")
        require("pmgr-ungate" not in off["log"], "default board is silent")

        on = run_case(args.binary, args.components, ",pmgr-ungate=on", blobs,
                      "ungate", args.output_dir, True)
        on_nodes, on_order = oracle.parse_adt(on["tree"])
        require(on_order == off_order == stock_order, "node set and order preserved")
        require(changed_properties(off_nodes, on_nodes) ==
                sorted(("/arm-io", h) for h in HATCHES),
                "exactly the two declared properties differ")
        for hatch in HATCHES:
            value = on_nodes["/arm-io"][hatch]["value"]
            require(len(value) == 1 and value[0] != 0,
                    f"{hatch} is one declared nonzero byte")
        # The hatches bypass the lookup; they must not delete the properties.
        for name in report["input_has_gate_functions"]:
            require(on_nodes["/arm-io"][name]["raw"] ==
                    stock_nodes["/arm-io"][name]["raw"],
                    f"{name} survives byte-exactly")
        require("pmgr-ungate serves /arm-io no-clock-gate and no-power-gate" in on["log"],
                "board declares the modification")
        require("declared guest modification" in on["log"] and
                "can no longer clock- or power-gate" in on["log"],
                "board says what the option removes")
        require(on["property_immutable"], "creation-only option")
        if args.previous_pin:
            report["previous_pin"] = unknown_binary_rejects(
                args.previous_pin, args.components, args.output_dir)
        report["arm_io_properties"] = {"default": len(off_nodes["/arm-io"]),
                                       "ungate": len(on_nodes["/arm-io"])}
        require(report["arm_io_properties"]["ungate"] ==
                report["arm_io_properties"]["default"] + 2,
                "/arm-io gains exactly two properties")
        report["tree_bytes"] = {"default": len(off["tree"]), "ungate": len(on["tree"])}
        report["passed"] = True
    except BaseException as error:  # noqa: BLE001 - recorded in the report
        report["error"] = repr(error)
    report["components_unchanged"] = before == {n: sha(p) for n, p in assets.items()}
    report["passed"] = report["passed"] and report["components_unchanged"]
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report.get(k) for k in
                      ("passed", "error", "components_unchanged",
                       "arm_io_properties", "tree_bytes")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
