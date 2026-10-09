#!/usr/bin/env python3
"""Whole-machine gate for the adt-dart-ids board option (stopped CPU).

Starts apple-modern with prepare-only loading and reads the served ADT back
out of guest RAM (the bytes the guest would see):
  * default board, stock tree: no dart,t8110 node carries a dart-id;
  * adt-dart-ids=on, stock tree: exactly the 25 dart,t8110 nodes gain a 4-byte
    dart-id equal to their ADT-order index 0..24, and nothing else differs;
  * adt-dart-ids=on, a tree that restores only dart-sep and already carries
    dart-id=0 on it (the tree the SEP work boots): the served tree is the same
    as the default board's, so the existing dart-sep value is kept;
  * adt-dart-ids=on, the Darwin-derived tree (every DART compatible stripped):
    clean startup refusal that names the reason;
  * creation-only property; the previous pin rejects the unknown property.
No guest code runs. Run under the shared QEMU lock.
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


def load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


voltage = load("test-apple-modern-pmgr-voltage-qemu")
machine_gate = voltage.machine_gate
oracle = voltage.oracle
require = machine_gate.require
EXPECTED_ORDER = ["aop", "pmp", "sep", "sio", "rsm", "mtp", "usb", "dcp", "disp0",
                  "dispgrt", "dcpext0", "dispext0", "scaler", "jpeg-h17a",
                  "jpeg0-h17p", "jpeg1-h17p", "isp", "ave", "ave1", "avd", "ane",
                  "apr", "apcie0", "apcie1", "apcie2"]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compatible_has(value: bytes, wanted: bytes = b"dart,t8110") -> bool:
    return wanted in [e for e in value.split(b"\0")]


def dart_nodes(nodes: dict, order: list) -> list:
    return [p for p in order if "compatible" in nodes[p]
            and compatible_has(nodes[p]["compatible"]["value"])]


def with_tree(components: Path, tree: Path, scratch: Path, label: str) -> Path:
    """Component directory identical to `components` except for the dtree."""
    directory = scratch / ("components-" + label)
    directory.mkdir()
    for name in machine_gate.ASSETS:
        source = (tree if name == "dtree" else components / name).resolve()
        if name == "dtree":
            (directory / name).write_bytes(source.read_bytes())
        else:
            try:
                os.link(source, directory / name)    # the board refuses symlinks
            except OSError:
                (directory / name).write_bytes(source.read_bytes())
    return directory


def run_case(binary: Path, components: Path, extra: str, label: str, evidence: Path) -> dict:
    started = time.monotonic()
    blobs = {name: (components / name).read_bytes() for name in machine_gate.ASSETS}
    with tempfile.TemporaryDirectory(prefix="dart-id-qemu-") as temp:
        scratch = Path(temp)
        process, qmp, argv, log = voltage.start(binary, components, extra, scratch, started)
        result = {"label": label, "argv": argv}
        try:
            require(qmp.request("query-status")["running"] is False, "CPU stopped")
            tree = voltage.served_tree(qmp, scratch, blobs)
            nodes, order = oracle.parse_adt(tree)
            result.update(tree=tree, nodes=nodes, order=order,
                          option=qmp.request("qom-get", {"path": "/machine",
                                                         "property": "adt-dart-ids"}))
            if extra:
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


def immutable(qmp) -> dict:
    qmp.sequence += 1
    request = {"execute": "qom-set", "id": qmp.sequence,
               "arguments": {"path": "/machine", "property": "adt-dart-ids", "value": False}}
    deadline = time.monotonic() + 3
    qmp.send(json.dumps(request).encode() + b"\n", deadline)
    while time.monotonic() < deadline:
        response = qmp.receive(deadline)
        if "event" in response:
            continue
        require("error" in response and "return" not in response,
                "adt-dart-ids is creation-only")
        require(response["error"]["desc"] == "apple-modern properties are fixed after initialization",
                "exact immutability message")
        return response["error"]
    raise RuntimeError("immutability deadline")


def refused(binary: Path, components: Path, extra: str, label: str, needle: str,
            evidence: Path) -> dict:
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(("bootkc", "sptm", "txm", "dtree", "tc"), machine_gate.ASSETS))
    machine += extra
    argv = [str(binary), "-M", machine, "-m", "8G", "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S"]
    run = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    (evidence / f"{label}-emulator.log").write_text(run.stdout + run.stderr)
    require(run.returncode != 0, f"{label}: startup refused")
    require(needle in run.stderr, f"{label}: refusal names the reason")
    return {"exit_code": run.returncode, "stderr": run.stderr.strip()}


def differences(base: dict, other: dict) -> list:
    out = []
    require(set(base) == set(other), "node set unchanged")
    for path, props in base.items():
        for name, prop in props.items():
            if name not in other[path]:
                out.append((path, name, "removed"))
            elif prop["raw"] != other[path][name]["raw"]:
                out.append((path, name, "changed"))
        out += [(path, name, "added") for name in other[path] if name not in props]
    return sorted(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--served-tree", type=Path, required=True,
                        help="Darwin-derived tree: every DART compatible stripped")
    parser.add_argument("--sep-tree", type=Path, required=True,
                        help="tree restoring only dart-sep, with dart-id=0 on it")
    parser.add_argument("--previous-binary", type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    assets = {name: args.components / name for name in machine_gate.ASSETS}
    inputs = {"served_tree": args.served_tree, "sep_tree": args.sep_tree}
    before = {name: sha(path) for name, path in {**assets, **inputs}.items()}
    stock_nodes, stock_order = oracle.parse_adt((args.components / "dtree").read_bytes())
    report = {"binary": str(args.binary), "binary_sha256": sha(args.binary),
              "passed": False, "firmware_executed": False, "guest_execution": False}
    try:
        stock_darts = dart_nodes(stock_nodes, stock_order)
        require([p.removeprefix("/arm-io/dart-") for p in stock_darts] == EXPECTED_ORDER,
                "stock tree: the 25 known dart,t8110 nodes in the known ADT order")
        require(not any("dart-id" in props for props in stock_nodes.values()),
                "stock tree carries no dart-id")
        # Default board: untouched.
        default = run_case(args.binary, args.components, "", "default", args.output_dir)
        require(default["option"] is False, "option defaults to false")
        require(default["order"] == stock_order, "default serves the stock node order")
        require(not any("dart-id" in props for props in default["nodes"].values()),
                "default board adds no dart-id")
        require("dart-id" not in default["log"], "default board does not mention the option")
        # Generated ids.
        on = run_case(args.binary, args.components, ",adt-dart-ids=on", "on", args.output_dir)
        require(on["option"] is True, "option reads back true")
        require(on["order"] == stock_order, "node set and order preserved")
        generated = {p: props["dart-id"]["value"] for p, props in on["nodes"].items()
                     if "dart-id" in props}
        require(list(generated) == stock_darts, "dart-id exactly on the 25 dart,t8110 nodes, in ADT order")
        require([struct.unpack("<I", v)[0] for v in generated.values()] == list(range(25)),
                "ids are 0..24 in ADT order, 4 bytes each")
        require(all(len(v) == 4 for v in generated.values()), "u32 each")
        diff = differences(default["nodes"], on["nodes"])
        require(diff == sorted((p, "dart-id", "added") for p in stock_darts),
                "nothing else in the served tree differs")
        require("served dart-id 0..24 on 25 dart,t8110 nodes in ADT order" in on["log"],
                "board declares the assignment")
        require(on["property_immutable"], "creation-only option")
        # The existing dart-sep tree is unchanged by the option.
        with tempfile.TemporaryDirectory(prefix="dart-id-trees-") as temp:
            scratch = Path(temp)
            sep_dir = with_tree(args.components, args.sep_tree, scratch, "sep")
            sep_nodes, sep_order = oracle.parse_adt(args.sep_tree.read_bytes())
            require(dart_nodes(sep_nodes, sep_order) == ["/arm-io/dart-sep"] and
                    sep_nodes["/arm-io/dart-sep"]["dart-id"]["value"] == b"\0\0\0\0",
                    "sep tree: only dart-sep keeps the compatible, with dart-id 0")
            sep_default = run_case(args.binary, sep_dir, "", "sep-tree-default", args.output_dir)
            sep_on = run_case(args.binary, sep_dir, ",adt-dart-ids=on", "sep-tree-on", args.output_dir)
            require(differences(sep_default["nodes"], sep_on["nodes"]) == [] and
                    list(sep_default["nodes"]["/arm-io/dart-sep"]) ==
                    list(sep_on["nodes"]["/arm-io/dart-sep"]),
                    "sep tree: served tree identical, property order included")
            require(sep_on["tree"] == sep_default["tree"], "sep tree: served bytes identical")
            require([p for p, props in sep_on["nodes"].items() if "dart-id" in props] ==
                    ["/arm-io/dart-sep"], "sep tree: no other node gains an id")
            report["sep_tree"] = {"dart_sep_id": sep_on["nodes"]["/arm-io/dart-sep"]["dart-id"]["value"].hex(),
                                  "served_bytes_identical": True}
            darwin_dir = with_tree(args.components, args.served_tree, scratch, "darwin")
            report["darwin_tree_refusal"] = refused(
                args.binary, darwin_dir, ",adt-dart-ids=on", "darwin-tree-refusal",
                "has no dart,t8110 node", args.output_dir)
            # The same tree without the option still boots the board.
            darwin_default = run_case(args.binary, darwin_dir, "", "darwin-tree-default", args.output_dir)
            require(not any("dart-id" in p for p in darwin_default["nodes"].values()),
                    "darwin tree: default adds no dart-id")
        if args.previous_binary:
            report["previous_pin_binary_sha256"] = sha(args.previous_binary)
            report["previous_pin"] = refused(args.previous_binary, args.components,
                                             ",adt-dart-ids=on", "previous-pin",
                                             "adt-dart-ids", args.output_dir)
        report["generated_ids"] = {p: struct.unpack("<I", v)[0] for p, v in generated.items()}
        report["passed"] = True
    except BaseException as error:
        report["error"] = repr(error)
    report["components_unchanged"] = before == {n: sha(p) for n, p in {**assets, **inputs}.items()}
    report["passed"] = report["passed"] and report["components_unchanged"]
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report.get(k) for k in ("passed", "error", "components_unchanged")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
