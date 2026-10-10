#!/usr/bin/env python3
"""Whole-machine gate for the opt-in md0-width-compat kernel-cache patch.

Every positive case starts apple-modern with the CPU stopped, so no guest code
runs. What is proved, all measured:

  * with the option OFF the kernel text that reaches guest RAM is byte-exact
    with the distribution boot kernel cache at both anchor sites, the option
    reads false, and the emulator log says nothing about md0-width-compat;
  * with the option ON exactly four instruction words in guest RAM differ from
    the file - the mdevstrategy shift and the three DKIOCGETBLOCKCOUNT words -
    and they differ in exactly the predicted way (the 64-bit UBFM form, and
    the sf bit for ADD/SUB/UDIV). The surrounding words of each anchor are
    still byte-exact, and the emulator announces the patch with both offsets;
  * the option is creation-only, with the board's existing message;
  * the distribution boot kernel cache is byte-identical before and after.

Negative oracles (each must fail, and the gate fails if one passes):

  * comparing the ON guest bytes against the stock encodings must NOT match;
  * a boot kernel cache whose mdevstrategy shift is already 64-bit: the anchor
    matches 0 times and the board refuses by name;
  * a boot kernel cache carrying a second copy of the DKIOCGETBLOCKCOUNT
    anchor: it matches 2 times and the board refuses by name;
  * a previous pin that does not know the property at all.

Run under the shared QEMU lock, and do not wrap it in `ulimit -v` (guest RAM
needs the address space).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
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
require = machine_gate.require


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# -------------------------------------------------- independent anchor model
# The same masks and ties the production source uses, re-derived here from the
# AArch64 field layout so a typo in either copy is caught.
def ldr_w(word: int, offset: int):
    if word & 0xFFC00000 != 0xB9400000:
        return None
    if ((word >> 10) & 0xFFF) * 4 != offset:
        return None
    return (word & 0x1F, (word >> 5) & 0x1F)


def find_anchors(text: bytes, base: int) -> dict:
    words = struct.unpack("<%dI" % (len(text) // 4), text[:len(text) // 4 * 4])
    strategy, blockcount = [], []
    for i in range(len(words) - 4):
        load1 = ldr_w(words[i], 8)
        if load1:
            size_rt = load1[0]
            shift = words[i + 1]
            cmp_x = words[i + 2]
            if (shift & 0xFFFFFC00 == 0x53144C00 and shift & 0x1F == size_rt
                    and (shift >> 5) & 0x1F == size_rt
                    and cmp_x & 0xFFE0FC1F == 0xEB00001F
                    and (cmp_x >> 16) & 0x1F == size_rt
                    and words[i + 3] & 0xFF00001F == 0x54000002):
                strategy.append(base + i * 4)
            load2 = ldr_w(words[i + 1], 16)
            if load2 and load2[1] == load1[1]:
                add, sub, udiv = words[i + 2], words[i + 3], words[i + 4]
                acc = add & 0x1F
                if (add & 0xFFE0FC00 == 0x0B003000
                        and (add >> 16) & 0x1F == size_rt
                        and (add >> 5) & 0x1F == load2[0]
                        and sub & 0xFFFFFC00 == 0x51000400
                        and sub & 0x1F == acc and (sub >> 5) & 0x1F == acc
                        and udiv & 0xFFE0FC00 == 0x1AC00800
                        and (udiv >> 5) & 0x1F == acc
                        and (udiv >> 16) & 0x1F == load2[0]):
                    blockcount.append(base + i * 4)
    return {"strategy": strategy, "blockcount": blockcount}


def widen_lsl(word: int) -> int:
    """LSL Wd, Wn, #12 -> LSL Xd, Xn, #12 (UBFM immr 52, imms 51)."""
    return 0xD3400000 | (52 << 16) | (51 << 10) | (word & 0x3FF)


def place_text(components: Path) -> dict:
    """Where the loader copies the BootKC __TEXT_EXEC segment in guest RAM."""
    blobs = {name: (components / name).read_bytes() for name in ASSETS}
    layout = machine_gate.expected_layout(blobs)
    copies = [c for c in layout["copies"]
              if c["image"] == "bootkc" and c["segment"] == "__TEXT_EXEC"]
    require(len(copies) == 1, "exactly one BootKC __TEXT_EXEC copy entry")
    copy = copies[0]
    return {"physical": copy["physical"], "fileoff": copy["offset"],
            "filesize": copy["file"], "args": layout["args"]}


def guest_address(place: dict, fileoff: int) -> int:
    require(place["fileoff"] <= fileoff <
            place["fileoff"] + place["filesize"],
            "anchor is inside the BootKC __TEXT_EXEC segment")
    return place["physical"] + fileoff - place["fileoff"]


def qmp_argv(binary: Path, components: Path, extra: str, ram: str,
             monitor: bool) -> list:
    machine = "apple-modern," + ",".join(
        name + "=" + str(components / asset)
        for name, asset in zip(PROPERTY_NAMES, ASSETS))
    machine += extra + ",boot-command-line=" + COMMAND_LINE
    argv = [str(binary), "-M", machine, "-m", ram, "-smp", "1", "-nodefaults",
            "-display", "none", "-serial", "none", "-monitor", "none", "-S"]
    if monitor:
        argv += ["-qmp", "stdio"]
    return argv


def immutable(qmp) -> dict:
    qmp.sequence += 1
    request = {"execute": "qom-set", "id": qmp.sequence,
               "arguments": {"path": "/machine",
                             "property": "md0-width-compat", "value": True}}
    deadline = time.monotonic() + 5
    qmp.send(json.dumps(request).encode() + b"\n", deadline)
    while time.monotonic() < deadline:
        response = qmp.receive(deadline)
        if "event" in response:
            continue
        require("error" in response and "return" not in response,
                "md0-width-compat is creation-only")
        require(response["error"]["desc"] ==
                "apple-modern properties are fixed after initialization",
                "exact immutability message")
        return response["error"]
    raise RuntimeError("immutability deadline")


def run_case(binary: Path, components: Path, label: str, evidence: Path,
             place: dict, reads: list, extra: str, ram: str = "8G") -> dict:
    """Start with the CPU stopped, read guest RAM, quit.

    `reads` are (name, guest physical address, length) triples."""
    started = time.monotonic()
    argv = qmp_argv(binary, components, extra, ram, True)
    result = {"label": label, "argv": argv, "ram": ram}
    with tempfile.TemporaryDirectory(prefix="md0-width-qemu-") as temp:
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
                "qom-get", {"path": "/machine",
                            "property": "md0-width-compat"})
            result["reads"] = {}
            for name, address, length in reads:
                qmp.request("pmemsave", {"val": address, "size": length,
                                         "filename": str(dump)})
                result["reads"][name] = {"address": address,
                                         "bytes": dump.read_bytes().hex()}
                dump.unlink()
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
            extra: str, ram: str = "8G") -> dict:
    argv = qmp_argv(binary, components, extra, ram, False)
    run = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    (evidence / f"{label}-emulator.log").write_text(run.stdout + run.stderr)
    require(run.returncode != 0, f"{label} exits non-zero")
    return {"label": label, "argv": argv, "exit_code": run.returncode,
            "stderr": run.stderr.strip()[-2000:]}


def mutated_components(source: Path, scratch: Path, name: str, place: dict,
                       edits: list, expect: tuple) -> Path:
    """A component directory whose bootkc copy carries `edits`
    [(fileoff, 4-byte word)]. The copy is checked with this script's own
    anchor model to hold `expect` = (strategy_matches, blockcount_matches),
    so an oracle cannot pass for the wrong reason. The small assets are
    copied; the big one is written once and deleted by the caller."""
    out = scratch / name
    out.mkdir(parents=True, exist_ok=True)
    for asset in ASSETS:
        if asset != "bootkc":
            shutil.copy(source / asset, out / asset)
    data = bytearray((source / "bootkc").read_bytes())
    for offset, word in edits:
        struct.pack_into("<I", data, offset, word)
    text = bytes(data[place["fileoff"]:place["fileoff"] + place["filesize"]])
    found = find_anchors(text, place["fileoff"])
    require((len(found["strategy"]), len(found["blockcount"])) == expect,
            "mutated %s has the intended anchor counts %s, got (%d, %d)"
            % (name, expect, len(found["strategy"]),
               len(found["blockcount"])))
    del text
    (out / "bootkc").write_bytes(bytes(data))
    del data
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--previous-pin", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    args.scratch.mkdir(parents=True, exist_ok=True)

    bootkc = args.components / "bootkc"
    before_hash = sha(bootkc)
    place = place_text(args.components)

    # Locate the anchors in the distribution file with this script's own model.
    with bootkc.open("rb") as stream:
        stream.seek(place["fileoff"])
        text = stream.read(place["filesize"])
    found = find_anchors(text, place["fileoff"])
    require(len(found["strategy"]) == 1 and len(found["blockcount"]) == 1,
            "each anchor occurs exactly once in the distribution BootKC")
    strategy = found["strategy"][0]
    blockcount = found["blockcount"][0]
    del text

    def file_words(offset: int, count: int) -> list:
        with bootkc.open("rb") as stream:
            stream.seek(offset)
            raw = stream.read(count * 4)
        return list(struct.unpack("<%dI" % count, raw))

    strategy_words = file_words(strategy, 4)
    blockcount_words = file_words(blockcount, 5)
    expected_strategy = list(strategy_words)
    expected_strategy[1] = widen_lsl(strategy_words[1])
    expected_blockcount = list(blockcount_words)
    for i in (2, 3, 4):
        expected_blockcount[i] = blockcount_words[i] | 0x80000000

    reads = [("strategy", guest_address(place, strategy), 16),
             ("blockcount", guest_address(place, blockcount), 20)]

    def words_of(case: dict, name: str, count: int) -> list:
        raw = bytes.fromhex(case["reads"][name]["bytes"])
        return list(struct.unpack("<%dI" % count, raw))

    cases, oracles = [], []

    off = run_case(args.binary, args.components, "default-off", args.evidence,
                   place, reads, "")
    cases.append(off)
    require(off["option"] is False, "option reads off by default")
    require(words_of(off, "strategy", 4) == strategy_words,
            "OFF: strategy words in guest RAM equal the distribution file")
    require(words_of(off, "blockcount", 5) == blockcount_words,
            "OFF: blockcount words in guest RAM equal the distribution file")
    require("md0-width-compat" not in off["log"],
            "OFF: the emulator says nothing about the patch")

    on = run_case(args.binary, args.components, "on", args.evidence, place,
                  reads, ",md0-width-compat=on")
    cases.append(on)
    require(on["option"] is True, "option reads on when set")
    require(words_of(on, "strategy", 4) == expected_strategy,
            "ON: only the strategy shift changed, to the 64-bit UBFM form")
    require(words_of(on, "blockcount", 5) == expected_blockcount,
            "ON: only the three arithmetic words changed, by the sf bit")
    got_strategy = words_of(on, "strategy", 4)
    got_blockcount = words_of(on, "blockcount", 5)
    require(got_strategy[0] == strategy_words[0] and
            got_strategy[2:] == strategy_words[2:],
            "ON: the load, compare and branch around the shift are untouched")
    require(got_blockcount[:2] == blockcount_words[:2],
            "ON: both struct loads are untouched")
    for i in (2, 3, 4):
        require(got_blockcount[i] ^ blockcount_words[i] == 0x80000000,
                "ON: exactly the sf bit changed in word %d" % i)
    require(("md0-width-compat patch" in on["log"] and
             ("0x%x" % strategy) in on["log"] and
             ("0x%x" % blockcount) in on["log"] and
             "REMOVES the 32-bit wrap" in on["log"]),
            "ON: the emulator declares the patch with both offsets")

    # oracle 1: the comparison can fail
    oracles.append({"label": "stock-words-must-not-match-on",
                    "passed": words_of(on, "strategy", 4) != strategy_words
                    and words_of(on, "blockcount", 5) != blockcount_words})
    require(oracles[-1]["passed"],
            "oracle: the ON bytes are not the stock bytes")

    # oracle 2: an already-widened shift leaves the anchor absent
    pre = mutated_components(args.components, args.scratch, "pre-widened",
                             place, [(strategy + 4, expected_strategy[1])],
                             (0, 1))
    ref = refusal(args.binary, pre, "oracle-anchor-absent", args.evidence,
                  ",md0-width-compat=on")
    require("matched 0 times" in ref["stderr"] and
            "md0-width-compat" in ref["stderr"],
            "oracle: an already-widened shift is refused as 0 matches")
    oracles.append({**ref, "passed": True})
    (pre / "bootkc").unlink()

    # oracle 3: a duplicated blockcount anchor is ambiguous. The copy is
    # written over the five words that follow the real anchor's basic block,
    # far enough away that the two cannot overlap.
    duplicate_at = strategy + 0x1000
    require(abs(duplicate_at - blockcount) > 64 and
            place["fileoff"] <= duplicate_at <
            place["fileoff"] + place["filesize"] - 20,
            "duplicate site is inside the segment and clear of both anchors")
    dup = mutated_components(
        args.components, args.scratch, "duplicate-anchor", place,
        [(duplicate_at + i * 4, blockcount_words[i]) for i in range(5)],
        (1, 2))
    ref = refusal(args.binary, dup, "oracle-anchor-ambiguous", args.evidence,
                  ",md0-width-compat=on")
    require("matched 2 times" in ref["stderr"] and
            "md0-width-compat" in ref["stderr"],
            "oracle: a duplicated anchor is refused as 2 matches")
    oracles.append({**ref, "passed": True})
    (dup / "bootkc").unlink()

    # oracle 4: the previous pin does not know the property
    ref = refusal(args.previous_pin, args.components, "oracle-previous-pin",
                  args.evidence, ",md0-width-compat=on")
    require("md0-width-compat" in ref["stderr"],
            "oracle: the previous pin rejects the unknown property")
    oracles.append({**ref, "passed": True})

    require(sha(bootkc) == before_hash,
            "the distribution BootKC is byte-identical after the gate")

    report = {
        "passed": True,
        "binary": str(args.binary), "binary_sha256": sha(args.binary),
        "previous_pin": str(args.previous_pin),
        "bootkc_sha256_before": before_hash,
        "bootkc_sha256_after": sha(bootkc),
        "bootkc_unchanged": True,
        "anchors": {
            "strategy_fileoff": "0x%x" % strategy,
            "blockcount_fileoff": "0x%x" % blockcount,
            "strategy_guest_physical": "0x%x" % guest_address(place, strategy),
            "blockcount_guest_physical":
                "0x%x" % guest_address(place, blockcount),
            "strategy_words_file": ["0x%08x" % w for w in strategy_words],
            "strategy_words_expected": ["0x%08x" % w
                                        for w in expected_strategy],
            "blockcount_words_file": ["0x%08x" % w for w in blockcount_words],
            "blockcount_words_expected": ["0x%08x" % w
                                          for w in expected_blockcount],
        },
        "cases": cases, "oracles": oracles,
        "guest_execution": False,
        "distribution_images_modified": False,
        "scope": ("Opt-in md0-width-compat: default off, the exact four-word "
                  "rewrite as it reaches guest RAM, the declared log line, "
                  "creation-only immutability, and four negative oracles."),
        "not_claimed": ("No guest code ran in this gate, so it says nothing "
                        "about whether a root mounts; that is the separate "
                        "bigroot measurement."),
    }
    text = json.dumps(report, indent=2)
    (args.evidence / "report.json").write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
