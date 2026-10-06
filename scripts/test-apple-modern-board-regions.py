#!/usr/bin/env python3
"""Test production CPU register-window planning with ASan/UBSan; no guest boot."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def digest(path: Path) -> dict:
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dtree", type=Path,
                        help="Unchanged decoded matching T8140 ADT")
    parser.add_argument("--evidence", type=Path,
                        help="Save private report and log, refusing existing files")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sources = ["hw/arm/apple-silicon/modern-boot-layout.c",
               "hw/arm/apple-silicon/modern-boot-metadata.c",
               "hw/arm/apple-silicon/modern-board-regions.c",
               "include/hw/arm/apple-silicon/modern-boot-layout.h",
               "include/hw/arm/apple-silicon/modern-boot-metadata.h",
               "include/hw/arm/apple-silicon/modern-board-regions.h",
               "scripts/test-apple-modern-board-regions.c"]
    before_sources = {p: digest(root / p) for p in sources}
    before_dtree = digest(args.dtree) if args.dtree else None
    with tempfile.TemporaryDirectory(prefix="modern-board-regions-") as temp:
        binary = Path(temp) / "test-regions"
        command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
                   "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   "-DAPPLE_MODERN_LAYOUT_STANDALONE", "-I" + str(root / "include"),
                   *(str(root / p) for p in sources if p.endswith(".c")),
                   "-o", str(binary)]
        subprocess.run(command, check=True, capture_output=True, text=True,
                       timeout=60)
        run = subprocess.run([str(binary), *([str(args.dtree.resolve())]
                              if args.dtree else [])], capture_output=True,
                             text=True, timeout=60)
        if run.returncode:
            raise RuntimeError(run.stdout + run.stderr)
    after_dtree = digest(args.dtree) if args.dtree else None
    assert before_dtree == after_dtree
    assert before_sources == {p: digest(root / p) for p in sources}
    windows = []
    for line in run.stdout.splitlines():
        if line.startswith("WINDOW "):
            _, name, base, size = line.split()
            windows.append({"name": name, "physical_address": int(base, 16),
                            "size": int(size, 16)})
    count = int(re.search(r"PASS (\d+)", run.stdout).group(1))
    report = {"scope": "Production-source register-RAM compatibility planning",
              "sanitizers": ["ASan", "UBSan"], "semantic_checks": count,
              "asan_options": os.environ.get("ASAN_OPTIONS", ""),
              "leak_check_disabled": "detect_leaks=0" in
                                     os.environ.get("ASAN_OPTIONS", ""),
              "source_hashes": before_sources,
              "dtree_before": before_dtree, "dtree_after": after_dtree,
              "dtree_unchanged": before_dtree == after_dtree,
              "actual_windows": windows, "guest_execution": False,
              "hardware_side_effects_or_protection_qualified": False}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / "modern-board-regions-review.json").open("x") as dst:
            json.dump(report, dst, indent=2); dst.write("\n")
        with (args.evidence / "modern-board-regions-tests.log").open("x") as dst:
            dst.write(run.stdout + run.stderr)
    print(json.dumps({"semantic_checks": count, "actual_windows": windows,
                      "dtree_unchanged": before_dtree == after_dtree}))


if __name__ == "__main__":
    main()
