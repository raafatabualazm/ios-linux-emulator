#!/usr/bin/env python3
"""Core gate for the opt-in md0 width patch (ASan+UBSan and NDEBUG).

Compiles the production anchored kernel-cache patch source twice and runs both
binaries against synthetic Mach-O fileset fixtures built in memory. No QEMU,
no guest execution, no Apple image is read.

Do NOT wrap this harness in `ulimit -v`: the sanitizer binary reserves a huge
virtual range and aborts immediately under a virtual-memory cap.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sources = ["hw/arm/apple-silicon/modern-kc-patch.c",
               "include/hw/arm/apple-silicon/modern-kc-patch.h",
               "scripts/test-apple-modern-md0-width.c",
               "scripts/test-apple-modern-md0-width.py"]
    before = {name: digest(root / name) for name in sources}
    runs = []
    with tempfile.TemporaryDirectory(prefix="modern-md0-width-") as temp:
        for mode, flags in [("sanitizers", ["-fsanitize=address,undefined",
                                            "-fno-omit-frame-pointer", "-g"]),
                            ("production-ndebug", ["-DNDEBUG", "-O2"])]:
            binary = Path(temp) / mode
            command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                       "-D_GNU_SOURCE", "-DAPPLE_MODERN_LAYOUT_STANDALONE",
                       "-I" + str(root / "include"), *flags,
                       *(str(root / name) for name in sources
                         if name.endswith(".c")), "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=180)
            if built.returncode:
                raise SystemExit(built.stdout + built.stderr)
            executed = subprocess.run([str(binary)], capture_output=True,
                                      text=True, timeout=300,
                                      env=dict(os.environ,
                                               ASAN_OPTIONS="detect_leaks=0"))
            if executed.returncode:
                raise SystemExit(executed.stdout + executed.stderr)
            match = re.search(r"PASS (\d+) semantic checks, (\d+) refusals",
                              executed.stdout)
            if not match:
                raise SystemExit("missing PASS line\n" + executed.stdout)
            runs.append({"mode": mode, "exit": executed.returncode,
                         "semantic_checks": int(match.group(1)),
                         "refusals": int(match.group(2)),
                         "reject_lines": executed.stdout.count("REJECT "),
                         "stdout": executed.stdout, "stderr": executed.stderr})
    if before != {name: digest(root / name) for name in sources}:
        raise SystemExit("Inputs changed during qualification")
    if runs[0]["semantic_checks"] != runs[1]["semantic_checks"]:
        raise SystemExit("sanitizer and NDEBUG builds disagree on check count")
    if runs[0]["refusals"] != runs[1]["refusals"]:
        raise SystemExit("sanitizer and NDEBUG builds disagree on refusals")
    report = {
        "passed": True,
        "source_sha256": before,
        "runs": runs,
        "sanitizers": ["ASan", "UBSan"],
        "semantic_checks": runs[0]["semantic_checks"],
        "refusals": runs[0]["refusals"],
        "firmware_executed": False,
        "guest_execution": False,
        "apple_image_read": False,
        "scope": ("Opt-in md0 width patch: Mach-O fileset location of the "
                  "kernel __TEXT_EXEC, the two source-derived anchors with "
                  "their register ties, exactly-once enforcement, the "
                  "four-word rewrite, every refusal path leaving the image "
                  "byte-identical, and the stock-vs-widened block-count "
                  "arithmetic including the 19,726,336-block acceptance "
                  "oracle."),
        "not_claimed": ("No guest ran here and no Apple image was opened; "
                        "the whole-machine gate and the real boot are "
                        "separate artefacts."),
    }
    text = json.dumps(report, indent=2)
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "core-result.json").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
