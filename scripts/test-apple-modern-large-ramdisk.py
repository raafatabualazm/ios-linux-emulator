#!/usr/bin/env python3
"""Core gate for the opt-in mapped large-ramdisk path (ASan+UBSan and NDEBUG).

Compiles the production mapping and layout sources twice and runs both
binaries against real scratch files. No QEMU, no guest execution. The
oversize fixture is a sparse file refused on st_size, so the gate costs no
disk and no measurable memory.

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
    sources = ["hw/arm/apple-silicon/modern-large-ramdisk.c",
               "hw/arm/apple-silicon/modern-boot-layout.c",
               "include/hw/arm/apple-silicon/modern-large-ramdisk.h",
               "include/hw/arm/apple-silicon/modern-boot-layout.h",
               "scripts/test-apple-modern-large-ramdisk.c",
               "scripts/test-apple-modern-large-ramdisk.py"]
    before = {name: digest(root / name) for name in sources}
    runs = []
    with tempfile.TemporaryDirectory(prefix="modern-large-ramdisk-") as temp:
        for mode, flags in [("sanitizers", ["-fsanitize=address,undefined",
                                            "-fno-omit-frame-pointer", "-g"]),
                            ("production-ndebug", ["-DNDEBUG", "-O2"])]:
            binary = Path(temp) / mode
            scratch = Path(temp) / (mode + "-scratch")
            scratch.mkdir()
            command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                       "-D_GNU_SOURCE", "-DAPPLE_MODERN_LAYOUT_STANDALONE",
                       "-I" + str(root / "include"), *flags,
                       *(str(root / name) for name in sources
                         if name.endswith(".c")), "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=180)
            if built.returncode:
                raise SystemExit(built.stdout + built.stderr)
            executed = subprocess.run([str(binary), str(scratch)],
                                      capture_output=True, text=True,
                                      timeout=300,
                                      env=dict(os.environ,
                                               ASAN_OPTIONS="detect_leaks=0"))
            if executed.returncode:
                raise SystemExit(executed.stdout + executed.stderr)
            match = re.search(r"PASS (\d+) semantic checks", executed.stdout)
            if not match:
                raise SystemExit("missing PASS line\n" + executed.stdout)
            runs.append({"mode": mode, "exit": executed.returncode,
                         "semantic_checks": int(match.group(1)),
                         "rejections": executed.stdout.count("REJECT "),
                         "stdout": executed.stdout, "stderr": executed.stderr})
    if before != {name: digest(root / name) for name in sources}:
        raise SystemExit("Inputs changed during qualification")
    if runs[0]["semantic_checks"] != runs[1]["semantic_checks"]:
        raise SystemExit("sanitizer and NDEBUG builds disagree on check count")
    report = {"passed": True, "source_sha256": before, "runs": runs,
              "sanitizers": ["ASan", "UBSan"],
              "semantic_checks": runs[0]["semantic_checks"],
              "firmware_executed": False, "guest_execution": False,
              "qemu_binding_claim": False,
              "scope": ("Opt-in mapped large-ramdisk: open/fstat/mmap policy "
                        "and the two boot-layout ramdisk size caps")}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / "core-result.json").open("x") as fp:
            json.dump(report, fp, indent=2)
            fp.write("\n")
    print(json.dumps({k: v for k, v in report.items() if k != "runs"}, indent=2))
    for run in runs:
        print(f"--- {run['mode']}: {run['semantic_checks']} checks, "
              f"{run['rejections']} rejections")


if __name__ == "__main__":
    main()
