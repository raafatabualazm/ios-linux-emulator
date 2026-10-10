#!/usr/bin/env python3
"""Compile the production image-patch facility under ASan/UBSan and in a
production -DNDEBUG build, then run the anchor hit/miss/multiple-hit,
length-mismatch, mask, option-parsing and unchanged-path core test.

No guest launch. Asserts the production sources are unchanged afterwards.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sources = ["hw/arm/apple-silicon/modern-boot-layout.c",
               "hw/arm/apple-silicon/modern-image-patch.c",
               "include/hw/arm/apple-silicon/modern-boot-layout.h",
               "include/hw/arm/apple-silicon/modern-image-patch.h",
               "scripts/test-apple-modern-image-patch.c"]
    before = {name: digest(root / name) for name in sources}
    csources = [n for n in sources if n.endswith(".c")]
    runs = []
    with tempfile.TemporaryDirectory(prefix="modern-image-patch-") as temp:
        for mode, flags in [("sanitizers", ["-fsanitize=address,undefined",
                                            "-fno-omit-frame-pointer", "-g"]),
                            ("production-ndebug", ["-DNDEBUG", "-O2"])]:
            binary = Path(temp) / mode
            command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                       "-DAPPLE_MODERN_LAYOUT_STANDALONE",
                       "-I" + str(root / "include"), *flags,
                       *(str(root / n) for n in csources), "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=120)
            if built.returncode:
                raise SystemExit(built.stdout + built.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=60,
                                 env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0"))
            runs.append({"mode": mode, "exit": run.returncode,
                         "stdout": run.stdout.strip(), "stderr": run.stderr[-600:]})
            if run.returncode:
                raise SystemExit(json.dumps(runs[-1], indent=2))
    after = {name: digest(root / name) for name in sources}
    if before != after:
        raise SystemExit("production sources changed during qualification")
    report = {"passed": True, "source_sha256": before, "runs": runs,
              "firmware_executed": False, "guest_launched": False}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "core-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True,
                      "runs": [(r["mode"], r["exit"], r["stdout"]) for r in runs]},
                     indent=1))


if __name__ == "__main__":
    main()
