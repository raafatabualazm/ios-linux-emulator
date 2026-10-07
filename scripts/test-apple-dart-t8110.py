#!/usr/bin/env python3
"""Run owned-RAM DMA/fault/reset tests against production t8110 core.

ASan/UBSan and NDEBUG passes. No firmware, message success synthesis or SEP
keys. This qualifies the production register/page-table core; the QEMU
AddressSpace/IOMMU wrapper requires a separate real DMA integration gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sources = ["hw/arm/apple-silicon/dart-t8110.c",
               "include/hw/arm/apple-silicon/dart-t8110.h",
               "scripts/test-apple-dart-t8110.c",
               "scripts/test-apple-dart-t8110.py"]
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
              for name in sources}
    logs = []
    with tempfile.TemporaryDirectory(prefix="dart-t8110-core-") as temp:
        for mode, extra in [("sanitizers", ["-fsanitize=address,undefined",
                                            "-fno-omit-frame-pointer", "-g"]),
                            ("production-ndebug", ["-DNDEBUG", "-O2"])]:
            binary = Path(temp) / mode
            command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                       "-DAPPLE_DART_T8110_STANDALONE", "-I" + str(root / "include"),
                       *extra, str(root / sources[0]), str(root / sources[2]),
                       "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=60)
            if built.returncode:
                raise SystemExit(built.stdout + built.stderr)
            # The sandbox monitor uses ptrace, which LeakSanitizer rejects.
            # ASan bounds and UBSan remain enabled; the fixture allocates no heap.
            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
            executed = subprocess.run([str(binary)], capture_output=True,
                                      text=True, timeout=30, env=env)
            logs.append({"mode": mode, "stdout": executed.stdout,
                         "stderr": executed.stderr, "exit": executed.returncode})
            if executed.returncode:
                raise SystemExit(executed.stdout + executed.stderr)
    report = {"passed": True, "scope": "production t8110 core with owned RAM",
              "qemu_dma_wrapper_exercised": False,
              "leak_sanitizer": "disabled: ptrace monitor; no fixture heap",
              "source_sha256": hashes, "runs": logs}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        target = args.evidence / "core-result.json"
        with target.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
