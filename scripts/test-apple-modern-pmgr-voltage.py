#!/usr/bin/env python3
"""Compile the production metadata builder and the voltage profile under
ASan/UBSan and in a production -DNDEBUG build; run the override/profile test.

No guest launch. With --components the test also builds the actual stock
iPhone17,3 tree with and without the profile and compares them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--components", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sources = ["hw/arm/apple-silicon/modern-boot-layout.c",
               "hw/arm/apple-silicon/modern-boot-metadata.c",
               "hw/arm/apple-silicon/modern-pmgr-voltage.c",
               "include/hw/arm/apple-silicon/modern-boot-layout.h",
               "include/hw/arm/apple-silicon/modern-boot-metadata.h",
               "include/hw/arm/apple-silicon/modern-pmgr-voltage.h",
               "scripts/test-apple-modern-boot-layout.c",
               "scripts/test-apple-modern-boot-metadata.c",
               "scripts/test-apple-modern-pmgr-voltage.c"]
    before = {name: digest(root / name) for name in sources}
    assets = ["bootkc", "sptm", "txm", "dtree", "restore-trustcache"]
    asset_before = ({n: digest(args.components / n) for n in assets}
                    if args.components else {})
    base = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
            "-DAPPLE_MODERN_LAYOUT_STANDALONE", "-I" + str(root / "include")]
    modes = {"sanitizers": ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"],
             # The test's own assert() oracle must stay live; only production
             # sources are built with NDEBUG, as in the shipping emulator.
             "production-ndebug": ["-O2"]}
    runs = []
    with tempfile.TemporaryDirectory(prefix="pmgr-voltage-") as temp:
        for mode, flags in modes.items():
            binary = Path(temp) / mode
            objects = []
            for name in sources[:3]:
                obj = Path(temp) / (mode + "-" + Path(name).stem + ".o")
                extra = ["-DNDEBUG"] if mode == "production-ndebug" else []
                subprocess.run([*base, *flags, *extra, "-c", str(root / name), "-o", str(obj)],
                               check=True, capture_output=True, text=True)
                objects.append(str(obj))
            test_obj = Path(temp) / (mode + "-test.o")
            subprocess.run([*base, *flags, "-c", str(root / sources[-1]), "-o", str(test_obj)],
                           check=True, capture_output=True, text=True)
            subprocess.run([*base, *flags, *objects, str(test_obj), "-o", str(binary)],
                           check=True, capture_output=True, text=True)
            command = [str(binary)] + ([str(args.components.resolve())] if args.components else [])
            run = subprocess.run(command, capture_output=True, text=True, timeout=120)
            match = re.search(r"PASS (\d+) override/profile checks \(\+(\d+) shared", run.stdout)
            runs.append({"mode": mode, "exit": run.returncode,
                         "checks": match.groups() if match else None,
                         "actual": [l for l in run.stdout.splitlines() if l.startswith("ACTUAL")],
                         "stdout_tail": run.stdout[-600:], "stderr": run.stderr[-600:]})
            if run.returncode:
                raise SystemExit(json.dumps(runs[-1], indent=2))
    assert before == {name: digest(root / name) for name in sources}
    asset_after = ({n: digest(args.components / n) for n in assets} if args.components else {})
    assert asset_before == asset_after
    report = {"passed": True, "source_sha256": before, "runs": runs,
              "components_unchanged": asset_before == asset_after,
              "firmware_executed": False, "guest_launched": False}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "core-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True, "runs": [(r["mode"], r["checks"], r["actual"]) for r in runs]},
                     indent=1))


if __name__ == "__main__":
    main()
