#!/usr/bin/env python3
"""Compile the production boot-layout parser under ASan/UBSan and as a -DNDEBUG
build and run the trust-cache version test; with --components also lay out the
real decoded components with Apple's own version-1 restore module and, when a
`static-trustcache` file is present, with Apple's version-2 static module.

The oracle is mutation based: each plausible mis-implementation of the version
and geometry checks must be rejected by the same test. No guest is launched, no
trust-cache entry is parsed, and the components are hashed before and after.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

LAYOUT = "hw/arm/apple-silicon/modern-boot-layout.c"
TEST = "scripts/test-apple-modern-trustcache-v2.c"
SOURCES = [LAYOUT, "include/hw/arm/apple-silicon/modern-boot-layout.h",
           "scripts/test-apple-modern-boot-layout.c", TEST]

# (name, exact text in the layout parser, replacement). Each is a plausible way
# to get the version-2 widening wrong.
MUTANTS = [
    ("v2-accepted-without-the-opt-in",
     "    } else if (version == 2 && allow_v2) {",
     "    } else if (version == 2) {"),
    ("v2-never-accepted",
     "    } else if (version == 2 && allow_v2) {",
     "    } else if (false) {"),
    ("v2-entry-size-left-at-22",
     "    } else if (version == 2 && allow_v2) {\n"
     "        entry_size = 24;",
     "    } else if (version == 2 && allow_v2) {\n"
     "        entry_size = 22;"),
    ("v1-entry-size-widened-to-24",
     "    if (version == 1) {\n        entry_size = 22;",
     "    if (version == 1) {\n        entry_size = 24;"),
    ("count-scaled-in-32-bit-arithmetic",
     "    if (!entries ||\n"
     "        (uint64_t)entries * entry_size + 24 != tc->size) {",
     "    if (!entries ||\n"
     "        (uint32_t)(entries * entry_size + 24) != tc->size) {"),
    ("empty-module-accepted",
     "    if (!entries ||\n        (uint64_t)entries * entry_size + 24 !=",
     "    if (false ||\n        (uint64_t)entries * entry_size + 24 !="),
    ("overlong-tail-accepted",
     "    if (!entries ||\n"
     "        (uint64_t)entries * entry_size + 24 != tc->size) {",
     "    if (!entries ||\n"
     "        (uint64_t)entries * entry_size + 24 > tc->size) {"),
    ("any-version-accepted",
     "    if (version == 1) {\n        entry_size = 22;",
     "    if (version != 2) {\n        entry_size = 22;"),
    ("header-bound-dropped",
     "    if (!tc->data || tc->size < 24 ||",
     "    if (!tc->data || tc->size < 4 ||"),
    ("oversize-bound-dropped",
     "    if (!tc->data || tc->size < 24 || tc->size > MAX_DT_SIZE) {",
     "    if (!tc->data || tc->size < 24 || false) {"),
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_test(root, temp, name, layout_source, flags, defs):
    base = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
            "-DAPPLE_MODERN_LAYOUT_STANDALONE", "-I" + str(root / "include")]
    layout_obj = temp / f"{name}-layout.o"
    subprocess.run([*base, *flags, *defs, "-c", str(layout_source),
                    "-o", str(layout_obj)], check=True, capture_output=True,
                   text=True)
    test_obj = temp / f"{name}-test.o"
    subprocess.run([*base, *flags, "-c", str(root / TEST), "-o", str(test_obj)],
                   check=True, capture_output=True, text=True)
    binary = temp / name
    subprocess.run([*base, *flags, str(layout_obj), str(test_obj),
                    "-o", str(binary)], check=True, capture_output=True,
                   text=True)
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--components", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    before = {name: digest(root / name) for name in SOURCES}
    assets = ["bootkc", "sptm", "txm", "dtree", "restore-trustcache",
              "static-trustcache"]
    asset_before = ({n: digest(args.components / n) for n in assets
                     if (args.components / n).exists()}
                    if args.components else {})
    modes = {"sanitizers": (["-fsanitize=address,undefined",
                             "-fno-omit-frame-pointer"], []),
             # Only the production source is built with NDEBUG; the test's own
             # explicit checks stay live, as in the shipping emulator.
             "production-ndebug": (["-O2"], ["-DNDEBUG"])}
    runs, mutants = [], []
    original = (root / LAYOUT).read_text()
    tail = [str(args.components.resolve())] if args.components else []
    with tempfile.TemporaryDirectory(prefix="tcv2-") as temporary:
        temp = Path(temporary)
        for mode, (flags, defs) in modes.items():
            binary = compile_test(root, temp, mode, root / LAYOUT, flags, defs)
            run = subprocess.run([str(binary), *tail], capture_output=True,
                                 text=True, timeout=300)
            match = re.search(r"PASS (\d+) trustcache-version checks "
                              r"\(\+(\d+) shared", run.stdout)
            runs.append({"mode": mode, "exit": run.returncode,
                         "checks": match.groups() if match else None,
                         "actual": [l for l in run.stdout.splitlines()
                                    if l.startswith(("ACTUAL", "SKIP"))],
                         "stdout_tail": run.stdout[-400:],
                         "stderr": run.stderr[-400:]})
            if run.returncode or not match:
                raise SystemExit(json.dumps(runs[-1], indent=2))
        for name, old, new in MUTANTS:
            if original.count(old) != 1:
                raise SystemExit(f"mutant {name}: target text occurs "
                                 f"{original.count(old)} times, expected once")
            mutated = temp / f"mutant-{name}.c"
            mutated.write_text(original.replace(old, new))
            flags, defs = modes["sanitizers"]
            try:
                binary = compile_test(root, temp, f"mutant-{name}", mutated,
                                      flags, defs)
            except subprocess.CalledProcessError as error:
                mutants.append({"mutant": name, "killed": True,
                                "exit": "compile-error",
                                "detail": error.stderr.strip()[:160]})
                continue
            run = subprocess.run([str(binary), *tail], capture_output=True,
                                 text=True, timeout=300)
            killed = run.returncode != 0
            detail = (run.stdout.strip().splitlines() or [""])[-1]
            mutants.append({"mutant": name, "killed": killed,
                            "exit": run.returncode,
                            "detail": (run.stderr.strip().splitlines() or
                                       [detail])[0][:160]})
            if not killed:
                raise SystemExit(f"mutant {name} survived: the test cannot "
                                 "fail for this error")
    assert before == {name: digest(root / name) for name in SOURCES}
    asset_after = ({n: digest(args.components / n) for n in assets
                    if (args.components / n).exists()}
                   if args.components else {})
    assert asset_before == asset_after
    report = {"passed": True, "source_sha256": before, "runs": runs,
              "mutants": mutants,
              "components_unchanged": asset_before == asset_after,
              "trustcache_entries_parsed": False, "guest_launched": False,
              "firmware_executed": False}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "core-result.json").write_text(
            json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True,
                      "runs": [(r["mode"], r["checks"], r["actual"])
                               for r in runs],
                      "mutants_killed":
                      f'{sum(m["killed"] for m in mutants)}/{len(mutants)}'},
                     indent=1))


if __name__ == "__main__":
    main()
