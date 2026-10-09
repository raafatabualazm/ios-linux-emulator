#!/usr/bin/env python3
"""Compile the production metadata builder under ASan/UBSan and as a -DNDEBUG
build and run the dart-id test; with --components also run it against the real
stock iPhone17,3 tree. Then prove the test can fail: each mutant of the
production loader must be rejected by the same test.

No guest launch. Sources and firmware components are hashed before and after.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

LOADER = "hw/arm/apple-silicon/modern-boot-metadata.c"
LAYOUT = "hw/arm/apple-silicon/modern-boot-layout.c"
TEST = "scripts/test-apple-modern-dart-id.c"
SOURCES = [LAYOUT, LOADER,
           "include/hw/arm/apple-silicon/modern-boot-layout.h",
           "include/hw/arm/apple-silicon/modern-boot-metadata.h",
           "scripts/test-apple-modern-boot-layout.c",
           "scripts/test-apple-modern-boot-metadata.c", TEST]

# (name, exact text in the loader, replacement). Plausible implementation errors.
MUTANTS = [
    ("ids-start-at-one",
     "tree->dart_value = tree->dart_count++;",
     "tree->dart_value = ++tree->dart_count;"),
    ("every-id-zero",
     "tree->dart_value = tree->dart_count++;",
     "tree->dart_value = 0; tree->dart_count++;"),
    ("existing-id-kept-twice",
     "    if (tree->dart_pending && !strcmp(name, \"dart-id\")) {\n        return true;\n    }\n",
     ""),
    ("prefix-match",
     "if (entry == wanted_length && !memcmp(list + start, wanted, entry)) {",
     "if (entry >= wanted_length && !memcmp(list + start, wanted, wanted_length)) {"),
    ("unterminated-entry-ignored",
     "size_t entry = end ? (size_t)(end - (list + start)) : length - start;",
     "size_t entry = end ? (size_t)(end - (list + start)) : 0;"),
    ("only-first-compatible-entry",
     "dart = compatible_has(tree->input.data + tree->cursor, length,\n"
     "                                  \"dart,t8110\");",
     "dart = compatible_has(tree->input.data + tree->cursor,\n"
     "                                  length > 11 ? 11 : length, \"dart,t8110\");"),
    ("property-count-not-adjusted",
     "        added += tree->dart_pending;\n",
     ""),
    ("pending-leaks-into-children",
     "    tree->dart_pending = false;\n    for (uint32_t i = 0; i < children; i++) {",
     "    for (uint32_t i = 0; i < children; i++) {"),
    ("no-dart-tree-accepted",
     "if (tree.assign_dart_ids && !tree.dart_count) {",
     "if (0) {"),
    ("override-conflict-accepted",
     "if (input->assign_dart_ids && !strcmp(o->name, \"dart-id\")) {",
     "if (0) {"),
    ("ids-ignore-flag",
     "tree.assign_dart_ids = input->assign_dart_ids;",
     "tree.assign_dart_ids = false;"),
    ("generated-id-wrong-size",
     "        uint8_t bytes[4];\n\n        put32(bytes, tree->dart_value);\n"
     "        if (!property(tree, \"dart-id\", bytes, sizeof(bytes), errp)) {",
     "        uint8_t bytes[8] = {0};\n\n        put32(bytes, tree->dart_value);\n"
     "        if (!property(tree, \"dart-id\", bytes, sizeof(bytes), errp)) {"),
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_test(root, temp, name, loader_source, flags, extra_defs):
    base = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
            "-DAPPLE_MODERN_LAYOUT_STANDALONE", "-I" + str(root / "include")]
    objects = []
    for source, tag in ((root / LAYOUT, "layout"), (loader_source, "loader")):
        obj = temp / f"{name}-{tag}.o"
        subprocess.run([*base, *flags, *extra_defs, "-c", str(source), "-o", str(obj)],
                       check=True, capture_output=True, text=True)
        objects.append(str(obj))
    test_obj = temp / f"{name}-test.o"
    subprocess.run([*base, *flags, "-c", str(root / TEST), "-o", str(test_obj)],
                   check=True, capture_output=True, text=True)
    binary = temp / name
    subprocess.run([*base, *flags, *objects, str(test_obj), "-o", str(binary)],
                   check=True, capture_output=True, text=True)
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--components", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    before = {name: digest(root / name) for name in SOURCES}
    assets = ["bootkc", "sptm", "txm", "dtree", "restore-trustcache"]
    asset_before = ({n: digest(args.components / n) for n in assets}
                    if args.components else {})
    modes = {"sanitizers": (["-fsanitize=address,undefined", "-fno-omit-frame-pointer"], []),
             # Only the production sources are built with NDEBUG; the test's own
             # assert()/DCHECK oracle stays live, as in the shipping emulator.
             "production-ndebug": (["-O2"], ["-DNDEBUG"])}
    runs, mutants = [], []
    original = (root / LOADER).read_text()
    command_tail = [str(args.components.resolve())] if args.components else []
    with tempfile.TemporaryDirectory(prefix="dart-id-") as temporary:
        temp = Path(temporary)
        for mode, (flags, defs) in modes.items():
            binary = compile_test(root, temp, mode, root / LOADER, flags, defs)
            run = subprocess.run([str(binary), *command_tail], capture_output=True,
                                 text=True, timeout=300)
            match = re.search(r"PASS (\d+) dart-id checks \(\+(\d+) shared", run.stdout)
            runs.append({"mode": mode, "exit": run.returncode,
                         "checks": match.groups() if match else None,
                         "actual": [l for l in run.stdout.splitlines() if l.startswith("ACTUAL")],
                         "stdout_tail": run.stdout[-500:], "stderr": run.stderr[-500:]})
            if run.returncode or not match:
                raise SystemExit(json.dumps(runs[-1], indent=2))
        for name, old, new in MUTANTS:
            if original.count(old) != 1:
                raise SystemExit(f"mutant {name}: target text occurs "
                                 f"{original.count(old)} times, expected once")
            mutated = temp / f"mutant-{name}.c"
            mutated.write_text(original.replace(old, new))
            flags, defs = modes["sanitizers"]
            binary = compile_test(root, temp, f"mutant-{name}", mutated, flags, defs)
            run = subprocess.run([str(binary), *command_tail], capture_output=True,
                                 text=True, timeout=300)
            killed = run.returncode != 0
            mutants.append({"mutant": name, "killed": killed, "exit": run.returncode,
                            "detail": (run.stderr.strip().splitlines() or [""])[0][:160]})
            if not killed:
                raise SystemExit(f"mutant {name} survived: the test cannot fail "
                                 "for this error")
    assert before == {name: digest(root / name) for name in SOURCES}
    asset_after = ({n: digest(args.components / n) for n in assets} if args.components else {})
    assert asset_before == asset_after
    report = {"passed": True, "source_sha256": before, "runs": runs, "mutants": mutants,
              "components_unchanged": asset_before == asset_after,
              "firmware_executed": False, "guest_launched": False}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "core-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True,
                      "runs": [(r["mode"], r["checks"], r["actual"]) for r in runs],
                      "mutants_killed": f'{sum(m["killed"] for m in mutants)}/{len(mutants)}'},
                     indent=1))


if __name__ == "__main__":
    main()
