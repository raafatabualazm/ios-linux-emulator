#!/usr/bin/env python3
"""Build the production AIC source under ASan/UBSan and as a -DNDEBUG build,
run the IRQ_CFG core test, then prove the test can fail: each mutant of the
production source must be rejected by the same test.

No guest launch. The sources are hashed before and after.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

SOURCE = "hw/intc/apple-modern-aic.c"
HEADER = "include/hw/intc/apple-modern-aic.h"
TEST = "scripts/test-apple-modern-aic-irq-config.c"

# (name, exact text in the production source, replacement). Each describes a
# plausible implementation error; the unmutated test passes, every mutant fails.
MUTANTS = [
    ("upper-bits-dropped",
     "s->irq_config[(offset - s->geometry.irq_config_offset) / 4] = value;",
     "s->irq_config[(offset - s->geometry.irq_config_offset) / 4] = value & 0xff;"),
    ("neighbour-written",
     "s->irq_config[(offset - s->geometry.irq_config_offset) / 4] = value;",
     "s->irq_config[((offset - s->geometry.irq_config_offset) / 4) ^ 1] = value;"),
    ("flag-ignored-rejects",
     "if (s->geometry.record_irq_config) {\n            s->irq_config[",
     "if (0) {\n            s->irq_config["),
    ("flag-ignored-accepts-and-drops",
     "return value == 0; /* refuse unsupported routing/delay/reserved bits */",
     "return true; /* mutant */"),
    ("reset-keeps-config",
     "    memset(s->irq_config, 0, sizeof(s->irq_config));\n",
     ""),
    ("read-returns-zero",
     "*value = s->irq_config[(offset - s->geometry.irq_config_offset) / 4];",
     "*value = 0;"),
    ("delivery-follows-target",
     "return pending_irq(s) >= 0;",
     "return pending_irq(s) >= 0 &&\n"
     "           !(s->irq_config[pending_irq(s)] & 0xf);"),
    ("accessor-unbounded",
     "return irq < s->geometry.max_irqs ? s->irq_config[irq] : 0;",
     "return s->irq_config[irq & 4095];"),
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(root: Path, temp: Path, name: str, source: Path, flags: list) -> Path:
    binary = temp / name
    command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
               "-DAPPLE_MODERN_AIC_STANDALONE", "-I" + str(root / "include"),
               *flags, str(source), str(root / TEST), "-o", str(binary)]
    subprocess.run(command, check=True, capture_output=True, text=True)
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    names = [SOURCE, HEADER, TEST]
    before = {name: digest(root / name) for name in names}
    modes = {"sanitizers": ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"],
             # Production flags: asserts compiled out of the model sources. The
             # test itself uses its own CHECK macro, so its oracle stays live.
             "production-ndebug": ["-O2", "-DNDEBUG"]}
    runs, mutants = [], []
    original = (root / SOURCE).read_text()
    with tempfile.TemporaryDirectory(prefix="aic-irq-config-") as temporary:
        temp = Path(temporary)
        for mode, flags in modes.items():
            binary = build(root, temp, mode, root / SOURCE, flags)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=120)
            match = re.search(r"PASS (\d+) AIC IRQ_CFG checks", run.stdout)
            runs.append({"mode": mode, "exit": run.returncode,
                         "checks": match.group(1) if match else None,
                         "stdout_tail": run.stdout[-300:], "stderr": run.stderr[-300:]})
            if run.returncode or not match:
                raise SystemExit(json.dumps(runs[-1], indent=2))
        for name, old, new in MUTANTS:
            if original.count(old) != 1:
                raise SystemExit(f"mutant {name}: target text occurs "
                                 f"{original.count(old)} times, expected once")
            mutated = temp / f"mutant-{name}.c"
            mutated.write_text(original.replace(old, new))
            # The mutated file includes the real header through -I.
            binary = build(root, temp, f"mutant-{name}", mutated,
                           modes["sanitizers"])
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=120)
            killed = run.returncode != 0
            mutants.append({"mutant": name, "killed": killed, "exit": run.returncode,
                            "detail": (run.stderr.strip().splitlines() or [""])[0][:160]})
            if not killed:
                raise SystemExit(f"mutant {name} survived: the test cannot fail "
                                 "for this error")
    assert before == {name: digest(root / name) for name in names}
    report = {"passed": True, "source_sha256": before, "runs": runs,
              "mutants": mutants, "guest_launched": False, "firmware_executed": False}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "core-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True,
                      "runs": [(r["mode"], r["checks"]) for r in runs],
                      "mutants_killed": f'{sum(m["killed"] for m in mutants)}/{len(mutants)}'}))


if __name__ == "__main__":
    main()
