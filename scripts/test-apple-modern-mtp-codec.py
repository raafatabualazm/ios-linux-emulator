#!/usr/bin/env python3
"""Compile the production multi-touch frame codec under ASan/UBSan and as a -DNDEBUG build and run the codec test;
then prove the test can fail: each mutant of the production codec must be rejected by the same test.

No guest launch. Sources are hashed before and after.
"""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

CODEC = "hw/arm/apple-silicon/modern-mtp-codec.c"
HEADER = "include/hw/arm/apple-silicon/modern-mtp-codec.h"
TEST = "scripts/test-apple-modern-mtp-codec.c"

# (name, exact text in the codec, replacement). Plausible implementation errors.
MUTANTS = [
    ("checksum-not-inverted", "    return ~sum;", "    return sum;"),
    ("padding-off-by-one", "(APPLE_MODERN_SCM_SUB_LEN + payload_len + 3) & ~(size_t)3", "(APPLE_MODERN_SCM_SUB_LEN + payload_len + 2) & ~(size_t)3"),
    ("transfer-id-and-interface-swapped", "    out[4] = transfer_id;\n    out[5] = iface;", "    out[4] = iface;\n    out[5] = transfer_id;"),
    ("payload-length-in-the-wrong-place", "        put16(out + 10, payload_len);", "        put16(out + 8, payload_len);"),
    ("retcode-truncated", "        put32(out + 12, retcode);", "        put32(out + 12, retcode >> 16);"),
    ("init-version-zero", "    put16(out + k, 1);                     /* descriptor packet version */", "    put16(out + k, 0);"),
    ("init-name-short", "    k += 16;\n    put16(out + k, 0);                     /* more packets: none */", "    k += 15;\n    put16(out + k, 0);"),
    ("init-ready-status-one", "    put16(out + k + 4, 0);                 /* 0 = HID, non-zero = inactive */", "    put16(out + k + 4, 1);"),
    ("init-ready-section-missing", "    put16(out + k, 4);                     /* section 4: ready status */\n    put16(out + k + 2, 2);\n    put16(out + k + 4, 0);                 /* 0 = HID, non-zero = inactive */\n    k += 6;\n", ""),
    ("mt-header-length-20", "    out[2] = APPLE_MODERN_MT_HDR_LEN;      /* header length */", "    out[2] = 20;"),
    ("mt-timestamp-big-endian", "    put32(out + 4, ms);                    /* milliseconds, non-zero, increasing */", "    put32(out + 4, (ms >> 24) | ((ms >> 8) & 0xff00) | ((ms << 8) & 0xff0000) | (ms << 24));"),
    ("mt-path-count-two", "    out[16] = 1;                           /* path count */", "    out[16] = 2;"),
    ("mt-path-stride-24", "    out[17] = APPLE_MODERN_MT_PATH_LEN;    /* path stride */", "    out[17] = 24;"),
    ("mt-stage-and-finger-swapped", "    path[1] = stage;\n    path[2] = 1;                           /* finger id */", "    path[1] = 1;\n    path[2] = stage;"),
    ("mt-x-and-y-swapped", "    put16(path + 4, (uint16_t)x);\n    put16(path + 6, (uint16_t)y);", "    put16(path + 4, (uint16_t)y);\n    put16(path + 6, (uint16_t)x);"),
    ("mt-velocity-wrapped-not-clamped", "    if (vx > INT16_MAX) {\n        vx = INT16_MAX;", "    if (vx > INT32_MAX) {\n        vx = INT16_MAX;"),
    ("mt-radius-swapped", "    put16(path + 12, 660);                 /* major radius, 0.01 mm */\n    put16(path + 14, 580);", "    put16(path + 12, 580);\n    put16(path + 14, 660);"),
    ("mt-velocity-unit-mm-per-second", "(int64_t)dpos * 80 / (int64_t)dt_ms", "(int64_t)dpos * 10 / (int64_t)dt_ms"),
    # several fingers in one frame (apple_modern_mt_frame_paths)
    ("mtn-count-off-by-one", "    out[16] = (uint8_t)n;", "    out[16] = (uint8_t)(n + 1);"),
    ("mtn-paths-overlap", "out + APPLE_MODERN_MT_HDR_LEN + i * APPLE_MODERN_MT_PATH_LEN;", "out + APPLE_MODERN_MT_HDR_LEN;"),
    ("mtn-finger-always-one", "    q[2] = c->id;                      /* one finger per path */", "    q[2] = 1;"),
    ("mtn-id-zero-based", "        q[0] = c->id;", "        q[0] = (uint8_t)i;"),
    ("mtn-empty-frame-accepted", "    if (n == 0 || n > APPLE_MODERN_MT_MAX_PATHS) {", "    if (n > APPLE_MODERN_MT_MAX_PATHS) {"),
    ("mtn-no-upper-bound", "    if (n == 0 || n > APPLE_MODERN_MT_MAX_PATHS) {", "    if (n == 0) {"),
    ("mtn-velocity-wraps", "v > INT16_MAX ? INT16_MAX : v < INT16_MIN ? INT16_MIN : v", "v"),
    ("mtn-y-is-x", "        put16(q + 6, (uint16_t)c->y);", "        put16(q + 6, (uint16_t)c->x);"),
    ("mtn-hand-zero", "        q[3] = 1;                          /* hand */", "        q[3] = 0;"),
]


def sha(paths):
    return {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}


def build_and_run(codec_src, out_dir, flags, tag):
    codec = Path(out_dir) / f"codec-{tag}.c"
    codec.write_text(codec_src)
    exe = Path(out_dir) / f"test-{tag}"
    cmd = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-DAPPLE_MODERN_MTP_CODEC_STANDALONE", "-Iinclude"] + flags + \
          [str(codec), TEST, "-o", str(exe)]
    cc = subprocess.run(cmd, capture_output=True, text=True)
    if cc.returncode:
        return None, cc.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    return run.returncode, (run.stdout + run.stderr).strip()


def main():
    before = sha([CODEC, HEADER, TEST])
    src = Path(CODEC).read_text()
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for tag, flags in (("asan", ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]),
                           ("ndebug", ["-DNDEBUG", "-O2"])):
            rc, out = build_and_run(src, tmp, flags, tag)
            print(f"{tag}: {'PASS' if rc == 0 else 'FAIL'}: {out.splitlines()[-1] if out else ''}")
            failures += rc != 0
        for name, old, new in MUTANTS:
            if src.count(old) != 1:
                print(f"mutant {name}: SKIPPED, pattern occurs {src.count(old)} times")
                failures += 1
                continue
            rc, out = build_and_run(src.replace(old, new), tmp, ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"], "mut")
            if rc is None:
                print(f"mutant {name}: does not compile (not a valid mutant): {out.splitlines()[0] if out else ''}")
                failures += 1
                continue
            caught = rc != 0
            print(f"mutant {name}: {'rejected' if caught else 'SURVIVED'}")
            failures += not caught
    if sha([CODEC, HEADER, TEST]) != before:
        print("sources changed during the run")
        failures += 1
    print("result:", "PASS" if failures == 0 else f"FAIL ({failures})")
    return failures


sys.exit(1 if main() else 0)
