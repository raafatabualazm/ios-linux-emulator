# Modern emulator implementation workspace

This directory contains the versioned firmware, app and runtime tools. The
workspace `modern-emulator/tools` and `modern-emulator/tests` paths link here.
Private firmware, IPAs, binaries, guest state and evidence stay outside this
checkout; `evidence` is an ignored local compatibility link.

The current integration base is `linux-restore` commit
`38f5665ecfc98ca2e5b32809717b81fc978cbbcd`. The original dirty checkout and both
publication worktrees remain separate. The new branch is `modern-ios`.

## Implemented and measured

- Apple multitouch queued reports capture their own position. Device reset
  invalidates older callbacks, and a single FIFO drain preserves arrival order
  despite QEMU's newest-first one-shot callbacks. The production scheduling/encoder/reset regression
  passes ASan and UBSan; the retained base fails that same test. The A13 IPI
  regression also passes. Migration and snapshot fidelity are not established.
- The retained FIFO candidate advances the iOS 14.0/18A5351d GUI through stock
  Setup. The user-approved beta agreement was accepted; the latest completed
  observation reached iPhone Analytics before becoming unresponsive. Runner 143
  and missing final result are recorded with unknown cause. A fresh bounded run
  is continuing that same isolated state. Home and IPA execution are unverified.
- Strict firmware selection prepared unchanged iPhone17,3/d47ap iOS27.0/24A437
  kernel, device tree, SPTM, TXM and stock restore trustcache with hashes.
- Modern layout and metadata pass 29 layout plus 41 metadata sanitizer checks.
  Working ADT/1152-byte boot arguments preserve 452 nodes and 5414 unrelated
  property values. The optional ramdisk layout is implemented; no matching
  full userspace is qualified yet.
- An opt-in modern register interface has 23 base registers and 9 VHE aliases,
  independent GL1/GL2 banks and CPU-owned alias metadata. It passes 299 sanitizer
  checks and two actual CPU instruction/reset runs. Guarded entry/exit and page
  protections remain unimplemented; default legacy CPU properties are unchanged.
- Experimental `apple-modern` prepares unchanged assets in RAM and defaults to
  halting the CPU. Whole-machine preparation/reset verifies PC/x0/EL2h, complete
  bootargs/ADT/stock trustcache, 23 sampled segments and zero BSS. One bounded
  unchanged-SPTM execution hit unsupported `MSR S3_1_C15_C9_4, XZR`; it did not
  boot the kernel or iOS. Modern interrupt/storage/display/touch devices remain
  unfinished.
- Runtime/diagnostics pass 52 tests, including a real loopback RFB handshake,
  signal-aware guest reaping, conservative dead-session recovery, and recorder
  run/PID binding. An interruption is never reported as guest success.
- IPA preflight validates the uploaded device arm64 app and stages unchanged
  bytes. Its development profile expired in December 2025. Normal installation
  requires a newly signed build accepted by the guest.

Detailed command references: [firmware](tools/firmware/README.md),
[apps](tools/apps/README.md). Runtime commands below run from the shared
`Inferno-and-Darwin-VM` workspace root.

## Build the integration candidate

Use a fresh out-of-tree build directory. The working build below is persistent;
`/tmp` is volatile on this host.

```sh
task_source="$(pwd)/Inferno/integration"
mkdir -p modern-emulator/build
cd modern-emulator/build
"$task_source/configure" \
  --target-list=aarch64-softmmu --enable-lzfse --enable-nettle --enable-gnutls \
  --disable-werror --disable-qom-cast-debug --disable-debug-info
ninja -j4 qemu-system-aarch64
```

Pin the resulting executable when preparing a state bundle. A binary update
requires a separately prepared bundle rather than changing a pinned manifest.

## Persistent isolated GUI state

```sh
python3 modern-emulator/tools/runtime/session.py prepare \
  --bundle Inferno/gui-runtime --state modern-emulator/runtime/NEW_STATE \
  --binary modern-emulator/bin/qemu-system-aarch64-input
python3 modern-emulator/tools/runtime/session.py run \
  --state modern-emulator/runtime/NEW_STATE --seconds 900
```

For VNC, append `--vnc 127.0.0.1:1` and connect a local viewer to port 5901.
The runner supplies the source `pc-bios` keymap directory; override it with
`--qemu-data /path/to/qemu-data` if needed. Resource paths/hash are recorded at
startup. GUI evidence/control commands are described in
[Private GUI diagnostics](tools/runtime/DIAGNOSTICS.md).

For a GTK window, append
`--display gtk,zoom-to-fit=on,show-cursor=on` to `run`. The state bundle includes
the root overlay and all eight ancillary/SEP stores. Keep them together across
restarts. The original root is a read-only backing image. Boot assets, original
root metadata and executable hashes are pinned. The original stores must be
stopped during preparation and use; procfs scans cover accessible descriptors.

Controls use screenshot coordinates with a top-left origin:

```sh
python3 modern-emulator/tools/runtime/session.py control \
  --state modern-emulator/runtime/NEW_STATE home
python3 modern-emulator/tools/runtime/session.py control \
  --state modern-emulator/runtime/NEW_STATE screenshot --output /tmp/new.ppm
python3 modern-emulator/tools/runtime/session.py control \
  --state modern-emulator/runtime/NEW_STATE swipe \
  --x 414 --y 1720 --to-x 414 --to-y 700 --duration 0.5
python3 modern-emulator/tools/runtime/session.py control \
  --state modern-emulator/runtime/NEW_STATE tap --x 414 --y 591
python3 modern-emulator/tools/runtime/session.py control \
  --state modern-emulator/runtime/NEW_STATE quit
```

`home` sends F6; it woke the measured integration welcome screen. `side` sends
F5. Input is explicit, with no timed automatic wake keys. Screenshots and
per-run logs have new destinations. A QMP acknowledgement means the event was
sent; verify the resulting guest screen. Wait for list scrolling to settle
before selecting a row. An unexpected early exit, including exit 0, is a failure.
Controlled termination is not a successful guest boot or application result.
Startup reliability remains unresolved: one restart of the earlier integration
bundle hit a guest SEP panic. This build currently has no GTK backend; use QMP
screenshots or VNC, or install GTK development dependencies and rebuild before
selecting `--display gtk`.

## Modern RAM preparation

The layout and metadata APIs are in
`include/hw/arm/apple-silicon/modern-boot-{layout,metadata}.h`. They describe
normal copies, reserved regions and boot metadata; region names do not enforce
page permissions. The bounds checks do not verify Apple signatures or every
Mach-O section/relocation semantic.

The experimental board takes decoded `bootkc`, `sptm`, `txm`, `dtree` and `tc`
machine properties; `ramdisk` is optional. It accepts one CPU, defaults to 8 GiB,
and has a 512 MiB per-file/1 GiB aggregate input bound. Use the
`boot-command-line` machine property for ordinary boot arguments. Generic QEMU
rejects `-append` without `-kernel`; this board takes explicit components.
`timebase-frequency` defaults to 24 MHz as an experiment value; a real T8140
frequency is not established. `mte` is optional and unqualified by the default
preparation test. Snapshot/migration and modern platform fidelity are unqualified.

Run the stopped preparation/reset gate from the workspace root:

```sh
python3 Inferno/integration/scripts/test-apple-modern-machine.py \
  --binary modern-emulator/bin/qemu-system-aarch64-modern-prep \
  --components /path/to/matched/decoded-components \
  --output-dir /path/to/new/private/report-directory
python3 Inferno/integration/scripts/test-apple-modern-cpu-qemu.py \
  --binary modern-emulator/bin/qemu-system-aarch64-modern-prep \
  --output-dir /path/to/new/private/cpu-report
python3 Inferno/integration/scripts/test-apple-modern-gxf.py
python3 Inferno/integration/scripts/test-apple-modern-boot-metadata.py \
  --components /path/to/matched/decoded-components \
  --evidence /path/to/new/private/metadata-report
```

The whole-machine gate never resumes the guest; its RAM dumps are transient.
The CPU gate executes a small owned register-test ROM on generic `virt`.
Neither qualifies an iOS boot or SpringBoard.

## Verification

```sh
python3 Inferno/integration/scripts/test-apple-mt-queue.py
python3 Inferno/integration/scripts/test-a13-ipi.py
python3 -m unittest discover -s modern-emulator/tests/firmware -v
python3 -m unittest discover -s modern-emulator/tests/apps -v
python3 -m unittest discover -s modern-emulator/tests/runtime -v
```

Private results live under `modern-emulator/evidence/` and per-run
`modern-emulator/runtime/*/runs/`. Those directories must not be published.
The modern SpringBoard/IPA objective is still unfinished.
