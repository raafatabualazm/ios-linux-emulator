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
- A separate AArch64 QEMU build reached Hello, accepted the opening swipe and
  English selection, then advanced through country selection to Quick Start. After restart and wake,
  manual setup and Continue reached the Wi-Fi page.
  That manual progression used the earlier coordinate/reset candidate. A fresh
  FIFO candidate reached Quick Start; manual setup was not retested while awake.
  This is iOS 14.0/18A5351d with inherited guest software-rendering changes.
  SpringBoard exists in a read-only process snapshot; its home screen and IPA
  execution remain unverified.
- Strict firmware selection prepared unchanged iPhone17,3/d47ap iOS27.0/24A437
  kernel, device tree, SPTM, TXM and stock restore trustcache with hashes. A matched
  ramdisk/full userspace and modern CPU/device integration remain required.
- The C modern layout module is included in the AArch64 build. ASan/UBSan
  verification passes 26 checks, including the actual prepared iOS 27 components
  (452 ADT nodes, 305 fileset entries, 19 regions and 24 copies). It validates
  bounded Mach-O command/segment tables, the selected ADT identity and the stock
  trustcache, then describes copies and reserved metadata regions. It has no
  board caller, populated boot metadata or modern execution path. Region names
  are ADT metadata and do not enforce page protections.
- IPA preflight validates the uploaded device arm64 app and stages unchanged
  bytes. Its development profile expired in December 2025. Normal installation
  requires a newly signed build accepted by the guest.

Detailed command references: [firmware](tools/firmware/README.md),
[apps](tools/apps/README.md). Runtime commands below run from the shared
`Inferno-and-Darwin-VM` workspace root.

## Build the integration candidate

Use a fresh out-of-tree build directory. `/tmp` is volatile on this host.

```sh
task_source="$(pwd)/Inferno/integration"
mkdir -p /tmp/inferno-modern-build
cd /tmp/inferno-modern-build
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
  --binary modern-emulator/bin/qemu-system-aarch64
python3 modern-emulator/tools/runtime/session.py run \
  --state modern-emulator/runtime/NEW_STATE --seconds 900
```

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

## Modern layout preparation

The public API is
`include/hw/arm/apple-silicon/modern-boot-layout.h`. The consumer must prepare and
bound its working ADT, boot arguments and matching persistent userspace, then
provide the modern CPU/platform devices. The module makes no guest writes,
changes no executable bytes and performs no Apple signature verification.
Its command/segment bounds checks are not a complete validator for Mach-O
sections, relocations or all load-command semantics.

Run the same C parser/layout under sanitizers from `Inferno/integration`:

```sh
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer -g -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
  hw/arm/apple-silicon/modern-boot-layout.c \
  scripts/test-apple-modern-boot-layout.c -o /tmp/test-modern-layout
/tmp/test-modern-layout /path/to/prepared/derived
```

Omit the last argument for synthetic checks only. The directory argument must
contain the unchanged decoded `bootkc`, `sptm`, `txm`, `dtree` and
`restore-trustcache` selected for the same identity. The test reports layout
preparation; it does not boot a guest.

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
