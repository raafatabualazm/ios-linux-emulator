# Modern emulator implementation workspace

This directory contains the versioned firmware, app and runtime tools. The
workspace `modern-emulator/tools` and `modern-emulator/tests` paths link here.
Private firmware, IPAs, binaries, guest state and evidence stay outside this
checkout; `evidence` is an ignored local compatibility link.

The current integration base is `linux-restore` commit
`38f5665ecfc98ca2e5b32809717b81fc978cbbcd`. The original dirty checkout and both
publication worktrees remain separate. Combined development is on `modern-ios`
in `Inferno/integration`. The qualified SPRR extension is isolated on
`darwin-cpu-verified` in `Inferno/darwin-cpu`; additional integration
system-register/AMCC/metadata/PTW and USB/runtime edits remain preserved.
This directory documents operating systems and hardware emulation, from CPU
and firmware handoff through display/input and the application lifecycle.

## Implemented and measured

- Apple multitouch queued reports capture their own position. Device reset
  invalidates older callbacks, and a single FIFO drain preserves arrival order
  despite QEMU's newest-first one-shot callbacks. The production scheduling/encoder/reset regression
  passes ASan and UBSan; the retained base fails that same test. The A13 IPI
  regression also passes. Migration and snapshot fidelity are not established.
- The iOS 14.0/18A5351d guest reaches interactive SpringBoard Home, reproduced
  on three retained boots; Settings opened by touch. Signed per-report deltas,
  60 Hz sampling and stationary frames form an empirical working configuration.
  The wake/swipe order also affects the result, so the comparisons do not isolate
  one cause or establish Apple wire units. A fresh nine-store copied state
  verified Home → Settings → Home → Notes → Home, with Notes Continue accepted
  and its empty list visible. F6 returns Home; the measured bottom-edge swipe
  still scrolls Settings. IPA installation and modern iOS GUI remain unverified.
- Strict firmware selection prepared unchanged iPhone17,3/d47ap iOS27.0/24A437
  kernel, device tree, SPTM, TXM and stock restore trustcache with hashes.
  Explicit optional extraction also prepares the matched restore ramdisk;
  full RAM copying across reset is verified, filesystem/recovery boot is not.
- Modern layout and metadata pass 29 layout plus 41 metadata sanitizer checks.
  Working ADT/1152-byte boot arguments preserve 452 nodes and 5414 unrelated
  property values. The optional ramdisk layout is implemented; no matching
  full userspace is qualified yet.
- An opt-in modern register interface has 23 base registers and 9 VHE aliases,
  independent GL1/GL2 banks and CPU-owned alias metadata. It passes 299 sanitizer
  checks and two actual CPU instruction/reset runs. Later Darwin ports add
  Apple timer views/stores, GENTER/GEXIT, guarded SP/exception/ERET routing,
  authenticated ERETAA and shared-context ASID invalidation. Four timer,
  four guarded and two actual board FIQ runs pass across reset. Default
  generic CPU profiles remain off; `apple-modern` enables the modern profiles.
- A separate modern SPRR model implements CONFIG/PPERM/UPERM banks, VHE aliases,
  raw leaf AP/UXN/PXN permission lookup, write-triggered TLB invalidation and
  A64 guarded AT context selection. ASan/UBSan fixtures pass 55,419
  permission/regime, 536 register/alias and 57,344 AT checks. Six actual
  synthetic-ROM execution passes cover omitted/disabled/enabled profiles,
  each before and after reset. Enabled passes include actual read/write/execute
  accesses, 21 expected level-3 permission faults, live permission changes
  without guest TLBI and ten authenticated guarded returns per pass.
- Experimental `apple-modern` prepares unchanged assets in RAM and defaults to
  halting the CPU. Whole-machine preparation/reset verifies PC/x0/EL2h, complete
  bootargs/ADT/stock trustcache, 23 sampled segments and zero BSS. Two bounded
  stock ADT CPU register windows provide 86,048 bytes of zeroed compatibility
  RAM; full reads and nonzero write/reset patterns pass. The final stopped
  board gate also verifies its enabled SPRR property. Unchanged SPTM now passes
  the former timer and SPRR register failures and stops at APSTS_EL1,
  `MRS S3_6_C15_C12_4,X0`, physical PC `0x100070a35d8`, source offset `0x9f5d8`.
  The 52.213 ms observation stopped cleanly, exited 0 and reaped its child,
  with executable and all five component hashes unchanged. XNU and modern
  userspace have not booted. Modern interrupt/storage/display/touch devices
  remain unfinished.
- Runtime/diagnostics passed a 96-case review with a real loopback RFB handshake,
  signal-aware guest reaping, conservative dead-session recovery, and recorder
  run/PID binding. Later companion fixes have their own regression gate.
  An interruption is never reported as guest success.
- IPA preflight validates the uploaded device arm64 app and stages unchanged
  bytes. Its development profile expired in December 2025. Normal installation
  requires a newly signed build accepted by the guest.

Detailed command references: [firmware](tools/firmware/README.md),
[apps](tools/apps/README.md). Runtime commands below run from the shared
`Inferno-and-Darwin-VM` workspace root.

### October 6 modern CPU checkpoint

The six SPRR CPU/reset passes used `qemu-system-aarch64-sprr-gate-v1`, SHA-256
`768d7d61daac4d7f5f60c23a760c68a2b6cdfd95b616cafe4336cda205ecd3df`.
The final board pin is `qemu-system-aarch64-darwin-sprr-v1`, SHA-256
`27f30b9bbd74be317190929b46fecab37f9fbbc94ab57c3b7654528f7f78e08a`.
Subsequent board-property and preparation-check changes passed the stopped
board/reset gate on this final pin. The preceding ten timer/guarded/FIQ runs
used `qemu-system-aarch64-darwin-port-v1`, SHA-256
`8bc7e5abcb091d05a20747e22e72b1bb124d12bf5f7e1d57820d3963435e9437`.
These are separate measured executable results.

The CPU windows are register RAM with no modeled hardware locks or side
effects. SPRR's UPERM register allows EL0 reads; EL0 writes remain unsupported
until mask controls are modeled. User-bank AT instructions were tested from
EL2/GL2 without executing an EL0 guest. Guarded EL0, AArch32, cross-EL guarded
behavior, CTRR/AMCC locking and migration remain unqualified. SPRR VHE aliases
have component checks; the SPRR execution ROM does not qualify VHE guest
execution. See [the Darwin port inventory](../../docs/darwin-port.md) for
supported behavior and retained reference revisions.

Private evidence:
`modern-emulator/evidence/features-20261006/{darwin-sprr-owned-rom-v1,sprr-board-preparation-final,darwin-sptm-sprr-v1}/`.
The next CPU interface is APSTS/control behavior. Integrate it from reference
evidence while preserving active pointer authentication and earlier source;
matched userspace and modern device adapters remain necessary for SpringBoard.

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

For the isolated SPRR source, use `Inferno/darwin-cpu` and a separate build
directory such as `modern-emulator/build-darwin-cpu`. The recorded native
build additionally used `--enable-fdt=internal --enable-vnc --disable-download`
with its already prepared local subproject dependencies. The existing
integration build and pinned GUI states remain separate.

To preserve a stopped state's setup progress with a different executable:

```sh
python3 modern-emulator/tools/runtime/session.py fork \
  --source-state modern-emulator/runtime/EXISTING_STATE \
  --state modern-emulator/runtime/NEW_STATE \
  --binary /path/to/new/qemu-system-aarch64
```

The command copies all nine writable stores and retains the pinned original raw
root backing. It rejects an active/marked source and checks source and copied
bytes before publishing a usable manifest. A failed copy can leave an incomplete
directory without a manifest. Boot assets and the original backing bundle must
remain available. Historical GUI/IPA qualification is not inherited.

## Persistent isolated GUI state

```sh
python3 modern-emulator/tools/runtime/session.py prepare \
  --bundle Inferno/gui-runtime --state modern-emulator/runtime/NEW_STATE \
  --binary modern-emulator/bin/qemu-system-aarch64-touch-v2
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
For an executable containing the new touch trace events, `run --trace-touch`
records host input, encoded contact reports and SPI reply construction in the
bounded emulator log. It preserves the normal wire format. Reply construction
does not establish guest driver or gesture acceptance.
Startup reliability remains unresolved: one restart of the earlier integration
bundle hit a guest SEP panic. This build currently has no GTK backend; use QMP
screenshots or VNC, or install GTK development dependencies and rebuild before
selecting `--display gtk`.

The retained Home recipe is F6, bottom-edge swipe, F6 while awake, another
swipe. Inspect each resulting screen; delayed input can let the guest sleep.
The verified Home bundle is `modern-emulator/runtime/ios14-home`. Use `fork`
to continue its progress in a new bundle. The `touch-v2` executable pin is a
private tested artifact; fresh builds must have their own executable pin.
White Settings rows are not modal-alert evidence, and a named screenshot does
not qualify an app launch. Home-to-app transitions require visual confirmation.

## Normal USB through a private companion

The phone's emulated USB device attaches to a separate x86 QEMU guest. Prepare
a new companion state from a stopped disk containing a USB-capable Linux kernel
and libimobiledevice tools. The runner creates a private QCOW2 overlay, copies
the seed/BIOS resources, and pins the source disk metadata and executable hashes.
It does not restore the phone, pair it, or install an app.

```sh
python3 modern-emulator/tools/runtime/companion.py prepare \
  --disk /path/to/stopped/companion.qcow2 --seed /path/to/seed.iso \
  --binary /path/to/qemu-system-x86_64-with-usb-tcp \
  --qemu-data Inferno/integration/pc-bios \
  --state modern-emulator/runtime/NEW_COMPANION
```

For a hardware comparison with the retained local `run-companion.sh`, add
`--hardware-profile historical` when preparing a **new** companion state. That
profile selects QEMU's `qemu64` CPU, 3 GiB RAM, four CPUs, inherited standard VGA
and chipset USB, plus the dedicated EHCI controller. It also retains the old
launcher's `cache=unsafe` disk mode, so overlay durability across a host crash is
not assured. The standard VGA and virtio network option ROMs are copied and
hashed with the BIOS resources. The profile is pinned in the manifest; it cannot
be switched at run time. Existing states and the default `isolated` profile keep
their `max`/2 GiB/two CPU/no-default-devices command. The historical comparison
has not yet established Linux boot or USB service acceptance in this runner.

In one terminal, start a separately forked phone state with `--usb`. It reserves
`PHONE_STATE/usb.sock` and waits up to 30 seconds for the companion listener;
the phone CPU starts after passive readiness succeeds. Within that wait, start
the companion in a second terminal using the exact endpoint:

```sh
python3 modern-emulator/tools/runtime/session.py run \
  --state modern-emulator/runtime/PHONE_STATE --seconds 900 --usb
python3 modern-emulator/tools/runtime/companion.py run \
  --state modern-emulator/runtime/NEW_COMPANION \
  --usb-socket modern-emulator/runtime/PHONE_STATE/usb.sock \
  --seconds 900 --ssh-port 32225
```

The companion uses TCG, restricted user networking and an optional SSH forward
bound to `127.0.0.1`; `--ssh-port 0` disables forwarding. Its duration is bounded
to 30–1800 seconds, with 512 MiB overlay and 8 MiB log caps. Credentials and
pairing records remain private. Stop the phone with `session.py control … quit`
before ending the companion; its own runner stops and reaps it at the bound.

Check the companion's running kernel, EHCI controller and Apple USB interfaces,
then `idevice_id -l` and `ideviceinfo -s -k ProductVersion` inside that guest.
A listening or connected socket establishes transport only. USB enumeration,
a successful lockdownd response and any installation service acceptance require
separate observations. Ordinary app installation additionally needs a current
signed IPA accepted by the device; the uploaded development profile is expired.

A companion socket can become ready while its BIOS is still starting. A future
Linux readiness gate should start the companion without the remote USB device,
verify its USB-capable kernel and EHCI controller through a bounded read-only
query, then add the remote device through QMP when the phone's waiting marker
exists. These stages must share the companion's original time bound, with the
phone retaining its 30-second listener wait. Deferred attachment is a design
step; the current runner attaches its remote USB device at startup.

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

The current SPRR extension has separate component, actual instruction and
stopped-board gates. Use fresh report destinations:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  python3 Inferno/darwin-cpu/scripts/test-apple-modern-sprr.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  python3 Inferno/darwin-cpu/scripts/test-apple-modern-sprr-registers.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  python3 Inferno/darwin-cpu/scripts/test-apple-modern-at.py
python3 Inferno/darwin-cpu/scripts/test-apple-modern-sprr-qemu.py \
  --binary modern-emulator/bin/qemu-system-aarch64-sprr-gate-v1 \
  --output-dir /path/to/new/private/sprr-report
python3 Inferno/darwin-cpu/scripts/test-apple-modern-machine.py \
  --binary modern-emulator/bin/qemu-system-aarch64-darwin-sprr-v1 \
  --components /path/to/matched/decoded-components \
  --qmp-stdio --check-register-reset-pattern \
  --output-dir /path/to/new/private/board-report
```

LeakSanitizer was disabled for recorded component runs after ptrace was denied
in the earlier environment. ASan/UBSan results do not claim leak checking.

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
