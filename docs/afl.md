# Optional Linux AFL syscall harness

The fork includes an opt-in AFL 2.57b forkserver for the `t8030` iOS 14
syscall lab. Normal builds leave it disabled. It requires Linux, System V
shared memory, an accessible `/proc`, and system TCG emulation. The normal
Linux restore and GUI workflow is described in [linux-restore.md](linux-restore.md).

## Build

Use the dependencies from the Linux restore guide, and build the optional
runtime in a separate directory:

```bash
mkdir build-afl
cd build-afl
../configure --target-list=aarch64-softmmu --enable-afl \
  --disable-guest-agent --enable-nettle --enable-gnutls --enable-lzfse \
  --disable-werror --disable-qom-cast-debug --disable-debug-info
ninja qemu-system-aarch64
cd ..
```

`--enable-afl` requires Linux and TCG; combining it with `--disable-tcg`
is an error. Without `--enable-afl`, HINT #0x30–0x33 retain their ordinary
no-op behavior, and the runtime is absent from the binary. An enabled build
starts its forkserver only when AFL supplies `__AFL_SHM_ID`; ordinary GUI and
shell boots work without AFL environment variables.

## Supply the prepared lab

The helper scripts require Python 3.11 or newer. Keep your locally prepared
firmware and disk files outside the repository; this fork does not include
Apple firmware or a fuzzer ramdisk.

Pass `--lab` for the directory containing:

```text
ios_scfuzzer.img
kernelcache.research.iphone12b
DeviceTree.n104ap.im4p
static_tc
root
nvram
sep_nvram
sep_ssc
```

Pass `--data` if these files are in a different directory:

```text
root_ticket.der
sep-firmware.n104.RELEASE.new.img4
AppleSEPROM-Cebu-B1
```

The helpers copy mutable NVRAM and SEP disks to each new run directory, and
create a sparse scratch `root` with the supplied root disk's size. If the
lab also contains `firmware`, `syscfg`, `ctrl_bits`, `effaceable`, or
`panic_log`, those namespaces are copied and attached automatically. Use
this profile with the ramdisk harness; it does not boot a configured GUI
from a copied root filesystem.

Paths are configurable through `--lab`, `--data`, and `--qemu`. Their
defaults are `./fuzz-inferno`, the supplied lab directory, and this
repository's `build-afl/qemu-system-aarch64`, respectively. The replay tool
also accepts `--seed` and `--crash-dir`; the smoke tool accepts `--afl` and
otherwise finds `afl-fuzz` on `PATH`. Use a fresh output directory for every
run.

## Validate and fuzz

The default coverage scope is pinned to `/bin/sysc_fuzz` in the prepared
ramdisk with SHA-256
`dfda491c79438ddd87b519747bbdc697d29c3d706b046ae9c57930178dcd7ab5`.
`AFL_HARNESS_SCOPE=0x1e7c:0x1e14` supplies the wrapper entry and return
offsets from its ASLR-adjusted HINT #0x31 PC. The scripts reject a different
ramdisk in this mode. The two syscall trace addresses in the replay helper
also belong to the pinned research kernel with KASLR disabled.

Set these paths to your prepared directories and AFL 2.57b binary:

```bash
INFERNO_LAB=/path/to/fuzz-inferno
INFERNO_DATA=/path/to/firmware-data
INFERNO_AFL=/path/to/AFL/afl-fuzz

python3 scripts/inferno-afl/validate_runtime.py \
  --lab "$INFERNO_LAB" --data "$INFERNO_DATA" \
  --repeat 200 --out-dir /tmp/inferno-repeat

python3 scripts/inferno-afl/run_afl_smoke.py \
  --lab "$INFERNO_LAB" --data "$INFERNO_DATA" --afl "$INFERNO_AFL" \
  --seconds 50 --out-dir /tmp/inferno-smoke
```

The replay uses AFL's actual forkserver protocol with seven guest CPUs. Its
built-in 14-byte seeds exercise `getpid` and `getppid`; `--seed` replaces the
initial `getpid` input. It records consumption offsets, map hashes,
syscall-entry traces, stop status, and per-case timing in `report.json`,
with complete serial and map files beside it. Check that every repeated
input has the same map, that the two syscalls have different maps, and that
empty input contributes no coverage beyond AFL's live-map marker. The
smoke helper records AFL's own `fuzzer_stats` in its report.

Replay a saved queue, hang, or crash input from a fresh guest boot:

```bash
python3 scripts/inferno-afl/validate_runtime.py \
  --lab "$INFERNO_LAB" --data "$INFERNO_DATA" \
  --case-file /path/to/saved-input --case-timeout 4 \
  --out-dir /tmp/inferno-replay
```

An invalid syscall number can terminate the guest harness with `SIGSYS`
and prevent the next persistent boundary. AFL classifies that timeout as a
hang. Inspect the serial log before treating a saved result as a kernel
crash. The persistent guest retains kernel state between inputs; there is
no snapshot reset.

## Runtime behavior and diagnostics

The HINT contract is: #0x30 queries AFL status, #0x31 captures the fuzzing
thread, #0x32 reads the testcase into guest memory, and #0x33 marks the
persistent boundary. Calls from privileged guest code are ignored. An
inactive #0x32 returns `-1` without reading a host file; requests over 1 MiB
are rejected before allocation or input consumption.

At each boundary, the calling vCPU stops synchronously and the parent
verifies that all child threads stopped before publishing the map. If it
cannot verify the stop within one second, it aborts the forkserver with an
error instead of publishing a potentially changing map. Scope filtering
omits asynchronous IRQ, FIQ, and SError handlers while preserving the edge
predecessor; nested handlers resume coverage only after every matching
exception return, including nesting deeper than the history stack.

`AFL_DEBUG=1` prints the registered kernel text ranges.
`AFL_HARNESS_SCOPE_DEBUG=1` prints scope anchors, sampled PCs, map writes,
boundary counts, and thread-stop diagnostics. Both are optional.
`--wide-coverage` disables the pinned wrapper scope; `--no-tid-filter`
also disables the thread filter and requires `--wide-coverage`. These
broader modes can include scheduler and interrupt activity, so the narrow
scope's repeatability results do not establish their stability or broad
kernel coverage.

## Interactive root shell

Create a separate Bash ramdisk from the pinned fuzzer image, then boot it
with isolated scratch disks:

```bash
python3 scripts/inferno-afl/prepare_shell.py \
  --source "$INFERNO_LAB/ios_scfuzzer.img" \
  --output /tmp/ios-shell.img
python3 scripts/inferno-afl/boot_shell.py \
  --lab "$INFERNO_LAB" --data "$INFERNO_DATA" \
  --image /tmp/ios-shell.img
```

The preparation command verifies the stock hash and changes only the
contiguous launch plist, preserving its length. At `bash-5.0#`, run `id`,
`uname -a`, and `echo SHELL_OK`. Ctrl-A followed by `x` quits QEMU. This
ramdisk shell is a separate guest profile from the normal Hello/Setup GUI.
