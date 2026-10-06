# Darwin-VM port into Inferno

## Direction and retained baselines

The modern integration uses Inferno as the QEMU base and adapts Darwin-VM's
modern CPU and boot code function by function. The reference wrapper is
`ffdf01874f5cc9cdfbfc7a3d117d4aef1e49b4d9`; its qemu-sptm submodule is
`2867d847d3471560e773120ee50c42dbcbb6d60b`. This is a local source integration,
separate from the prepared course runtime and the published Inferno worktrees.

The existing T8030 devices, legacy guarded CPU path and iOS 14 GUI work remain.
New CPU properties default to false. Only the experimental `apple-modern`
board enables the modern register, timer and guarded profiles together.
Its default `prepare-only=true` populates memory and halts the CPU.

## Port inventory — October 6, 2026

| Feature | Inferno integration | Evidence or remaining work |
| --- | --- | --- |
| SPTM/TXM/BootKC loading | Strict modern layout and metadata modules; EL2 entry and x0 bootargs | Whole-machine RAM/reset oracle; modern OS boot still unqualified |
| ADT, trustcache, optional restore ramdisk | Stock inputs, bounded copies and metadata construction | Preserves 452 nodes and 5414 unrelated properties; full ramdisk copy checked across reset |
| Modern guarded registers/VHE | Independent GL1/GL2 banks and CPU-owned alias snapshots | Production ownership/alias tests and actual CPU instructions |
| Apple timer views | Eight views use generic timer callbacks; independent VOFF/KCTL/RDIR stores and RDIR_EL12 alias | 102 component checks and four actual CPU/reset runs |
| GENTER/GEXIT and guarded exceptions | Separate CURRENTG and SP/exception banks; normal ERET and authenticated ERETAA retain their target | Production state checks and four actual CPU/reset runs |
| Guarded translation contexts | Separate existing guarded TB/TLB indexes; shared architectural TTBR/TCR invalidation covers both contexts | 128 production callback/mask checks, including rejected old-mask oracle |
| CPU implementation register windows | Two bounded, nonoverlapping stock ADT windows mapped as register RAM | 28 component checks; all 86,048 bytes read before/after reset and after nonzero test writes |
| Hypervisor virtual timer interrupt | Existing generic timer output wired directly to CPU FIQ, as in Darwin | Two actual board/reset runs: masking, ordinary EL2 and GL2 FIQ, ERET and GEXIT |
| Modern SPRR/CTRR/AMCC permissions | Existing legacy implementation retained | Modern enforcement and locking are not implemented by this port |
| Modern AIC and SEP | Darwin reference inventory retained | Reference models are partial; ordinary interrupt/service behavior needs implementation |
| Modern storage, DART, display and touch | Existing Inferno models retained | Target generation adapters, complete userspace and end-to-end GUI remain required |

Darwin's simplified timer model is explicit: AGTCNTVOFF does not change
architectural CNTVOFF, and Apple KCTL/RDIR stores do not implement their
hardware control effects. Counter units and access checks remain those of the
generic timers. CPU register windows are ordinary zeroed RAM; they do not
implement hardware locks or side effects. These are compatibility ports,
with no claim of Apple hardware equivalence.

The modern guarded profile currently supports AArch64 EL1/EL2 entry and
same-EL GEXIT. Guarded EL0/AArch32 returns are rejected. Cross-EL guarded
behavior, complete migration and modern protection remain unqualified.
Pointer authentication remains active; the instruction gate includes a real
matching-key PACIA/ERETAA return. Existing firmware executable bytes, trustcache
and unrelated ADT properties are retained.

## Reproducible checks

Run from this source checkout after building an AArch64 executable:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-timers.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-gxf.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-context.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-guarded-state.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-board-regions.py
python3 scripts/test-apple-modern-timer-qemu.py --binary /path/to/qemu-system-aarch64
python3 scripts/test-apple-modern-guarded-qemu.py --binary /path/to/qemu-system-aarch64
python3 scripts/test-apple-modern-board-timer-qemu.py \
  --binary /path/to/qemu-system-aarch64 --components /private/derived-components \
  --output-dir /private/new-fiq-report
python3 scripts/test-apple-modern-machine.py \
  --binary /path/to/qemu-system-aarch64 --components /private/derived-components \
  --qmp-stdio --check-register-reset-pattern --output-dir /private/new-report
```

The component checks run ASan and UBSan. LeakSanitizer is disabled because the
current sandbox prevents its ptrace operation; leak checking is not claimed.
The instruction gates execute owned synthetic ROMs. The machine preparation
gate stays stopped, compares complete boot metadata and payload samples, and
uses standard loader devices for owned register-window write/reset checks.
The optional stdio transport avoids sockets while preserving the existing
Unix QMP transport. Neither preparation nor a clean emulator exit establishes
an iOS boot.

The October 6 CPU/preparation candidate is pinned privately with SHA-256
`8bc7e5abcb091d05a20747e22e72b1bb124d12bf5f7e1d57820d3963435e9437`.
Private evidence lives under `modern-emulator/evidence/features-20261006/`:
`darwin-timer-final-pin`, `darwin-guarded-owned-rom-v3`,
`independent-timer-window-review`, and
`independent-board-register-reset-pattern-v2`, `darwin-board-fiq-v2` and
`darwin-sptm-entry-v1`. Firmware, tickets, IPAs,
complete guest stores and raw logs remain outside versioned source.

## Next integration gates

The unchanged matched SPTM observation on this candidate passed the earlier
AGTCNTVOFF_EL2 failure and stopped at `SPRR_CONFIG_EL1`
(`MSR S3_6_C15_C1_0,X0`) at physical PC `0x100070a3520`. The 51.02 ms
observation stopped and reaped cleanly with unchanged input hashes. It did
not reach XNU. Darwin's page walker consumes this register and separate
user/privileged permission tables; acknowledging its writes without the
permission checks would be an incomplete port.

1. Port modern SPRR state, bank selection and permission checks together,
   preserving the existing A13 path and validating normal translation behavior.
2. Reobserve unchanged SPTM after that gate and compare the next required
   interface with the pinned Darwin source.
3. Port required CPU and device behavior with targeted regression
   checks, preserving the legacy branch and current boot metadata.
4. Obtain and prepare matching full userspace, implement modern persistent
   storage/display/input, then verify SpringBoard and the IPA app journey.

The retained local iOS 14 result already demonstrates Home → Settings → Home
→ Notes → Home. Modern SpringBoard and uploaded IPA execution remain open.
