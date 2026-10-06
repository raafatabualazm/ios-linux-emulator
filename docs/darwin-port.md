# Darwin-VM port into Inferno

## Direction and retained baselines

The modern integration uses Inferno as the QEMU base and adapts Darwin-VM's
modern CPU and boot code function by function. The reference wrapper is
`ffdf01874f5cc9cdfbfc7a3d117d4aef1e49b4d9`; its qemu-sptm submodule is
`2867d847d3471560e773120ee50c42dbcbb6d60b`. This is a local source integration,
separate from the prepared course runtime and the published Inferno worktrees.

The existing T8030 devices, legacy guarded CPU path and iOS 14 GUI work remain.
New CPU properties default to false. Only the experimental `apple-modern`
board enables the modern register, timer, guarded and SPRR profiles together.
Its default `prepare-only=true` populates memory and halts the CPU.

The tested SPRR extension is developed in the isolated `darwin-cpu-verified`
worktree. `Inferno/integration` retains the additional system-register, AMCC,
metadata, PTW and USB/runtime work. Reconciliation must preserve those edits;
the isolated checkpoint does not qualify the retained additional models.

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
| Modern SPRR permissions | Separate CONFIG/PPERM/UPERM banks, VHE aliases, raw leaf permission lookup and write-triggered TLB invalidation | 55,419 permission/regime and 536 register/alias component checks; six actual CPU/reset passes with normal/guarded permission faults |
| A64 guarded AT contexts | Modern and legacy guarded contexts select the requested translation regime | 57,344 recorded component checks and actual EL2/GL2 AT instructions; A32 callback remains unchanged |
| Modern CTRR/AMCC | Existing legacy implementation and additional integration carryover retained | Hardware lock behavior and modern enforcement remain unqualified |
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
behavior and complete migration remain unqualified.
Pointer authentication remains active; the instruction gate includes a real
matching-key PACIA/ERETAA return. Existing firmware executable bytes, trustcache
and unrelated ADT properties are retained.

The separate `apple-modern-sprr` property requires the modern register and
guarded profiles. Any nonzero CONFIG_EL1 or CONFIG_EL2 enables the Darwin
compatibility lookup. Its table selector uses raw leaf AP[7:6] and
UXN/PXN[54:53], before hierarchical permission folding. The requested stage-1
regime selects the EL1, EL2 or user bank, including the distinct guarded EL1
AT regime. Guest permission writes flush the CPU's TLB; descriptor translation,
ordinary faults and stage-2 checks remain in the existing walker.

UPERM is readable at EL0 but EL0 writes remain unsupported until their mask
controls are modeled. The execution gate exercises the user bank through AT
instructions from EL2/GL2; it does not execute an EL0 guest. Guarded EL0,
AArch32, hardware masks/locks and migration are outside the qualified SPRR
behavior. Register/alias component checks cover VHE, but the new SPRR ROM does
not qualify VHE guest execution.

## Reproducible checks

Run from this source checkout after building an AArch64 executable:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-timers.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-gxf.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-context.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-guarded-state.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-board-regions.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-sprr.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-sprr-registers.py
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 scripts/test-apple-modern-at.py
python3 scripts/test-apple-modern-timer-qemu.py --binary /path/to/qemu-system-aarch64
python3 scripts/test-apple-modern-guarded-qemu.py --binary /path/to/qemu-system-aarch64
python3 scripts/test-apple-modern-sprr-qemu.py \
  --binary /path/to/qemu-system-aarch64 --output-dir /private/new-sprr-report
python3 scripts/test-apple-modern-board-timer-qemu.py \
  --binary /path/to/qemu-system-aarch64 --components /private/derived-components \
  --output-dir /private/new-fiq-report
python3 scripts/test-apple-modern-machine.py \
  --binary /path/to/qemu-system-aarch64 --components /private/derived-components \
  --qmp-stdio --check-register-reset-pattern --output-dir /private/new-report
```

The component checks run ASan and UBSan. LeakSanitizer was disabled for the
recorded runs because their environment denied ptrace; leak checking is not
claimed. That observation describes the earlier environment.
The instruction gates execute owned synthetic ROMs. The machine preparation
gate stays stopped, compares complete boot metadata and payload samples, and
uses standard loader devices for owned register-window write/reset checks.
The optional stdio transport avoids sockets while preserving the existing
Unix QMP transport. Neither preparation nor a clean emulator exit establishes
an iOS boot.

The first October 6 CPU/preparation candidate is pinned privately with SHA-256
`8bc7e5abcb091d05a20747e22e72b1bb124d12bf5f7e1d57820d3963435e9437`.
Ten actual timer/guarded/FIQ execution runs pass on that pin across reset.
Six additional SPRR execution passes used the CPU gate candidate with SHA-256
`768d7d61daac4d7f5f60c23a760c68a2b6cdfd95b616cafe4336cda205ecd3df`:
default omitted, explicitly disabled and enabled, each before and after reset.
Each enabled pass checks 35 actual read/write/execute accesses, 30 AT operations,
21 expected level-3 permission faults and ten authenticated guarded returns.
Live permission writes revoke and restore cached accesses without guest TLBI.

The final board candidate, `qemu-system-aarch64-darwin-sprr-v1`, has SHA-256
`27f30b9bbd74be317190929b46fecab37f9fbbc94ab57c3b7654528f7f78e08a`.
The subsequent change enables SPRR on `apple-modern` and checks its actual QOM
property. Its stopped preparation/reset gate passes the retained metadata
oracle and all 86,048 CPU-window bytes, including nonzero write/reset patterns.
Keep this board result distinct from the six runs on the preceding CPU pin.

Private evidence lives under `modern-emulator/evidence/features-20261006/`:
`darwin-timer-final-pin`, `darwin-guarded-owned-rom-v3`,
`independent-timer-window-review`, and
`independent-board-register-reset-pattern-v2`, `darwin-board-fiq-v2` and
`darwin-sptm-entry-v1`, `darwin-sprr-owned-rom-v1`,
`independent-sprr-review`, `sprr-board-preparation-final` and
`darwin-sptm-sprr-v1`. Firmware, tickets, IPAs,
complete guest stores and raw logs remain outside versioned source.

## Next integration gates

The earlier 51.02 ms matched SPTM observation passed AGTCNTVOFF_EL2 and stopped
at SPRR_CONFIG_EL1, physical PC `0x100070a3520`. The final SPRR board candidate
passes both former blockers and next encounters unsupported **APSTS_EL1**:
`MRS S3_6_C15_C12_4,X0`, physical PC `0x100070a35d8`, source offset `0x9f5d8`.
The 52.213 ms observation stopped cleanly, exited 0 and reaped its child;
executable and all five component hashes remained unchanged. XNU and modern
iOS userspace have not booted.

1. Reconcile the qualified SPRR port with preserved integration carryover,
   retaining the existing A13 path and earlier source/runtime work.
2. Model the required APSTS/control behavior from the pinned reference and
   measured semantics, then reobserve unchanged SPTM at a bounded gate.
3. Port required CPU and device behavior with targeted regression
   checks, preserving the legacy branch and current boot metadata.
4. Obtain and prepare matching full userspace, implement modern persistent
   storage/display/input, then verify SpringBoard and the IPA app journey.

The retained local iOS 14 result already demonstrates Home → Settings → Home
→ Notes → Home. Modern SpringBoard and uploaded IPA execution remain open.
