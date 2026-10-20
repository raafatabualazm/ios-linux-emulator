# SMP RE Report — t8140 / XNU 27.0.0 (24A437) / apple-modern

Grok Bot, 2026-10-20 (Africa/Cairo UTC+3). angr 10.0.4 + unicorn 2.1.4 + capstone on box.
Kernel: `kernelcache.research.iphone17.bin` sha256 `e29fab902c8ca38f0a78e87511648099b2b4207d8d4a81665b54cb17893a68db`
(`Darwin Kernel Version 27.0.0 … root:xnu-13432.2.10~2/RELEASE_ARM64_T8140`).

## 1. How XNU starts a secondary CPU (verified)

**Not** RVBAR / `cpu-impl-reg` poke, **not** an SPTM GENTER from the kernel start path.
It is a **PMGR MISC_CORES** MMIO write reached through IOKit:

```
cpu_start (BootKC VA 0xfffffff00ad3c2b0)
  → gPMGR vtable[0x540] IOPMGR::enableCPUCore(cpu_index, 0)   // x2 entry addr = 0
  → AbstractPMGR::enableCPUCore  mask = 1 << ADT_cpu_id
  → enableCPUCores               0xfffffff0092ad130
  → ApplePMGR::configMiscCores   0xfffffff0092aca0c  (vtable +0x9e0)
  → leaf store                   0xfffffff0092af9e0 → str at 0xfffffff0092afabc
       str w23, [x8, w20, uxtw]   // w23=mask, w20=offset into RegMap window
```

AppleT8140PMGR binds **MISC_CORES = RegMap 0x69 @ +0x4000**, RegMap 0x69 → `/arm-io/pmgr` `reg[0x18]`.
On the served d47ap tree that is physical **`0x300734000`**.

| offset | meaning |
|--------|---------|
| +0 | disable bitmask (bit N = ADT cpu-id N) |
| +4 | **enable** bitmask |
| +8+4n | per-cluster |

**No read-back / status poll** on RegMap 0x69 (completion poll only accepts RegMap 0 and 0x64). Fire-and-forget.

Secondary reset PC (SPTM): **`sptm_entry_physical − 0x388`** (= `sptm_base + 0x9C000`), not the LC_UNIXTHREAD entry. Kernel hands PMGR no entry address; SPTM already set the bare reset vector.

### Unicorn confirmation (`smp/unicorn_misc_cores.py`)
Emulated the two instructions at `0xfffffff0092afab8` with a fake RegMap descriptor:
- bytes `080c40f9174934b8` = `ldr x8,[x0,#0x18]; str w23,[x8,w20,uxtw]`
- With w20=4, w23=0x2 (cpu-id 1): **WRITE @ MMIO+4 size=4 value=0x2** ✓

## 2. Fast IPI (verified)

`sleh_fiq` @ `0xfffffff00ad42cf4`:

```
ldr w8, [gFastIPI]          ; must be 1
mrs x20, S3_5_C15_C1_1      ; IPI_SR_EL1
tbz w20, #0, …              ; bit0 = IPI pending
msr S3_5_C15_C1_1, #1       ; ACK bit0, WRITE-1-TO-CLEAR, before handler
isb
bl  cpu_signal_handler_internal
…
tst x20, #2                 ; bit1 independent source
msr S3_5_C15_C1_1, #2       ; W1C bit1 with value 2 @ 0xfffffff00ad42dd0
```

Delivery is **FIQ**, independent of AIC. AIC affinity rewrite is unused by XNU 27 on AIC2/AIC3 (`no-aic-ipi-required` on all six cores).

### Unicorn confirmation (`smp/unicorn_fast_ipi.py`)
With IPI_SR seeded to `0x3`, after the bit0 ack path: **IPI_SR → 0x2** (bit0 cleared, bit1 untouched) ✓

## 3. ADT / MPIDR mapping

| ADT `reg` (MPIDR-packed) | cluster | role |
|--------------------------|---------|------|
| 0,1,2,3 | E (0) | ECPU_0..3 |
| 0x100, 0x101 | P (1) | PCPU_0..1 |

PMGR core-mask bit N uses **ADT cpu-id** (= vCPU index N). Fast-IPI targeting uses **ADT `reg`**.
Boot CPU = node with `state="running"`. `cpu-id` property is **not** read by the kernel topology code.

## 4. A13 precedent vs t8140

| | Inferno A13 (`a13.c` / `t8030.c`) | t8140 (this RE + Claude `claude/apple-modern-smp`) |
|--|--|--|
| Core start | RVBAR + park secondaries | **MISC_CORES PMGR write**; SPTM owns reset PC |
| IPI | `ipi_sr`, `apple_a13_deliver_ipi`, deferred IPI timer, cluster deliver | Same **sysreg** shape (`S3_5_C15_C1_1` W1C); FIQ OR-gate needed |
| AIC | AICv1/v2 with IPI regs | AIC2/AIC3 — **off critical path** for SMP |
| max_cpus | `A13_MAX_CPU 6` (+SEP) | 6 application cores |

Port the A13 **IPI + cluster FIQ OR** pattern; do **not** port A13 RVBAR start.

## 5. Claude branch status (mirrored)

Branch `claude/apple-modern-smp` @ `1172066` already contains:
- `da0e9ac` — `-smp N`, mp-affinity from ADT `reg`, start-powered-off, fast-IPI device, `modern_cpu_release()`
- `e4464c0` — all-cpu-register-windows (cpu-impl-reg / cpm-impl-reg)
- `d8849f0` — **MISC_CORES served** at ADT-derived `0x300734000`, enable → `modern_cpu_release`
- `1c15c5a` — mcc compat group (ladder toward `ApplePMGR: Started`)

**Real blocker for guest asking for cpu1:** `ApplePMGR: Started` never logged (0/110+ `Starting`). Ladder: pmgr compat → mcc wait → cpm window → voltage-states → MISC_CORES. MISC_CORES alone is not enough until IOPMGR is published.

## 6. Patch plan for `modern-machine.c` (box branch `grok/smp-re`)

Branch created as `grok/smp-re` ← `claude/apple-modern-smp` (already has the implementation). This RE **confirms** that code; no divergent patch required for MISC_CORES / fast-IPI ack semantics.

Remaining work (not done here — needs guest PMGR Started):
1. Finish PMP / PTD so `ApplePMGR: Started` fires (rung after mcc).
2. Boot `-smp 2 -accel tcg,thread=multi` with `pmgr`+`mcc`+`all-cpu-register-windows`+MISC_CORES on; confirm `CPU 1/TCG` host time > 0.
3. Unit tests already in tree: `scripts/test-apple-modern-pmgr-misc-cores.c` (resolver → `0x300734000`).

Scripts in this folder: `unicorn_misc_cores.py`, `unicorn_fast_ipi.py`, disasm dumps in `dis1.txt`.

## 7. Hashes

| artifact | sha256 |
|----------|--------|
| kc.bin | e29fab902c8ca38f0a78e87511648099b2b4207d8d4a81665b54cb17893a68db |
| Claude smp HEAD | 11720669506421e5ac476ece7a02d7c9d933fab5 |
| Inferno master snapshot | 3e3ff1977c50986c9e2c81334d52e83ffeee56b3 |
