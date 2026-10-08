# Sparse SOCNI performance channels

`modern-mcc-socni=on` enables an experimental T8140 SOCNI register subset.
It defaults off. The plan requires stock `mcc,t8140`, 12 register tuples,
`socni-reg-idx=3`, `socni-count=3`, and matched reg[3..5] spans of `0x8000`.
Each bank must have exactly one bus translation to its expected physical base.
All ranges, DRAM and device exclusions are validated before sparse mapping.

## Register ownership

| Bank | Base | Channels | Control span | Counter span |
| --- | --- | --- | --- | --- |
| 0 | `0x24f008000` | 31 | base through base+`0x7b` | base+`0x4000` through base+`0x40f7` |
| 1 | `0x250008000` | 36 | base through base+`0x8f` | base+`0x4000` through base+`0x411f` |
| 2 | `0x251008000` | 35 | base through base+`0x8b` | base+`0x4000` through base+`0x4117` |

Each channel has an independent uint32 control at base+index*4 and a read-only
uint64 counter at base+`0x4000`+index*8. The callbacks accept aligned four-byte
control transactions and eight-byte counter loads. Counter stores and other
callback widths are rejected. The gaps and neighboring registers remain unmapped.
Silicon counter writability and clear behavior are not established by this
observed access subset. Migration is explicitly rejected.

The width rules apply to callback transactions. QEMU's sparse subpage path
divides an aligned 64-bit CPU control load into two 32-bit transactions before
leaf validation. The owned CPU gate qualifies the combined low/high result
and counts both reads; it does not claim rejection of that load. This follows
`system/physmem.c`'s `subpage_accepts`, `subpage_read`, `flatview_access_valid`
and `memory_access_size`. A leaf accepts callback alone sees the narrowed
transactions, rather than the original instruction width. Other aggregate
CPU accesses and silicon wide-control behavior remain unqualified.

In the owned EL2 profile, misaligned loads raise an architectural Device-memory
alignment fault, ESR `0x96000021`, before MMIO. Counter half-width and unmapped
loads produce decode external abort `0x96000010`; mapped counter-store
rejections produce external abort `0x96000250`. Precise PCs and syndromes are
checked separately.

## Declared virtual behavior

`mcc-socni-reset` supplies the initial uint64 snapshot of all 102 counters.
Its default is zero; physical reset values are unmeasured. Controls and
diagnostic counts reset to zero. Controls retain all 32 bits, and guest reads
neither update nor clear counters.

The event API selects one established bank/channel. A nonzero event amount
updates its counter only when that channel's low two control bits equal 3.
Addition wraps modulo 64 bits. Enable gating follows the driver's enabled
value 3 and disabled value 0; event semantics, overflow width and partial
enable states remain a declared virtual profile. Other control bits retain
their values without implemented side effects.

**No CPU, cache or bus event producer is connected.** Guest samples retain
their initial values. Host elapsed time and MMIO accesses do not generate
traffic estimates. Connecting a producer requires established channel meaning
and separate qualification. DCS, AMCC and DSID performance families have
separate ownership; this subset supplies no cache readiness, memory timing,
protection, interrupts or full MCC publication.

## Evidence

The retained BootKC SHA-256 is
`a36b924108b63eefd7cc8fa9e54acc3a07544786d3edb316fbcf3b9fb7426b35`.
The live descriptor capture contains 102 SOCNI entries with contiguous indices
0..30, 0..35 and 0..34 for banks 0, 1 and 2. Descriptor `+0x14` selects the
bank, `+0x20` contains index*4, `+0x28` contains control value 3 and `+0x5c`
contains `0x4000`+index*8. These belong to subtype 1, independent of AMCC's
bit-mask controls.

Linked initializer `0xfffffff009825fa8` constructs that geometry. Control
consumer `0xfffffff009825ff4` writes 3 or 0 using a plain 32-bit store helper.
The common `readPerfValue` consumer selects SOCNI mapping descriptors from
object+`0x568` and samples through `LDR X` at `0xfffffff009822fb4`.
The preceding measured fault was the first bank counter at `0x24f00c000`.
Descriptor `+0x60` is an accounting scale, not an access width.

Private metadata and bounded driver references are retained in
`modern-emulator/evidence/features-20261008/mcc-provider-review/`.
No firmware payloads, keys or tickets belong in public source or this document.

## Qualification

`scripts/test-apple-modern-mcc-socni.py` compiles the standalone C gate in
ASan/UBSan and NDEBUG modes. It checks all 102 channels, full-width values,
independence, virtual enable states, modulo addition, saturating diagnostics,
invalid accesses, reset and strict layout validation on copied metadata.

`scripts/test-apple-modern-mcc-socni-qemu.py` executes an owned EL2 ROM in
preparation mode. It checks all counters and controls, exact exception PCs and
ESRs, two reset passes, read-only diagnostics, creation-only board properties
and migration rejection. Its default-off oracle omits the enable property and
requires the first real counter load to fault before device diagnostics.

Read-only diagnostics at `/machine/mcc-socni` are `mmio-read-count`,
`mmio-write-count` and `event-update-count`. They count accepted operations
and enabled nonzero event updates, saturate at UINT64_MAX and clear on reset.

Qualification results must be read from retained reports. The gate and model
do not establish SpringBoard, SEP execution, restored storage or SOC fidelity.
