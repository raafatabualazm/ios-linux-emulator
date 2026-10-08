# Sparse AMCC performance channels

`modern-mcc-perf=on` enables an experimental T8140 AMCC register subset.
It defaults off and leaves earlier board configurations unchanged. The plan
requires the matched stock `mcc,t8140` schema, one AMCC, four DCS instances,
AMCC reg[2] and exactly one translation to physical base `0x220000000`.
It checks DRAM, device exclusions, aliasing and malformed ranges before mapping.
Every board exclusion append is bounded; the shared capacity is now 64 entries.

## Register ownership

Six independent sparse views are mapped. The gaps remain unmapped.

| Bank | Control, eight bytes | Eight counters, 64 bytes |
| --- | --- | --- |
| 0 | `0x220028000` | `0x220029000..0x22002903f` |
| 1 | `0x220068000` | `0x220069000..0x22006903f` |
| 2 | `0x2200a8000` | `0x2200a9000..0x2200a903f` |

Each counter is read only, at eight-byte stride. Controls retain all 64 bits.
Only aligned eight-byte accesses are accepted. Unsupported widths, counter
stores and unmapped neighbors raise actual CPU external aborts. Migration is
explicitly rejected until the state and connected providers have a qualified
migration contract.

## Declared virtual behavior

`mcc-perf-reset` sets the initial uint64 value of all 24 counters. Its default
is zero, a declared virtual profile; hardware reset contents are unmeasured.
Controls reset to zero. Reads do not increment counters. Disabling an event
does not clear its stored count.

The event API accepts a bank, counter and uint64 amount. A selected channel
increments only when its low-eight control bit is enabled. Addition wraps
modulo 64 bits. Enable gating follows the driver mask consumers; arithmetic
width and overflow are virtual choices, with no silicon equivalence claim.
Other control bits retain their values and have no implemented side effects.

**No CPU, cache or bus event producer is connected.** Guest samples therefore
remain at the declared initial values. Host elapsed time and MMIO activity do
not generate physical-traffic estimates. Integrating actual event producers
requires established channel semantics and separate qualification.

The model implements the observed AMCC access subset. Silicon counter
writability and clear behavior remain unestablished. SOCNI, DCS and DSID
performance families are outside this module, as are memory timing, cache
allocation, protection, interrupts and device readiness.

## Evidence for the subset

The retained iOS 27 BootKC has SHA-256
`a36b924108b63eefd7cc8fa9e54acc3a07544786d3edb316fbcf3b9fb7426b35`.
The live `readPerfValue` descriptors contain 24 AMCC entries across three
banks, masks `1 << counter`, control offsets `0x28000 + bank * 0x40000`, and
count offsets `control + 0x1000 + counter * 8`. The failing AFI AF RD read
targets physical `0x220069000`.

Linked initializer `0xfffffff009825ee4` constructs the descriptor addresses
without clearing MMIO counters. Sampling dispatches to a plain `LDR X` at
`0xfffffff009822fb4`. The control consumer at `0xfffffff009825f54` passes a
64-bit mask to `0xfffffff0098233b4`, which reads the old word and writes
`(old & ~mask) | (value & mask)` through `STR X` at
`0xfffffff009823364`. Descriptor field `+0x60` scales accounting; it is not an
access width. These observations establish geometry and access operations.

Private evidence is retained under
`modern-emulator/evidence/features-20261008/mcc-provider-review/`, including
the read-only live descriptor capture and bounded control disassemblies.
No firmware payloads, keys or tickets belong in this document or public source.

## Qualification

`scripts/test-apple-modern-mcc-perf.py` checks virtual event gating,
independence, full-width data, overflow, reset, diagnostics and strict layout
under ASan/UBSan and NDEBUG. `test-apple-modern-mcc-perf-qemu.py` executes an
owned EL2 ROM in preparation mode; it checks full-width counter sampling,
actual control RMW, exact exception PCs/ESRs, reset, read-only diagnostics,
creation-only board properties and migration rejection. The disabled-model
oracle must stop on the first real counter load before querying diagnostics.

Read-only QOM diagnostics are available at `/machine/mcc-perf`:
`mmio-read-count`, `mmio-write-count` and `event-update-count`. They count
accepted operations or enabled nonzero event updates, saturate at UINT64_MAX,
and clear on reset.

This qualification does not establish SpringBoard, SEP execution, a restored
system disk or memory-controller fidelity.
