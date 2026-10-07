# Modern SEP DART provider

The `apple-modern` machine has an opt-in `sep-dart` provider. It models normal
T8110 DART register and DMA behavior independently of the SEP processor and its
firmware. The property defaults to **off**. Existing `apple-dart` and legacy
boards are unchanged.

With `sep-dart=on`, the modern board gives `sep-sim` the IOVA address space of
`mapper-sep`. This replaces that optional simulator's earlier physical address
simplification. Disabled streams, invalid page tables and denied permissions
reject DMA. The model does not implement SEP firmware, keys, attestation,
cryptographic services or SpringBoard.

## Geometry and mapper relationships

The retained d47ap stock tree describes:

| Node/property | Value |
| --- | --- |
| `/arm-io/dart-sep/compatible` | `dart,t8110` |
| DART translated MMIO base/span | `0x280b80000` / `0x20000` |
| DART fault interrupt | AIC input 353 |
| DART page size | `0x4000` (16 KiB) |
| DART `sid-count` | 3 |
| `/arm-io/sep/iommu-parent` | two u32 phandles: `0x68`, `0x69` |
| `mapper-sep` / `mapper-sep-mpm` | phandle `0x68` / `0x69`, `reg` 0 / 1 |

`iommu-parent` contains phandles, not stream numbers. The board resolves the two
named mapper nubs and validates their stream numbers against `sid-count`. The
simulator uses stream 0; stream 1 has a separate address space but its MPM
protocol role is not implemented.

The board preserves the supplied tree's properties. A supplied tree must retain
`iommu-parent`; a variant that removed it is rejected when `sep-dart` is enabled.
Guest driver matching also needs the DART and mapper `compatible` properties.
Darwin's standard fixup prunes them, so the observed `dtree-sep-dart` is a declared
variant generated from stock, with its own provenance record. Restoring only a
compatible string does not prove the driver will start.

The board declares a **42-bit VA, 42-bit PA, revision 2** device profile. Its VA
aperture covers the tree's IOVA reservation beginning at 1 TiB. These capability
register values and the client count are emulation choices; they have not been
measured on T8140 hardware. Stream alias readback and zero reset values are also
declared choices.

## Register and descriptor behavior

The normal register ABI is based on the
[Linux DART driver](https://github.com/torvalds/linux/blob/master/drivers/iommu/apple-dart.c):

| Function | Offset |
| --- | --- |
| Capabilities | `0x0`, `0x4`, `0x8`, `0xc` |
| Synchronous all/SID TLB flush command | `0x80` |
| Sticky fault status / interrupt mask | `0x100` / `0x104` |
| Fault address low/high | `0x170` / `0x174` |
| Per-stream fault bitmap | `0x1c0` |
| Protect / unprotect / protection lock | `0x200` / `0x204` / `0x208` |
| Stream enable / disable aliases | `0xc00` / `0xc20` |
| Stream TCR / one TTBR per stream | `0x1000` / `0x1400` |

TCR translation, explicit physical bypass, remapping and optional four-level mode
are modeled. TCR zero disables DMA. Fault status and stream bitmaps accept W1C;
the first fault retains its address until cleared. The interrupt mask suppresses
delivery while retaining fault state. Protection can be locked until reset.
Reset clears streams, translation tables, fault state, counters and IRQ, and
notifies IOMMU clients to discard prior mappings.

The scoped remap selects a target TTBR while retaining the original stream's
gates. The register fields are documented by the references; interaction with a
target stream's own TCR/gates remains unverified hardware behavior.

The
[Linux page-table implementation](https://github.com/torvalds/linux/blob/master/drivers/iommu/io-pgtable-dart.c)
and [m1n1 T8110 model](https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/m1n1/hw/dart8110.py)
describe compressed physical addresses and read/write permissions. This model
uses 16 KiB pages and two or three PTE reads, with indices at bits 25/14 or
36/25/14. Subpage restrictions narrow the returned IOMMU granule to four bytes.
Invalid PTE reads and permissions produce normal modeled faults. QEMU's
`IOMMU_NONE` query returns translation permissions without producing a DMA
transaction fault.

There is no internal PTE cache. Flush commands emit normal QEMU IOMMU invalidation
notifications. DAPF, TZ tagging, diagnostic/performance registers and extended
commands are unimplemented. Unknown aligned registers return zero, writes are
ignored, and both are counted. The device is explicitly **unmigratable**.

The lifetime MMIO/IOMMU regions are initialized once. Realize creates separately
allocated stream address spaces; unrealize detaches them before unmapping and
disabling MMIO in one memory transaction. This order matters: QEMU's address-space
detachment alone does not request a topology-cache rebuild, so an earlier version
left cached FlatViews holding the device's owner references. Deferred RCU cleanup
uses the separate address-space allocations, and the same device object can be
realized again. The caller must quiesce DMA before unrealizing it.

## Build, observation and gates

Build in the isolated worktree using its existing configuration:

```sh
ninja -C build qemu-system-aarch64
```

Add `sep-dart=on` to a prepared `apple-modern` machine with `modern-aic=on`; add
`sep-sim=on` if testing that optional provider. To inspect the guest's DART
register requests, use:

```text
-global apple-dart-t8110.trace=on -d unimp
```

Trace output is capped at 256 lines per reset. Read-only QOM counters on
`/machine/dart-sep` include `mmio-reads`, `mmio-writes`, `unknown-reads`,
`unknown-writes`, `translations`, `faults`, and `flushes`. Trace payloads contain
register values and addresses, not SEP message contents.

Run the production-core gate from the isolated checkout:

```sh
python3 scripts/test-apple-dart-t8110.py
```

The v3 core gate runs 1,234 checks under ASan/UBSan and production `NDEBUG`, with two
owned DMA/fault/reset passes in each mode. It verifies high IOVAs, page crossing,
table-level faults, denied writes with unchanged RAM, read denial, fault masks
and clearing, explicit bypass, lower-address walks, remapping, protection,
flush requests and permission-query semantics, that the first fault (address,
direction, code) is retained until cleared while later faults are only counted,
that a four-level walk reports an IOVA at or above 2^va_bits as an address fault,
and that a reset clears a pending fault, its address, stream bits and the mask.
A mutation study (15 of 16 hand-made defects are detected) leaves one mutant
alive on purpose: ignoring ERROR_FLAG in the interrupt mask would pin a choice
that is declared, not documented. LeakSanitizer is disabled because
the workspace monitor uses ptrace; this fixture allocates no heap.

**That gate exercises the production core through an owned-RAM adapter.** It
does not exercise QEMU's AddressSpace implementation, actual IOMMU notifier
delivery or device lifecycle. Those require the separate QEMU integration
fixture and are recorded separately. Likewise, a guest driver binding or a
mailbox interrupt pass does not establish that SEP DMA or sepOS is working.

The v3 actual-QEMU fixture passed **210 checks**, including real
`dma_memory_read`/`dma_memory_write`, permission queries, fault registers and IRQ,
reset, same-object re-realize, and finalization of both mapped and never-mapped
devices. It observed 11 faults, 28 translations and seven IRQ rises/falls. It
links the existing emulator objects with an owned-data test main; neither guest
code nor Apple firmware executes. The retained v2 fixture failed owner release;
its evidence is superseded by the v3 result rather than overwritten.

Exact wrapper gate command, run from the workspace root with a fresh output
directory:

```sh
python3 Inferno/wt/sep-sim/scripts/test-apple-dart-t8110-qemu-dma.py \
  --build-dir Inferno/wt/sep-sim/build \
  --binary modern-emulator/bin/qemu-system-aarch64-sep-transport-v3 \
  --output-dir modern-emulator/evidence/features-20261007/sep-transport/dma-qemu-repeat
```

The current build executable must match the supplied immutable pin. The script
records fixture snapshots and linker-input hashes and refuses to overwrite
evidence. This fixture qualifies the normal QEMU DMA wrapper; an iOS firmware
run must independently show the guest driving that provider.

## Transport behavioral negative oracle

The owned-ROM transport gate also has a behavioral mutation qualification:

```sh
python3 Inferno/wt/sep-sim/scripts/test-apple-modern-sep-transport-mutation.py \
  --build-dir Inferno/wt/sep-sim/build \
  --binary modern-emulator/bin/qemu-system-aarch64-sep-transport-v3 \
  --components modern-emulator/evidence/firmware-20261002/boot-components/derived \
  --output-dir /new/private/evidence/directory
```

It compiles a private copy of `sep-sim.c` changing only the harmless PING ACK
data word from zero to one, then links the exact existing QEMU objects with that
one object replaced. Production source, linker inputs and the immutable binary
are checked unchanged. The unmodified pin must pass twice across reset; the
mutant must fail on `ping_message` readback while all fourteen diagnostic
properties remain present and read-only. A missing instrument or timeout cannot
satisfy this oracle. The first run retained 1,296 unchanged linker inputs and
rejected the expected PING mismatch. Only owned code and basic mailbox messages
execute; no firmware validation, key service or cryptographic request is sent.

This closes the specific missing behavioral-negative finding for PING reply
data. It does not establish completeness of the protocol or SEP boot.
