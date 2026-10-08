# Sparse T8140 DSID quota storage

Default-off `modern-mcc-quota=on` supplies ordinary 32-bit storage for 32 DSID
groups in four AMCC planes. The common declared virtual reset word is selected
by `mcc-quota-reset=VALUE` (default zero). Physical initial contents are unknown.
This profile does not claim a measured silicon reset or cache allocation.

The matched stock reg[2] base is 0x220000000. Plane quota cells occupy
`base + plane*0x40000 + 0xa000 + group*4`, plane 0..3, group 0..31. Each cell
supports aligned 32-bit reads and writes. Plane writes change only that cell.
The mapped global **write** view at `base + 0x100000 + 0xa000 + group*4`
propagates its complete word to the same group in all four planes. Broadcast
propagation is a declared virtual inference from paired driver setters and
getters, not independently measured T8140 hardware behavior. All 32 bits are
retained; the normal quota consumer interprets the low six bits.

Global reads remain unqualified and raise an external abort. Group 32, the
preceding word and other AMCC addresses remain unmapped. No cache-ready flag,
cache timing, IRQ, usage counter or memory-protection range is synthesized.
Reset restores all 128 words to the selected virtual profile and clears
diagnostics. Migration is explicitly rejected. Machine properties are immutable
after initialization. Read-only `/machine/mcc-quota` diagnostics are
`mmio-read-count`, `mmio-write-count`, and `broadcast-write-count`.

## Evidence and boundary

The unchanged matched iOS 27 BootKC (`a36b9241...`) faults at physical
0x22000a02c, group 11, after four measured DCS configuration-word read returns.
Its plain load is linked 0xfffffff009822e98, called from quota getter
0xfffffff009823544; the consumer at 0xfffffff0098235d8 uses only six quota bits
to calculate a byte count. A normal setter at 0xfffffff009824050 rejects group
indices >=32. Stock initial policy also stops at 31 and skips its 65535
sentinel. Although the getter alone permissively accepts 32, the setter and
initial policy establish the supported sparse boundary of 0..31.

Setter callback 0xfffffff009824274 dispatches to accessor 0xfffffff0098231c4,
which adds 0x100000 and reaches plain 32-bit store 0xfffffff009823140. The
paired getter selects an active plane and uses its 0x40000 stride. A generic
global read accessor exists; actual quota global read behavior is unproven,
so this limited model rejects it.

[m1n1 draft PR #664](https://github.com/AsahiLinux/m1n1/pull/664), retained at
commit `4aef00368a1a7b27be36385f00bb37005b5fee6b`, confirms four planes,
0x40000 plane stride and the separate 0x100000 global view. It does not define
quota reset content. Cache enable/status +0x2800/+0x2804 and protection
+0xaf0/+0xb00/+0xb20 remain outside this implementation. Its twelve cache
ways are not used to guess quota values.

Mapping requires exact `mcc,t8140`, twelve register tuples, AMCC index 2,
one AMCC and four DCS channels per AMCC. The complete reg[2] aperture must
have the matched 0x140000 extent and an unambiguous physical translation.
All five sparse 128-byte views must be disjoint from DRAM and mapped devices.
The default preserves an unmapped quota aperture.

Local evidence is retained under
`modern-emulator/evidence/features-20261008/{mcc-next-register-review,mcc-quota}/`.
The normal guest probe keeps `function-mcc_ctrl`, stock voltage metadata,
`dramcfg-data` and SEP/DART dependencies. Register qualification executes only
an owned AArch64 ROM; it establishes no new iOS, PMGR readiness or SEP service
result. Those require a separate normal guest probe and additional devices.

## Qualification

- `scripts/test-apple-modern-mcc-quota.py --dtree PATH --evidence PATH` runs
  sanitizer and NDEBUG core/layout checks: 128-cell independence, all-bit
  broadcast retention, reset, invalid accesses, saturation, strict geometry,
  ambiguity and collision rejection.
- `scripts/test-apple-modern-mcc-quota-qemu.py --binary PATH --components PATH
  --output-dir PATH` executes only an owned ROM. Two reset passes check groups
  0/11/31 in all four planes, complete 32-bit values, global writes, independent
  group and plane storage, exact PC/ESR for ten sparse neighbors and the mapped
  global read rejection, read-only diagnostics and migration rejection.
- `--no-device` deliberately returns failure, with
  `no_device_oracle_validated=true` only after its first actual quota load faults
  at the exact owned instruction and unmapped external-abort ESR, before any
  diagnostic queries. This qualifies the default-off behavior oracle.
