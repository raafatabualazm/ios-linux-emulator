# apple-modern PMGR power-state cells

`modern-pmgr=on` enables a bounded power-state register device. The default is
off. The prepared ADT is read without edits; no MCC function is deleted and no
voltage table or interrupt property is synthesized.

## Reference basis

The normal device layout comes from these primary implementation sources:

- [m1n1 PMGR, commit 2460b604](https://github.com/AsahiLinux/m1n1/blob/2460b604c6f016956ead711823605eea840c602e/src/pmgr.c)
  defines the packed 48-byte device record and the `ps-groups` path. Each group
  selects a `reg` tuple and a group offset; a real device adds its 24-bit offset.
  Flag 0x10 describes a virtual domain without a physical power-state cell.
- [m1n1 register definitions](https://github.com/AsahiLinux/m1n1/blob/2460b604c6f016956ead711823605eea840c602e/proxyclient/m1n1/hw/pmgr.py)
  define desired/actual nibbles and reset, disable and automatic-control bits.
- [Linux PMGR driver, commit 7b63ef2d](https://github.com/torvalds/linux/blob/7b63ef2d55f24519e7e9e5f4d15dbea03f126e40/drivers/pmdomain/apple/pmgr-pwrstate.c)
  requests a target and polls the actual nibble, controls reset and disable,
  enables automatic power management, and programs the minimum-state field.

These are an ordinary Apple power-controller interface basis, **not an Apple
T8140 specification or a measured T8140 reset-state capture**. Synchronous
completion is a declared device abstraction.

ACTUAL follows TARGET exactly, and MIN is applied as a floor only while
AUTO_ENABLE is set. That is not a free choice: XNU's `_setPSLevel` polls mask
0xf0 for `level << 4`, Linux's `apple-pmgr-pwrstate.c` polls
`FIELD_GET(APPLE_PMGR_PS_ACTUAL, reg) == pstate`, and m1n1's `pmgr.c` polls
`PMGR_PS_ACTUAL` against `FIELD_PREP(..., target_mode)` -- all three wait for
equality, so a floor on an explicit request makes them time out rather than
converge. Restricting the floor to AUTO_ENABLE follows the Linux binding's own
wording for `apple,min-state`: "Specifies the minimum power state for auto-PM."
**Whether T8140 silicon clamps ACTUAL when AUTO_ENABLE is clear has not been
measured**, and no public source states it.

## Matched ADT geometry

The unchanged d47ap/t8140 stock tree describes 296 devices: **138 hardware
cells and 158 virtual domains**, grouped into two register windows:

| Group | Physical window | ADT size |
| --- | --- | --- |
| 0 | 0x300700000 | 0xcc000 |
| 1 | 0x308280000 | 0x80000 |

SEP_AON, device id 0x9, occupies group 0 + 0x60. SEP, device id 0x69,
occupies group 0 + 0xc00. The live guest fault review independently measured
an external abort on a load from **0x300700060**, making SEP_AON a real guest
dependency. An owned ROM separately qualifies its actual device mapping.

Each window is a nonterminating container with only the known **8-byte cell
slots** mapped. The existing SEP register RAM at 0x3082dc000 remains visible
in a hole in group 1; the owned-ROM gate checks its readback. The model does
not map broad writable register RAM over existing devices.

The planner rejects malformed schemas, unsupported compatibility, wrapping
bus or register ranges, oversized windows, invalid group/index/offset values,
duplicate real ids/cells, missing hardware cells, and overlaps between mapped
cells and DRAM or supplied device exclusions. It accepts only the current
16-bit device-id and `ps-groups` schema; it is not a legacy PMGR replacement.
The tree's `compatible` may be absent after the existing Darwin fixup. When
present, it must be `pmgr1,t8140`.

## Supported register behavior

The first 32-bit word of each slot implements:

| Bits | Behavior |
| --- | --- |
| 3:0 | Requested target |
| 7:4 | Read-only actual state, synchronously `max(target, minimum)` |
| 10 | Stored device-disable control |
| 19:16 | Stored minimum-state control |
| 28 | Stored automatic-enable control |
| 31 | Stored reset control |

All other bits read zero and ignore writes. The second word at slot +4 reads
zero and ignores writes, with unknown-access counters. A 64-bit access is
split into two 32-bit operations; its upper word cannot overwrite another cell.
Registers outside the known cell slots are unmapped. The sparse containers
allow preexisting hardware leaves there to continue receiving accesses.

**Initial-state limit:** every hardware cell and every diagnostic counter
resets to zero. This is a declared emulator reset state, not a reproduction
of an iBoot-programmed running device. No stock `on` flag is used as an
unmeasured ready value. No virtual-domain state is invented.

Device-disable/reset/automatic bits are stored controls only. The device does
not gate a real SEP CPU, simulate automatic gating, track parent dependency,
produce the history flags, implement voltage/DVFS or MCC/PMP hardware, change
clock frequencies, or drive PMGR interrupts. These require independent normal
models or measurements. A successful power-cell readback does not show that
ApplePMGR published `Wait`, SEP booted, or SpringBoard ran.

## Diagnostics and tests

Read-only `uint64` QOM properties on `/machine/pmgr` count MMIO reads/writes,
unknown slot-word reads/writes and actual-state transitions. They saturate
instead of wrapping, reset with the device, and do not change on QOM reads.
Migration is explicitly rejected through QEMU's unmigratable VMState flag;
power-register state cannot silently disappear during a migration.

```sh
python3 scripts/test-apple-modern-pmgr.py --dtree /path/to/dtree.stock
python3 scripts/test-apple-modern-pmgr-qemu.py \
  --binary build/qemu-system-aarch64 --components /path/to/derived \
  --output-dir /new/evidence/directory
```

The production-source core gate runs ASan/UBSan and `-DNDEBUG`: **2,961 checks
each**, including the unchanged matched ADT, controls, minimum states,
read-only actual bits, bounds, exclusions, reset and counter saturation.
The QEMU gate executes only an owned AArch64 ROM: **2/2 passes** across reset,
16 counted reads, 13 counted writes, 2 unknown reads, 2 unknown writes and 7
transitions per pass. It verifies the preexisting RAM leaf survives the sparse
container and migration is rejected with a PMGR-specific error before a file
is created. Firmware inputs remain unchanged and are never executed by this gate.

`--oracle no-device` keeps the same ROM and emulator but turns the device off.
It fails on the guest's MMIO exception before QOM instrumentation is checked.
This is a behavioral negative oracle. It does not measure every possible
implementation fault, real power timings, a full Apple driver handshake or
an iOS boot.
