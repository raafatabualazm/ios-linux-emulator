# Explicit PMGR calibration image input

`apple-modern,pmgr-aon-fuse-image=/private/path/image.bin` optionally supplies
the exact 16 KiB `PMGR_AON_FUSE` bank. Without this property the bank remains
unmapped. The property is fixed after board initialization. The image must be
a regular file, not a symlink; wrong lengths and changes during reading fail.
The device copies the input once and retains it unchanged across reset.

The matched stock T8140 ADT's PMGR `reg[30]` is bus offset `0xf82c8000`, size
`0x4000`, translated to physical `0x3082c8000`. The planner validates that
specific geometry, bus translation, DRAM and other device exclusions, and
every sparse PMGR power cell. Existing power-window containers can surround
this bank without shadowing it. Other bank geometries are unsupported.

The ordinary immutable 32-bit word interface is based on the primary
[Linux eFuse driver](https://github.com/torvalds/linux/blob/7b63ef2d55f24519e7e9e5f4d15dbea03f126e40/drivers/nvmem/apple-efuses.c)
and its [factory-programmed bank binding](https://github.com/torvalds/linux/blob/7b63ef2d55f24519e7e9e5f4d15dbea03f126e40/Documentation/devicetree/bindings/nvmem/apple%2Cefuses.yaml).
These references do not specify T8140 fuse values. Four-byte accesses and
naturally aligned eight-byte reads are supported; an eight-byte read splits
into two little-endian words. Writes receive an access-error external abort.
Programming circuitry and unaligned accesses are unsupported. Migration is
explicitly rejected. Reset clears only diagnostics, retaining the input bytes.

Read-only QOM properties on `/machine/pmgr-fuse` are `mmio-read-count` and
`rejected-write-count`. They saturate and do not reveal image contents.
Paths and hashes may be recorded privately; device data must not be committed
to source or copied into project memories.

## Qualified scope

```sh
python3 scripts/test-apple-modern-pmgr-fuse.py --dtree /path/to/dtree.stock
python3 scripts/test-apple-modern-pmgr-fuse-qemu.py \
  --binary /path/to/pinned/qemu --components /path/to/derived \
  --output-dir /new/private/evidence
```

The source core gate passes **8,232 checks** under ASan/UBSan and `NDEBUG`.
The actual CPU gate passes twice across reset, reading exact owned input
words, a split doubleword, and unchanged data after a rejected write. It checks
eight MMIO reads and one rejected write per pass, diagnostic immutability,
and migration rejection naming this device. Actual startup rejects empty,
short and long images. The no-input oracle fails on a real unmapped-MMIO
exception before checking device counters. The existing power-cell CPU gate
also passes twice with the input property absent.

**No genuine calibration image is available in the current workspace.** The
fixture bytes are owned test data and have never been used for an iOS boot.
The live diagnostic driver reads ten bank words for reporting; adjacent code
also consumes calibration bit fields. The implementation does not supply
factory values, synthesize voltage tables, publish MCC functions, execute SEP
firmware or establish further iOS/SpringBoard progress.
