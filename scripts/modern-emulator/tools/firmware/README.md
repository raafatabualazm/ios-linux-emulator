# Matched firmware preparation

`prepare_firmware.py` reads a local IPSW or uses strict HTTP byte ranges. It selects
an exact product, board, version, build and identity variant, then keeps each
original Image4 member beside its decoded payload and SHA-256 provenance.

The prepared target is iPhone 16 / `iPhone17,3`, board `d47ap`, T8140, iOS 27.0
build `24A437`, `Customer Erase Install (IPSW)`. Existing files are under
[`boot-components`](../../evidence/firmware-20261002/boot-components/provenance.json).
The kernel, device tree, SPTM, TXM and stock restore trustcache are decoded.
The matched restore ramdisk has an explicit optional selection. Preparation
extracts unchanged bytes; it does not establish a bootable recovery filesystem.
The full system image remains separate work and is never selected by this tool.

For another preparation, supply a **new** private output directory:

```bash
python3 modern-emulator/tools/firmware/prepare_firmware.py IPSW_PATH_OR_URL \
  --output NEW_OUTPUT_DIRECTORY \
  --product iPhone17,3 --board d47ap --version 27.0 --build 24A437 \
  --variant 'Customer Erase Install (IPSW)' \
  --img4-tool Inferno/data/img4lib/img4
```

Use `--inspect-only` for metadata and selected member sizes. Original images are
kept unchanged; the decoder performs ordinary decompression. Encrypted payloads
and ticket wrappers are rejected. The default 300 MiB limits HTTP bytes and all
output file contents, reserving 1 MiB for provenance. File allocation overhead is
outside that content limit. The tool checks an overall deadline between network
reads and applies socket timeouts; use an external process watchdog when a strict
wall-clock limit is required.

## Optional matched restore ramdisk

`--ramdisk-only` selects the same identity's `RestoreRamDisk` without repeating
the boot components. `--include-ramdisk` prepares it alongside the normal boot
selection. The two flags are mutually exclusive. The default selection and
300 MiB budget remain unchanged; opt-in ramdisk selections allow an explicitly
requested budget up to **640 MiB**. Each ramdisk original and decoded payload
is capped at **256 MiB**. Normal boot member bounds remain 128 MiB.

The matching iOS 27 archive advertises a 243,269,659-byte restore member. Its
original and uncompressed IM4P octets together need approximately 486 MB,
plus manifest/provenance. Use 512 MiB for ramdisk alone, or 600 MiB when also
retaining the five boot components:

```bash
timeout --signal=TERM --kill-after=10s 360s \
  python3 modern-emulator/tools/firmware/prepare_firmware.py IPSW_PATH_OR_URL \
  --output NEW_PRIVATE_RAMDISK_DIRECTORY \
  --product iPhone17,3 --board d47ap --version 27.0 --build 24A437 \
  --variant 'Customer Erase Install (IPSW)' \
  --ramdisk-only --limit-mib 512 --img4-tool Inferno/data/img4lib/img4
```

The selected Image4 type must be `rdsk`; encrypted wrappers are rejected using
the existing parser. No keys, decryption options or guest modifications are
accepted. Provenance retains exact identity/source, selected ZIP member, original
and decoded SHA-256 values, transfer ranges, and content-budget accounting.
`filesystem_qualified` remains false: mountability, recovery boot, full userspace
and GUI need separate validation. Partial preparation retains bounded truthful
provenance and never replaces an existing output directory.

The matching Apple archive was prepared on 2026-10-03 with `--ramdisk-only`
and a 512 MiB budget. It completed in 105.061 seconds, transferred 187,255,779
bytes and retained 487,409,342 bytes including manifest/provenance. The original
243,269,659-byte `rdsk` wrapper and its 243,269,632-byte extracted payload passed
19 read-only provenance, hash and budget checks. All five earlier decoded boot
assets remained unchanged. An APFS container signature was observed; filesystem
qualification and recovery boot remain pending. Private evidence:
[`ramdisk provenance`](../../evidence/firmware-20261003/restore-ramdisk/provenance.json)
and [`ramdisk review`](../../evidence/firmware-20261003/restore-ramdisk-review.json).

Verification:

```bash
python3 -m unittest discover -s modern-emulator/tests/firmware -p 'test_*.py' -v
```

The 25 passing cases cover bounded ranges, entity changes, truncated ZIP/HTTP/DER,
identity ambiguity, component type mismatches, unsafe paths, encrypted input,
output symlinks, provenance accounting, optional selection, ramdisk type/encryption
checks and bounded opt-in budgets. Retained artifact hashes and sizes
were checked independently of another download; see
[`review.json`](../../evidence/firmware-20261002/review.json).
