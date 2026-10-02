# Matched firmware preparation

`prepare_firmware.py` reads a local IPSW or uses strict HTTP byte ranges. It selects
an exact product, board, version, build and identity variant, then keeps each
original Image4 member beside its decoded payload and SHA-256 provenance.

The prepared target is iPhone 16 / `iPhone17,3`, board `d47ap`, T8140, iOS 27.0
build `24A437`, `Customer Erase Install (IPSW)`. Existing files are under
[`boot-components`](../../evidence/firmware-20261002/boot-components/provenance.json).
The kernel, device tree, SPTM, TXM and stock restore trustcache are decoded.
The matched restore ramdisk and full system image remain separate work.

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

Verification:

```bash
python3 -m unittest discover -s modern-emulator/tests/firmware -p 'test_*.py' -v
```

The 16 passing cases cover bounded ranges, entity changes, truncated ZIP/HTTP/DER,
identity ambiguity, component type mismatches, unsafe paths, encrypted input,
output symlinks and provenance accounting. Retained artifact hashes and sizes
were checked independently of another download; see
[`review.json`](../../evidence/firmware-20261002/review.json).
