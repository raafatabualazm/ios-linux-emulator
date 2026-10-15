# Gemini bundle review and SEP follow-up

The reviewed 2026-10-15 bundle targets historical commit `7df8564`. Its exact
before/after file hashes reproduce there, but it is not a complete native
storage/SEP implementation. The shared source had already advanced, including
the standalone metadata compile fix. Later `9cb9aaa` incorporated its display,
PMGR permissive and ANS mapping proposals; the original bundle remains intact
in the workspace `Gemini-Fixes` directory.

Confirmed findings and disposition:

- New bootstrap ART/DPA/manifest/patch replies and `opcode + 100` acknowledgements
  lack recovered processing/state contracts. Native guest SEP traffic is still
  zero upstream of PMGR Started. Those additional replies are not enabled.
- An empty DER sequence does not establish the device-state schema. The original
  hardcoded SKS container was eight bytes too long for modern IPCv1. Versioned
  framing, exact SHA-256 coverage and length/DMA/endpoint checks now replace it.
  Modern legacy fake keybag/state and unknown-request echoes are refused.
- PMGR permissive mode only handles holes inside existing regions. It cannot map
  the missing cluster control or LTR control/status addresses. The qualified
  profile leaves it off. One explicitly disassembled eight-byte cluster region
  now accepts the actual value-1 store at `0x211e440f8` with adjacent holes intact.
- SART callbacks advertised 64-bit implementation accesses but stored one word.
  The original CPU test reads `0x55667788` after writing `0x1122334455667788`.
  Splitting implementation accesses into 32-bit words fixes the loss and reset
  tests pass. The current model covers only the first 0x4000 bytes of SART reg[0];
  stock SART has three apertures of sizes 0xc000, 0x4000 and 0x4000.
- The old ANS CPU gate uses `prepare-only=on`, which skips those new mappings.
  The dedicated SART gate enables normal mappings but verifies PC and exact
  owned ROM bytes before execution; no Apple firmware runs in that test.
- `sepfw-absent=on` explicitly disables the chosen firmware-load flag and is not
  a positive SEP firmware-bootstrap acceptance profile.

Qualification: SKS parser 2,505 checks in each ASan/UBSan and NDEBUG build;
actual CPU SKS 149 checks per pass across reset; SART 25 checks per pass across
reset; PMGR core 271,805 checks per mode; actual CPU PMGR 664 results/132 exact
faults per pass across reset, plus default-off and old-binary negative controls.
Native NVMe write/flush/process-crash/fresh-read/RO/IRQ/DMA/crypto-refusal and
combined ANS/DCP/MTP construction/reset also pass on the recorded combined pin.

The next measured native frontier is DPE counter high-word read `0x30020a70c`
at linked `0xfffffff0092a778c`. The function snapshots high/low/high until stable.
Native ANS/SEP traffic remains zero; no PMGR Started, encrypted APFS mount,
wrapped-VEK service or SEP-backed keychain result is claimed. Existing voltage
analogy/zero calibration and boot compatibility flags remain declared diagnostics.

The complete review, original hashes, exact executable/source pins, negative
controls, disassembly and closed process/input receipts are in workspace
`Gemini-Fixes/REVIEW.md` and
`modern-emulator/evidence/features-20261015/gemini-fixes-review/`.
