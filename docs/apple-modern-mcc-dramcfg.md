# Sparse T8140 MCC DRAM configuration words

Default-off `modern-mcc-dramcfg=on` supplies four **32-bit stateful words**, at
stock DCS reg[8..11] +0x1d48. `mcc-dramcfg-reset=VALUE` selects the common virtual
reset value (default zero). Neither value is presented as a silicon reset or
as factory calibration. Writes update the selected bank independently. Reset
restores that declared value and clears read/write diagnostics. Migration is
explicitly rejected. Every neighboring address remains unmapped.

The matched iOS 27 BootKC reads this word, saves it per DCS channel and later
restores it or writes the second word of the unchanged eight-byte `dramcfg-data`
property. The surrounding method names dynamic DRAM configuration mode. This
model supplies storage semantics for that configuration only: host-backed guest
RAM has no DRAM timing simulation. Bit meanings and real hardware initial values
remain unestablished. It implements no cache-way enable/status, IRQ, DVFS,
memory-protection aperture or SEP service.

Mapping requires exact `mcc,t8140`, twelve register tuples, DCS index 8, four
channels per AMCC and one AMCC. Each complete DCS bank must have its matched
0x8000 extent and unambiguous stock physical translation. The sparse words must
be disjoint from DRAM and other mapped device extents. No broad MCC zero-RAM
aperture is introduced. Properties become immutable after initialization.

Local evidence: `modern-emulator/evidence/features-20261008/mcc-provider-review/`.
Read-only tracing preserves `function-mcc_ctrl`, stock voltage tables and
`dramcfg-data`; no fuse input is supplied. The initial fault is the genuine load
at physical 0x220401d48, linked PC 0xfffffff009822e98. This experiment retains the
inherited restore-shell compatibility modes and is not a full restored boot.

Newer primary reference [m1n1 draft PR #664](https://github.com/AsahiLinux/m1n1/pull/664)
adds T8140 MCC support and places cache enable/status separately at +0x2800/+0x2804.
It does not define this DRAM configuration word; no cache behavior is inferred
from the sparse implementation.

Qualification scripts:

- `scripts/test-apple-modern-mcc-dramcfg.py --dtree PATH --evidence PATH`
  runs sanitizer and NDEBUG core/layout checks.
- `scripts/test-apple-modern-mcc-dramcfg-qemu.py --binary PATH --components PATH
  --output-dir PATH` executes only an owned AArch64 ROM, checking four-bank
  read/write, two reset passes, real neighboring-register faults, read-only
  diagnostics and explicit migration rejection.
- `--no-device` is a behavior oracle: the same owned ROM must fault at its first
  real configuration-word load before checking diagnostics.
