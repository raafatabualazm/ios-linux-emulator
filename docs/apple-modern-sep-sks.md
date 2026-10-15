# Modern SEP simulator: SKS framing and limits

The `apple-modern` V6 SEP simulator uses the versioned wire framing recovered
from the matched T8140 AppleSEPKeyStore AP driver. This is a protocol simulator;
it does not execute SEP firmware or implement encrypted Data/keychain services.

| IPC version | Header, excluding length prefix | Body offset | Hashed header bytes |
| --- | ---: | ---: | --- |
| 1 | 72 | 76 | wire offsets 20 through 75 |
| 2 | 80 | 84 | wire offsets 20 through 83 |

The four-byte little-endian prefix contains the header length. The first 16
bytes of SHA-256 over the indicated header bytes followed by the body occupy
wire offsets 4 through 19. Local AP helpers at linked addresses
`0xfffffff0095ec4c4`, `0xfffffff0095ec49c`, `0xfffffff0095ec5f4`, and
`0xfffffff0095ecc10` establish these sizes and spans in BootKC SHA-256
`a36b924108b63eefd7cc8fa9e54acc3a07544786d3edb316fbcf3b9fb7426b35`.
The simulator's historical V2/V4 wrapper path retains its 80-byte v1 container;
that legacy format is not accepted by the V6 path.

Modern SKS checks message/header/body lengths, version, digest, configured DMA
capacities, and the unsupported encrypted-message flag before dispatch. Invalid
requests receive no success reply. `sim-sks-rejected-count` reports framing and
capacity refusals without exposing payloads. Invalid OOL endpoint indices are
also checked in release builds. Reset clears OOL addresses, sizes and counters.

Only the existing neutral client-terminate compatibility reply is enabled for
modern SKS. Legacy fake keybag handles, constant keybag bytes, device-state text,
and unknown-request echoes are refused on V6. The existing V2/V4 service stubs
remain historical compatibility behavior. Implementing their modern equivalents
requires actual request/response schemas, state and cryptography. A syntactically
valid empty DER sequence or a guessed bootstrap `opcode + 100` acknowledgement
does not supply those contracts.

Validation:

- `scripts/test-apple-sep-sks-wire.py`: bounded parser tests in ASan/UBSan and
  NDEBUG, including truncated/unaligned inputs and the legacy/modern boundary.
- `scripts/test-apple-modern-sep-sks-qemu.py`: an owned ARM64 program exchanges
  actual mailbox/DMA messages; Python independently computes exact v1/v2 response
  bytes and SHA-256. Tests malformed frames, DMA capacity, unsupported operations,
  invalid endpoints and reset. No Apple firmware or key operation executes.
- The previous integrated binary fails the behavioral v1 reply-length oracle:
  88 bytes observed versus 80 expected for the four-byte response body.

The latest bounded native iOS observation still stops before SEP traffic at the
PMGR store `0x211e440f8`. The framing tests establish transport correctness only;
they do not establish native SEP bootstrap, a wrapped VEK, keychain keys or
encrypted APFS persistence.
