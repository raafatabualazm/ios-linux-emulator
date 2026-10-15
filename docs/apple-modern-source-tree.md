# Modern Emulator source tree

The canonical workspace checkout is `Inferno/integration`, branch `modern-ios`.
`modern-emulator/source` points to this checkout. The workspace tools, tests and
README also point into it. Edit and build this source for continued development.
The former `Inferno/wt/codex-native-storage` path is a compatibility link to the
same checkout; it no longer contains an independent worktree.

Merge `7df8564` combines native storage (`0c838cf`) with Claude's display/input
merge (`740387b`, containing display `913486c` and input `2ecfd12`). It includes:

- The opt-in native ANS adapter, normal NVMe block backend and CPU persistence
  gate described in [the ANS documentation](apple-modern-native-ans.md).
- DCP mode-push callbacks selected through `dcp-attach-cbs`, including `MODES`.
- The opt-in `modern-mtp-input` GPIO and DockChannel register models. The MTP
  firmware and HID peer are not implemented; this does not establish touch delivery.
- The bounded PMGR accounting-register continuation and quiet PMP receipt peer.

Concrete PMGR regions are mapped before display logging apertures, so a broad
display trace window cannot claim the PMC registers. The complete combined
profile uses a bounded 256-entry exclusion array; planners still reject counts
above the limit and conflicting concrete mappings.

Use an out-of-tree build and pin the resulting executable before running guests.
Historical branches, private evidence and immutable runtime pins retain their
original provenance. Firmware, tickets, keys and disk images remain outside Git.

From the workspace root, the merged construction/reset gate is:

```sh
python3 modern-emulator/source/scripts/test-apple-modern-feature-merge-qemu.py \
  --binary /path/to/pinned/qemu-system-aarch64 \
  --components /path/to/derived-components \
  --output /new/evidence/combined
```

It creates ANS, DCP mode-push, MTP GPIO/DockChannel and the native platform
register models together, verifies their properties and mappings across reset,
keeps the CPU stopped, and verifies the owned backend and input hashes. It does
not execute firmware or qualify pixels, touch events or encryption.

The independent actual-CPU block gate is:

```sh
python3 modern-emulator/source/scripts/test-apple-modern-ans-qemu.py \
  --binary /path/to/pinned/qemu-system-aarch64 \
  --components /path/to/derived-components \
  --output-dir /new/evidence/ans
```

That gate checks write/flush, process-crash recovery before rewriting data,
read-only refusal, DMA/TCB/crypto refusals, interrupts and reset. Native iOS disk
publication and SEP-backed encrypted APFS remain separate, unfinished work.
