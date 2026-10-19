# claude/setup-skip tools

Scripts and receipts only. The pinned image, checkpoint-v2 and the 0-byte patch
list are never modified, and the built checkpoints (268 MB each) stay in the
private evidence tree, not in git.

- `run_owned.py` — copy of the shared launcher with the single hard-pinned
  checkpoint sha256 assert replaced by an (image, checkpoint) -> profile
  allowlist. The live copy used for boots is `run_owned_claude.py` in the
  evidence directory, placed there so `ROOT`/`HERE` resolve as the original does.
- `warm-fixture-v3/build-checkpoint-v3.py` — derives a guarded checkpoint-v3
  from pinned checkpoint-v2 plus one preference edit. One variant per run.
- `warm-fixture-v3/verify-checkpoint-v3.py` — independent fresh reader that
  qualifies a built checkpoint over the composed state.
- `warm-fixture-v3/*.receipt.json` — build receipts with every input pin,
  record index, offset, old/new value, page hash and node checksum.

Findings and boot status: `Grok/handoffs-20261019/RESULT-1.md`.
