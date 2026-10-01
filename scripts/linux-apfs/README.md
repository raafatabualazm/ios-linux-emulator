# Offline APFS dyld patch helper

These tools support the iOS 14 GUI setup described in this repository. They extract the dyld shared cache, invoke your external `InfernoFSPatcher`, and copy its same-size changes back through verified APFS extents. The patcher receives only the extracted file by default, preserving its default software-rendering fixes. Firmware and the external patcher are not included.

Requirements: 64-bit Linux with procfs for the Python helper, Python 3.11 or newer, and Go 1.26.5 or newer to build `extent-probe`. The pinned APFS dependency does not compile on 32-bit hosts because several of its constants overflow `int`. Go dependencies are pinned in `go.mod` and checked by `go.sum`; building needs a populated module cache or network access. The filesystem operation itself needs no network, mounted volume, macOS host, or APFS write driver.

From this directory:

```sh
go build -o /tmp/extent-probe .
python3 patch-filesystem.py /path/to/ios14.raw \
  --extent-probe /tmp/extent-probe \
  --patcher /path/to/InfernoFSPatcher \
  --workdir /path/to/new-recovery-directory
```

The image must be a regular raw file. The defaults are an APFS container at byte offset `24576` and volume `role:system`; use `--base` and `--volume` for a different layout. Compressed DMG, QCOW2 and other image wrappers require conversion to a separate raw image first. The target is `/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e`. Optional `--unredact-logs` is passed to the external patcher. There are no launchd edits.

Stop QEMU, unmount the image, and stop all other image writers before running. Keep a separate backup of the complete image. The helper checks QEMU file descriptors and locks against cooperating helper processes; those checks cannot exclude every external writer or a VM started afterward. Use a disposable image with no snapshots, clones or other shared ownership of the patched blocks. This tool does not implement APFS copy-on-write, allocation, encryption, seal updates or metadata repair, and cannot prove exclusive block ownership.

The supported extent layout uses 4096-byte APFS blocks with contiguous logical extents and uncompressed, unencrypted file data. Sparse extents, overlapping physical extents, incomplete mappings, malformed diffs and out-of-image addresses are rejected before writing. The final extent may include allocation padding past the file's logical end. Other APFS layouts are outside the supported scope. Diff records must be sorted and nonoverlapping; offsets and sizes cannot change the file length.

Before applying changes, the helper saves and syncs the originals, patched files, forward/reverse diffs and hash manifest. It compares current file hashes with the originals and verifies logical/raw extent bytes. Successful writes are synced, reread through APFS and checked against complete patched-file hashes. An application failure triggers undo of every attempted file, followed by complete original-hash verification. Manifest write failures do not prevent that undo. `manifest.json` records `verified`, `rolled-back`, or `rollback-required`; updates replace the previous manifest atomically.

Keep the recovery directory after success. A process kill, power failure or failed undo can require manual recovery from the full-image backup. When `rollback-required` is recorded, or the helper is killed while `applying`, keep the VM stopped. An interrupted operation may leave the last durable status in the manifest. To retry an undo while offline:

```sh
/tmp/extent-probe -img /path/to/ios14.raw -base 24576 -vol role:system \
  -patch '/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e=/path/to/recovery/dyld_shared_cache_arm64e.undo'
```

Then extract the file and compare its SHA-256 with `before_sha256` in the manifest. If the filesystem cannot be read or the hash does not match, restore the complete image backup. Low-level `extent-probe -patch` has no automatic undo; prefer the Python helper. The Go tool loads the diff into memory, while extraction and file comparison use bounded chunks.

Focused tests use synthetic image extents and mocked subprocesses; they exercise rejected writes, boundary splitting, aliases, short reads, rollback and manifest failures without changing firmware:

```sh
go test ./...
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_patch_filesystem.py
```
