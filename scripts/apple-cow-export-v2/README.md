This separate exporter reads a qualified COW manifest and selects an APFS
System or Data volume explicitly. It does not replace the original pinned
System exporter or its orchestration/decoder pipeline.

System remains the default (`--volume role:system`), with volume-relative
directories `/private/var/db/diagnostics` and `/private/var/db/uuidtext`.
Data defaults to `/db/diagnostics` and `/db/uuidtext` and requires a declared
guest mount prefix. For a Data volume mounted at `/private/var`:

```
apfscowexport-v2 --manifest CAPTURE/manifest.json --out NEW_EXPORT \
  --volume role:data --guest-mount /private/var
```

`--dir` always means an absolute path **inside the selected volume**. A Data
path containing its declared guest mount prefix is refused to prevent an
accidental System namespace lookup. `--require-directories` turns missing
directories into failures; otherwise missing directories remain recorded,
as in the original System exporter. Requested paths must be directories.

A UUID, name or index selector also works. Pair UUID/name/index selection
with `--expected-role system` or `--expected-role data` when the caller knows
the intended role. Other APFS roles are refused. Reports retain the actual
volume name, UUID and role, volume paths and their declared guest paths.
The declared mapping does not prove a guest mounted that volume.

Ordinary files only: compressed logs remain unsupported; symlinks and
special entries are skipped. Default limits are 512 MiB and 10,000 files.
The source and COW delta remain read-only. Capture consistency remains
paused/crash-consistent, not fsck-clean. No daemon tracev3 decoding occurs.

Build with Go >=1.26.5. The retained qualification used Go1.27.1 and the
separately indexed, existing APFS dependency; its exact replacement paths,
source hashes and compiler/binary hashes are in the evidence pin. Keep any
local dependency replacements in a fresh build copy, outside an active
pipeline module.

The reproducible host gate builds a sparse 513 MiB logical two-volume
fixture (about 208 KiB allocated), never a guest:

```
go build -o apfscowexport-v2 .
go build -o apfscowfixture-v2 ./cmd/fixture
python3 qualify.py --exporter ./apfscowexport-v2 \
  --fixture-builder ./apfscowfixture-v2 --out NEW_GATE
```

It checks distinct System/Data contents and UUIDs, role and UUID selection,
guest/volume namespace mapping, a Data-only COW page that leaves System
unchanged, and selector/path/budget refusals. The probe files are ordinary
fixture bytes, not valid tracev3 records. This qualifies reading two volumes
in one captured container. Separate backing-device capture and a real Data
mount remain unqualified.
