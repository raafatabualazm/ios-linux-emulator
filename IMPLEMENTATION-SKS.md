# IMPLEMENTATION-SKS — Full SKS protocol replies (not just sks-failfast)

**Date:** 2026-10-17 (Africa/Cairo)  
**Branch:** `grok/sks-unblock` @ `3460507`  
**Worktree:** `Grok/impl-20261017/src`  
**Isolation:** edits only under `Grok/`; Claude/Codex/Gemini trees untouched.

## Goal

Retire reliance on `sks-failfast` for Keychain / lock-state by making `sep-sim`
speak enough of the SEP keystore protocol that:

1. Bootstrap reaches `NOTIFY_ALIVE` and advertises **EP18 `sks `** (and EP7 `msks`).
2. AppleSEPManager goes alive → `waitForMatchingService` completes without the KC NOP.
3. SKS cmds `0x03` / `0x04` / `0x19` / `0x1B` (+ `0x01`/`0x05`/`0x0A`) return
   AP-contract success bodies (unlocked, no passcode, empty DER device state).

`sks-failfast` remains as a **fallback flag** for the Apple-logo GUI path.

## Sources of truth

| Source | Role |
| --- | --- |
| `sks-replies/SKS-REPLIES.md` (§4, §10 j410) | Reply layouts + AP vs SEPOS conflict on 0x04 |
| `Grok/sep-fw-20261017/pplx-abi/AUDIT.md` | Merge plan: keep failfast; stub 0x03/04/19/1B; fail-closed only UNKNOWN; no applehax/0xAF |
| `j410-24A437/split/macho_0011c000.bin` | Dispatcher `0x140a90`; 0x04 → `-0xc` @ `0x1415c4` (do **not** mirror) |
| Box `/workspace/scratch/sep-kc` | Connect gate + KeyStore RE |

## What landed (commit `3460507`)

### Endpoint bring-up (already present + extended)

- Bootstrap ACKs **36→136, 37→137, 7→107** (Grok RE; required before IMG4).
- `BOOT_IMG4` → `106` + **`CONTROL_OP_NOTIFY_ALIVE` (13)** + `advertise_eps()`.
- EP list now includes **`EP_MOBILE_SKS` (7, `msks`)** alongside EP18 `sks `.
- OOL for KEYSTORE remains 2/2 pages in/out.

### Modern wire framing

- Vendored `sep-sks-wire.c` / `.h` (sha256 `180afb0d…2bbc`, matches SKS-REPLIES artifact table).
- V6 sets `sks_modern=true`: v1 header 72 / body@76; v2 header 80 / body@84; SHA-256 over hash span; reject `ENCRYPTED`.
- `keystore_send_ipc_resp` strips the internal 8 trailing header bytes on modern v1.

### SKS command replies (AP contract)

| Cmd | Behavior |
| ---: | --- |
| 0x01 Create | selector=1, handle `0x31474142` (`BAG1`) |
| 0x02 Copy | selector=0, **blob_len=0** (no `0xAF` fill) |
| **0x03 Load** | selector=0, handle `BAG1` |
| **0x04 Lock** | **SUCCESS stub** (selector=0, lock\|bit22, device_state=0x3). Comment notes SEPOS `-0xc`. |
| 0x05 Unload | selector=0 |
| 0x08 Wrap | soft empty mailbox reply (no invented wrap bytes) |
| **0x0A Null D** | selector=0 (SEPOS agrees) |
| 0x0C Unwrap D | soft selector=0 (no VEK bytes) |
| 0x0D Make System | selector=0 |
| **0x19 State** | selector=0, **empty DER** `{0x30,0x00}` — **no `applehax`** |
| **0x1B Term** | selector=0 |

### Unknown cmds — fail-closed

- Log + increment `sim-sks-rejected-count`.
- **Never** echo the request OOL as a success reply.
- Optional device property **`sks-fail-closed=on`** → `qemu_system_vmstop_request(INTERNAL_ERROR)`.
- Default: drop (no reply); guest may timeout that one opcode without fake success.

### Keep / fallback

- `sks-failfast` / `sepfw-absent` + KC open-wait NOP (`68acd9b`) unchanged.
- Use when serial does not show `SEP/OS is alive` or walker still sees msg **2862**.

## Tests

| Suite | Result |
| --- | --- |
| `tests/test_sks_replies.py` (11 host layout/hash tests) | **PASS** |
| `scripts/test-apple-sep-sks-wire.py` (ASan + NDEBUG, 2505 checks) | **PASS** |

## Build

| Artifact | sha256 |
| --- | --- |
| `build/qemu-system-aarch64` | `5972a2886433937b0ea9a808c9b6d2e110da9ad3e15aad8f871d9eedd5ee2d9b` |
| `src/.../sep-sim.c` | `06b8d7c51637f0d5fcf120bb9dc5b845f63a064837d46d33f6d2055944a50f80` |
| `src/.../sep-sks-wire.c` | `180afb0dbe4e50b295c53b585a22d934c5bcd2aa19f0d336455565ffe44d2bbc` |

## Patch for review

`patches/0004-apple-modern-grounded-SKS-protocol-replies-EP18.patch`

## v5 boot plan

`runs/sks-protocol-v5/` — 420 s display + walker @ 120/300 s.

```
sep-sim=on
adt-compat-restore=smc+sep
sks-failfast OFF   # first attempt
ramdisk-patches=v4-notifyd-runatload.txt
```

### Evaluate

1. No stuck msg **2862** in backboardd (walker).
2. Serial: `SEP/OS is alive` / no `Waiting 60 seconds for AppleSEPManager`.
3. Apple logo or better frames (vs cursor-only).
4. Serial / logs for Keychain / `aks_get_lock_state` progress.
5. Next blocker if any.

If (1)/(2) fail with failfast off → rerun with `sks-failfast=on` and report the gap.

## Remaining gaps (honest)

- **No real SEP crypto:** VEK / FairPlay / AES-KW wrap still cannot be faked.
- **AppleSEPManager publish without failfast** depends on Booter completing bootstrap against the sim; DMA/OOL without `sep-dart` is identity-mapped (declared simplification).
- **0x04 success body** is an **AP stub**, not a replay of A17 SEPOS (which returns `-0xc`).
- **IPA sideload** still needs AMFI/trustd policy (orthogonal to SKS).
- Modern refuse-all gate from integration was **lifted** for the §4 cmds; keep hash/flag checks.

## How to run

```bash
cd Grok/impl-20261017/build && ninja -j6 qemu-system-aarch64
cd ../tests && python3 test_sks_replies.py
cd ../src && python3 scripts/test-apple-sep-sks-wire.py --output /tmp/sks-wire.json
cd ../runs && python3 -u run_v5_protocol.py
```

## v5 boot results (failfast OFF)

**Run:** `runs/sks-protocol-v5/` (420.6 s, rc=0). Full write-up: `RESULTS.md`.

| Criterion | Result |
| --- | --- |
| EP bring-up without failfast | **FAIL** — no `SEP/OS is alive`, no Booter accept strings |
| No stuck 2862 | **FAIL** — tid 667 on msg 2862 at 120s and 300s |
| Apple logo / real frames | **FAIL** — lit=128 (cursor) all frames |
| SKS replies exercised on EP18 | **Not observed** (no mailbox traffic logged) |

**Gap:** `sep-sim=on` + `adt-compat-restore=smc+sep` maps the simulator, but the AP
does not complete Booter→NOTIFY_ALIVE in this configuration. Failfast remains
required for the GUI path until mailbox dialogue is proven (enable
`-d guest_errors`, confirm MMIO/IRQs, optionally emit NOTIFY_ALIVE earlier).

## v5b (fallback, in progress)

Same binary with **`sks-failfast=on,sepfw-absent=on`** + `sep-sim=on` +
`-d guest_errors` → expect Apple logo (as v3/v4) and capture any SKS opcode
logs from the sim.

## v5b boot results (failfast ON fallback)

**Run:** `runs/sks-protocol-v5b/` (420.6 s, rc=0). Full write-up: `RESULTS.md`.

| Criterion | Result |
| --- | --- |
| No stuck 2862 | **PASS** |
| Apple logo | **PASS** (lit=13362) |
| Live EP18 SKS traffic | **None** (Booter skipped under failfast) |
| Host SKS unit tests | **PASS** (11 + 2505 wire checks) |

## What works with failfast OFF vs ON

| Mode | 2862 clear | Logo | Live SKS stubs hit |
| --- | --- | --- | --- |
| `sep-sim=on`, failfast **OFF** (v5) | No | No | No (no mailbox traffic) |
| `sep-sim=on`, failfast **ON** (v5b) | Yes | Yes | No (Booter skipped) |


## Gap 1 closure (commit pending) — why Booter never reached sep-sim

**Diagnostic (sep-diag-v6a, failfast OFF, 240s):** QOM counters on
`/machine/unattached/device[2]` (apple-sep-sim) stayed at
`wrapper/ap-mmio-*=0`, `transport-ap-*=0`, `sim-dispatch=0`,
`sim-reply-count=1` (reset ANNOUNCE only) for the whole run. So the AP never
touched the mailbox MMIO — the break is **before** Booter ACKs, not in the
ACK/IRQ path.

**Static RE (cite VAs):**

| Finding | Evidence |
| --- | --- |
| Match chain | `AppleASCWrapV6SEP` IONameMatch `iop-sep,ascwrap-v6` → publishes `AppleA7IOPNub`; `AppleSEPManager` personality `IONameMatch=iop-nub,sep` / `IOProviderClass=AppleA7IOPNub` (BootKC plist @ `0x4439945`) |
| Compatible restore works | `adt-compat-restore=smc+sep` restores 5 props; map_sep did **not** emit the "no compatible" warn |
| Firmware-loaded gate | `AppleASCWrapV6` @ `0xfffffff00856e31c`: `ldr` core window bit0; clear → REQUIRE `"ASC firmware must be loaded by iBoot"`. SEP `reg[1]` (off `0x72050000`, size `0x60000`) was **unmapped** |
| SEPFW required for preload | `AppleSEPFirmware` preload @ `0xfffffff0096108c8`: looks up `/chosen/memory-map` **SEPFW**; null/zero size → REQUIRE. Stock Darwin-derived tree has **no** SEPFW entry. SEPPatches/uStuff must be both-present or both-absent (both absent OK) |
| Boot send sites (unchanged) | BootTmmManifest 36 @ `0xfffffff00961ace0`, BootPatch 37 @ `…ad48`, BootTz0 5 @ `…adfc`, LoadSEPART 7 @ `…b110`, BootImg4 6 nearby; `"SEP/OS is alive"` @ `0xfffffff009626070` needs status `this+0xc8 ∈ {1,2}` |

**Fix (this commit):**

1. **SEPFW carveout** (16 MiB unmanaged DRAM tail) when `sep-sim=on` and not
   `sepfw-absent` / `sks-failfast`; published as `/chosen/memory-map SEPFW`
   (zeros; sep-sim does not validate contents).
2. **SEP core window** (`reg[1]`) mapped with bit0 DECLARED 1 (same shape as
   gfx-asc / dcp core).
3. **`pre-loaded=1` / `running=1`** on `/arm-io/sep/iop-sep-nub` (same DECLARED
   iBoot flags modern-smc uses).

**Next:** v6 boot failfast OFF → expect non-zero MMIO/dispatch counters,
`SEP/OS is alive`, live 0x03/0x04/0x19/0x1B, and msg 2862 clear.

## Remaining gaps (post gap-1 fix; update after v6)

1. Confirm v6 failfast OFF: MMIO counters, `SEP/OS is alive`, live SKS 0x03/04/19/1B, 2862 clear.
2. After alive: verify `aks_get_lock_state` / MKB unlocked via 0x04/0x19 replies.
3. Still cannot fake VEK / FairPlay / real Keychain wrap.
4. Encrypted d47 SEP firmware is unused; carveout is zeros (sim ACK path only).

## Hashes (recap)

| Artifact | sha256 |
| --- | --- |
| `build/qemu-system-aarch64` | `5972a2886433937b0ea9a808c9b6d2e110da9ad3e15aad8f871d9eedd5ee2d9b` |
| `sep-sim.c` | `06b8d7c51637f0d5fcf120bb9dc5b845f63a064837d46d33f6d2055944a50f80` |
| `sep-sks-wire.c` | `180afb0dbe4e50b295c53b585a22d934c5bcd2aa19f0d336455565ffe44d2bbc` |
| Commit | `3460507` |
| Patch | `patches/0004-apple-modern-grounded-SKS-protocol-replies-EP18.patch` |
