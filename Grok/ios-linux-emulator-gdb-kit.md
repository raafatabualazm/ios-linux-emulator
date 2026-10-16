# T8140 gdb inspection kit (xnu-13432.2.10 / iOS 27.0 24A437)

Offline static RE kit so a QEMU gdbstub session can find **backboardd**’s stuck main thread and what it waits on (mach_msg / launchd event-stream check-in), using only memory/register reads.

Related prior notes: [`ios-linux-emulator-aw-hang-t8140.md` §9](ios-linux-emulator-aw-hang-t8140.md) (Biome `xpc_set_event_stream_handler` stall).

---

## 0. Kernel variant

| File | Version string |
|------|----------------|
| `kernelcache.release.iPhone17,3` | `Darwin Kernel Version 27.0.0: … xnu-13432.2.10~2/RELEASE_ARM64_T8140` |
| `kernelcache.research.iPhone17,3` | same `RELEASE_ARM64_T8140` string |

**Unslid PC check** (guest reported `0xfffffff02abeaaf0` ⇒ unslid `0xfffffff00abeaaf0` with slide `0x20000000`):

Both kernels have **identical** bytes at that VA:

```
ldr x10, [x9, #0x1b8]
ldr x10, [x10, #0x58]
cmp x10, x11
b.ne …
mrs x10, pmc0          ; s3_2_c15_c0_0
mrs x12, pmc1
… (PMC accounting / idle-style poll)
```

**Conclusion:** guest is the **RELEASE** T8140 kernel (matches `RELEASE_ARM64_T8140`); research file differs elsewhere (~1.6M bytes) but not at this PC. Kit offsets are taken from the **extracted `com.apple.kernel` of the release fileset** (`/tmp/kern-res/com.apple.kernel` ≡ release TEXT).

KASLR: **slide = `0x20000000`** (runtime = unslid + slide). Confirmed by prior guest gdb session.

Closest public source for layouts: **xnu-12377.121.6** at `/workspace/ios27-re/xnu-src` (structs; field *order* trusted, sizes verified against this binary where noted).

---

## 1. Globals and field offsets

Legend: **PROVEN** = accessor / init disassembly on this kernelcache. **ENC** = ObjC type-encoding in `__TEXT.__cstring` for this kernel. **INFERRED** = layout math from source + encoding; must be validated on a live guest.

### 1.1 Globals (unslid)

| Symbol | Unslid VA | Evidence |
|--------|-----------|----------|
| `kernproc` **slot** (holds `proc_t`) | `0xfffffff007e8b7d0` | **PROVEN** — hundreds of `adrp+ldr` sites; `proc_getpid`-style `cmp` then `ldr wN,[xProc,#0x60]` |
| `allproc` (`LIST_HEAD`, `.lh_first`) | `0xfffffff00b790280` | **PROVEN** — `bsd_init` `LIST_INSERT_HEAD`: `adrp …#0xb790000; add …#0x280; str kernproc,[allproc]; str &allproc,[kernproc,#8]` at `0xfffffff00b091540`–`0x580` |

File contents of the kernproc slot are **0** in the extracted Mach-O (filled at runtime / fixups). Read it **after** boot with slide applied: `*(proc_t *)(0xfffffff007e8b7d0 + slide)`.

### 1.2 `proc`

| Field | Offset | Evidence |
|-------|--------|----------|
| `p_list.le_next` | `0x00` | **PROVEN** (LIST_ENTRY at start; insert writes `[proc]` / `[proc,#8]`) |
| `p_list.le_prev` | `0x08` | **PROVEN** |
| `p_pptr` | `0x10` | layout after `p_list` |
| `p_proc_ro` | `0x18` | **PROVEN** — `str x0,[x25,#0x18]` in bsd_init after `proc_ro` alloc |
| `p_pid` | `0x60` | **PROVEN** — `cmp` vs kernproc then `ldr wN,[x8,#0x60]` (many sites) |
| `p_stat` | `0x64` | **PROVEN** — `strb …,[x8,#0x64]` in bsd_init |
| `p_comm` | `0x55c` | **PROVEN** — `proc_best_name` @ `0xfffffff00b0de25c`: `add x10,x0,#0x55c` / `ldrb [x0,#0x56d]` |
| `p_name` | `0x56d` | **PROVEN** (same); sizes 0x11 / 0x21 match `command_t` / `proc_name_t` |
| `p_lflag` | `0x448` | **PROVEN** — `orr w9,#2; str [x8,#0x448]` for `P_LHASTASK` |
| **`proc_struct_size`** | **`0x768`** | **PROVEN** — `add x10,x8,#0x768; cmp` task↔proc in bsd_init; also `sub x10,x9,#0x768` |
| `proc_and_task_size` | `0xe38` | **PROVEN** — zone create `mov w1,#0xe38` with name `"proc_task"` |

**Modern layout:** `task = (task_t)((uintptr_t)proc + proc_struct_size)` (`proc_get_task_raw`). Do **not** use a separate `proc->task` pointer for membership; use adjacency + `P_LHASTASK`.

`current_thread`: **`mrs xn, tpidr_el1`** (**PROVEN** throughout; e.g. bsd_init / assert paths).

### 1.3 `task` (encoding size ≈ `0x6c8`)

From embedded `^{task=…}` type encoding + `task.h` field order:

| Field | Offset | Evidence |
|-------|--------|----------|
| `map` | `0x28` | **ENC+source** |
| `threads` (`queue_head_t`) | `0x50` | **ENC+source** |
| `itk_space` | `0x310` | **ENC+source** |
| `bsd_info_ro` / `proc_ro` | `0x3c8` | **ENC** (`^{proc_ro}`) |
| `shared_region_id` (`char*`) | `0x428` | **ENC** |
| `shared_region` | `0x430` | **ENC** |
| `task_shared_region_slide` | near `0x438` / later | **INFERRED** — probe; or read `vm_shared_region.sr_slide` |

### 1.4 `thread` (encoding size ≈ `0x5e8`)

| Field | Offset | Evidence |
|-------|--------|----------|
| `wait_event` | `0x18` | **ENC+source** (immediately after links union) |
| `wait_result` | `0xd8` | **ENC** (exact byte **INFERRED**) |
| `kernel_stack` | `0xf0` | **ENC** |
| `machine` | `0x100` | **ENC** |
| `machine.contextData` | `0x108` | **ENC** (`^{arm_context}`) |
| `machine.upcb` | `0x110` | **ENC** |
| `machine.kpcb` | `0x120` | **ENC** |
| `machine.kstackptr` | `0x150` | **ENC** walk with `CONFIG_SPTM` `kredzonestack` present on this KC |
| `state` | `0x1f0` | **ENC** |
| `saved` (ith union) | `0x370` | **PROVEN** via `ith_state` |
| `ith_object` | `0x390` | **PROVEN** — `recv_bufs`(24)+`option`(8) then object; panic path uses `#0x398` for state |
| `ith_state` | `0x398` | **PROVEN** — `ldr/str wN,[x20,#0x398]` in `ipc_mqueue_receive_results` |
| `threads` (global list link) | `0x3f8` | **ENC** |
| `task_threads` | `0x408` | **ENC** |
| `map` | `0x420` | **ENC** |
| `ith_special_reply_port` | `0x450` | **ENC** (after `mutex`) — **INFERRED** exact |
| `thread_id` | `0x4e8` | **PROVEN** — `thread_tid`: `cbz x0; ldr x0,[x0,#0x4e8]; ret` @ `0xfffffff00ac2534c` |

`TH_*` bits: `WAIT=1, SUSP=2, RUN=4, UNINT=8, IDLE=0x80` (source).

### 1.5 `ipc_port` / `ipc_space`

| Field | Offset | Evidence |
|-------|--------|----------|
| `sizeof(ipc_object)` | `0x18` | **PROVEN** — dominant `add xd,x0,#0x18` for `io_waitq` |
| `ip_waitq` | `0x18` | source + `WQ_OPAQUE_SIZE=40` on arm64 |
| `ip_messages` | `0x40` | `0x18+0x28` |
| `ip_receiver_name` | `0x4c` | `imq_receiver_name` inside mqueue |
| `ip_receiver` | `0x60` | **PROVEN** — top PAC-auth `ldr [x0,#0x60]` frequency + layout |
| `ip_kobject` | `0x68` | next union |
| `ipc_space.is_table` | `0x40` | **INFERRED** |
| `ipc_space.is_task` | `0x48` | **INFERRED** — script round-trips via `task.itk_space` |

RELEASE `sizeof(ipc_port)=144` (source static assert).

### 1.6 `vm_map` / `pmap` / saved state

| Field | Offset | Evidence |
|-------|--------|----------|
| `pmap->tte` | `0x00` | **PROVEN** (source) |
| `pmap->ttep` | `0x08` | **PROVEN** (source) |
| `vm_map.pmap` | probe `0x58,0x60,0x68,0x70,0x78` | **INFERRED** — script probes; validate `tte` looks like kernel VA |
| `arm_saved_state64.fp/lr/sp/pc` | `+0xf0 / +0xf8 / +0x100 / +0x108` from `arm_saved_state*` | **PROVEN** (header: `ash` 8 bytes + `x[29]` then fp/lr/sp/pc) |
| `arm_context.ss` | `0x00` | source — `contextData` points at `arm_context`; user GPRs in `.ss` |

Page tables: **16K granule** (`PAGE_SHIFT=14`). Walk geometry in the script is **best-effort / INFERRED** — calibrate with a known user mapping before trusting.

### 1.7 PAC

Kernel pointers are ARM64e-signed. When reading from gdb, **strip PAC** before using as addresses (script: `strip_pac`). Prefer comparing stripped values. Do not try to re-sign.

---

## 2. Script: `/workspace/xnu-t8140-walk.py`

### Usage

```text
# QEMU: -gdb tcp::1234  (or your stub)
gdb-multiarch
(gdb) target remote :1234
(gdb) source /workspace/xnu-t8140-walk.py
(gdb) walk-allproc 0x20000000
(gdb) walk-backboardd 0x20000000
(gdb) python walk_backboardd(slide=0x20000000)
(gdb) python translate_user_va(task_addr, 0x1a0000000, slide=0x20000000)
(gdb) python shared_cache_slide_hint(task_addr)
```

### What it does

1. Walks `allproc`, prints `pid` / `p_comm`/`p_name` / `proc` / `task`.
2. Finds **backboardd**, enumerates `task.threads` via `task_threads` queue links.
3. For each thread: `thread_id`, `state`, `wait_event`, `wait_result`, `ith_state`, `ith_object`.
4. Reads `upcb` / `kpcb` / `contextData` → user & kernel `pc/lr/fp/sp`; FP-unwinds kernel frames (unslid LRs for symbolicate).
5. If `TH_WAIT` and `ith_object` set: treats it as the receive port, resolves `ip_receiver` → `ipc_space` → `is_task` (with round-trip) → owner `pid/name`; also probes `ith_special_reply_port`.
6. Optional user VA walk via `task.map` → probed `pmap` → `tte`/`ttep` (prints phys; phys→kva needs physmap base).

Robustness: every read is try/except; walks are bounded; PAC stripped.

### Symbolicate unslid PCs

```bash
ipsw kernel symbolicate --lookup 0xfffffff00XXXXXXX \
  /tmp/kc-rel-syms/kernelcache.release.iPhone17,3.symbols.json
```

(Default ipsw map is mostly C++ / tables; for C functions use string-xref RE or a signatures pack. Unslid LR from the script is still the right input.)

### Shared cache slide (user backtrace)

1. Prefer `task.shared_region` → read `sr_slide` if you RE that struct on this build.
2. Or dyld `all_image_infos` in the task (needs user VA translate).
3. User PC in dyld cache: `pc - shared_cache_base` or `pc - slide` depending on how you define slide; match against `dyld_shared_cache_arm64e.symbols` under `24A437__iPhone17,3/dsc/`.

---

## 3. launchd `RequireTrusted` vs kernel

### What we know on disk

`com.apple.biomed.plist` (**PROVEN**, extracted):

```xml
PublishesEvents = {
  com.apple.biome.compute.publisher = { RequireTrusted = true };
  com.apple.biome.compute.publisher.user = { RequireTrusted = true };
  …
}
MachServices includes com.apple.biome.compute.publisher.service(.user)
```

Guest stall (§9): backboardd blocks in `xpc_set_event_stream_handler("com.apple.biome.compute.publisher")` → sync launchd routine; biomed publisher never activates; timing-independent (v37).

### Kernel facility (honest split)

| Claim | Status |
|-------|--------|
| `RequireTrusted` is a **launchd/xpc** policy on event publishers | **PROVEN** (plist key; not a kernel string — absent from KC/dsc search for `RequireTrusted`) |
| cryptexd log `security.mac.image4.kmod.evaluate_trust: trap not present` is **the** RequireTrusted check | **INFERRED / likely false** — that trap is Image4 **kmod** trust for cryptex; KC has related sysctls (`security.mac.image4.nonce.*`, `security.mac.image4.image.activate`) but **no** `evaluate_trust` / `RequireTrusted` string in the kernelcache |
| launchd likely checks publisher **CS / platform** flags (`CS_PLATFORM_BINARY` / `TFRO_PLATFORM` / AMFI) via task/csops-style queries when registering a `RequireTrusted` stream | **INFERRED** — classic launchd behavior; **not** confirmed on this iOS 27 `launchd` binary yet |
| A **kernelcache patch** making Image4 `evaluate_trust` succeed | **Probably irrelevant** to this biome check-in if the check is pure launchd codesign policy; would only matter if launchd actually calls that trap (unproven) |
| A **kernelcache patch** forcing `TFRO_PLATFORM` / csflags for biomed | **Possible** if RE of launchd shows that path — heavier and AMFI-adjacent; still needs launchd confirmation |

### launchd binary

`launchd` is **not** in the dyld shared cache. Remote extract was started:

```bash
ipsw extract --files --pattern 'sbin/launchd$' -o /tmp/launchd-extract \
  --remote 'https://updates.cdn-apple.com/2026FallFCS/5130b3f9-3b4e-469a-b60e-93f6b310cdd9/iPhone17,3_27.0_24A437_Restore.ipsw'
```

Once present: `strings`/`rg` for `RequireTrusted`, then xref in a disassembler to see whether it calls into AMFI/csops, `task_info`, or an Image4 trap.

Until then: **do not** spend a week on a launch-cache editor or Image4 stub solely on the cryptexd log line. Prefer:

1. **gdb walk** (this kit) — see which port / `wait_event` backboardd sleeps on and which task owns the receive right (launchd vs biomed vs none).
2. launchd/libxpc Debug logging (data-only).
3. Only after launchd RE: decide kernel patch vs plist/`RequireTrusted` strip vs publisher activation fix.

---

## 4. Suggested gdb session (stuck biome check-in)

1. Break / interrupt when guest is in the known stall window (~90s+).
2. `walk-backboardd 0x20000000`.
3. Find the thread with `TH_WAIT` + last log was biome activate (~tid matching sequencer).
4. Note `wait_event`, `ith_object`, port owner pid/name.
5. If owner is **launchd**: inspect launchd threads the same way (`find_proc_by_name("launchd")` pattern — add a one-liner or reuse walk).
6. If owner is **biomed** or port has no receiver: publisher never checked in / trust path failed.
7. Kernel stack unslid LRs → `ipsw kernel symbolicate --lookup` (or manual) for `ipc_mqueue_receive` / `mach_msg` / `assert_wait`.

---

## 5. Uncertainty checklist

| Item | Trust |
|------|-------|
| `allproc`, `kernproc` slot, `p_pid`, `p_comm`, `proc_struct_size`, `thread_id`, `ith_state`/`ith_object`, `ip_receiver` | High (PROVEN) |
| task/thread encoding field offsets (`map`, `threads`, `wait_event`, machine.*, `task_threads`) | High (ENC matches source order) |
| `wait_result` exact byte, `kstackptr` exact, `ith_special_reply_port` exact | Medium |
| `ipc_space.is_task`, `vm_map.pmap` | Medium/low — **probe on guest** |
| 16K page-table walk indices | Low until calibrated |
| launchd RequireTrusted → Image4 trap | Low (probably wrong coupling) |

Untested on a live QEMU session in this turn: all offsets labeled INFERRED; PROVEN offsets are from static disassembly only (no guest read-back here).

---

## 6. Files

| Path | Role |
|------|------|
| `/workspace/xnu-t8140-walk.py` | gdb Python walker |
| `/workspace/ios-linux-emulator-gdb-kit.md` | this doc |
| `/workspace/ios27-re/24A437__iPhone17,3/kernelcache.release.iPhone17,3` | guest KC |
| `/tmp/kern-res/com.apple.kernel` | extracted fileset entry used for RE |
| `/tmp/kc-rel-syms/kernelcache.release.iPhone17,3.symbols.json` | ipsw C++/table symbols |
| `/workspace/ios27-re/xnu-src` | xnu-12377.121.6 layouts |
