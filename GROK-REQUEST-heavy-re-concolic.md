# Request to Grok — heavy static RE + unicorn concolic for the iOS 27 / t8140 GUI gate-chain

Target: iOS 27 **24A437**, SoC **t8140** (A18, iPhone17,3), kernel **H17P / xnu-13432.2.10 RELEASE_ARM64_T8140**, apfs 3288.2.1, sandbox 300.0, AMFI 1.0.5. QEMU "apple-modern" board (direct kernel/ramdisk boot, no iBoot, no SEP).

Address note: my VAs are from the **release** kernelcache `bootkc` (sha a36b9241), `file_off = VA − 0xfffffff007004000`, runtime slide `0x20000000`. Your `kernelcache.research.iPhone17,3` differs by ~1.6 MB in places — please **cross-reference by the quoted strings/symbols** (stable) and give me your research-KC VAs + on-disk bytes back. Your toolchain (ipsw extract of com.apple.kernel / com.apple.filesystems.apfs / com.apple.security.sandbox / AMFI, `mlib.py`, and your `dcp-symex` unicorn concolic harness) is the right environment; angr is being stood up on my side for isolated-function constraint solving but you own the deep static + concolic.

Deliverable style (as in your prior addenda): per item give the function + VA, disasm evidence, exact on-disk bytes, a minimal **opt-in kernelcache byte-patch** candidate (old word → new word, with decode), confidence, and honest bounds.

## Already established (build on this; do NOT redo)
- **Root cause of the whole GUI blockage = restore-mode boot.** `rd=md0` makes launchd enter "Restore environment" and **skip all ~25 boot-tasks** (keybag, data-protection, usermanagerd/persona, dirs_cleaner, mount-phase, fsck…). Result: persona type 6 never created, container store never set up, user/501 "on-demand-only" → containermanagerd can't provision biomed's container → biomed xpcproxy stalls ~169 s → temporary-sandbox → `com.apple.biome.compute.publisher` not ready when backboardd's AttentionAwareness subscribes (~54 s) → backboardd main thread wedges → no window server → no IOMFB open → no CADisplay mint → `FBSDisplayLayoutService publishing nil` (null id `0xFFFFFFFFFFFFFFFF`) → no SpringBoard.
- **Trust/CS is NOT the wedge** (I forced `csops(CS_OPS_STATUS)`→CS_PLATFORM_BINARY and `csproc_get_platform_binary`→1 kernel-wide; byte-identical wedge). Your APFS-81 (ENEEDAUTH) correction confirmed: tolerated, not the stall.
- **HPD subscribe mechanism recovered**: IOMobileFramebufferUserClient **selector 72** `s_set_notify` (@0xa181b38) → `set_notify` (@0xa17fb24) → provider vtable **0x698** `add_notification` (@0xa153c88), `ilk=scalarInput[2]`, ilk 0 = hotplug. `s_map_display_type` = **sel 88**, stores type→UC+0x10c, filtered by `hotPlug_notify_gated` (@0xa156c24, `cmp w10,#1`). Caller is QuartzCore's in-process display client (`IOMobileFramebufferEnableHotPlugDetectNotifications`) — userspace, no dyld TEXT available to me.
- **Staged DCP getters** in the model: A353 `display_healthcheck_rate_ns`→1 h; A437 `get_block`→present; A410/A411 is_main_display→true; A103/A453 size→1024×768; ProductAttributes Name/ProductName/DeviceName="Built-in Display".
- **Constraint for me (not you)**: my dyld subcache is linkedit-only, so CoreDisplay/containermanagerd/full-system-launchd bodies are unreachable on my side — those are where I most need your help or a TEXT-bearing cache.

## P1 — rootvp-auth: let `rootdev=md0` boot (THE gate to normal mode)
`rootdev=md0` (which launchd does NOT match as restore) panics: `rootvp not authenticated after mounting @bsd_init.c:976`.
- String `"rootvp not authenticated after mounting @%s:%d"` @ release file 0x9547f (VA 0x709947f).
- Panic call @ VA `0xfffffff00b091f18` (`adrp x0,0x7099000; add #0x47f; bl panic`), line `mov w9,#0x3d0`(976).
- Cold block `0xb091dfc..0xb091f18` entered by 14 guards (decode branches from raw words — capstone linear disasm desyncs here): `0xb0911b4 b.ne→ec0; 0xb091320 b.lo→dfc; 0xb091360 b.lo→e08; 0xb0913a4 b.lo→e14; 0xb0915ec b.ne→ee0; 0xb091800 b.lo→e20; 0xb09181c cbz→e58; 0xb09185c cbnz→e74; 0xb091b40 b.eq→e2c; 0xb091b5c cbz→e2c; 0xb091b78 cbnz→e2c; 0xb091c58 b.ne→e9c` (targets are `0xb091...`).
- Candidate auth region `0xb091b20..b78`: `ldr x0,[0xb790000+0xd88]` (root mount/vnode global `0xb790d88`); `ldr w8,[x0,#0x70]; orr w8,#0x4000; str`; vtable `blraa x8` with `cbnz w0 → panic`.
ASK: How does the `rd=md0` path currently SKIP this check (the ramdisk-boot detection / global set from the `rd=` boot-arg — `bsd_rooted_ramdisk`/`IORamDiskBSDRoot`-style)? Which single guard differs for `rootdev=md0`? Give the minimal patch so `rootdev=md0` takes the authenticated path without breaking `rd=md0`. If a clean "if booted-from-ramdisk skip auth" branch exists, prefer making it unconditional-skip. **Concolic**: solve for the boot-arg/global state that makes the taken path = authenticated.

## P2 — RequireSuccess boot-tasks / SEP after normal boot
With normal boot the boot-tasks RUN; several are `RequireSuccess` and likely fail on our missing SEP/sealed-volume: **keybag, data-protection, fsck, mount-phase-1/2, fips, tzinit, launchd_cache_loader**. From /sbin/launchd (boot-task table) + the kexts: which are RequireSuccess (fatal), what each needs, which fail in a no-SEP emulation, and for each — can it pass via DATA (dtree/fs) or a kernelcache patch, or must it be skipped safely? Rank. This is the SEP wall; be blunt about depth.

## P3 — persona type 6 + container provisioning
`kpersona_find_by_type(6)`→ESRCH. What is persona type 6 (enum)? What creates it (`usermanagerd --init` + keybag on Data — kernel vs userspace role)? Would a normal boot (keybag + usermanagerd boot-tasks) create persona 6 + the container store and thus clear the biomed stall, or are there further keybag/SEP gaps? Minimal conditions for containermanagerd to provision biomed's container fast.

## P4 — biomed 169 s xpcproxy stall (confirm userspace vs fixable)
Kernel anchors for the container path: `Sandbox temporary-sandbox` @file 0xc2c212; `Invalid persona_uuid … not present in keybag, volume mapping failed!` @ 0x7297e9; `container_inspect_for_proc(): no user state for pid` @ 0xb58f75. Is the 169 s a fixed timeout in the xpcproxy↔containermanagerd↔persona round-trip, and is a kernel-side fail-fast viable, or is it strictly resolved by P3 (persona)? (containermanagerd/xpcproxy bodies are userspace — your reach, not mine.)

## P5 — DCP main-display mint getters (concolic on t8140dcp.bin)
Grok mainDisplay predicate: `+[CADisplay mainDisplay]` global `0x1e7025308`, set only when a CARenderServer reply dict carries `kCADisplayName`+`kCADisplayDeviceName` comparing LCD/Internal (userspace CoreDisplay register 0x18475d3c0, lookup 0x1843ff330). OPEN values I need the exact reply bytes for (built-in 1024×768 LCD): the **display-ID/EDID source** (why BLSDisplayReference id stays `0xFFFF…`), `A413 get_display_area`(in8/out4), `A414 get_display_area`(in8/out8), color/gamma/matrix getters, `A034 update_notify_clients_dcp`(8/8), `A033`(44/44), `A384`(0/4). **Concolic ask**: run each handler in `t8140dcp.bin` under your dcp-symex harness and recover the reply struct the kernel/CoreDisplay validates.

## P6 — HPD delivery filter
Confirm what per-client state (`UC+0x10c` display type, filtered by `hotPlug_notify_gated` `cmp w10,#1` @0xa156c24) the held HPD edge (`hpdState 1`) requires so that once the window server calls selector 72, delivery actually fires and CoreDisplay mints.

## P7 — DCP swap path for real pixels (concolic-heavy)
Recover, via unicorn concolic on `t8140dcp.bin`: **A407 real `swap_submit`** (~7472 B struct — the fields that matter: surface DVA, stride, size, pixel format, src/dst rect, swap_id) and its ACK; **D201/D202 `map_buf`/`unmap_buf`**; and the **`D575 hotPlug_notify` `IOMFB_TiledDisplayInfo`** struct (in≥0x58/out 0x4c — layout unrecovered; I currently send it null-flagged). These are the last mile to a composited frame once mint succeeds.

## P8 — ENEEDAUTH / root-snapshot (your earlier Tier A/C; confirm relevance after P1)
`apfs_find_named_root_snapshot_xid` returns ENEEDAUTH via `mov w20,#0x51` @ your `0xfffffff00a9cf92c` because the apfs payload global (`0xb999000+0xf8` your base) is NULL (no `/chosen/system-volume-auth-blob`). DT fallback `/chosen/root-snapshot-name` @ `0xfffffff00a94f5d8`. Confirm whether, once P1 (rootvp-auth) is patched, this still needs the DT `root-snapshot-name` data fix or the one-word NOP — or becomes moot.

## Synthesis I need from you
Ordered roadmap current-state → composited SpringBoard frame; per gate: fix kind (data/kernelcache-patch/userspace), exact bytes/values, concolic-recovered where applicable, confidence; the single hardest gate; and the first concolic experiments to run. Flag anything that needs a TEXT-bearing dyld_shared_cache (userspace) that I should source for you.
