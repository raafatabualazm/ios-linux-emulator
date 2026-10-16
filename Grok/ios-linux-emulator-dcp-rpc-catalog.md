# T8140 / iOS 27 (24A437) DCP RPC catalog

Assets: `kernelcache.release.iPhone17,3` kexts AppleMobileDispH17P-DCP + IOMobileGraphicsFamily-DCP; Asahi `m1n1/fw/dcp/ipc.py`; emulator `ied-hpd/.../modern-dcp-iop.c`.

Confidence: **proven** = this BootKC strings/sizes/disasm; **asahi** = name from Asahi tables; **inferred/uncertain** = guess.

## Method
1. Found 5 DCP→AP lookup functions (tag→handler) by `mov x0,#0` + `movk w8,#0x44xx` pattern; unicorn-emulated every D000–D999 against PAC-stripped lookups → **127 handlers**.
2. Extracted min in/out lengths from each handler’s `cmp w3`/`cmp w5` gates (kIOReturnBadArgument `0xe00002c2` on fail).
3. AP→DCP: scanned `movk …,#0x413x` immediates at call sites → **~248 A tags** with (in_len,out_len) in w3/w5.
4. Names: Asahi ipc.py + this-kext strings (hotPlug, setDCPAVProp*, start_hardware_boot, SystemConsoleMode, …).
5. **angr**: not used — arm64e PAC defeats default angr. Fallback = unicorn concrete + guided disasm (documented below).

## ABI vs Asahi (important)
| Item | This BootKC | Asahi V13.5 | Asahi V14.7 |
|---|---|---|---|
| removeProperty | **D106** (in≥0x40) | D107 | D107 |
| create_provider… | **D107–D110** | D108–D111 | D108–D111 |
| start_hardware_boot | **D120** | D120 | D121 |
| setDCPAVPropStart/Chunk/End | **D126/127/128** | D126/127/128 | D127/128/129 |
| hotPlug_notify_gated | **D575** (in≥0x58, vtable+0x8c8) | D576 | D576 |
| setSystemConsoleMode | **D600** | (near D594) | — |

Emulator startup CB list D107–D110 as create_* is **correct for this kernel**.

## D128 / ProductAttributes constraint (guided, not angr)
`setDCPAVPropEnd` @ `0xfffffff0091ed910`:
- Requires prior Start+Chunk (else “setDCPAVPropStart not called”).
- Writes `buf[len-1] = 0`, then `OSUnserializeXML(buf, len)`.
- On success: `setProperty(key, obj)`; on fail logs `OSUnserializeXML failed`.
- Emulator must pass **NUL-terminated** XML whose length **includes** the NUL (already noted in `modern-dcp-iop.c`).
- Key is `char[0x40]` with forced NUL at `[0x3f]` in the D128 wrapper.

## Top gaps vs emulator (boot-path first)

| Pri | Tag | Issue | Why it matters |
|---|---|---|---|
| 1 | *(process)* | backboardd Biome stall | No CA WindowServer → no HPD registrant; D575 stays “not registered yet”. Display mint is blocked **above** DCP. |
| 2 | A* ALLZERO | Most A replies are zero-filled | After HPD, CA reads modes/properties; zeros can keep display “nil”. |
| 3 | D111/D112 | create_backlight / nvram never sent | Startup only sends D107–D110; backlight match may fail later. |
| 4 | D201/D202 | map_buf/unmap_buf not stubbed | Needed once swaps start; today never reached. |
| 5 | A407 large | swap_submit only special-cased when in<0x80 | Real submit is ~7KB; ALLZERO will break presentation. |
| 6 | A437 | get_block_dcp returns zeros | Timing/param blocks empty. |
| 7 | D576–D593 | Not in attach set | Mac numbering must not be used (already learned). |
| 8 | ProductAttributes | Optional vs TimingElements | v10 experiment; mint needs TimingElements+HPD listener more than ProductAttributes. |
| 9 | D575 out 0x4c | Emulator leaves out area as 0xdeadbeef pattern only for out_len==4 | For D575 out=0x4c, ensure status path returns 0 (handler writes tiled copy when nullflag=0). |
| 10 | A353 | Nonzero ns period required | Already stubbed to 1h; keep nonzero. |

## Full DCP→AP table (handlers found)

| Tag | Name | in≥ | out≥ | Emu | Conf |
|---|---|---:|---:|---|---|
| D000 | did_boot_signal | — | 4 | sent_startup_cb | proven |
| D001 | did_power_on_signal | — | 4 | sent_startup_cb | proven |
| D107 | create_provider_service | — | 4 | sent_startup_cb | proven-size+emu |
| D108 | create_product_service | — | 4 | sent_startup_cb | proven-size+emu |
| D109 | create_PMU_service | — | 4 | sent_startup_cb | proven-size+emu |
| D110 | create_iomfb_service | — | 4 | sent_startup_cb | proven-size+emu |
| D300 | pr_publish | 16 | — | sent_startup_cb | proven |
| D104 | set_boolean_property | 68 | — | sent_startup_cb | proven |
| D102 | set_number_property | 68 | — | sent_startup_cb | proven |
| D120 | start_hardware_boot | — | 4 | sent_startup_cb | proven-str |
| D126 | setDCPAVPropStart | 4 | 4 | sent_attach_MODES | proven-str |
| D127 | setDCPAVPropChunk | 4104 | 4 | sent_attach_MODES | proven-str+emu |
| D128 | setDCPAVPropEnd | 64 | 4 | sent_attach_MODES | proven-str |
| D575 | hotPlug_notify_gated | 88 | 76 | sent_attach_D575 | proven-disasm |
| D600 | setSystemConsoleMode_gated | 4 | — | sent_attach_D600 | proven-str |
| D201 | map_buf | 12 | — | missing | proven-str |
| D202 | unmap_buf | 24 | — | missing | proven-str |
| D594 | swap_complete_ap_gated | 1840 | — | missing | proven-str |
| D582 | swap_complete_head_of_line | 12 | — | missing | proven-str |
| D002 | will_power_off_signal | — | — | missing | asahi+size |
| D003 | rt_bandwidth_setup_ap | 4 | 20 | missing | proven-str |
| D004 | — | 8 | — | missing | table-only |
| D005 | — | 8 | — | missing | table-only |
| D006 | set_frame_sync_props | 84 | 80 | missing | asahi+size |
| D007 | — | 4 | — | missing | table-only |
| D100 | match_pmu_service | — | — | missing | asahi |
| D101 | UNK_get_some_field | — | 4 | missing | asahi |
| D103 | trigger_user_cal_loader | — | — | missing | proven-str |
| D105 | set_property (bool/dict?) | 128 | — | missing | inferred |
| D106 | removeProperty | 64 | — | missing | proven-size |
| D111 | create_backlight_service | — | 4 | missing | asahi-shifted |
| D112 | create_nvram_service OR set_idle | — | 4 | missing | uncertain |
| D113 | create_nvram_service | — | — | missing | uncertain |
| D114 | get_tiling_state | 16 | — | missing | asahi-name-only |
| D115 | set_tiling_state | 16 | — | missing | asahi-name-only |
| D116 | cb_start_hardware_boot | 12 | — | missing | asahi-name-only |
| D117 | set_idle_caching_state_ap | 20 | — | missing | asahi-name-only |
| D118 | cb_is_waking_from_hibernate | — | — | missing | asahi-name-only |
| D119 | — | 4 | — | missing | table-only |
| D121 | is_dark_boot | — | 4 | missing | proven-str kern.darkboot |
| D122 | cb_setDCPAVPropStart | — | 4 | missing | asahi-name-only |
| D123 | cb_setDCPAVPropChunk | — | 4 | missing | asahi-name-only |
| D124 | read_edt_data | 100 | — | missing | proven-str |
| D125 | cb_read_edt_data | 72 | — | missing | asahi-name-only |
| D129 | allocate_bandwidth | 28 | — | missing | asahi |
| D130 | cb_allocate_bandwidth | 8 | — | missing | asahi-name-only |
| D131 | — | 16 | — | missing | table-only |
| D132 | — | 4 | — | missing | table-only |
| D133 | — | — | 4 | missing | table-only |
| D200 | — | — | 4 | missing | table-only |
| D203 | — | — | 4 | missing | table-only |
| D204 | — | — | 4 | missing | table-only |
| D205 | — | 12 | — | missing | table-only |
| D206 | match_pmu_service_2 | — | 4 | missing | asahi |
| D207 | match_backlight_service | — | 4 | missing | asahi |
| D208 | cb_get_calendar_time_ms | 4 | — | missing | asahi-name-only |
| D209 | cb_get_calendar_time_ms | — | 8 | missing | asahi-name-only |
| D210 | — | 4 | 1308 | missing | table-only |
| D211 | cb_update_backlight_factor_prop | 4 | 20 | missing | asahi-name-only |
| D400 | get_property | 76 | — | missing | proven-str |
| D401 | sr_get_uint_prop | 80 | — | missing | asahi |
| D402 | — | 76 | — | missing | table-only |
| D403 | — | 76 | — | missing | table-only |
| D404 | sr_set_uint_prop | 72 | — | missing | asahi |
| D405 | — | 76 | — | missing | table-only |
| D406 | set_fx_prop | 72 | — | missing | asahi |
| D407 | — | 72 | — | missing | table-only |
| D408 | sr_getClockFrequency | 8 | — | missing | asahi-name-only |
| D409 | — | 12 | — | missing | table-only |
| D410 | — | 20 | — | missing | table-only |
| D411 | sr_mapDeviceMemoryWithIndex | 16 | — | missing | proven-str |
| D412 | — | 1096 | — | missing | table-only |
| D413 | sr_setProperty_dict | — | — | missing | asahi-name-only |
| D414 | sr_setProperty_int | 80 | — | missing | asahi-name-only |
| D415 | sr_setProperty_bool | 76 | — | missing | asahi-name-only |
| D416 | — | 132 | — | missing | table-only |
| D417 | — | 1096 | — | missing | table-only |
| D418 | — | — | — | missing | table-only |
| D419 | — | 80 | — | missing | table-only |
| D420 | — | 76 | — | missing | table-only |
| D421 | — | 132 | — | missing | table-only |
| D422 | — | 72 | — | missing | table-only |
| D423 | — | 68 | — | missing | table-only |
| D424 | — | 68 | — | missing | table-only |
| D450 | — | 8 | — | missing | table-only |
| D451 | allocate_buffer | 20 | — | missing | proven-str |
| D452 | map_physical | 8 | — | missing | asahi |
| D453 | withAddressRange | 8 | — | missing | asahi |
| D454 | release_descriptor | 4 | — | missing | proven-str |
| D550 | — | 1092 | — | missing | table-only |
| D551 | — | — | — | missing | table-only |
| D552 | setProperty_dict | — | — | missing | asahi-name-only |
| D553 | — | — | — | missing | table-only |
| D554 | — | 76 | — | missing | table-only |
| D555 | — | 76 | — | missing | table-only |
| D556 | — | 72 | — | missing | table-only |
| D557 | — | 128 | — | missing | table-only |
| D558 | — | 128 | — | missing | table-only |
| D559 | — | 1092 | — | missing | table-only |
| D560 | — | — | — | missing | table-only |
| D561 | setProperty_dict | — | — | missing | asahi-name-only |
| D562 | — | — | — | missing | table-only |
| D563 | setProperty_int | 76 | — | missing | asahi-name-only |
| D564 | — | 76 | — | missing | table-only |
| D565 | setProperty_bool | 72 | — | missing | asahi-name-only |
| D566 | — | 128 | — | missing | table-only |
| D567 | setProperty_str | 128 | — | missing | asahi-name-only |
| D568 | — | 128 | — | missing | table-only |
| D569 | — | 68 | — | missing | table-only |
| D570 | — | — | — | missing | table-only |
| D571 | — | 8 | — | missing | table-only |
| D572 | powerUpDART | 4 | — | missing | proven-str |
| D573 | — | 4 | — | missing | table-only |
| D574 | powerUpDART | 4 | — | missing | asahi-name-only |
| D576 | get_dot_pitch OR powerstate (shifted) | 4 | — | missing | uncertain-vs-asahi |
| D577 | powerstate_notify | 8 | — | missing | asahi-name-only |
| D578 | idle_fence_create | — | — | missing | asahi-name-only |
| D579 | idle_fence_complete | 4 | — | missing | asahi-name-only |
| D580 | — | — | — | missing | table-only |
| D581 | swap_complete_head_of_line | — | — | missing | asahi-name-only |
| D583 | serializeDebugInfoCb | 4 | — | missing | asahi-name-only |
| D584 | clear_default_surface | — | — | missing | asahi-name-only |
| D585 | — | 12 | — | missing | table-only |
| D586 | create_default_fb_surface | 8 | — | missing | proven-str |
| D587 | — | — | — | missing | table-only |
| D588 | resize_default_fb_surface_gated | 24 | — | missing | asahi-name-only |
| D589 | swap_complete_ap_gated | 228 | — | missing | asahi-name-only |
| D590 | — | 20 | — | missing | table-only |
| D591 | swap_complete_intent_gated | 4 | — | missing | asahi-name-only |
| D592 | abort_swap_ap_gated | — | — | missing | asahi-name-only |
| D593 | enable_backlight_message_ap_gated | 8 | — | missing | asahi-name-only |
| D595 | swap_complete batch? | — | — | missing | proven-str |
| D596 | isDFBAllocated | 20 | — | missing | asahi-name-only |
| D597 | preserveContents | 4 | — | missing | asahi-name-only |
| D598 | find_swap_function_gated | 4 | — | missing | asahi-name-only |
| D599 | — | 4 | — | missing | table-only |
| D601 | — | — | 4 | missing | table-only |
| D602 | — | — | 4 | missing | table-only |
| D603 | find_swap_function / iomfb_swap_fn | — | — | missing | proven-str |
| D700 | — | 4 | — | missing | table-only |

## Full AP→DCP table (call sites)

| Tag | Name | in | out | Emu | Conf |
|---|---|---:|---:|---|---|
| A401 | start_signal | 0 | 4 | bool_true | asahi |
| A000 | late_init_signal | 4 | 4 | bool_true | asahi |
| A352 | applyProperty | 8 | 4 | bool_true | asahi |
| A353 | display_healthcheck_rate_ns | 0 | 8 | u64_1h_ns | proven-str |
| A453 | get_display_size | 4 | 8 | size_1024x768 | proven |
| A443 | do_create_default_frame_buffer | 12 | 4 | size_1024x768 | asahi-name-only |
| A441 | display_height | 4204 | 4 | width_1024 | asahi-name-only |
| A442 | get_display_size | 92 | 4100 | height_768 | asahi-name-only |
| A410 | is_main_display / set_display_device | 8 | 4 | bool_true | emu+asahi-shift |
| A411 | is_main_display | 4 | 4 | bool_true | emu |
| A412 | get_digital_out_state | 0 | 4 | status_0 | emu |
| A406 | swap_start_dcp | 16 | 8 | swap_id++ | asahi-v14.7 |
| A407 | swap_submit_dcp | 7472 | 12 | swap_id++ | asahi-v14.7 |
| A472 | setPowerState | 0 | 4 | echo_power | asahi-name-only |
| A001 | — | 0 | 4 | ALLZERO | callsite-only |
| A002 | — | 0 | 0 | bool_true | callsite-only |
| A003 | — | 4 | 0 | void_ack | callsite-only |
| A004 | — | 4 | 0 | void_ack | callsite-only |
| A005 | — | 4 | 0 | void_ack | callsite-only |
| A006 | — | 4 | 0 | void_ack | callsite-only |
| A007 | — | 4 | 0 | void_ack | callsite-only |
| A008 | — | 4 | 0 | void_ack | callsite-only |
| A009 | — | 4 | 0 | void_ack | callsite-only |
| A010 | — | 4 | 0 | void_ack | callsite-only |
| A011 | — | 8 | 0 | void_ack | callsite-only |
| A012 | — | 8 | 0 | void_ack | callsite-only |
| A013 | — | 4 | 0 | void_ack | callsite-only |
| A014 | — | 0 | 4 | ALLZERO | callsite-only |
| A015 | — | 0 | 4 | ALLZERO | callsite-only |
| A016 | — | 4 | 0 | void_ack | callsite-only |
| A017 | — | 0 | 0 | void_ack | callsite-only |
| A018 | — | 0 | 4 | ALLZERO | callsite-only |
| A019 | — | 0 | 4 | ALLZERO | callsite-only |
| A020 | — | 0 | 4 | bool_true | callsite-only |
| A021 | — | 0 | 0 | void_ack | callsite-only |
| A022 | — | 12 | 8 | ALLZERO | callsite-only |
| A023 | — | 0 | 4 | ALLZERO | callsite-only |
| A024 | — | 0 | 0 | bool_true | callsite-only |
| A025 | — | 0 | 4 | ALLZERO | callsite-only |
| A026 | — | 0 | 4 | ALLZERO | callsite-only |
| A027 | — | 0 | 4 | ALLZERO | callsite-only |
| A028 | — | 0 | 0 | void_ack | callsite-only |
| A029 | setup_video_limits | 8 | 4 | ALLZERO | asahi-name-only |
| A030 | — | 108 | 0 | bool_true | callsite-only |
| A031 | — | 0 | 4 | bool_true | callsite-only |
| A032 | — | 0 | 4 | bool_true | callsite-only |
| A033 | — | 44 | 44 | ALLZERO | callsite-only |
| A034 | update_notify_clients_dcp | 8 | 8 | ALLZERO | asahi-name-only |
| A035 | is_hilo | 0 | 8 | bool_true | asahi-name-only |
| A036 | apt_supported | 0 | 4 | bool_true | asahi-name-only |
| A037 | get_dfb_info | 0 | 4 | bool_true | asahi-name-only |
| A038 | get_dfb_compression_info | 0 | 4 | ALLZERO | asahi-name-only |
| A039 | — | 0 | 4 | ALLZERO | callsite-only |
| A040 | — | 0 | 0 | void_ack | callsite-only |
| A041 | — | 8 | 4 | ALLZERO | callsite-only |
| A100 | — | 4 | 3088 | ALLZERO | callsite-only |
| A101 | — | 3088 | 4 | ALLZERO | callsite-only |
| A102 | test_control | 8 | 4 | ALLZERO | asahi-name-only |
| A103 | get_config_frame_size | 12 | 8 | size_1024x768 | asahi-name-only |
| A104 | set_config_frame_size | 8 | 0 | void_ack | asahi-name-only |
| A105 | program_config_frame_size | 0 | 0 | void_ack | asahi-name-only |
| A106 | — | 0 | 4 | ALLZERO | callsite-only |
| A107 | — | 0 | 4 | ALLZERO | callsite-only |
| A108 | — | 4 | 4 | ALLZERO | callsite-only |
| A109 | — | 0 | 4 | ALLZERO | callsite-only |
| A110 | — | 4 | 0 | void_ack | callsite-only |
| A111 | — | 12 | 0 | void_ack | callsite-only |
| A112 | — | 4 | 4 | ALLZERO | callsite-only |
| A113 | — | 16 | 4 | ALLZERO | callsite-only |
| A114 | — | 0 | 0 | void_ack | callsite-only |
| A115 | aot_enabled | 0 | 4 | bool_true | asahi-name-only |
| A116 | — | 0 | 4 | bool_true | callsite-only |
| A117 | — | 4 | 4 | ALLZERO | callsite-only |
| A118 | — | 12 | 12 | ALLZERO | callsite-only |
| A119 | — | 4204 | 4 | ALLZERO | callsite-only |
| A120 | — | 92 | 4100 | ALLZERO | callsite-only |
| A121 | — | 12 | 4 | ALLZERO | callsite-only |
| A122 | — | 4204 | 4 | ALLZERO | callsite-only |
| A123 | — | 24 | 4 | ALLZERO | callsite-only |
| A124 | — | 12 | 4 | ALLZERO | callsite-only |
| A125 | — | 12 | 4 | ALLZERO | callsite-only |
| A126 | — | 20 | 8 | ALLZERO | callsite-only |
| A127 | — | 128 | 124 | ALLZERO | callsite-only |
| A128 | — | 128 | 4 | ALLZERO | callsite-only |
| A129 | — | 52 | 52 | ALLZERO | callsite-only |
| A130 | init_ca_pmu | 4 | 0 | bool_true | asahi-name-only |
| A131 | pmu_service_matched | 4 | 0 | bool_true | asahi-name-only |
| A132 | backlight_service_matched | 32 | 4 | bool_true | asahi-name-only |
| A133 | — | 0 | 4 | ALLZERO | callsite-only |
| A134 | — | 0 | 0 | void_ack | callsite-only |
| A135 | — | 0 | 4 | ALLZERO | callsite-only |
| A136 | — | 0 | 4 | ALLZERO | callsite-only |
| A137 | — | 0 | 4 | ALLZERO | callsite-only |
| A200 | — | 8 | 4 | handled | callsite-only |
| A201 | — | 8 | 4 | handled | callsite-only |
| A202 | — | 8 | 4 | ALLZERO | callsite-only |
| A203 | — | 8 | 4 | ALLZERO | callsite-only |
| A204 | — | 4 | 4 | bool_true | callsite-only |
| A205 | — | 4 | 4 | ALLZERO | callsite-only |
| A206 | — | 4 | 4 | ALLZERO | callsite-only |
| A350 | — | 0 | 4 | height_768 | callsite-only |
| A351 | — | 0 | 4 | width_1024 | callsite-only |
| A354 | — | 16 | 12 | ALLZERO | callsite-only |
| A355 | — | 1500 | 1492 | ALLZERO | callsite-only |
| A356 | — | 0 | 4 | ALLZERO | callsite-only |
| A357 | set_create_DFB | 112 | 104 | ALLZERO | asahi-name-only |
| A358 | vi_set_temperature_hint | 0 | 4 | ALLZERO | asahi-name-only |
| A359 | — | 20 | 8 | ALLZERO | callsite-only |
| A360 | — | 0 | 4 | ALLZERO | callsite-only |
| A361 | — | 4 | 0 | void_ack | callsite-only |
| A362 | — | 4 | 0 | void_ack | callsite-only |
| A363 | — | 4 | 0 | void_ack | callsite-only |
| A364 | — | 124 | 116 | ALLZERO | callsite-only |
| A365 | — | 124 | 116 | ALLZERO | callsite-only |
| A366 | — | 4 | 0 | void_ack | callsite-only |
| A367 | — | 36 | 32 | ALLZERO | callsite-only |
| A368 | — | 36 | 32 | ALLZERO | callsite-only |
| A369 | — | 0 | 4 | ALLZERO | callsite-only |
| A370 | — | 4 | 8 | ALLZERO | callsite-only |
| A371 | — | 4 | 8 | ALLZERO | callsite-only |
| A372 | — | 12 | 12 | ALLZERO | callsite-only |
| A373 | get_system_type | 12 | 12 | ALLZERO | asahi-name-only |
| A374 | vi_set_temperature_hint | 1500 | 1492 | ALLZERO | asahi-name-only |
| A375 | — | 24 | 20 | ALLZERO | callsite-only |
| A376 | — | 8 | 12 | ALLZERO | callsite-only |
| A377 | set_create_DFB | 20 | 20 | ALLZERO | asahi-name-only |
| A378 | vi_set_temperature_hint | 40 | 32 | ALLZERO | asahi-name-only |
| A379 | — | 0 | 4 | ALLZERO | callsite-only |
| A380 | — | 0 | 4 | ALLZERO | callsite-only |
| A381 | — | 0 | 20 | bool_true | callsite-only |
| A382 | — | 0 | 0 | void_ack | callsite-only |
| A383 | — | 0 | 4 | ALLZERO | callsite-only |
| A384 | — | 0 | 4 | ALLZERO | callsite-only |
| A385 | — | 0 | 4 | ALLZERO | callsite-only |
| A386 | — | 0 | 4 | ALLZERO | callsite-only |
| A387 | — | 4 | 0 | void_ack | callsite-only |
| A388 | — | 52 | 52 | ALLZERO | callsite-only |
| A389 | — | 0 | 0 | void_ack | callsite-only |
| A390 | — | 0 | 4 | ALLZERO | callsite-only |
| A391 | — | 4 | 4 | ALLZERO | callsite-only |
| A392 | — | 0 | 4 | ALLZERO | callsite-only |
| A393 | — | 0 | 0 | void_ack | callsite-only |
| A394 | — | 0 | 4 | ALLZERO | callsite-only |
| A395 | — | 4 | 0 | void_ack | callsite-only |
| A396 | — | 0 | 0 | void_ack | callsite-only |
| A397 | — | 0 | 4 | ALLZERO | callsite-only |
| A398 | — | 0 | 0 | void_ack | callsite-only |
| A399 | — | 0 | 4 | ALLZERO | callsite-only |
| A400 | — | 0 | 0 | void_ack | callsite-only |
| A402 | — | 0 | 0 | void_ack | callsite-only |
| A403 | — | 0 | 0 | void_ack | callsite-only |
| A404 | — | 12 | 4 | ALLZERO | callsite-only |
| A405 | — | 0 | 4 | ALLZERO | callsite-only |
| A408 | swap_submit_dcp | 4084 | 12 | handled | asahi-name-only |
| A409 | set_display_device | 3400 | 4 | ALLZERO | asahi-name-only |
| A413 | get_display_area | 8 | 4 | ALLZERO | asahi-name-only |
| A414 | get_display_area | 8 | 8 | ALLZERO | asahi-name-only |
| A415 | — | 12 | 12 | ALLZERO | callsite-only |
| A416 | — | 4 | 4 | ALLZERO | callsite-only |
| A417 | — | 4 | 4 | ALLZERO | callsite-only |
| A418 | get_gamma_table | 8 | 4 | ALLZERO | asahi-name-only |
| A419 | set_gamma_table | 4 | 0 | void_ack | asahi-name-only |
| A420 | — | 3088 | 3088 | ALLZERO | callsite-only |
| A421 | set_matrix | 3088 | 3088 | ALLZERO | asahi-name-only |
| A422 | set_contrast | 80 | 76 | ALLZERO | asahi-name-only |
| A423 | set_contrast | 80 | 4 | ALLZERO | asahi-name-only |
| A424 | — | 8 | 8 | ALLZERO | callsite-only |
| A425 | get_color_remap_mode | 4 | 4 | ALLZERO | asahi-name-only |
| A426 | setBrightnessCorrection | 4 | 4 | ALLZERO | asahi-name-only |
| A427 | setBrightnessCorrection | 8 | 8 | ALLZERO | asahi-name-only |
| A428 | — | 4 | 4 | ALLZERO | callsite-only |
| A429 | — | 112 | 16 | ALLZERO | callsite-only |
| A430 | — | 52 | 12 | ALLZERO | callsite-only |
| A431 | — | 4 | 4 | ALLZERO | callsite-only |
| A432 | — | 56 | 16 | ALLZERO | callsite-only |
| A433 | — | 4 | 4 | ALLZERO | callsite-only |
| A434 | — | 4 | 4 | ALLZERO | callsite-only |
| A435 | set_block_dcp | 4 | 4 | ALLZERO | asahi-name-only |
| A436 | get_block_dcp | 8 | 4 | ALLZERO | asahi-name-only |
| A437 | get_block_dcp | 8 | 8 | zeros_logged | asahi-v14.7 |
| A438 | swap_set_color_matrix | 160 | 160 | ALLZERO | asahi-name-only |
| A439 | set_parameter_dcp | 4 | 4 | ALLZERO | asahi-name-only |
| A440 | display_width | 8 | 8 | width_1024 | asahi-name-only |
| A444 | printRegs | 4204 | 4 | height_768 | asahi-name-only |
| A445 | printRegs | 24 | 4 | size_1024x768 | asahi-name-only |
| A446 | printRegs | 12 | 4 | ALLZERO | asahi-name-only |
| A447 | enable_disable_video_power_savings | 12 | 4 | ALLZERO | asahi-name-only |
| A448 | enable_disable_video_power_savings | 16 | 8 | ALLZERO | asahi-name-only |
| A449 | enable_disable_video_power_savings | 132 | 124 | ALLZERO | asahi-name-only |
| A450 | — | 40 | 4 | ALLZERO | callsite-only |
| A451 | — | 0 | 4 | width_1024 | callsite-only |
| A452 | — | 0 | 4 | height_768 | callsite-only |
| A454 | first_client_open | 0 | 4 | bool_true | asahi-name-only |
| A455 | last_client_close_dcp | 0 | 0 | bool_true | asahi-name-only |
| A456 | writeDebugInfo | 4 | 4 | bool_true | asahi-name-only |
| A457 | flush_debug_flags | 4 | 4 | ALLZERO | asahi-name-only |
| A458 | io_fence_notify | 4 | 4 | ALLZERO | asahi-name-only |
| A459 | io_fence_notify | 4 | 4 | ALLZERO | asahi-name-only |
| A460 | setDisplayRefreshProperties | 4 | 4 | ALLZERO | asahi-name-only |
| A461 | — | 4 | 4 | ALLZERO | callsite-only |
| A462 | — | 24 | 24 | ALLZERO | callsite-only |
| A463 | flush_supportsPower | 8 | 8 | bool_true | asahi-name-only |
| A464 | abort_swaps_dcp | 20 | 20 | ALLZERO | asahi-name-only |
| A465 | — | 8 | 0 | bool_true | callsite-only |
| A466 | flush_supportsPower | 0 | 0 | bool_true | asahi-name-only |
| A467 | update_dfb | 4 | 4 | ALLZERO | asahi-name-only |
| A468 | remove_gain_maps | 4 | 12 | echo_power | asahi-name-only |
| A469 | isKeepOnScreen | 4 | 0 | void_ack | asahi-name-only |
| A470 | update_dfb | 20 | 4 | ALLZERO | asahi-name-only |
| A471 | update_dfb | 16 | 4 | ALLZERO | asahi-name-only |
| A473 | isKeepOnScreen | 8 | 4 | echo_power | asahi-name-only |
| A474 | — | 16 | 0 | bool_true | callsite-only |
| A475 | — | 0 | 4 | bool_true | callsite-only |
| A476 | — | 8 | 0 | void_ack | callsite-only |
| A477 | get_shared_disp_state | 8 | 4 | ALLZERO | asahi-name-only |
| A478 | — | 4 | 0 | void_ack | callsite-only |
| A479 | — | 8 | 4 | bool_true | callsite-only |
| A480 | — | 12 | 12 | ALLZERO | callsite-only |
| A481 | — | 12 | 12 | ALLZERO | callsite-only |
| A482 | — | 576 | 4 | ALLZERO | callsite-only |
| A483 | — | 560 | 4 | ALLZERO | callsite-only |
| A484 | — | 16 | 8 | echo_power | callsite-only |
| A485 | — | 0 | 4 | bool_true | callsite-only |
| A486 | — | 4 | 0 | void_ack | callsite-only |
| A487 | — | 4 | 0 | void_ack | callsite-only |
| A488 | — | 0 | 4 | ALLZERO | callsite-only |
| A489 | — | 0 | 4 | ALLZERO | callsite-only |
| A490 | — | 4 | 0 | void_ack | callsite-only |
| A491 | — | 4 | 8 | ALLZERO | callsite-only |
| A492 | — | 52 | 4 | ALLZERO | callsite-only |
| A500 | — | 4 | 0 | void_ack | callsite-only |
| A501 | — | 16 | 4 | ALLZERO | callsite-only |

## Do you need full DCP firmware?
**No — not for minting a connected display.** A richer stub that (1) keeps the existing CB sequences, (2) returns non-ALLZERO for post-HPD property/mode getters (A437 blocks, digital-out, matrix), and (3) implements map_buf + swap_submit well enough for software scanout is the durable path. Full DCP firmware would still not help until backboardd’s Biome registration unblocks and a HPD listener exists. GPU is independently skippable (Inferno precedent).

## Artifacts
- `/workspace/dcp-rpc-catalog.json` — machine-readable
- `/workspace/dcp-symex/` — scanners, `d_handlers.json`, `a_calls.json`, unicorn lookup emulator
