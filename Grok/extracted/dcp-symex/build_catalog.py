#!/usr/bin/env python3
"""Build DCP RPC catalog for T8140 iOS 27 (24A437)."""
import json, re, struct
from pathlib import Path

# --- Asahi name tables (parsed from ipc.py, version-annotated) ---
# Prefer names that match our size/string evidence for this BootKC.
ASAHI = {}
ipc = Path('/workspace/asahi-m1n1/proxyclient/m1n1/fw/dcp/ipc.py').read_text()
# crude: collect Tag = Call/Callback(... "name" ...)
for m in re.finditer(r'([AD]\d{3})\s*=\s*(?:Call|Callback)\([^)]*?"([^"]+)"', ipc):
    ASAHI.setdefault(m.group(1), []).append(m.group(2))
for m in re.finditer(r'([AD]\d{3})\s*=\s*(\w+)', ipc):
    if m.group(2) not in ('Call','Callback','if','else'):
        ASAHI.setdefault(m.group(1), []).append(m.group(2))

# Names proven by THIS kernel's strings / sizes (override Asahi when conflict)
PROVEN = {
    'D000': ('did_boot_signal', 'out u32/bool', 'proven'),
    'D001': ('did_power_on_signal', 'out u32/bool', 'proven'),
    'D002': ('will_power_off_signal', 'void', 'asahi+size'),
    'D003': ('rt_bandwidth_setup_ap', 'out rt_bw_config', 'proven-str'),
    'D006': ('set_frame_sync_props', 'in/out large', 'asahi+size'),
    'D100': ('match_pmu_service', 'void', 'asahi'),
    'D101': ('UNK_get_some_field', 'out u32', 'asahi'),
    'D102': ('set_number_property', 'in key[0x40]+u32', 'proven'),
    'D103': ('trigger_user_cal_loader', 'void', 'proven-str'),
    'D104': ('set_boolean_property', 'in key[0x40]+u32', 'proven'),
    'D105': ('set_property (bool/dict?)', 'in >=0x80', 'inferred'),
    'D106': ('removeProperty', 'in key[0x40]', 'proven-size'),
    'D107': ('create_provider_service', 'out bool', 'proven-size+emu'),
    'D108': ('create_product_service', 'out bool', 'proven-size+emu'),
    'D109': ('create_PMU_service', 'out bool', 'proven-size+emu'),
    'D110': ('create_iomfb_service', 'out bool', 'proven-size+emu'),
    'D111': ('create_backlight_service', 'out bool', 'asahi-shifted'),
    'D112': ('create_nvram_service OR set_idle', 'out bool', 'uncertain'),
    'D113': ('create_nvram_service', '?', 'uncertain'),
    'D120': ('start_hardware_boot', 'out bool', 'proven-str'),
    'D121': ('is_dark_boot', 'out bool', 'proven-str kern.darkboot'),
    'D124': ('read_edt_data', 'in large', 'proven-str'),
    'D126': ('setDCPAVPropStart', 'in u32 total_len; out bool', 'proven-str'),
    'D127': ('setDCPAVPropChunk', 'in data[0x1000]+off+len; out bool', 'proven-str+emu'),
    'D128': ('setDCPAVPropEnd', 'in key[0x40]; out bool', 'proven-str'),
    'D129': ('allocate_bandwidth', 'in >=0x1c', 'asahi'),
    'D201': ('map_buf', 'in BufferDescriptor…', 'proven-str'),
    'D202': ('unmap_buf', 'in BufferDescriptor…', 'proven-str'),
    'D206': ('match_pmu_service_2', 'out bool', 'asahi'),
    'D207': ('match_backlight_service', 'out bool', 'asahi'),
    'D300': ('pr_publish', 'in prop_id+value(+unk)', 'proven'),
    'D400': ('get_property', 'in FourCC+key; out data', 'proven-str'),
    'D401': ('sr_get_uint_prop', '…', 'asahi'),
    'D404': ('sr_set_uint_prop', '…', 'asahi'),
    'D406': ('set_fx_prop', '…', 'asahi'),
    'D411': ('sr_mapDeviceMemoryWithIndex', '…', 'proven-str'),
    'D451': ('allocate_buffer', '…', 'proven-str'),
    'D452': ('map_physical', '…', 'asahi'),
    'D453': ('withAddressRange', '…', 'asahi'),
    'D454': ('release_descriptor', '…', 'proven-str'),
    'D572': ('powerUpDART', 'in bool', 'proven-str'),
    'D575': ('hotPlug_notify_gated', 'in 0x58 state+tiled+bool+nullflag; out 0x4c', 'proven-disasm'),
    'D576': ('get_dot_pitch OR powerstate (shifted)', 'in>=4', 'uncertain-vs-asahi'),
    'D582': ('swap_complete_head_of_line', '…', 'proven-str'),
    'D586': ('create_default_fb_surface', '…', 'proven-str'),
    'D594': ('swap_complete_ap_gated', 'in large blobs', 'proven-str'),
    'D595': ('swap_complete batch?', '…', 'proven-str'),
    'D600': ('setSystemConsoleMode_gated', 'in bool; out?', 'proven-str'),
    'D603': ('find_swap_function / iomfb_swap_fn', '…', 'proven-str'),
    'A000': ('late_init_signal', 'in4 out4 bool', 'asahi'),
    'A352': ('applyProperty', 'in8 out4', 'asahi'),
    'A353': ('display_healthcheck_rate_ns', 'out u64', 'proven-str'),
    'A401': ('start_signal', 'out bool', 'asahi'),
    'A406': ('swap_start_dcp', 'in16 out8', 'asahi-v14.7'),
    'A407': ('swap_submit_dcp', 'in huge', 'asahi-v14.7'),
    'A410': ('is_main_display / set_display_device', 'out bool', 'emu+asahi-shift'),
    'A411': ('is_main_display', 'out bool', 'emu'),
    'A412': ('get_digital_out_state', 'out status', 'emu'),
    'A437': ('get_block_dcp', 'in8 out8', 'asahi-v14.7'),
    'A453': ('get_display_size', 'out w,h', 'proven'),
}

d_handlers = json.load(open('/workspace/dcp-symex/d_handlers.json'))
a_calls = json.load(open('/workspace/dcp-symex/a_calls.json'))
tag_refs = json.load(open('/workspace/dcp-symex/tag_refs.json'))

# Emulator handling from modern-dcp-iop.c (static parse)
emu_src = Path('/workspace/ied-hpd/hw/arm/apple-silicon/modern-dcp-iop.c').read_text()
emu_true = set(re.findall(r'!strcmp\(tag_str, "(A\d{3})"\)', emu_src.split('Methods returning bool')[1].split('} else if')[0]))
emu_special = {}
for tag in re.findall(r'!strcmp\(tag_str, "(A\d{3})"\)', emu_src):
    emu_special.setdefault(tag, 'handled')
# more precise
emu_special.update({t: 'bool_true' for t in emu_true})
for t in ['A412']: emu_special[t] = 'status_0'
for t in ['A437']: emu_special[t] = 'zeros_logged'
for t in ['A406','A407']: emu_special[t] = 'swap_id++'  # A407 only if in<0x80
for t in ['A472','A473','A468','A484']: emu_special[t] = 'echo_power'
for t in ['A353']: emu_special[t] = 'u64_1h_ns'
for t in ['A453','A443','A444','A445','A103']: emu_special[t] = 'size_1024x768'
for t in ['A441','A440','A451','A351']: emu_special[t] = 'width_1024'
for t in ['A442','A444','A452','A350']: emu_special[t] = 'height_768'

emu_cbs_startup = ['D107','D108','D109','D110','D300','D104','D102','D000','D001','D120']
emu_cbs_attach = ['D126','D127','D128','D575','D600']  # MODES expands to 126-128

# Boot priority (lower = earlier / more critical for mint)
BOOT_PRI = {
    'A401': 1, 'D000': 2, 'D001': 3, 'D107': 4, 'D108': 5, 'D109': 6, 'D110': 7,
    'D300': 8, 'D104': 9, 'D102': 10, 'D120': 11,
    'A000': 12, 'A352': 13, 'A353': 14,
    'A453': 20, 'A443': 21, 'A441': 22, 'A442': 23,
    'A410': 24, 'A411': 25, 'A412': 26,
    'D126': 30, 'D127': 31, 'D128': 32, 'D575': 33, 'D600': 34,
    'A406': 40, 'A407': 41, 'A472': 42,
    'D201': 50, 'D202': 51, 'D594': 52, 'D582': 53,
}

catalog = []

def parse_size(checks, kind):
    if not checks: return None
    for c in checks:
        if kind == 'in' and c.startswith('in_len>='):
            return int(c.split('>=')[1].rstrip('?'), 0)
        if kind == 'out' and c.startswith('out_len>='):
            return int(c.split('>=')[1].rstrip('?'), 0)
    return None

# All D tags from handlers
for t, v in sorted(d_handlers.items()):
    name, layout, conf = PROVEN.get(t, (None, None, 'table-only'))
    if not name and t in ASAHI:
        name = ASAHI[t][0]; conf = 'asahi-name-only'
    in_sz = parse_size(v.get('size_checks'), 'in')
    out_sz = parse_size(v.get('size_checks'), 'out')
    emu = 'missing'
    if t in emu_cbs_startup: emu = 'sent_startup_cb'
    elif t in ('D126','D127','D128'): emu = 'sent_attach_MODES'
    elif t == 'D575': emu = 'sent_attach_D575'
    elif t == 'D600': emu = 'sent_attach_D600'
    elif t == 'D300' or t == 'D104': emu = 'sent_nested_prop'
    stub = None
    if out_sz == 4: stub = 'out[0]=1 (success/true) typically'
    if t == 'D575': stub = 'in: state=1 at +0, tiled null flag at +0x54=1, bool +0x53=0; out zeros ok if status 0'
    if t == 'D128': stub = 'key[0x40]; AP NUL-forces buf[len-1]; OSUnserializeXML must succeed'
    if t == 'D126': stub = 'u32 total_length including trailing NUL'
    if t == 'D127': stub = 'data FIRST [0x1000], then u32 offset, u32 length (iOS order ≠ Asahi)'
    catalog.append({
        'tag': t, 'tag_hex': '0x' + struct.pack('>I', int.from_bytes(t.encode(),'big')).hex(),
        'name': name, 'dir': 'DCP->AP', 'in_size_min': in_sz, 'out_size_min': out_sz,
        'layout': layout, 'confidence': conf,
        'handler': v.get('handler'), 'lookup': v.get('lookup'),
        'kext': v.get('kext','').split('.')[-1],
        'stub_reply': stub, 'emu_status': emu,
        'boot_priority': BOOT_PRI.get(t, 900),
        'asahi_aliases': ASAHI.get(t, [])[:3],
        'strings': [s for s in v.get('deep_strings', []) or v.get('strings', []) if 'InstanceTracker' not in s][:6],
    })

# All A tags from call sites
for t, es in sorted(a_calls.items()):
    e = es[0]
    name, layout, conf = PROVEN.get(t, (None, None, 'callsite-only'))
    if not name and t in ASAHI:
        name = ASAHI[t][0]; conf = 'asahi-name-only'
    in_sz = e.get('in_len'); out_sz = e.get('out_len')
    emu = emu_special.get(t, 'ALLZERO' if (out_sz and out_sz > 0) else 'void_ack')
    stub = None
    if t in emu_true: stub = 'out[0]=1'
    elif t == 'A353': stub = 'u64 nanoseconds period (nonzero; emu uses 1h)'
    elif t == 'A453': stub = 'u32 width, u32 height'
    elif t in ('A441','A440','A451','A351'): stub = 'u32 width'
    elif t in ('A442','A452','A350'): stub = 'u32 height'
    elif t == 'A412': stub = 'u32 IOReturn 0'
    elif t in ('A406',): stub = 'u32 swap_id, u32 0'
    catalog.append({
        'tag': t, 'tag_hex': '0x' + struct.pack('>I', int.from_bytes(t.encode(),'big')).hex(),
        'name': name, 'dir': 'AP->DCP', 'in_size': in_sz, 'out_size': out_sz,
        'layout': layout, 'confidence': conf,
        'call_site': e.get('site'), 'func': e.get('func'),
        'kext': e.get('kext'),
        'stub_reply': stub, 'emu_status': emu,
        'boot_priority': BOOT_PRI.get(t, 800),
        'asahi_aliases': ASAHI.get(t, [])[:3],
    })

catalog.sort(key=lambda x: (x['boot_priority'], x['tag']))
json.dump({'kernel': '24A437 iPhone17,3 RELEASE_ARM64_T8140',
           'sources': ['AppleMobileDispH17P-DCP','IOMobileGraphicsFamily-DCP','AsahiLinux/m1n1 ipc.py','modern-dcp-iop.c'],
           'notes': {
               'abi': 'iOS 27 D1xx is hybrid vs Asahi: removeProperty=D106, create_*=D107.. like pre-13.5; start_hardware_boot=D120, AVProp=D126-128 like post-13.5 pre-14.7. D575=hotPlug (Asahi Mac D576).',
               'angr': 'Skipped: arm64e/PAC. Used unicorn concrete lookup + guided disassembly.',
               'd128_constraint': 'setDCPAVPropEnd forces buf[len-1]=NUL then OSUnserializeXML(buf,len); setProperty(key, obj).',
           },
           'methods': catalog}, open('/workspace/dcp-rpc-catalog.json','w'), indent=1)

# Markdown
lines = []
lines.append('# T8140 / iOS 27 (24A437) DCP RPC catalog')
lines.append('')
lines.append('Assets: `kernelcache.release.iPhone17,3` kexts AppleMobileDispH17P-DCP + IOMobileGraphicsFamily-DCP; Asahi `m1n1/fw/dcp/ipc.py`; emulator `ied-hpd/.../modern-dcp-iop.c`.')
lines.append('')
lines.append('Confidence: **proven** = this BootKC strings/sizes/disasm; **asahi** = name from Asahi tables; **inferred/uncertain** = guess.')
lines.append('')
lines.append('## Method')
lines.append('1. Found 5 DCP→AP lookup functions (tag→handler) by `mov x0,#0` + `movk w8,#0x44xx` pattern; unicorn-emulated every D000–D999 against PAC-stripped lookups → **127 handlers**.')
lines.append('2. Extracted min in/out lengths from each handler’s `cmp w3`/`cmp w5` gates (kIOReturnBadArgument `0xe00002c2` on fail).')
lines.append('3. AP→DCP: scanned `movk …,#0x413x` immediates at call sites → **~248 A tags** with (in_len,out_len) in w3/w5.')
lines.append('4. Names: Asahi ipc.py + this-kext strings (hotPlug, setDCPAVProp*, start_hardware_boot, SystemConsoleMode, …).')
lines.append('5. **angr**: not used — arm64e PAC defeats default angr. Fallback = unicorn concrete + guided disasm (documented below).')
lines.append('')
lines.append('## ABI vs Asahi (important)')
lines.append('| Item | This BootKC | Asahi V13.5 | Asahi V14.7 |')
lines.append('|---|---|---|---|')
lines.append('| removeProperty | **D106** (in≥0x40) | D107 | D107 |')
lines.append('| create_provider… | **D107–D110** | D108–D111 | D108–D111 |')
lines.append('| start_hardware_boot | **D120** | D120 | D121 |')
lines.append('| setDCPAVPropStart/Chunk/End | **D126/127/128** | D126/127/128 | D127/128/129 |')
lines.append('| hotPlug_notify_gated | **D575** (in≥0x58, vtable+0x8c8) | D576 | D576 |')
lines.append('| setSystemConsoleMode | **D600** | (near D594) | — |')
lines.append('')
lines.append('Emulator startup CB list D107–D110 as create_* is **correct for this kernel**.')
lines.append('')
lines.append('## D128 / ProductAttributes constraint (guided, not angr)')
lines.append('`setDCPAVPropEnd` @ `0xfffffff0091ed910`:')
lines.append('- Requires prior Start+Chunk (else “setDCPAVPropStart not called”).')
lines.append('- Writes `buf[len-1] = 0`, then `OSUnserializeXML(buf, len)`.')
lines.append('- On success: `setProperty(key, obj)`; on fail logs `OSUnserializeXML failed`.')
lines.append('- Emulator must pass **NUL-terminated** XML whose length **includes** the NUL (already noted in `modern-dcp-iop.c`).')
lines.append('- Key is `char[0x40]` with forced NUL at `[0x3f]` in the D128 wrapper.')
lines.append('')
lines.append('## Top gaps vs emulator (boot-path first)')
lines.append('')
lines.append('| Pri | Tag | Issue | Why it matters |')
lines.append('|---|---|---|---|')
lines.append('| 1 | *(process)* | backboardd Biome stall | No CA WindowServer → no HPD registrant; D575 stays “not registered yet”. Display mint is blocked **above** DCP. |')
lines.append('| 2 | A* ALLZERO | Most A replies are zero-filled | After HPD, CA reads modes/properties; zeros can keep display “nil”. |')
lines.append('| 3 | D111/D112 | create_backlight / nvram never sent | Startup only sends D107–D110; backlight match may fail later. |')
lines.append('| 4 | D201/D202 | map_buf/unmap_buf not stubbed | Needed once swaps start; today never reached. |')
lines.append('| 5 | A407 large | swap_submit only special-cased when in<0x80 | Real submit is ~7KB; ALLZERO will break presentation. |')
lines.append('| 6 | A437 | get_block_dcp returns zeros | Timing/param blocks empty. |')
lines.append('| 7 | D576–D593 | Not in attach set | Mac numbering must not be used (already learned). |')
lines.append('| 8 | ProductAttributes | Optional vs TimingElements | v10 experiment; mint needs TimingElements+HPD listener more than ProductAttributes. |')
lines.append('| 9 | D575 out 0x4c | Emulator leaves out area as 0xdeadbeef pattern only for out_len==4 | For D575 out=0x4c, ensure status path returns 0 (handler writes tiled copy when nullflag=0). |')
lines.append('| 10 | A353 | Nonzero ns period required | Already stubbed to 1h; keep nonzero. |')
lines.append('')
lines.append('## Full DCP→AP table (handlers found)')
lines.append('')
lines.append('| Tag | Name | in≥ | out≥ | Emu | Conf |')
lines.append('|---|---|---:|---:|---|---|')
for m in catalog:
    if m['dir'] != 'DCP->AP': continue
    lines.append(f"| {m['tag']} | {m['name'] or '—'} | {m.get('in_size_min') or '—'} | {m.get('out_size_min') or '—'} | {m['emu_status']} | {m['confidence']} |")

lines.append('')
lines.append('## Full AP→DCP table (call sites)')
lines.append('')
lines.append('| Tag | Name | in | out | Emu | Conf |')
lines.append('|---|---|---:|---:|---|---|')
for m in catalog:
    if m['dir'] != 'AP->DCP': continue
    lines.append(f"| {m['tag']} | {m['name'] or '—'} | {m.get('in_size') if m.get('in_size') is not None else '—'} | {m.get('out_size') if m.get('out_size') is not None else '—'} | {m['emu_status']} | {m['confidence']} |")

lines.append('')
lines.append('## Do you need full DCP firmware?')
lines.append('**No — not for minting a connected display.** A richer stub that (1) keeps the existing CB sequences, (2) returns non-ALLZERO for post-HPD property/mode getters (A437 blocks, digital-out, matrix), and (3) implements map_buf + swap_submit well enough for software scanout is the durable path. Full DCP firmware would still not help until backboardd’s Biome registration unblocks and a HPD listener exists. GPU is independently skippable (Inferno precedent).')
lines.append('')
lines.append('## Artifacts')
lines.append('- `/workspace/dcp-rpc-catalog.json` — machine-readable')
lines.append('- `/workspace/dcp-symex/` — scanners, `d_handlers.json`, `a_calls.json`, unicorn lookup emulator')
lines.append('')

Path('/workspace/ios-linux-emulator-dcp-rpc-catalog.md').write_text('\n'.join(lines))
print('methods', len(catalog), 'D', sum(1 for m in catalog if m['dir']=='DCP->AP'), 'A', sum(1 for m in catalog if m['dir']=='AP->DCP'))
