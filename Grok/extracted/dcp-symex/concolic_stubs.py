"""Concolic-ish: run each A-call stub, intercept the RPC send helper, fill the out
buffer with a non-zero pattern, and record what the stub returns / writes.

PAC/arm64e: skip auth/sign ops by advancing PC. angr not used (arm64e/PAC).
"""
import json, struct, traceback
from unicorn import *
from unicorn.arm64_const import *
from capstone import *
import lief

KX = '/workspace/ios27-re/24A437__iPhone17,3/kx/'
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
A = json.load(open('/workspace/dcp-symex/a_calls.json'))

PAC_SKIP = {'pacia','pacib','pacda','pacdb','paciza','pacizb','pacdza','pacdzb',
            'autia','autib','autda','autdb','autiza','autizb','autdza','autdzb',
            'xpaci','xpacd','pacia1716','pacib1716','autia1716','autib1716',
            'bti','pacibsp','autibsp','retab'}

SEND = {
    'AppleMobileDispH17P-DCP': 0xfffffff009201358,
    'IOMobileGraphicsFamily-DCP': None,  # find later
}

def find_send_iomfb():
    # Search for a common call target from A40x sites
    refs = A.get('A401', [])
    for e in refs:
        if e['call'] and e['call'][0] == 'blraa':
            return None  # indirect
    return None

def kext_for(short):
    if short.startswith('Apple'): return 'com.apple.driver.AppleMobileDispH17P-DCP'
    return 'com.apple.iokit.IOMobileGraphicsFamily-DCP'

def load_mu(k):
    b = lief.MachO.parse(KX + k).at(0)
    raw = open(KX + k, 'rb').read()
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for s in b.segments:
        if s.virtual_size == 0: continue
        base = s.virtual_address & ~0xfff
        size = ((s.virtual_address + s.virtual_size + 0xfff) & ~0xfff) - base
        try: mu.mem_map(base, size)
        except Exception: pass
        mu.mem_write(s.virtual_address, raw[s.file_offset:s.file_offset + s.file_size])
    mu.mem_map(0x10000000, 0x800000)
    return mu

OBJ = 0x10100000
ARG = 0x10200000
STK = 0x10380000
RET = 0x10001000

results = {}
# Only run stubs that use a direct bl to a known send (AppleMobileDispH17P)
mu_cache = {}
for t, es in sorted(A.items()):
    e = es[0]
    short = e['kext']
    if short != 'AppleMobileDispH17P-DCP':
        continue
    if not e['call'] or e['call'][0] != 'bl':
        continue
    try:
        send = int(e['call'][1], 16)
    except Exception:
        continue
    k = kext_for(short)
    if k not in mu_cache:
        try:
            mu_cache[k] = load_mu(k)
        except Exception as ex:
            results[t] = {'err': str(ex)}; continue
    mu = mu_cache[k]
    # reset writable region
    mu.mem_write(0x10000000, b'\x00' * 0x800000)
    # fake object with vtable of zeros (many stubs autda vtable; we skip PAC)
    mu.mem_write(OBJ, struct.pack('<Q', OBJ + 0x100))
    mu.mem_write(OBJ + 0x100, b'\x00' * 0x400)
    in_len = e['in_len'] or 0
    out_len = e['out_len'] or 0
    # fill inout scratch
    mu.mem_write(ARG, b'\xaa' * 0x4000)

    captured = {}
    def hook(mu, addr, size, user):
        ins = bytes(mu.mem_read(addr, 4))
        i = next(cs.disasm(ins, addr), None)
        if not i: return
        if i.mnemonic in PAC_SKIP:
            mu.reg_write(UC_ARM64_REG_PC, addr + 4); return
        if i.mnemonic in ('blraa','blrab','braa','brab'):
            # just skip (return to next); for blraa treat as ret-like nop
            mu.reg_write(UC_ARM64_REG_PC, addr + 4); return
        if addr == send:
            # intercept: w1=tag, x2=in, w3=in_len, x4=out, w5=out_len
            tag = mu.reg_read(UC_ARM64_REG_W1)
            il = mu.reg_read(UC_ARM64_REG_W3)
            ol = mu.reg_read(UC_ARM64_REG_W5)
            outp = mu.reg_read(UC_ARM64_REG_X4)
            inp = mu.reg_read(UC_ARM64_REG_X2)
            try:
                tin = bytes(mu.mem_read(inp, min(il, 64))) if il and inp else b''
            except: tin = b''
            # fill out with ascending pattern + 1 at byte0 for bools
            if ol and outp:
                buf = bytearray(ol)
                for j in range(ol): buf[j] = (j + 1) & 0xff
                if ol >= 4: buf[0] = 1
                try: mu.mem_write(outp, bytes(buf))
                except: pass
            captured['tag'] = struct.pack('>I', tag).decode('latin1', 'replace')
            captured['in_len'] = il; captured['out_len'] = ol
            captured['in_hex'] = tin.hex()
            # return success (0) in x0, back to LR
            mu.reg_write(UC_ARM64_REG_X0, 0)
            lr = mu.reg_read(UC_ARM64_REG_LR)
            mu.reg_write(UC_ARM64_REG_PC, lr); return
        if i.mnemonic in ('ret',):
            mu.emu_stop()

    mu.hook_add(UC_HOOK_CODE, hook)
    mu.reg_write(UC_ARM64_REG_X0, OBJ)
    mu.reg_write(UC_ARM64_REG_X1, 0)
    mu.reg_write(UC_ARM64_REG_X2, ARG)
    mu.reg_write(UC_ARM64_REG_X3, ARG + 0x1000)
    mu.reg_write(UC_ARM64_REG_X4, ARG + 0x2000)
    mu.reg_write(UC_ARM64_REG_X5, ARG + 0x3000)
    mu.reg_write(UC_ARM64_REG_SP, STK)
    mu.reg_write(UC_ARM64_REG_LR, RET)
    fn = int(e['func'], 16)
    try:
        mu.emu_start(fn, RET, count=800)
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        results[t] = {
            'func': e['func'],
            'declared_in': in_len, 'declared_out': out_len,
            'rpc': captured,
            'x0': hex(x0),
            'x0_lo32': x0 & 0xffffffff,
            'boolish': (x0 & 1) if (out_len in (0,4) or captured.get('out_len') in (0,4)) else None,
        }
    except UcError as ex:
        results[t] = {'err': str(ex), 'rpc': captured}
    # clear hooks for next
    mu.hook_del(mu._hooks[UC_HOOK_CODE][0][0]) if False else None
    # unicorn doesn't make hook_del easy; remake mu for safety every 20
    if len(results) % 20 == 0:
        try: mu_cache[k] = load_mu(k)
        except: pass

json.dump(results, open('/workspace/dcp-symex/a_concolic.json','w'), indent=1)
print('ran', len(results))
for t,v in sorted(results.items()):
    if 'err' in v and not v.get('rpc'): print(t, 'ERR', v['err']); continue
    r = v.get('rpc', {})
    print(t, 'in', r.get('in_len'), 'out', r.get('out_len'), 'x0', v.get('x0_lo32'), 'tag', r.get('tag'))
