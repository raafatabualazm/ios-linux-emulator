"""Fixed XNU t8140 / iOS 27 24A437 guest walker (gdb Python). READ-ONLY.

Replaces Grok/xnu-t8140-walk.py, which had two bugs found by Codex:
  * truncated signed kernel pointers to 36 bits with prefix 0xfffffff000000000;
    this guest uses T1SZ=25 -> 39-bit kernel VAs, T0SZ=21 -> 43-bit user VAs.
  * subtracted 0x408 from task-queue links; links hold THREAD BASES.
Offsets come from Codex's validated notes
(modern-emulator/evidence/features-20261017/codex-backboardd-wait/re-memory/
 ipc-and-kernel-context.md + README.md, BootKC a36b9241...) and its capture.py
page-walk (reused with attribution). Nothing here writes guest memory/registers.

Usage (guest paused under gdb, gdb attached to -gdb tcp:...):
  WALK_MODE=procs|threads|msg|port|kstack WALK_PROC=backboardd WALK_TID=705 \
  WALK_PORT=0x1413 WALK_OUT=/path/out.json WALK_SLIDE=0x20000000 \
  gdb -batch -ex 'target remote 127.0.0.1:PORT' -x xnu-t8140-walk.py
Modes:
  procs   - allproc list with pid/name/proc_ro/task/ipc_space (reciprocity-checked)
  threads - threads of WALK_PROC: state, wait_event, user saved state, back-link
  msg     - decode each WALK_PROC thread's trapped user mach_msg (x0 buffer):
            header, msgh_id (2862 = io_service_open_extended), remote right
  port    - dump port named WALK_PORT in WALK_PROC (or WALK_PORT_ADDR=0x...):
            +0 io_bits, +1 state, +0x48 receiver/kobject union, kobject vtable
  kstack  - kernel saved context + FP unwind for WALK_TID (thread+0x150, PAC
            disc 0x6d42; ctx+0x50 FP, ctx+0x58 LR, ctx+0x60 SP)
"""
import gdb, json, os, struct
from datetime import datetime, timezone

MASK64 = (1 << 64) - 1
SLIDE = int(os.environ.get('WALK_SLIDE', '0x20000000'), 16)  # kernel slide; verified below
ALLPROC = 0xfffffff00b790280          # unslid global (re-memory/README.md)
KC_HDR = 0xfffffff007004000           # unslid Mach-O header of the BootKC

# --- validated offsets (Codex re-memory, BootKC a36b9241) ---
PROC_RO, PROC_PID, PROC_NAME = 0x18, 0x60, 0x55c
PRO_PROC, PRO_TASK = 0x0, 0x8
TASK_MAP, TASK_THREADS, TASK_SPACE, TASK_PRO = 0x28, 0x50, 0x310, 0x3c8
TH_WAIT_EVENT, TH_KSTACK, TH_UPCB, TH_KPCB, TH_KCTX = 0x18, 0xf0, 0x110, 0x120, 0x150
TH_STATE, TH_ITH_OBJ, TH_ITH_STATE = 0x1f0, 0x390, 0x398
TH_NEXT, TH_PREV, TH_RO, TH_ID = 0x408, 0x410, 0x418, 0x4e8
TRO_OWNER, TRO_TASK = 0x0, 0x28
SPACE_TABLE, SPACE_TASK = 0x48, 0x50
PORT_BITS, PORT_STATE_BYTE, PORT_MQ, PORT_NAME, PORT_MSGCNT = 0x0, 0x1, 0x28, 0x34, 0x38
PORT_RECV_UNION, PORT_KOBJ_ALT = 0x48, 0x50


def reg(name):
    return int(gdb.parse_and_eval('$' + name)) & MASK64


class Memory:
    """Physical-mode reads + explicit stage-1 walk (from Codex capture.py)."""
    def __init__(self):
        self.inf = gdb.selected_inferior()
        self.root = reg('TTBR1_EL2')
        self.tcr = reg('TCR_EL2')
        self.kbits = 64 - ((self.tcr >> 16) & 63)   # T1SZ -> 39
        self.ubits = 64 - (self.tcr & 63)           # T0SZ -> 43
        assert (self.tcr >> 30) & 3 == 1 and (self.tcr >> 14) & 3 == 2, '16K granules required'
        self.cache = {}

    def canon(self, p):            # kernel canonicalization with live width (NOT 36-bit)
        low = p & ((1 << self.kbits) - 1)
        return low | (MASK64 ^ ((1 << self.kbits) - 1)) if low >> (self.kbits - 1) else low

    def ucanon(self, p):           # user pointers: strip PAC to ubits
        return p & ((1 << self.ubits) - 1)

    def physical(self, pa, size):
        out = bytearray()
        while size:
            base, off = pa & ~0x3fff, pa & 0x3fff
            if base not in self.cache:
                assert len(self.cache) < 8192, 'bounded page cache exhausted'
                self.cache[base] = bytes(self.inf.read_memory(base, 0x4000))
            n = min(size, 0x4000 - off)
            out += self.cache[base][off:off + n]; pa += n; size -= n
        return bytes(out)

    def translate(self, va, root=None, bits=None):
        if root is None:
            root, bits = self.root, self.kbits
            va = self.canon(va)
        start = max(0, 3 - ((bits - 15) // 11))
        root_width = bits - (14 + 11 * (3 - start))
        table = (root & 0x0000ffffffffffff) & ~((1 << max(3, root_width + 3)) - 1)
        for level in range(start, 4):
            shift = 14 + 11 * (3 - level)
            width = root_width if level == start else 11
            pte = struct.unpack('<Q', self.physical(table + 8 * ((va >> shift) & ((1 << width) - 1)), 8))[0]
            if pte & 3 in (0, 2) and not (level == 3 and pte & 3 == 3):
                if pte & 3 != 1 or level == 3:
                    raise OSError('invalid PTE va=%#x L%d pte=%#x' % (va, level, pte))
            if level == 3 or pte & 3 == 1:
                mask = (1 << shift) - 1
                return (pte & 0x0000ffffffffc000 & ~mask) | (va & mask)
            table = pte & 0x0000ffffffffc000
        raise OSError('no translation')

    def read(self, va, n, root=None, bits=None):
        out = bytearray()
        while n:
            c = min(n, 0x4000 - (va & 0x3fff))
            out += self.physical(self.translate(va, root, bits), c); va += c; n -= c
        return bytes(out)

    def u64(self, va): return struct.unpack('<Q', self.read(va, 8))[0]
    def u32(self, va): return struct.unpack('<I', self.read(va, 4))[0]
    def ptr(self, va): return self.canon(self.u64(va))
    def words(self, va, n):
        return {hex(i): hex(v) for i, (v,) in zip(range(0, n, 8), struct.iter_unpack('<Q', self.read(va, n)))}


def procs(m):
    assert m.read(KC_HDR + SLIDE, 4) == bytes.fromhex('cffaedfe'), 'kernel slide wrong (set WALK_SLIDE)'
    out, seen, p = [], set(), m.ptr(ALLPROC + SLIDE)
    while p and p not in seen and len(seen) < 2048:
        seen.add(p)
        pro = m.ptr(p + PROC_RO)
        assert m.ptr(pro + PRO_PROC) == p, 'proc_ro owner mismatch @%#x' % p
        task = m.ptr(pro + PRO_TASK)
        # task.proc_ro@0x3c8 reciprocity is validated by kernel for live tasks; soft-check
        # here so a stale/partial allproc entry does not abort the whole walk (Codex capture.py
        # likewise keys off proc_ro.task without hard-failing every reverse link).
        tro_ok = False
        try:
            tro_ok = m.ptr(task + TASK_PRO) == pro
        except Exception:
            tro_ok = False
        nm = m.read(p + PROC_NAME, 0x32)
        name = (nm[0x11:].split(b'\0')[0] or nm[:0x11].split(b'\0')[0]).decode(errors='replace')
        row = {'proc': hex(p), 'pid': m.u32(p + PROC_PID), 'name': name, 'proc_ro': hex(pro),
               'task': hex(task), 'task_proc_ro_ok': tro_ok}
        if tro_ok:
            try: row['ipc_space'] = hex(m.ptr(task + TASK_SPACE))
            except Exception as e: row['ipc_space_error'] = str(e)
        out.append(row)
        p = m.ptr(p)
    return out


def threads(m, task):
    head = task + TASK_THREADS
    th, prev, rows, seen = m.ptr(head), head, [], set()
    while th != head and th and len(seen) < 512:
        assert th not in seen, 'thread queue cycle'
        seen.add(th)
        back = m.ptr(th + TH_PREV)
        tro = m.ptr(th + TH_RO)
        row = {'thread': hex(th), 'tid': m.u64(th + TH_ID),
               'backlink_ok': back == prev,                 # thread+0x410 must name the previous element
               'tro': hex(tro), 'tro_owner_ok': m.ptr(tro + TRO_OWNER) == th,
               'tro_task_ok': m.ptr(tro + TRO_TASK) == task,
               'state': hex(m.u32(th + TH_STATE)), 'waiting': (m.u32(th + TH_STATE) & 5) == 1,
               'wait_event': hex(m.u64(th + TH_WAIT_EVENT)),
               'ith_object': hex(m.ptr(th + TH_ITH_OBJ)), 'ith_state': hex(m.u32(th + TH_ITH_STATE))}
        try:
            u = m.ptr(th + TH_UPCB)
            raw = m.read(u, 0x118)
            flavor = struct.unpack_from('<I', raw)[0]
            row['user'] = {'upcb': hex(u), 'flavor_ok': flavor == 0x15,
                           'x': [hex(v) for v in struct.unpack_from('<29Q', raw, 8)],
                           'fp': hex(struct.unpack_from('<Q', raw, 0xf0)[0]),
                           'lr': hex(struct.unpack_from('<Q', raw, 0xf8)[0]),
                           'sp': hex(struct.unpack_from('<Q', raw, 0x100)[0]),
                           'pc': hex(struct.unpack_from('<Q', raw, 0x108)[0]),
                           'cpsr': hex(struct.unpack_from('<I', raw, 0x110)[0])}
        except Exception as e:
            row['user'] = {'error': str(e)}
        rows.append(row)
        prev, th = th, m.ptr(th + TH_NEXT)          # NO -0x408: links are thread bases
    return rows


def user_root(m, task):
    """task.map+0x28 -> vm_map.pmap+0x58 -> pmap.ttep+0x8 (runtime-validated)."""
    pmap = m.ptr(m.ptr(task + TASK_MAP) + 0x58)
    return m.u64(pmap + 0x8) & 0x0000ffffffffffff


def lookup(m, space, name):
    enc = m.u64(space + SPACE_TABLE)
    v = enc & ((1 << m.kbits) - 1)
    if not v & (1 << 38):
        nbytes, base = (v & 0x3fff) << 14, m.canon((v & ~0x3fff) | (1 << 38))
    else:
        nbytes, base = ((v & 0x10) | 0x20) << (v & 0xf), m.canon(v & ~0x1f)
    idx = name >> 8
    assert name >= 0x100 and idx * 24 + 24 <= nbytes, 'name outside table'
    ent = base + idx * 24
    bits = m.u32(ent + 8)
    ok = bool(bits & 0x1f0000) and ((bits & 0xfc000000) | 0x03000000) == ((name << 24) & 0xffffffff)
    return {'name': hex(name), 'entry': hex(ent), 'ie_bits': hex(bits), 'valid': ok,
            'port': hex(m.ptr(ent))}


def port_dump(m, port, owners):
    b0 = m.u32(port + PORT_BITS)
    state = (m.read(port + PORT_STATE_BYTE, 1)[0]) & 7
    union = m.ptr(port + PORT_RECV_UNION)
    r = {'port': hex(port), 'io_bits_u32': hex(b0), 'io_bits_kotype_lo10': b0 & 0x3ff,
         'state': state, 'state_is_receive_in_space': state in (1, 2),
         'name_at_34': hex(m.u32(port + PORT_NAME)), 'msgcount_limit': [m.read(port + PORT_MSGCNT, 2).hex(), m.read(port + 0x3a, 2).hex()],
         'union_at_48': hex(union), 'alt_at_50': hex(m.ptr(port + PORT_KOBJ_ALT)),
         'words': m.words(port, 0x90)}
    if state in (1, 2):
        r['receiver_space_owner'] = owners.get(hex(union))
    else:
        # kobject / destination: read the object's PAC-signed vtable pointer
        for key, obj in (('union_at_48', union), ('alt_at_50', m.ptr(port + PORT_KOBJ_ALT))):
            if not obj:
                continue
            try:
                vt = m.ptr(obj)
                r['kobject_' + key] = {'object': hex(obj), 'vtable': hex(vt), 'vtable_unslid': hex((vt - SLIDE) & MASK64),
                                       'vtable_words': m.words(vt, 0x40), 'object_words': m.words(obj, 0x60)}
            except Exception as e:
                r['kobject_' + key] = {'object': hex(obj), 'error': str(e)}
    return r


def kstack(m, th):
    ctx = m.ptr(th + TH_KCTX)                      # signed (disc 0x6d42); canon strips PAC
    w = struct.unpack('<13Q', m.read(ctx, 0x68))
    kbase = m.ptr(th + TH_KSTACK)
    frames, fp, lr, used = [], m.canon(w[10]), m.canon(w[11]), set()
    frames.append({'pc': hex(lr), 'pc_unslid': hex((lr - SLIDE) & MASK64), 'from': 'ctx+0x58'})
    for _ in range(64):
        if not (kbase - 0x10000 <= fp < kbase + 0x10000) or fp in used or fp & 0xf:
            break
        used.add(fp)
        nfp, nlr = struct.unpack('<QQ', m.read(fp, 16))
        lr = m.canon(nlr)
        frames.append({'fp': hex(fp), 'pc': hex(lr), 'pc_unslid': hex((lr - SLIDE) & MASK64)})
        if m.canon(nfp) <= fp:
            break
        fp = m.canon(nfp)
    return {'thread': hex(th), 'ctx': hex(ctx), 'kstack_base': hex(kbase),
            'saved': {'x19_x28': [hex(x) for x in w[:10]], 'fp': hex(w[10]), 'lr_raw': hex(w[11]), 'sp': hex(w[12])},
            'frames': frames}

TRAP_RET_UNSLID = 0x237ef7cd4   # _mach_msg2_trap svc return site (Codex re-calls README)


def user_frames(m, root, fp, limit=48):
    frames, used = [], set()
    cur = m.ucanon(fp)
    for _ in range(limit):
        if not cur or cur in used or cur & 0xf:
            break
        used.add(cur)
        try:
            nfp, nlr = struct.unpack('<QQ', m.read(cur, 16, root, m.ubits))
        except Exception as e:
            frames.append({'fp': hex(cur), 'error': str(e)}); break
        frames.append({'fp': hex(cur), 'lr': hex(m.ucanon(nlr))})
        nxt = m.ucanon(nfp)
        if not (cur < nxt < cur + 0x200000):
            break
        cur = nxt
    return frames


def owning_image(m, root, va, max_pages=4096):
    """Scan back page-aligned for a Mach-O header; return (base, install_name, off)."""
    if not va:
        return None
    page = va & ~0xfff
    for _ in range(max_pages):
        try:
            magic = m.read(page, 4, root, m.ubits)
        except Exception:
            page -= 0x1000
            continue
        if magic == bytes.fromhex('cffaedfe'):
            # Mach-O 64. Parse load commands for LC_ID_DYLIB (0xd) install name.
            try:
                hdr = m.read(page, 0x20, root, m.ubits)
                ncmds = struct.unpack_from('<I', hdr, 16)[0]
                off = page + 0x20
                name = None
                for _ in range(min(ncmds, 128)):
                    c = m.read(off, 8, root, m.ubits)
                    cmd, csize = struct.unpack('<II', c)
                    if csize < 8 or csize > 0x4000:
                        break
                    if cmd in (0xd, 0xc, 0x8000001f):  # ID_DYLIB, LOAD_DYLIB, (not exe)
                        if cmd == 0xd:
                            raw = m.read(off, csize, root, m.ubits)
                            noff = struct.unpack_from('<I', raw, 8)[0]
                            if 8 <= noff < csize:
                                name = raw[noff:].split(b'\x00')[0].decode('utf-8', 'replace')
                            break
                    off += csize
                return {'base': hex(page), 'name': name, 'off': hex(va - page)}
            except Exception as e:
                return {'base': hex(page), 'name': None, 'err': str(e)}
        page -= 0x1000
    return None


def annotate_frames(m, root, frames, limit=16):
    out = []
    for f in frames[:limit]:
        lr = f.get('lr')
        if not lr:
            out.append(f); continue
        img = owning_image(m, root, int(lr, 16))
        g = dict(f)
        if img:
            g['img'] = img.get('name'); g['img_off'] = img.get('off'); g['img_base'] = img.get('base')
        out.append(g)
    return out


def full(m, tgt, owners):
    task, space = int(tgt['task'], 16), int(tgt['ipc_space'], 16)
    root = user_root(m, task)
    out = []
    for t in threads(m, task):
        row = dict(t)
        u = t.get('user', {})
        if 'x' in u:
            pc = m.ucanon(int(u['pc'], 16))
            row['user_pc'] = hex(pc)
            row['user_lr'] = hex(m.ucanon(int(u['lr'], 16)))
            row['user_frames'] = user_frames(m, root, int(u['fp'], 16))
            if row.get('in_mach_trap') or os.environ.get('WALK_ANNOTATE_ALL'):
                try:
                    row['user_frames'] = annotate_frames(m, root, row['user_frames'])
                    pcimg = owning_image(m, root, pc)
                    if pcimg:
                        row['user_pc_img'] = pcimg.get('name'); row['user_pc_off'] = pcimg.get('off')
                except Exception as e:
                    row['annotate_err'] = str(e)
            try:
                code = m.read(pc - 4, 8, root, m.ubits)
                row['in_mach_trap'] = code == bytes.fromhex('011000d4c0035fd6')
            except Exception as e:
                row['in_mach_trap'] = None; row['pc_read_error'] = str(e)
            if row.get('in_mach_trap'):
                row['dsc_slide_from_trap'] = hex(pc - TRAP_RET_UNSLID)
                try:
                    buf = m.ucanon(int(u['x'][0], 16))
                    raw = m.read(buf, 0x50, root, m.ubits)
                    bits, size, rem, loc, vou, mid = struct.unpack_from('<6I', raw)
                    msg = {'buffer': hex(buf), 'bits': hex(bits), 'size': size, 'remote': hex(rem),
                           'local': hex(loc), 'msgh_id': mid, 'bytes': raw.hex(),
                           'x1_options': u['x'][1], 'x4_rcv_name': u['x'][4]}
                    if rem and rem != 0xffffffff:
                        try:
                            r = lookup(m, space, rem); msg['remote_right'] = r
                            msg['remote_port'] = port_dump(m, int(r['port'], 16), owners)
                        except Exception as e:
                            msg['remote_error'] = str(e)
                    row['mach_msg'] = msg
                except Exception as e:
                    row['mach_msg_error'] = str(e)
        try:
            row['kstack'] = kstack(m, int(t['thread'], 16))
        except Exception as e:
            row['kstack_error'] = str(e)
        try:
            io = m.ptr(int(t['thread'], 16) + TH_ITH_OBJ)
            if io:
                row['ith_object_port'] = port_dump(m, io, owners)
        except Exception as e:
            row['ith_object_error'] = str(e)
        out.append(row)
    return out


def main():
    mode = os.environ.get('WALK_MODE', 'procs')
    m = Memory()
    rec = {'mode': mode, 'captured_utc': datetime.now(timezone.utc).isoformat(),
           'kernel_va_bits': m.kbits, 'user_va_bits': m.ubits, 'slide': hex(SLIDE),
           'tcr': hex(m.tcr), 'ttbr1': hex(m.root)}
    ps = procs(m)
    owners = {p['ipc_space']: {'pid': p['pid'], 'name': p['name']} for p in ps if 'ipc_space' in p}
    rec['process_count'] = len(ps)
    if mode == 'procs':
        rec['processes'] = ps
    elif mode == 'full':
        rec['processes'] = ps
        rec['targets'] = {}
        for name in os.environ.get('WALK_PROCS', 'backboardd,SpringBoard,notifyd').split(','):
            c = [p for p in ps if p['name'] == name and 'ipc_space' in p]
            if not c:
                rec['targets'][name] = {'error': 'not found / no ipc_space'}; continue
            try:
                rec['targets'][name] = {'proc': c[0], 'threads': full(m, c[0], owners)}
            except Exception as e:
                import traceback
                rec['targets'][name] = {'proc': c[0], 'error': str(e), 'tb': traceback.format_exc()}
    else:
        name = os.environ.get('WALK_PROC', 'backboardd')
        tgts = [p for p in ps if p['name'] == name and p.get('task_proc_ro_ok', True)]
        if not tgts:
            tgts = [p for p in ps if p['name'] == name]
        assert tgts, 'process %s not found' % name
        tgt = tgts[0]; rec['target'] = tgt
        assert 'ipc_space' in tgt, 'target %s lacks ipc_space (task.proc_ro reciprocity failed)' % name
        task, space = int(tgt['task'], 16), int(tgt['ipc_space'], 16)
        ths = threads(m, task)
        if mode == 'threads':
            rec['threads'] = ths
        elif mode == 'msg':
            root = user_root(m, task); out = []
            for t in ths:
                u = t.get('user', {})
                if 'x' not in u:
                    continue
                pc = int(u['pc'], 16)
                row = {'tid': t['tid'], 'pc': u['pc'], 'waiting': t['waiting']}
                try:
                    code = m.read(m.ucanon(pc) - 4, 8, root, m.ubits)
                    row['in_mach_trap'] = code == bytes.fromhex('011000d4c0035fd6')   # svc #0x80; ret
                    if row['in_mach_trap']:
                        buf = m.ucanon(int(u['x'][0], 16))
                        raw = m.read(buf, 0x50, root, m.ubits)
                        bits, size, rem, loc, vou, mid = struct.unpack_from('<6I', raw)
                        row.update(buffer=hex(buf), bits=hex(bits), size=size, remote=hex(rem), local=hex(loc),
                                   msgh_id=mid, is_io_service_open_extended=(mid == 2862), bytes=raw.hex())
                        if rem:
                            row['remote_right'] = lookup(m, space, rem)
                except Exception as e:
                    row['error'] = str(e)
                out.append(row)
            rec['messages'] = out
            rec['stuck_io_service_open_extended'] = [r['tid'] for r in out if r.get('msgh_id') == 2862]
        elif mode == 'port':
            if os.environ.get('WALK_PORT_ADDR'):
                port = int(os.environ['WALK_PORT_ADDR'], 16)
            else:
                rec['right'] = lookup(m, space, int(os.environ['WALK_PORT'], 16))
                port = int(rec['right']['port'], 16)
            rec['port'] = port_dump(m, port, owners)
        elif mode == 'kstack':
            tid = int(os.environ['WALK_TID'], 0)
            th = [t for t in ths if t['tid'] == tid]
            assert th, 'tid %d not in %s' % (tid, name)
            rec['kstack'] = kstack(m, int(th[0]['thread'], 16))
    rec['physical_pages_read'] = len(m.cache)
    return rec


rec = {}
try:
    gdb.execute('maintenance packet Qqemu.PhyMemMode:1', to_string=True)
    rec = main()
except Exception as exc:
    import traceback
    rec = {'error': str(exc), 'traceback': traceback.format_exc()}
finally:
    gdb.execute('maintenance packet Qqemu.PhyMemMode:0', to_string=True)
    out = os.environ.get('WALK_OUT', '/tmp/xnu-walk.json')
    open(out, 'w').write(json.dumps(rec, indent=2) + '\n')
    print(json.dumps({'out': out, 'error': rec.get('error'), 'stuck': rec.get('stuck_io_service_open_extended')}))
