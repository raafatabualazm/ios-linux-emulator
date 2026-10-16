#!/usr/bin/env python3
"""
xnu-t8140-walk.py — gdb Python helper for QEMU gdbstub inspection of
Apple T8140 / iOS 27 (xnu-13432.2.10) guest.

Usage (from gdb-multiarch attached to QEMU gdbstub):

  (gdb) source /workspace/xnu-t8140-walk.py
  (gdb) python walk_allproc(slide=0x20000000)
  (gdb) python walk_backboardd(slide=0x20000000)
  (gdb) python translate_user_va(task_addr, user_va, slide=0x20000000)

SLIDE is the KASLR slide (runtime = unslid + SLIDE). Default 0x20000000.

Offsets are for Darwin 27.0.0 xnu-13432.2.10~2 RELEASE_ARM64_T8140
(kernelcache.release.iPhone17,3). See /workspace/ios-linux-emulator-gdb-kit.md
for provenance (PROVEN vs INFERRED).

Only uses gdb.selected_inferior().read_memory — no writes.
"""
from __future__ import annotations

import struct
from typing import Optional, Tuple, List

try:
    import gdb  # type: ignore
except ImportError:
    gdb = None  # allow import for unit-style dry checks


# ---------------------------------------------------------------------------
# Offsets (unslid VAs for globals; field offsets relative to object base)
# ---------------------------------------------------------------------------

# Globals (unslid). Runtime = UN SLID + SLIDE.
KERNPROC_SLOT = 0xFFFFFFF007E8B7D0   # PROVEN: ldr site; holds proc_t*
ALLPROC       = 0xFFFFFFF00B790280   # PROVEN: LIST_INSERT_HEAD in bsd_init

# proc
OFF_P_LIST_NEXT = 0x00               # PROVEN (LIST_ENTRY at start)
OFF_P_LIST_PREV = 0x08
OFF_P_PPTR      = 0x10               # layout
OFF_P_PROC_RO   = 0x18               # PROVEN (bsd_init str to +0x18)
OFF_P_PID       = 0x60               # PROVEN (proc_getpid after kernproc cmp)
OFF_P_STAT      = 0x64               # PROVEN (strb in bsd_init)
OFF_P_COMM      = 0x55C              # PROVEN (proc_best_name)
OFF_P_NAME      = 0x56D              # PROVEN (proc_best_name)
OFF_P_LFLAG     = 0x448              # PROVEN (P_LHASTASK bit)
PROC_STRUCT_SIZE = 0x768             # PROVEN (task == proc + 0x768)
PROC_AND_TASK_SIZE = 0xE38           # PROVEN (zone element size)
P_LHASTASK = 0x2                     # from source P_LHASTASK

# task (adjacent: task = proc + PROC_STRUCT_SIZE)
OFF_TASK_MAP           = 0x28        # PROVEN (type encoding + source order)
OFF_TASK_THREADS       = 0x50        # PROVEN (queue_head_t threads)
OFF_TASK_ITK_SPACE     = 0x310       # PROVEN (type encoding)
OFF_TASK_BSD_INFO_RO   = 0x3C8       # PROVEN (^{proc_ro} in encoding)
OFF_TASK_SHARED_REGION_ID = 0x428    # PROVEN (encoding)
OFF_TASK_SHARED_REGION = 0x430       # PROVEN (encoding)
# task_shared_region_slide: INFERRED near shared_region; probe if needed
OFF_TASK_SR_SLIDE_CANDIDATES = (0x438, 0x650, 0x654)  # INFERRED

# thread
OFF_TH_WAIT_EVENT   = 0x18           # PROVEN (encoding + source: after links union)
OFF_TH_WAIT_RESULT  = 0xD8           # encoding-derived (label INFERRED-exact)
OFF_TH_KERNEL_STACK = 0xF0           # encoding-derived
OFF_TH_MACHINE      = 0x100          # PROVEN (encoding machine_thread start)
OFF_TH_CTXDATA      = 0x108          # PROVEN (machine.contextData)
OFF_TH_UPCB         = 0x110          # PROVEN (machine.upcb)
OFF_TH_KPCB         = 0x120          # PROVEN (machine.kpcb)
OFF_TH_KSTACKPTR    = 0x150          # encoding-derived (CONFIG_SPTM layout)
OFF_TH_STATE        = 0x1F0          # encoding-derived
OFF_TH_SAVED        = 0x370          # PROVEN (ith_state at +0x398)
OFF_TH_ITH_OBJECT   = 0x390          # PROVEN (recv_bufs=24 + option=8)
OFF_TH_ITH_STATE    = 0x398          # PROVEN (strange ith_state panic)
OFF_TH_THREADS      = 0x3F8          # encoding (global threads list)
OFF_TH_TASK_THREADS = 0x408          # encoding (task_threads link)
OFF_TH_MAP          = 0x420          # encoding
OFF_TH_ITH_SPECIAL_REPLY = 0x450     # encoding-derived (after mutex)
OFF_TH_THREAD_ID    = 0x4E8          # PROVEN (thread_tid accessor)

# TH_ states (from xnu thread.h, stable)
TH_WAIT   = 0x01
TH_SUSP   = 0x02
TH_RUN    = 0x04
TH_UNINT  = 0x08
TH_TERMINATE = 0x10
TH_TERMINATE2 = 0x20
TH_IDLE   = 0x80

# ipc_port (RELEASE size 144)
OFF_IP_OBJECT         = 0x00
OFF_IP_WAITQ          = 0x18         # sizeof(ipc_object)=24 PROVEN by add freq
OFF_IP_MESSAGES       = 0x40         # waitq WQ_OPAQUE_SIZE=40 on arm64
OFF_IP_RECEIVER_NAME  = 0x4C         # imq_receiver_name inside messages
OFF_IP_RECEIVER       = 0x60         # PROVEN (PAC-load frequency + layout)
OFF_IP_KOBJECT        = 0x68         # next union after receiver

# ipc_space
OFF_IS_TABLE = 0x40                  # INFERRED (layout)
OFF_IS_TASK  = 0x48                  # INFERRED (layout); verify round-trip

# vm_map / pmap
OFF_MAP_PMAP_CANDIDATES = (0x58, 0x60, 0x68, 0x70, 0x78)  # INFERRED; probe
OFF_PMAP_TTE  = 0x00                 # PROVEN (source: first field)
OFF_PMAP_TTEP = 0x08                 # PROVEN (source: second field)

# arm_saved_state / ss_64 (ash=8, then ss_64)
OFF_SS_ASH = 0x00
OFF_SS64_X0 = 0x08
OFF_SS64_FP = 0x08 + 29 * 8          # 0xF0
OFF_SS64_LR = 0x08 + 30 * 8          # 0xF8
OFF_SS64_SP = 0x08 + 31 * 8          # 0x100
OFF_SS64_PC = 0x08 + 32 * 8          # 0x108

# ARM64 16K page tables (T8140)
PAGE_SHIFT = 14
PAGE_SIZE = 1 << PAGE_SHIFT          # 16384
TTE_SHIFT = 11                       # 2048 entries per table? depends on attr
# For 16K granule, L1/L2/L3 index bits: typically 11 bits per level (2048 ents)
# T8140 user space often 3-level. Masks below are conventional 16K:
Tn_INDEX_SHIFT = (PAGE_SHIFT, PAGE_SHIFT + 11, PAGE_SHIFT + 22)  # L3,L2,L1 rough

# PAC strip for kernel pointers (top byte / PAC bits)
def strip_pac(ptr: int) -> int:
    if ptr == 0:
        return 0
    # Kernel VAs: 0xfffffff0xxxxxxxx — keep low 40-48 bits of VA, force canonical
    # Heuristic: if looks like kernel ptr with PAC in high bits, clear [63:40] sign
    # and restore 0xfffffff0 prefix when bit 39 suggests kernel.
    raw = ptr & 0x0000FFFFFFFFFFFF
    # If original had 0xfffff... high bits, restore kernel canonical form
    if (ptr >> 40) & 0xFFFFF:
        # Keep as-is if already looks like 0xfffffff0...
        if (ptr >> 36) == 0xFFFFFFF:
            return ptr
        # Reconstruct: Apple kernel tips are typically 0xfffffff0xxxxxxxx
        return 0xFFFFFFF000000000 | (raw & 0xFFFFFFFFF)
    return raw


def read_bytes(addr: int, n: int) -> bytes:
    if gdb is None:
        raise RuntimeError("not running under gdb")
    inf = gdb.selected_inferior()
    return bytes(inf.read_memory(addr, n))


def u64(addr: int) -> int:
    return struct.unpack_from("<Q", read_bytes(addr, 8))[0]


def u32(addr: int) -> int:
    return struct.unpack_from("<I", read_bytes(addr, 4))[0]


def u16(addr: int) -> int:
    return struct.unpack_from("<H", read_bytes(addr, 2))[0]


def read_cstr(addr: int, maxlen: int = 64) -> str:
    try:
        data = read_bytes(addr, maxlen)
    except Exception:
        return "<unreadable>"
    if b"\x00" in data:
        data = data[: data.index(b"\x00")]
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return repr(data)


def kva(unslid: int, slide: int) -> int:
    return unslid + slide


def safe_u64(addr: int) -> Optional[int]:
    try:
        return u64(addr)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Process / task / thread walks
# ---------------------------------------------------------------------------

def iter_allproc(slide: int, limit: int = 512):
    """Yield (proc_addr, pid, name) walking allproc.lh_first."""
    head = kva(ALLPROC, slide)
    first = safe_u64(head)
    if first is None:
        print(f"[!] cannot read allproc at {head:#x}")
        return
    first = strip_pac(first)
    p = first
    seen = set()
    n = 0
    while p and p not in seen and n < limit:
        seen.add(p)
        n += 1
        try:
            pid = u32(p + OFF_P_PID)
            name = read_cstr(p + OFF_P_COMM, 17)
            longname = read_cstr(p + OFF_P_NAME, 33)
            if longname:
                name = longname
            yield p, pid, name
            nxt = strip_pac(u64(p + OFF_P_LIST_NEXT))
            p = nxt
        except Exception as e:
            print(f"[!] walk broke at proc {p:#x}: {e}")
            break


def walk_allproc(slide: int = 0x20000000, limit: int = 512):
    print(f"=== allproc walk (slide={slide:#x}) ===")
    print(f"allproc@ {kva(ALLPROC, slide):#x}  kernproc_slot@ {kva(KERNPROC_SLOT, slide):#x}")
    kp = safe_u64(kva(KERNPROC_SLOT, slide))
    if kp is not None:
        print(f"kernproc = {strip_pac(kp):#x}")
    for p, pid, name in iter_allproc(slide, limit):
        print(f"  pid={pid:5d}  proc={p:#x}  task={p + PROC_STRUCT_SIZE:#x}  {name}")


def find_proc_by_name(name: str, slide: int = 0x20000000) -> Optional[int]:
    for p, pid, n in iter_allproc(slide):
        if n == name or n.startswith(name):
            return p
    return None


def task_from_proc(proc: int) -> Optional[int]:
    try:
        lflag = u32(proc + OFF_P_LFLAG)
        if not (lflag & P_LHASTASK):
            print(f"[!] proc {proc:#x} P_LHASTASK clear (lflag={lflag:#x})")
        return proc + PROC_STRUCT_SIZE
    except Exception as e:
        print(f"[!] task_from_proc: {e}")
        return None


def iter_task_threads(task: int, limit: int = 128):
    """Yield thread addresses from task->threads queue."""
    head = task + OFF_TASK_THREADS
    try:
        first = strip_pac(u64(head))  # queue_head.next
    except Exception as e:
        print(f"[!] cannot read task.threads: {e}")
        return
    # queue_entry at OFF_TH_TASK_THREADS — next pointer is first field of queue_chain
    t = first
    seen = set()
    n = 0
    while t and t not in seen and n < limit:
        # queue head points at &thread->task_threads, not thread base
        # thread = entry_addr - OFF_TH_TASK_THREADS
        thr = t - OFF_TH_TASK_THREADS if t != head else 0
        if thr and thr not in seen:
            seen.add(thr)
            n += 1
            yield thr
        try:
            nxt = strip_pac(u64(t))  # le_next / next of queue_chain at task_threads
        except Exception:
            break
        if nxt == head or nxt == 0 or nxt == t:
            break
        t = nxt


def thread_summary(thr: int) -> str:
    try:
        tid = u64(thr + OFF_TH_THREAD_ID)
        state = u32(thr + OFF_TH_STATE)
        wait_event = u64(thr + OFF_TH_WAIT_EVENT)
        wait_result = u32(thr + OFF_TH_WAIT_RESULT)
        ith_state = u32(thr + OFF_TH_ITH_STATE)
        ith_obj = strip_pac(u64(thr + OFF_TH_ITH_OBJECT))
        flags = []
        if state & TH_WAIT: flags.append("WAIT")
        if state & TH_RUN: flags.append("RUN")
        if state & TH_SUSP: flags.append("SUSP")
        if state & TH_UNINT: flags.append("UNINT")
        if state & TH_IDLE: flags.append("IDLE")
        if state & TH_TERMINATE: flags.append("TERM")
        return (f"tid={tid} state={state:#x}({','.join(flags) or '?'}) "
                f"wait_event={wait_event:#x} wait_result={wait_result} "
                f"ith_state={ith_state:#x} ith_object={ith_obj:#x}")
    except Exception as e:
        return f"<error {e}>"


def read_saved_state(ss_addr: int, label: str = "ss") -> dict:
    """Read PC/LR/FP/SP from an arm_saved_state*."""
    out = {"addr": ss_addr, "label": label}
    if not ss_addr:
        return out
    try:
        out["fp"] = u64(ss_addr + OFF_SS64_FP)
        out["lr"] = u64(ss_addr + OFF_SS64_LR)
        out["sp"] = u64(ss_addr + OFF_SS64_SP)
        out["pc"] = u64(ss_addr + OFF_SS64_PC)
    except Exception as e:
        out["error"] = str(e)
    return out


def thread_contexts(thr: int) -> dict:
    """Collect user/kernel saved state pointers and a few frames."""
    info = {"thread": thr}
    try:
        info["upcb"] = strip_pac(u64(thr + OFF_TH_UPCB))
        info["kpcb"] = strip_pac(u64(thr + OFF_TH_KPCB))
        info["contextData"] = strip_pac(u64(thr + OFF_TH_CTXDATA))
        info["kstackptr"] = strip_pac(u64(thr + OFF_TH_KSTACKPTR))
        info["kernel_stack"] = u64(thr + OFF_TH_KERNEL_STACK)
    except Exception as e:
        info["error"] = str(e)
        return info
    # Prefer upcb for user; contextData->ss is equivalent user context
    user_ss = info["upcb"]
    if not user_ss and info["contextData"]:
        user_ss = info["contextData"]  # arm_context.ss at offset 0
    info["user"] = read_saved_state(user_ss, "user")
    info["kern"] = read_saved_state(info["kpcb"], "kern")
    return info


def fp_unwind(fp: int, slide: int, max_frames: int = 16, user: bool = False) -> List[dict]:
    """Naive frame-pointer unwind. For user frames, caller must have translated
    the FP to a kernel-readable address (or use translate_user_va per frame)."""
    frames = []
    seen = set()
    for _ in range(max_frames):
        if not fp or fp in seen:
            break
        seen.add(fp)
        try:
            saved_fp = u64(fp)
            saved_lr = u64(fp + 8)
        except Exception:
            break
        frames.append({"fp": fp, "lr": saved_lr, "lr_unslid": saved_lr - slide if not user else saved_lr})
        fp = saved_fp
    return frames


def resolve_port_owner(port: int, slide: int) -> dict:
    """Given an ipc_port*, return receiver name + owning task/pid if possible."""
    out = {"port": port}
    if not port:
        return out
    try:
        out["ip_receiver_name"] = u32(port + OFF_IP_RECEIVER_NAME)
        space = strip_pac(u64(port + OFF_IP_RECEIVER))
        out["ip_receiver"] = space
        kobj = strip_pac(u64(port + OFF_IP_KOBJECT))
        out["ip_kobject"] = kobj
        if space:
            # Probe is_task
            for off in (OFF_IS_TASK, 0x40, 0x50):
                try:
                    task = strip_pac(u64(space + off))
                    if not task:
                        continue
                    # Round-trip: task.itk_space should be ~space
                    sp2 = strip_pac(u64(task + OFF_TASK_ITK_SPACE))
                    if sp2 == space or abs(sp2 - space) < 0x1000:
                        out["is_task_off"] = off
                        out["task"] = task
                        proc = task - PROC_STRUCT_SIZE
                        out["proc"] = proc
                        out["pid"] = u32(proc + OFF_P_PID)
                        out["name"] = read_cstr(proc + OFF_P_COMM, 17)
                        break
                except Exception:
                    continue
    except Exception as e:
        out["error"] = str(e)
    return out


def walk_backboardd(slide: int = 0x20000000):
    print(f"=== backboardd inspection (slide={slide:#x}) ===")
    proc = find_proc_by_name("backboardd", slide)
    if not proc:
        print("[!] backboardd not found in allproc")
        return
    print(f"proc={proc:#x} pid={u32(proc + OFF_P_PID)} name={read_cstr(proc + OFF_P_COMM)}")
    task = task_from_proc(proc)
    if not task:
        return
    print(f"task={task:#x}")
    threads = list(iter_task_threads(task))
    print(f"threads: {len(threads)}")
    blocked = []
    for thr in threads:
        s = thread_summary(thr)
        print(f"  thr={thr:#x}  {s}")
        st = u32(thr + OFF_TH_STATE)
        if st & TH_WAIT:
            blocked.append(thr)
        ctx = thread_contexts(thr)
        u = ctx.get("user", {})
        k = ctx.get("kern", {})
        if "pc" in u:
            print(f"    user  pc={u['pc']:#x} lr={u.get('lr', 0):#x} fp={u.get('fp', 0):#x}")
        if "pc" in k:
            print(f"    kern  pc={k['pc']:#x} lr={k.get('lr', 0):#x} fp={k.get('fp', 0):#x} "
                  f"(unslid pc={(k['pc'] - slide) & 0xffffffffff:#x})")
            if k.get("fp"):
                frames = fp_unwind(k["fp"], slide, user=False)
                for i, fr in enumerate(frames[:8]):
                    print(f"      #{i} lr_unslid={fr['lr_unslid']:#x}")
    print(f"\n=== blocked threads ({len(blocked)}) — mach_msg receive probe ===")
    for thr in blocked:
        ith_obj = strip_pac(safe_u64(thr + OFF_TH_ITH_OBJECT) or 0)
        ith_state = u32(thr + OFF_TH_ITH_STATE)
        wait_event = safe_u64(thr + OFF_TH_WAIT_EVENT) or 0
        print(f"  thr={thr:#x} ith_state={ith_state:#x} ith_object={ith_obj:#x} wait_event={wait_event:#x}")
        # ith_object for receive is ipc_object_t == &port->ip_object == port
        if ith_obj:
            owner = resolve_port_owner(ith_obj, slide)
            print(f"    port owner: {owner}")
        # special reply port
        try:
            srp = strip_pac(u64(thr + OFF_TH_ITH_SPECIAL_REPLY))
            if srp:
                print(f"    ith_special_reply_port={srp:#x} -> {resolve_port_owner(srp, slide)}")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# User VA translation (16K granule, best-effort)
# ---------------------------------------------------------------------------

def find_map_pmap(map_addr: int) -> Tuple[Optional[int], Optional[int]]:
    """Probe candidate pmap offsets; return (pmap, offset_used)."""
    for off in OFF_MAP_PMAP_CANDIDATES:
        try:
            pmap = strip_pac(u64(map_addr + off))
            if not pmap:
                continue
            tte = safe_u64(pmap + OFF_PMAP_TTE)
            ttep = safe_u64(pmap + OFF_PMAP_TTEP)
            if tte and ttep is not None:
                # tte should look like a kernel pointer
                if (tte >> 36) == 0xFFFFFFF or (strip_pac(tte) >> 36) == 0xFFFFFFF:
                    return strip_pac(pmap), off
                if ttep != 0 and ttep < (1 << 40):  # plausible phys
                    return strip_pac(pmap), off
        except Exception:
            continue
    return None, None


def translate_user_va(task: int, user_va: int, slide: int = 0x20000000) -> Optional[int]:
    """Best-effort user VA -> kernel-accessible phys-backed VA via pmap->tte.

    NOTE: Returns a *physical address* (ttep-relative walk result as phys), or
    None. Mapping phys->kva needs the guest's physmap (typically physmap_base
    + phys). On many Apple Silicon XNU builds, phystokv is phys + gVirtBase
    offset; the script prints phys and leaves kva conversion to the operator
    if the physmap base is unknown.

    INFERRED page-table geometry — verify against a known mapped page first.
    """
    try:
        map_addr = strip_pac(u64(task + OFF_TASK_MAP))
    except Exception as e:
        print(f"[!] task.map: {e}")
        return None
    pmap, off = find_map_pmap(map_addr)
    if not pmap:
        print(f"[!] could not find pmap on map {map_addr:#x}; tried {OFF_MAP_PMAP_CANDIDATES}")
        return None
    print(f"[*] map={map_addr:#x} pmap={pmap:#x} (off={off:#x})")
    tte_kv = strip_pac(u64(pmap + OFF_PMAP_TTE))
    ttep = u64(pmap + OFF_PMAP_TTEP)
    print(f"[*] tte_kv={tte_kv:#x} ttep_phys={ttep:#x}")

    # 16K, 3-level style walk (INFERRED — indices may need adjustment)
    # Level shifts for 16KB granule with 47-bit VA are often 36, 25, 14
    levels = (36, 25, 14)
    table_phys = ttep
    table_kv = tte_kv
    for li, shift in enumerate(levels):
        idx = (user_va >> shift) & ((1 << 11) - 1)  # 11-bit index typical
        try:
            entry = u64(table_kv + idx * 8)
        except Exception as e:
            print(f"[!] L{li} read failed at {table_kv:#x}[{idx}]: {e}")
            return None
        print(f"  L{li} idx={idx} entry={entry:#x}")
        if entry == 0:
            print("[!] invalid entry")
            return None
        # Leaf detection: bit 1 clear often means block/page; varies by format
        # ARM LPAE: type bits [1:0] — 0b11 table, 0b01 block/page depending on level
        etype = entry & 0x3
        next_phys = entry & 0x0000FFFFFFFFC000  # phys mask rough for 16K
        if li == len(levels) - 1 or etype == 0x1:
            phys = next_phys | (user_va & (PAGE_SIZE - 1))
            print(f"[*] phys={phys:#x}")
            return phys
        # next table — convert phys to kv using same slide as root (tte - ttep)
        physmap_off = tte_kv - ttep
        table_kv = next_phys + physmap_off
        table_phys = next_phys
    return None


def shared_cache_slide_hint(task: int) -> None:
    """Print shared_region pointer / candidate slide fields (INFERRED)."""
    try:
        sr = strip_pac(u64(task + OFF_TASK_SHARED_REGION))
        print(f"task.shared_region={sr:#x}")
        for off in OFF_TASK_SR_SLIDE_CANDIDATES:
            v = safe_u64(task + off)
            if v is not None:
                print(f"  task+{off:#x} = {v:#x}")
    except Exception as e:
        print(f"[!] {e}")


# ---------------------------------------------------------------------------
# gdb command wrappers
# ---------------------------------------------------------------------------

if gdb is not None:
    class WalkAllproc(gdb.Command):
        """walk-allproc [slide]"""
        def __init__(self):
            super().__init__("walk-allproc", gdb.COMMAND_USER)

        def invoke(self, arg, from_tty):
            slide = int(arg.strip(), 0) if arg.strip() else 0x20000000
            walk_allproc(slide)

    class WalkBackboardd(gdb.Command):
        """walk-backboardd [slide]"""
        def __init__(self):
            super().__init__("walk-backboardd", gdb.COMMAND_USER)

        def invoke(self, arg, from_tty):
            slide = int(arg.strip(), 0) if arg.strip() else 0x20000000
            walk_backboardd(slide)

    WalkAllproc()
    WalkBackboardd()
    print("[xnu-t8140-walk] loaded. Commands: walk-allproc, walk-backboardd")
    print("  or: python walk_backboardd(slide=0x20000000)")
