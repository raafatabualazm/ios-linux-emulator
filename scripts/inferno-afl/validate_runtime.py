#!/usr/bin/env python3
"""Independent bounded Inferno replay using AFL's real forkserver protocol.

Copies mutable disks, leaves the installed lab untouched, records each input's
consumption, bitmap and stop status, and traces two exact XNU syscall entries.
"""
import ctypes
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import struct
import subprocess
import time

HERE = Path(__file__).resolve().parent
LAB = Path('fuzz-inferno')
DATA = LAB
QEMU = HERE.parents[1] / 'build-afl/qemu-system-aarch64'
SEED = None
CRASH_DIR = LAB / 'out-inferno/crashes'
OPTIONAL_NAMESPACES = [('firmware', 2, 2), ('syscfg', 3, 3),
                       ('ctrl_bits', 4, 4), ('effaceable', 6, 6),
                       ('panic_log', 7, 8)]
GETPID = 'fffffff007e79260'
GETPPID = 'fffffff007e79270'
PINNED_RAMDISK_SHA256 = 'dfda491c79438ddd87b519747bbdc697d29c3d706b046ae9c57930178dcd7ab5'
DEFAULT_HARNESS_SCOPE = '0x1e7c:0x1e14'


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def add_path_arguments(parser):
    parser.add_argument('--lab', type=Path, default=LAB,
                        help='prepared harness and disk directory (default: ./fuzz-inferno)')
    parser.add_argument('--data', type=Path,
                        help='ticket and SEP firmware directory (default: --lab)')
    parser.add_argument('--qemu', type=Path, default=QEMU,
                        help='AFL-enabled QEMU executable (default: repository build-afl)')


def configure_paths(args, parser):
    global LAB, DATA, QEMU
    LAB = args.lab.expanduser().resolve()
    DATA = (args.data or LAB).expanduser().resolve()
    QEMU = args.qemu.expanduser().resolve()
    if not LAB.is_dir() or not DATA.is_dir():
        parser.error('--lab and --data must refer to prepared directories')
    if not QEMU.is_file() or not os.access(QEMU, os.X_OK):
        parser.error(f'QEMU executable is missing or not executable: {QEMU}')


def prepare_disks(work):
    for name in ['sep_nvram', 'sep_ssc', 'nvram']:
        shutil.copyfile(LAB / name, work / name)
    # Attach additional namespaces when present, supporting both compact
    # harness labs and complete restored layouts without machine-specific flags.
    for name, _, _ in OPTIONAL_NAMESPACES:
        if (LAB / name).is_file():
            shutil.copyfile(LAB / name, work / name)
    with (work / 'root').open('wb') as stream:
        stream.truncate((LAB / 'root').stat().st_size)


def arguments(work):
    argv = [str(QEMU), '-display', 'none', '-monitor', 'none',
            '-M', f't8030,trustcache={LAB}/static_tc,ticket={DATA}/root_ticket.der,'
                  f'sep-fw={DATA}/sep-firmware.n104.RELEASE.new.img4,'
                  f'sep-rom={DATA}/AppleSEPROM-Cebu-B1,kaslr-off=true,'
                  f'usb-conn-addr={work}/unused-usb.sock',
            '-kernel', str(LAB / 'kernelcache.research.iphone12b'),
            '-dtb', str(LAB / 'DeviceTree.n104ap.im4p'),
            '-initrd', str(LAB / 'ios_scfuzzer.img'),
            '-append', 'debug=0x14e kextlog=0xffff serial=3 -v rd=md0 wdt=-1',
            '-smp', '7', '-m', '4G', '-serial', f'file:{work}/serial.log',
            '-d', 'exec,nochain', '-dfilter', f'0x{GETPID}+0x10,0x{GETPPID}+0x10',
            '-D', str(work / 'syscall-trace.log')]
    for name in ['sep_nvram', 'sep_ssc']:
        argv += ['-drive', f'file={work}/{name},if=pflash,format=raw']
    argv += ['-drive', f'file={work}/root,format=raw,if=none,id=root',
             '-device', 'nvme-ns,drive=root,bus=nvme-bus.0,nsid=1,nstype=1,logical_block_size=4096,physical_block_size=4096',
             '-drive', f'file={work}/nvram,format=raw,if=none,id=nvram',
             '-device', 'apple-nvram,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram,logical_block_size=4096,physical_block_size=4096']
    for name, nsid, nstype in OPTIONAL_NAMESPACES:
        if (work / name).is_file():
            argv += ['-drive', f'file={work}/{name},format=raw,if=none,id={name}',
                     '-device', f'nvme-ns,drive={name},bus=nvme-bus.0,nsid={nsid},nstype={nstype},logical_block_size=4096,physical_block_size=4096']
    return argv


def read_word(fd, timeout):
    data = b''
    deadline = time.monotonic() + timeout
    while len(data) < 4:
        ready, _, _ = select.select([fd], [], [], max(0, deadline-time.monotonic()))
        if not ready:
            raise TimeoutError('forkserver response timed out')
        chunk = os.read(fd, 4-len(data))
        if not chunk:
            raise EOFError('forkserver closed the response pipe')
        data += chunk
    return struct.unpack('<I', data)[0]


def main():
    global SEED, CRASH_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument('--prime-fd9', action='store_true')
    parser.add_argument('--crashes', action='store_true')
    parser.add_argument('--crash-index', type=int)
    parser.add_argument('--case-file', type=Path,
                        help='replay this AFL queue, hang, or crash file after boot')
    parser.add_argument('--out-dir', type=Path,
                        help='new directory for copied disks, logs, maps, and report')
    add_path_arguments(parser)
    parser.add_argument('--no-tid-filter', action='store_true')
    parser.add_argument('--smp', type=int, default=7)
    parser.add_argument('--seed', type=Path, help='getpid seed (default: built-in 14-byte seed)')
    parser.add_argument('--crash-dir', type=Path, help='saved crash directory (default: LAB/out-inferno/crashes)')
    parser.add_argument('--repeat', type=int, default=0,
                        help='extra interleaved repetitions of both compact syscall seeds')
    parser.add_argument('--tcg-thread', choices=['single', 'multi'])
    parser.add_argument('--wide-coverage', action='store_true',
                        help='collect all filtered kernel coverage instead of only the syscall wrapper')
    parser.add_argument('--boot-timeout', type=float, default=75,
                        help='seconds to wait for the initial persistent boundary (default: 75)')
    parser.add_argument('--case-timeout', type=float, default=20,
                        help='seconds to wait for each later case boundary (default: 20)')
    args = parser.parse_args()
    configure_paths(args, parser)
    SEED = args.seed.expanduser().resolve() if args.seed else None
    CRASH_DIR = (args.crash_dir or LAB / 'out-inferno/crashes').expanduser().resolve()
    scope = None if args.wide_coverage else os.getenv(
        'AFL_HARNESS_SCOPE', DEFAULT_HARNESS_SCOPE)
    if scope and args.no_tid_filter:
        parser.error('scoped coverage requires the HINT #0x31 thread filter; use --wide-coverage to disable both')
    if scope and sha(LAB / 'ios_scfuzzer.img') != PINNED_RAMDISK_SHA256:
        parser.error('scoped coverage requires the pinned iOS 14 harness ramdisk; use --wide-coverage for another image')
    if args.repeat < 0:
        parser.error('--repeat must be nonnegative')
    if args.boot_timeout <= 0 or args.case_timeout <= 0:
        parser.error('timeouts must be positive')
    label = (f'runtime-crash-{args.crash_index}' if args.crash_index is not None
             else 'runtime-case' if args.case_file
             else 'runtime-prime' if args.prime_fd9 else 'runtime-observe')
    work = args.out_dir or Path.cwd() / (label + ('-no-tid-filter' if args.no_tid_filter else '') + (f'-smp{args.smp}' if args.smp != 7 else ''))
    work.mkdir(parents=True, exist_ok=False)
    prepare_disks(work)
    artifacts = [QEMU, LAB / 'ios_scfuzzer.img', LAB / 'kernelcache.research.iphone12b',
                 LAB / 'DeviceTree.n104ap.im4p', LAB / 'static_tc',
                 HERE / 'extracted/sysc_fuzz']
    report = {'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'coverage_scope': scope or 'wide kernel coverage',
              'artifacts': {str(p): sha(p) for p in artifacts if p.is_file()}, 'cases': []}
    libc = ctypes.CDLL(None, use_errno=True)
    libc.shmat.restype = ctypes.c_void_p
    libc.shmdt.argtypes = [ctypes.c_void_p]
    shm_id = libc.shmget(0, 65536, 0o1000 | 0o600)
    if shm_id < 0:
        raise OSError(ctypes.get_errno(), 'shmget')
    address = libc.shmat(shm_id, None, 0)
    if address == ctypes.c_void_p(-1).value:
        libc.shmctl(shm_id, 0, None)
        raise OSError(ctypes.get_errno(), 'shmat')
    report['map_shm_id'] = shm_id
    report['map_parent_address'] = hex(address)
    control_r, control_w = os.pipe()
    status_r, status_w = os.pipe()
    os.dup2(control_r, 198)
    os.dup2(status_w, 199)
    os.close(control_r)
    os.close(status_w)
    env = dict(os.environ, __AFL_SHM_ID=str(shm_id), __AFL_PERSISTENT='1', AFL_DEBUG='1')
    if scope:
        env['AFL_HARNESS_SCOPE'] = scope
    else:
        env.pop('AFL_HARNESS_SCOPE', None)
    # Default matches the installed launcher; the opt-in run measures the
    # per-CPU filter's effect on the same guest syscall cases.
    if args.no_tid_filter:
        env['AFL_NO_TID_FILTER'] = '1'
    else:
        env.pop('AFL_NO_TID_FILTER', None)
    env.pop('AFL_NO_FORKSRV', None)
    argv = arguments(work)
    argv[argv.index('-smp') + 1] = str(args.smp)
    if args.tcg_thread:
        argv += ['-accel', 'tcg,thread=' + args.tcg_thread]
    report['argv'] = argv
    child = None
    proc = None
    try:
        with (work/'testcase').open('w+b', buffering=0) as testcase, (work/'qemu.log').open('wb') as log:
            if args.prime_fd9:
                os.dup2(testcase.fileno(), 9)
            proc = subprocess.Popen(argv, stdin=testcase, stdout=log, stderr=log,
                                    env=env, pass_fds=((9, 198, 199) if args.prime_fd9 else (198, 199)), start_new_session=True)
            os.close(198)
            os.close(199)
            report['forkserver_hello'] = read_word(status_r, 10)
            seed = SEED.read_bytes() if SEED else b'\x00\x14' + b'\x07\x00' * 6
            vector_args = b'\x07\x00' * 6
            cases = [('boot_boundary', seed), (f'supplied_getpid_{len(seed)}', seed),
                     ('empty', b''), ('compact_getpid_14', b'\x00\x14'+vector_args),
                     ('compact_getppid_14', b'\x00\x27'+vector_args),
                     (f'supplied_getpid_{len(seed)}_repeat', seed),
                     ('compact_getpid_14_repeat', b'\x00\x14'+vector_args)]
            if args.repeat:
                cases += [(f'{kind}_repeat_{i:03}', b'\x00'+bytes([nr])+vector_args)
                          for i in range(args.repeat)
                          for kind, nr in [('getpid', 20), ('getppid', 39)]]
            if args.crash_index is not None:
                path = sorted(CRASH_DIR.glob('id:*'))[args.crash_index]
                cases = [('boot_boundary', seed), (f'saved_crash_{args.crash_index}', path.read_bytes())]
            elif args.case_file:
                cases = [('boot_boundary', seed), ('candidate', args.case_file.read_bytes())]
            elif args.crashes:
                cases += [('saved_crash_'+str(i), path.read_bytes()) for i, path in enumerate(
                    sorted(CRASH_DIR.glob('id:*')))]
            trace = work/'syscall-trace.log'
            previous = 0
            for index, (name, data) in enumerate(cases):
                testcase.seek(0)
                testcase.truncate()
                testcase.write(data)
                testcase.seek(0)
                ctypes.memset(address, 0, 65536)
                before = time.monotonic()
                os.write(control_w, struct.pack('<I', 0))
                child = read_word(status_r, 10)
                report['active_case'] = name
                (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')
                try:
                    fd9_target = os.readlink(f'/proc/{child}/fd/9')
                except OSError as exc:
                    fd9_target = repr(exc)
                wait_timeout = args.boot_timeout if not index else args.case_timeout
                try:
                    status = read_word(status_r, wait_timeout)
                except TimeoutError:
                    bitmap = ctypes.string_at(address, 65536)
                    (work / (name+'.map')).write_bytes(bitmap)
                    logs = trace.read_bytes() if trace.exists() else b''
                    new = logs[previous:]
                    previous = len(logs)
                    (work / (name+'.trace')).write_bytes(new)
                    row = {'name': name, 'size': len(data), 'hex': data.hex(),
                           'parent_file_offset_after_case': testcase.tell(),
                           'child_pid': child, 'fd9_target': fd9_target,
                           'seconds': round(time.monotonic()-before, 4),
                           'result': 'forkserver_boundary_timeout',
                           'timeout_seconds': wait_timeout,
                           'map_nonzero_excluding_marker': sum(v != 0 for v in bitmap[1:]),
                           'map_sha256': hashlib.sha256(bitmap).hexdigest(),
                           'getpid_entry_traces': new.count(('/'+GETPID+'/').encode()),
                           'getppid_entry_traces': new.count(('/'+GETPPID+'/').encode())}
                    report['cases'].append(row)
                    report['status'] = 'completed_with_timeout'
                    report['timed_out_case'] = name
                    (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')
                    print(json.dumps(row), flush=True)
                    break
                bitmap = ctypes.string_at(address, 65536)
                (work / (name+'.map')).write_bytes(bitmap)
                logs = trace.read_bytes() if trace.exists() else b''
                new = logs[previous:]
                previous = len(logs)
                (work / (name+'.trace')).write_bytes(new)
                row = {'name': name, 'size': len(data), 'hex': data.hex(),
                       'parent_file_offset_after_case': testcase.tell(), 'child_pid': child,
                       'fd9_target': fd9_target,
                       'seconds': round(time.monotonic()-before, 4),
                       'wait_status': status, 'stopped': os.WIFSTOPPED(status),
                       'stop_signal': os.WSTOPSIG(status) if os.WIFSTOPPED(status) else None,
                       'exit_code': os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
                       'signal': os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
                       'map_nonzero_excluding_marker': sum(v!=0 for v in bitmap[1:]),
                       'map_sha256': hashlib.sha256(bitmap).hexdigest(),
                       'getpid_entry_traces': new.count(('/'+GETPID+'/').encode()),
                       'getppid_entry_traces': new.count(('/'+GETPPID+'/').encode())}
                report['cases'].append(row)
                (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')
                print(json.dumps(row), flush=True)
            if report.get('status') != 'completed_with_timeout':
                report['status'] = 'completed'
    except Exception as exc:
        report['status'] = 'failed'
        report['error'] = repr(exc)
        raise
    finally:
        if proc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        for fd in [control_w, status_r]:
            os.close(fd)
        if args.prime_fd9:
            os.close(9)
        libc.shmdt(address)
        libc.shmctl(shm_id, 0, None)
        (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
