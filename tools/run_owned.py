#!/usr/bin/env python3
"""Pinned v71 replay with an owned debugger, shared lock and bounded lifetime."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def qemus():
    found = []
    for d in Path('/proc').iterdir():
        if not d.name.isdigit():
            continue
        try:
            if (d / 'comm').read_text().startswith('qemu-system'):
                found.append(int(d.name))
        except (OSError, ProcessLookupError):
            pass
    return found


def owns_listener(pid, port):
    """Check /proc without creating a debugger connection or resuming a CPU."""
    try:
        sockets = {os.readlink(fd) for fd in Path(f'/proc/{pid}/fd').iterdir()}
        for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
            fields = line.split()
            if (fields[1] == f'0100007F:{port:04X}' and fields[3] == '0A'
                    and f'socket:[{fields[9]}]' in sockets):
                return True
    except (OSError, ProcessLookupError):
        pass
    return False


def host_sample():
    """Read-only host contention witness; touches no guest and no QMP."""
    sample = {'epoch': time.time(), 'nproc': os.cpu_count()}
    try:
        sample['loadavg'] = Path('/proc/loadavg').read_text().split()[:3]
    except OSError:
        pass
    want_mem = {'MemAvailable', 'MemFree', 'SwapFree', 'SwapTotal', 'Shmem',
                'Committed_AS', 'CommitLimit', 'Dirty', 'Writeback'}
    try:
        mem = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, _, rest = line.partition(':')
            if key in want_mem:
                mem[key] = int(rest.split()[0])
        sample['meminfo_kb'] = mem
    except (OSError, ValueError, IndexError):
        pass
    want_vm = {'pswpin', 'pswpout', 'pgmajfault', 'allocstall_movable',
               'pgscan_direct'}
    try:
        vm = {}
        for line in Path('/proc/vmstat').read_text().splitlines():
            key, _, value = line.partition(' ')
            if key in want_vm:
                vm[key] = int(value)
        sample['vmstat'] = vm
    except (OSError, ValueError):
        pass
    return sample


def write_identity(out, identity):
    temporary = out / 'identity.json.tmp'
    temporary.write_text(json.dumps(identity, indent=2) + '\n')
    temporary.replace(out / 'identity.json')


def main():
    if sys.flags.optimize:
        raise SystemExit('Run without Python optimization: fixture guards require assertions')
    ap = argparse.ArgumentParser()
    ap.add_argument('name')
    ap.add_argument('--seconds', type=int, default=900)
    ap.add_argument('--gdb-port', type=int, default=23519)
    ap.add_argument('--binary')
    ap.add_argument('--patch-list', type=Path)
    ap.add_argument('--ramdisk', type=Path)
    ap.add_argument('--checkpoint', type=Path)
    ap.add_argument('--acm-no-sep', action='store_true')
    ap.add_argument('--cachemode-patch', action='store_true')
    ap.add_argument('--frames', action='store_true')
    ap.add_argument('--final-snapshot', action='store_true',
                    help='save the final private filesystem delta before stopping the owned guest')
    ap.add_argument('--vnc-display', type=int,
                    help='serve the emulated display on localhost:5900+N')
    ap.add_argument('--early-usermanagerd', action='store_true',
                    help='start paused and run the guarded native UserManager ordering diagnostic')
    ap.add_argument('--early-seconds', type=int, default=240)
    args = ap.parse_args()
    if args.vnc_display is not None and not 1 <= args.vnc_display <= 99:
        ap.error('--vnc-display must be in 1..99')
    if args.early_usermanagerd and not 1 <= args.early_seconds < args.seconds:
        ap.error('--early-seconds must be positive and less than --seconds')
    if args.early_usermanagerd and not (args.patch_list and args.ramdisk):
        ap.error('--early-usermanagerd requires its qualified image and duplicate-init patch list')
    if not args.name.replace('-', '').isalnum():
        raise SystemExit('name must be alphanumeric/hyphens')
    out = HERE / args.name
    out.mkdir(exist_ok=False)
    lock = (ROOT / '.locks/qemu.lock').open('a+')
    deadline = time.monotonic() + 900
    print('Waiting for the shared lock and other QEMU processes', flush=True)
    while True:
        if time.monotonic() > deadline:
            raise SystemExit('No guest started: another lane remains active')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            time.sleep(2)
            continue
        others = qemus()
        if not others:
            break
        fcntl.flock(lock, fcntl.LOCK_UN)
        time.sleep(2)
    baseline = ROOT / 'modern-emulator/evidence/features-20261017/v71-a386-true/argv.json'
    av = json.loads(baseline.read_text())['argv']
    src = Path(args.binary or av[0])
    pin = out / 'qemu-system-aarch64'
    shutil.copy2(src, pin)
    assert sha(src) == sha(pin)
    qmp = '/tmp/codex-swap-' + str(os.getpid()) + '.sock'
    machine = av[av.index('-M') + 1]
    for key, path in [('ramdisk-patches',args.patch_list), ('ramdisk',args.ramdisk)]:
        if not path:
            continue
        replacement = str(path.resolve(strict=True))
        assert ',' not in replacement
        options = machine.split(',')
        matches = [i for i, option in enumerate(options) if option.startswith(key+'=')]
        assert len(matches) == 1
        options[matches[0]] = key + '=' + replacement
        machine = ','.join(options)
    if args.checkpoint:
        checkpoint = str(args.checkpoint.resolve(strict=True))
        assert ',' not in checkpoint
        machine += ',ramdisk-checkpoint=' + checkpoint
    av = [str(pin), '-M', machine, '-m', '24G', '-smp', '1', '-nodefaults',
          '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(out / 'serial.log'),
          '-qmp', 'unix:' + qmp + ',server=on,wait=off',
          '-gdb', 'tcp:127.0.0.1:' + str(args.gdb_port)]
    if args.early_usermanagerd:
        av.append('-S')
    if args.vnc_display is not None:
        # The executable is copied out of its build directory for each run;
        # retain its text keymaps rather than depending on an installed QEMU.
        keymaps = ROOT / 'Inferno/wt/codex-springboard/pc-bios/keymaps'
        assert (keymaps / 'en-us').is_file(), 'missing source QEMU VNC keymaps'
        data = out / 'qemu-data'
        shutil.copytree(keymaps, data / 'keymaps')
        av += ['-L', str(data), '-vnc', f'127.0.0.1:{args.vnc_display}']
    ident = {'source_binary': str(src), 'binary_sha256': sha(pin), 'argv': av,
             'baseline': str(baseline), 'gdb_port': args.gdb_port, 'qmp': qmp,
             'started_epoch': time.time(), 'input_hashes': {}}
    ident['requested_seconds'] = args.seconds
    ident['final_snapshot_requested'] = args.final_snapshot
    if args.vnc_display is not None:
        ident['vnc_address'] = f'127.0.0.1:{5900 + args.vnc_display}'
        ident['vnc_keymaps'] = {str(path.relative_to(out)): sha(path)
                                for path in sorted((out / 'qemu-data/keymaps').rglob('*'))
                                if path.is_file()}
    helpers = [HERE / 'run_owned.py', HERE / 'capture-threads.py']
    if args.acm_no_sep:
        helpers.append(HERE / 'hotpatch-acm-no-sep.py')
    if args.early_usermanagerd:
        helpers += [HERE / 'backboard-re/run-launchd-ordering.py',
                    HERE / 'backboard-re/launchd-config/stop-launchd-main.py',
                    HERE / 'backboard-re/launchd-umd-policy.py']
    retained = out / 'helper-sources'
    retained.mkdir()
    ident['retained_helpers'] = []
    for helper in helpers:
        copy = retained / helper.name
        shutil.copy2(helper, copy)
        assert sha(helper) == sha(copy)
        ident['retained_helpers'].append({'source': str(helper), 'retained': str(copy),
                                          'sha256': sha(copy)})
    for item in machine.split(','):
        if '=' not in item:
            continue
        k, v = item.split('=', 1)
        if k in {'bootkc', 'sptm', 'txm', 'dtree', 'tc', 'ramdisk-patches', 'ramdisk-checkpoint'} or (k == 'ramdisk' and args.ramdisk):
            ident['input_hashes'][k] = {'path': v, 'sha256': sha(v)}
    if args.early_usermanagerd:
        profiles = {
            ('e669d16bfa0fb360b9605fe62767653cabfbe785c760f7324683558c1ac6ceee',
             '7faef8ed2eeccdc691027731184539921cb11d7e68fc5b5b868acf2d29df4694'):
                'migration image with duplicate-init runtime patch',
            ('97e99ce7a509279a3f09a86788d301e4c8cee33e09ef6d687e0a100e9579effd',
             'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'):
                'v11 snapshot-apps warm filesystem; image patches already materialized',
        }
        pair = (ident['input_hashes']['ramdisk']['sha256'],
                ident['input_hashes']['ramdisk-patches']['sha256'])
        assert pair in profiles, 'early ordering requires a qualified image/list pair disabling duplicate late init'
        ident['ordering_fixture_profile'] = profiles[pair]
    if args.checkpoint:
        checkpoints = {
            ('97e99ce7a509279a3f09a86788d301e4c8cee33e09ef6d687e0a100e9579effd',
             '1c89ce23fd2d4424ef8eb8a69e40cddad3b6b89346a9e541a164fda50334341d'):
                'v13 snapshot3, completed LS database, guarded private page overlay',
            ('97e99ce7a509279a3f09a86788d301e4c8cee33e09ef6d687e0a100e9579effd',
             'b4d5394c869c971558bad0b7d1d9e62f5aa32f570b71cc86cfda2e15d2f1372a'):
                'v3 setup-completion: checkpoint-v2 plus com.apple.purplebuddy '
                'SetupDone/SetupVersion/SetupFinishedAllSteps; single variable',
            ('97e99ce7a509279a3f09a86788d301e4c8cee33e09ef6d687e0a100e9579effd',
             '9386d16a8b8c4097f83112cc702590ca578891d8ebd4e762ae82bd1ce3e9c3d8'):
                'v3 setup-watchdog: checkpoint-v2 plus com.apple.springboard '
                'FBLaunchWatchdogExceptions purplebuddy +180s; single variable',
        }
        pair = (ident['input_hashes']['ramdisk']['sha256'],
                ident['input_hashes']['ramdisk-checkpoint']['sha256'])
        assert pair in checkpoints, 'checkpoint requires a qualified image/checkpoint pair'
        ident['checkpoint_profile'] = checkpoints[pair]
    proc = None
    debugger = None
    boot_resumed = not args.early_usermanagerd
    stop = False
    def handle(_sig, _frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)
    try:
        with (out / 'qemu.out').open('wb') as log:
            proc = subprocess.Popen(av, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        ident['pid'] = proc.pid
        ident['host_at_start'] = host_sample()
        write_identity(out, ident)
        print(json.dumps({'pid': proc.pid, 'qmp': qmp, 'gdb_port': args.gdb_port,
                          'out': str(out)}), flush=True)
        end = time.monotonic() + args.seconds
        if args.early_usermanagerd:
            early_end = min(end, time.monotonic() + args.early_seconds)
            while not owns_listener(proc.pid, args.gdb_port):
                if (proc.poll() is not None or stop or (out / 'STOP').exists()
                        or time.monotonic() >= early_end):
                    raise RuntimeError('Owned paused debugger listener did not become ready')
                time.sleep(0.25)
            env = dict(os.environ, LAUNCHD_EARLY_IDENTITY=str(out / 'identity.json'),
                       LAUNCHD_EARLY_OUT=str(out / 'launchd-early.json'),
                       LAUNCHD_POLICY_OUT=str(out / 'launchd-umd-policy.json'))
            with (out / 'launchd-ordering-gdb.log').open('wb') as log:
                debugger = subprocess.Popen(
                    ['gdb-multiarch', '-q', '-nx', '-batch',
                     '-ex', 'set pagination off', '-ex', 'set confirm off',
                     '-ex', 'set remotetimeout 10',
                     '-ex', 'target remote 127.0.0.1:' + str(args.gdb_port),
                     '-ex', 'source ' + str(HERE / 'backboard-re/run-launchd-ordering.py')],
                    env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            ident['early_debugger_pid'] = debugger.pid
            ident['early_debugger_deadline_seconds'] = args.early_seconds
            ident['early_helpers'] = {
                str(path): sha(path) for path in [
                    HERE / 'backboard-re/run-launchd-ordering.py',
                    HERE / 'backboard-re/launchd-config/stop-launchd-main.py',
                    HERE / 'backboard-re/launchd-umd-policy.py']}
            write_identity(out, ident)
            while debugger.poll() is None and proc.poll() is None:
                if stop or (out / 'STOP').exists() or time.monotonic() >= early_end:
                    # Kill this owned guest first: debugger teardown must never
                    # resume a boot after an incomplete ordering diagnostic.
                    proc.kill()
                    proc.wait()
                    debugger.kill()
                    debugger.wait()
                    raise RuntimeError('Early ordering diagnostic interrupted or timed out')
                time.sleep(0.25)
            statefile = out / 'launchd-ordering.json'
            state = json.loads(statefile.read_text()) if statefile.exists() else {}
            if debugger.poll() != 0 or state.get('state') != 'native_policy_accepted_and_resumed':
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                raise RuntimeError('Early ordering diagnostic failed; owned guest stopped')
            print('Native UserManager boot policy accepted; guest resumed', flush=True)
            boot_resumed = True
            # Charge --seconds from the real boot, not from the paused -S window:
            # v14 lost 71.7 s and v15 91.5 s of their budgets before the guest ran.
            end = time.monotonic() + args.seconds
        last_frame = 0
        last_sample = 0.0
        frame_number = 0
        patched = False
        acm_patched = False
        while proc.poll() is None and time.monotonic() < end and not stop:
            if (out / 'STOP').exists():
                break
            if args.acm_no_sep and not acm_patched:
                applied = subprocess.run(['python3', str(HERE / 'hotpatch-acm-no-sep.py'), str(out)],
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         timeout=60)
                print(applied.stdout, flush=True)
                if applied.returncode:
                    raise RuntimeError('Guarded ACM absent-provider patch failed')
                acm_patched = True
            if args.cachemode_patch and not patched:
                with (out / 'qemu.out').open('rb') as output:
                    output.seek(max(0, (out / 'qemu.out').stat().st_size - 65536))
                    tail = output.read()
                if b"tag='A406'" in tail:
                    applied = subprocess.run(['python3', str(HERE / 'hotpatch-cachemode.py'), str(out)],
                                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                             timeout=40)
                    print(applied.stdout, flush=True)
                    if applied.returncode:
                        raise RuntimeError('Guarded cache-mode patch failed')
                    patched = True
            if args.frames and time.monotonic() - last_frame >= 15:
                last_frame = time.monotonic()
                frames = out / 'frames'
                frames.mkdir(exist_ok=True)
                frame_number += 1
                ppm = frames / f'{frame_number:04d}.ppm'
                png = ppm.with_suffix('.png')
                try:
                    with socket.socket(socket.AF_UNIX) as sock:
                        sock.settimeout(3)
                        sock.connect(qmp)
                        with sock.makefile('rwb', buffering=0) as stream:
                            stream.readline()
                            for command in [{'execute': 'qmp_capabilities'},
                                            {'execute': 'screendump', 'arguments': {'filename': str(ppm)}}]:
                                stream.write((json.dumps(command) + '\n').encode())
                                while True:
                                    response = json.loads(stream.readline())
                                    if 'error' in response:
                                        raise RuntimeError(response['error'])
                                    if 'return' in response:
                                        break
                    from PIL import Image
                    picture = Image.open(ppm).convert('RGB')
                    picture.save(png)
                    ppm.unlink()
                    colored = sum(1 for pixel in picture.getdata() if any(pixel))
                    with (out / 'frames.jsonl').open('a') as f:
                        f.write(json.dumps({'file': str(png), 'epoch': time.time(),
                                            'nonblack_pixels': colored, 'sha256': sha(png)}) + '\n')
                except Exception as error:
                    print('Frame capture:', repr(error), flush=True)
            if time.monotonic() - last_sample >= 30:
                last_sample = time.monotonic()
                try:
                    with (out / 'host-stats.jsonl').open('a') as hs:
                        hs.write(json.dumps(host_sample()) + '\n')
                except OSError:
                    pass
            time.sleep(1)
    finally:
        if debugger is not None and debugger.poll() is None:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
            debugger.kill()
            debugger.wait()
        if proc is not None:
            if args.final_snapshot and boot_resumed and proc.poll() is None:
                capture = ROOT / 'modern-emulator/evidence/features-20261009/w14-sbkeys/tools/capture_ramdisk_cow.py'
                image = ident['input_hashes'].get('ramdisk', {}).get('path')
                if image:
                    print('Saving final filesystem snapshot before owned guest shutdown', flush=True)
                    snapshot_result = {'requested': True, 'state': 'not_started',
                                       'started_epoch': time.time()}
                    with (out / 'capture-final.log').open('wb') as snapshot_log:
                        try:
                            snapshot = subprocess.run(
                                ['python3', str(capture), '--pid', str(proc.pid),
                                 '--qmp', qmp, '--image', image, '--out', str(out / 'snapshot-final'),
                                 '--max-bytes', str(2 << 30)],
                                stdout=snapshot_log, stderr=subprocess.STDOUT, timeout=240)
                            print('Final filesystem snapshot exit:', snapshot.returncode, flush=True)
                            snapshot_result.update(returncode=snapshot.returncode,
                                                   state='captured' if snapshot.returncode == 0 and
                                                   (out / 'snapshot-final/manifest.json').exists() else 'failed')
                        except subprocess.TimeoutExpired:
                            print('Final filesystem snapshot exceeded its capture budget', flush=True)
                            snapshot_result['state'] = 'timed_out'
                    snapshot_result['finished_epoch'] = time.time()
                    (out / 'final-snapshot-result.json').write_text(json.dumps(snapshot_result, indent=2) + '\n')
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            result = {'pid': proc.pid, 'returncode': proc.returncode, 'closed_epoch': time.time(),
                      'host_at_end': host_sample(),
                      'binary_unchanged': sha(pin) == ident['binary_sha256'],
                      'inputs_unchanged': {k: sha(v['path']) == v['sha256']
                                           for k, v in ident['input_hashes'].items()}}
            (out / 'cleanup.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
