#!/usr/bin/env python3
"""Run a bounded AFL smoke test with valid, 14-byte syscall seeds."""
import json
import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

import validate_runtime as rt

WORK = Path.cwd() / 'afl-smoke'
AFL = Path(shutil.which('afl-fuzz') or 'afl-fuzz')


def main():
    global WORK, AFL
    parser = argparse.ArgumentParser()
    rt.add_path_arguments(parser)
    parser.add_argument('--afl', type=Path, default=AFL,
                        help='AFL 2.57b afl-fuzz executable (default: PATH)')
    parser.add_argument('--smp', type=int, default=7)
    parser.add_argument('--no-tid-filter', action='store_true')
    parser.add_argument('--wide-coverage', action='store_true',
                        help='collect all filtered kernel coverage instead of only the syscall wrapper')
    parser.add_argument('--out-dir', type=Path,
                        help='new directory for copied disks, seeds, and AFL results')
    parser.add_argument('--seconds', type=int, default=50,
                        help='maximum AFL runtime (default: 50)')
    args = parser.parse_args()
    rt.configure_paths(args, parser)
    AFL = args.afl.expanduser().resolve()
    if not AFL.is_file() or not os.access(AFL, os.X_OK):
        parser.error(f'afl-fuzz executable is missing or not executable: {AFL}')
    if args.seconds <= 0 or args.smp <= 0:
        parser.error('--seconds and --smp must be positive')
    scope = None if args.wide_coverage else os.getenv(
        'AFL_HARNESS_SCOPE', rt.DEFAULT_HARNESS_SCOPE)
    if scope and args.no_tid_filter:
        parser.error('scoped coverage requires the HINT #0x31 thread filter; use --wide-coverage to disable both')
    if scope and rt.sha(rt.LAB / 'ios_scfuzzer.img') != rt.PINNED_RAMDISK_SHA256:
        parser.error('scoped coverage requires the pinned iOS 14 harness ramdisk; use --wide-coverage for another image')
    if args.smp != 7 or args.no_tid_filter:
        WORK = WORK.with_name(WORK.name + (f'-smp{args.smp}' if args.smp != 7 else '')
                              + ('-no-tid-filter' if args.no_tid_filter else ''))
    if args.out_dir:
        WORK = args.out_dir
    WORK.mkdir(parents=True, exist_ok=False)
    corpus = WORK / 'corpus'
    corpus.mkdir()
    (corpus / 'getpid').write_bytes(b'\x00\x14' + b'\x07\x00' * 6)
    (corpus / 'getppid').write_bytes(b'\x00\x27' + b'\x07\x00' * 6)
    rt.prepare_disks(WORK)
    qemu = rt.arguments(WORK)
    qemu[qemu.index('-smp') + 1] = str(args.smp)
    i = qemu.index('-d')
    del qemu[i:i+6]
    argv = [str(AFL), '-m', '16G', '-t', '10000', '-i', str(corpus),
            '-o', str(WORK / 'out')] + qemu
    env = dict(os.environ, AFL_SKIP_CPUFREQ='1',
               AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES='1',
               AFL_NO_AFFINITY='1', AFL_NO_UI='1')
    if scope:
        env['AFL_HARNESS_SCOPE'] = scope
    else:
        env.pop('AFL_HARNESS_SCOPE', None)
    if args.no_tid_filter:
        env['AFL_NO_TID_FILTER'] = '1'
    else:
        env.pop('AFL_NO_TID_FILTER', None)
    (WORK / 'argv.json').write_text(json.dumps(argv, indent=2) + '\n')
    start = time.monotonic()
    with (WORK / 'afl-console.log').open('wb') as log:
        process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            process.wait(timeout=args.seconds)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    report = {'elapsed_seconds': round(time.monotonic()-start, 3),
              'coverage_scope': scope or 'wide kernel coverage',
              'afl_exit_code': process.returncode}
    stats = WORK / 'out' / 'fuzzer_stats'
    if stats.exists():
        report['fuzzer_stats'] = {
            key.strip(): value.strip()
            for line in stats.read_text().splitlines() if ':' in line
            for key, value in [line.split(':', 1)]
        }
    (WORK / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
