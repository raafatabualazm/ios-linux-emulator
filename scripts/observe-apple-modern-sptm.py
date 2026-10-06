#!/usr/bin/env python3
"""Make one bounded, unchanged SPTM entry observation on apple-modern.

Requires an immutable executable and the five matching decoded components
with their preparation provenance. Starts stopped, uses QMP child stdio,
requests at most 100ms of execution (50ms by default), then stops and quits.
No disks, ramdisk, guest patches, host network or trust changes are supplied.
An observation, exception trace or clean exit does not qualify iOS/GUI/IPA boot.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import stat
import struct
import sys
import threading
import time
import subprocess


sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    'modern_machine_oracle', Path(__file__).with_name('test-apple-modern-machine.py'))
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)
ASSETS = ORACLE.ASSETS
CAP = 1 << 20
OVERALL_SECONDS = 15.0
MAX_EXECUTION_SECONDS = 0.1
ASSET_CAPS = {'bootkc': 128 << 20, 'sptm': 16 << 20, 'txm': 16 << 20,
              'dtree': 4 << 20, 'restore-trustcache': 16 << 20}


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def digest(path, deadline):
    initial = path.stat()
    require(stat.S_ISREG(initial.st_mode), 'Regular input: ' + str(path))
    sha = hashlib.sha256()
    with path.open('rb') as source:
        for data in iter(lambda: source.read(1 << 20), b''):
            require(time.monotonic() < deadline, 'Overall hash deadline')
            sha.update(data)
    final = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    require(identity(initial) == identity(final), 'Input changed during hashing')
    return {'bytes': final.st_size, 'sha256': sha.hexdigest()}


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, CAP))
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)


def exception_observation(trace, layout, blobs):
    lines = trace.splitlines()
    begins = [i for i, line in enumerate(lines) if line.startswith('Taking exception ')]
    result = {'exception_records': len(begins), 'first_exception_context': []}
    if not begins:
        return result
    end = begins[1] if len(begins) > 1 else len(lines)
    context = lines[begins[0]:min(end, begins[0] + 12)]
    result['first_exception_context'] = context
    undefined = next((number for number, begin in enumerate(begins)
                      if '[Undefined Instruction]' in lines[begin]), None)
    if undefined is None:
        return result
    begin = begins[undefined]
    end = begins[undefined + 1] if undefined + 1 < len(begins) else len(lines)
    context = lines[begin:min(end, begin + 12)]
    result['first_undefined_exception_context'] = context
    result['first_undefined_exception_record'] = undefined
    import re
    match = re.search(r'\bwith ELR(?:_GL)?\s+(0x[0-9a-fA-F]+)', '\n'.join(context))
    if match is None:
        return result
    pc = int(match[1], 16)
    for copy in layout['copies']:
        begin = copy['physical']
        if begin <= pc and pc + 4 <= begin + copy['file']:
            offset = copy['offset'] + pc - begin
            word = struct.unpack_from('<I', blobs[copy['image']], offset)[0]
            instruction = {'faulting_physical_pc': hex(pc), 'image': copy['image'],
                           'segment': copy['segment'], 'source_offset': hex(offset),
                           'instruction_word': hex(word)}
            if (word & 0xffc00000) == 0xd5000000 and ((word >> 19) & 3) >= 2:
                fields = {'read': bool((word >> 21) & 1), 'op0': (word >> 19) & 3,
                          'op1': (word >> 16) & 7, 'crn': (word >> 12) & 15,
                          'crm': (word >> 8) & 15, 'op2': (word >> 5) & 7, 'rt': word & 31}
                fields['encoding'] = (f"S{fields['op0']}_{fields['op1']}_"
                                      f"C{fields['crn']}_C{fields['crm']}_{fields['op2']}")
                instruction['system_instruction_fields'] = fields
            result['first_exception_instruction_from_unchanged_source'] = instruction
            break
    else:
        result['first_exception_instruction_decode'] = (
            'ELR not within an unchanged file-backed physical copy; no VA translation inferred')
    return result


def observe(binary, components, provenance_path, output, duration_ms):
    started = time.monotonic()
    deadline = started + OVERALL_SECONDS
    report = {'scope': 'One bounded unchanged SPTM entry execution observation; '
                       'no guest kernel boot qualification',
              'binary': str(binary), 'components': str(components),
              'modern_guest_boot': False, 'gui_verified': False, 'ipa_executed': False,
              'guest_patched': False, 'protections_bypassed': False,
              'execution_requested': False, 'observation_completed': False,
              'execution_watchdog_fired': False, 'overall_watchdog_fired': False,
              'limits': {'overall_seconds': OVERALL_SECONDS,
                         'requested_execution_ms': duration_ms,
                         'execution_hard_limit_ms': MAX_EXECUTION_SECONDS * 1000,
                         'child_log_file_bytes': CAP,
                         'qmp_frame_bytes': ORACLE.MAX_QMP_FRAME,
                         'qmp_request_seconds': 3}}
    process = qmp = execution_watchdog = overall_watchdog = None
    asset_paths = {name: components / name for name in ASSETS}
    auxiliary_paths = {'provenance': provenance_path, 'layout_oracle': Path(ORACLE.__file__),
                       'observation_tool': Path(__file__).resolve()}
    log_paths = {name: output / name for name in
                 ('emulator.log', 'interrupt-trace.log', 'serial.log')}
    before = auxiliary_before = None
    execution_started = None

    def kill_owned(flag):
        report[flag] = True
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass

    def guard():
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Overall observation deadline')
        require(not report['execution_watchdog_fired'], 'Execution watchdog fired')
        require(not report['overall_watchdog_fired'], 'Overall watchdog fired')
        for path in log_paths.values():
            require(not path.exists() or path.stat().st_size <= CAP,
                    'Child log file bound: ' + path.name)
        return remaining

    try:
        require(not binary.stat().st_mode & 0o222, 'Use a pinned executable without writable mode bits')
        require(binary.stat().st_size <= 512 << 20, 'Executable size bound')
        report['binary_sha256'] = digest(binary, deadline)['sha256']
        for name, path in asset_paths.items():
            require(0 < path.stat().st_size <= ASSET_CAPS[name], 'Component size bound: ' + name)
            require(',' not in str(path) and '\n' not in str(path), 'QEMU component option path')
        require(provenance_path.stat().st_size <= 2 << 20, 'Provenance size bound')
        before = {name: digest(path, deadline) for name, path in asset_paths.items()}
        report['component_hashes_before'] = before
        auxiliary_before = {name: digest(path, deadline) for name, path in auxiliary_paths.items()}
        report['auxiliary_hashes_before'] = auxiliary_before
        provenance = json.loads(provenance_path.read_text())
        require(provenance.get('status') == 'prepared-unmodified' and
                provenance.get('security_changes') == [], 'Unmodified matched preparation provenance')
        artifacts = {item['component']: item['derived'] for item in provenance['artifacts']}
        for name, actual in before.items():
            require(artifacts[name]['sha256'] == actual['sha256'] and
                    artifacts[name]['size'] == actual['bytes'], 'Matched prepared component: ' + name)
        report['firmware_identity'] = {key: provenance.get(key) for key in
                                      ('requested_product', 'requested_board',
                                       'product_version', 'product_build')}
        blobs = {name: path.read_bytes() for name, path in asset_paths.items()}
        layout = ORACLE.expected_layout(blobs)
        options = ','.join(['apple-modern',
                           *(f"{('tc' if name == 'restore-trustcache' else name)}={path}"
                             for name, path in asset_paths.items()),
                           'prepare-only=false', 'boot-command-line=-v'])
        argv = [str(binary), '-M', options, '-m', '8G', '-smp', '1', '-S',
                '-nodefaults', '-nic', 'none', '-display', 'none',
                '-serial', 'file:' + str(log_paths['serial.log']), '-monitor', 'none',
                '-qmp', 'stdio', '-d', 'int', '-D', str(log_paths['interrupt-trace.log'])]
        report['argv'] = argv
        guard()
        with log_paths['emulator.log'].open('wb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=log, preexec_fn=child_limits)
            overall_watchdog = threading.Timer(max(0, deadline - time.monotonic()),
                                               kill_owned, args=('overall_watchdog_fired',))
            overall_watchdog.daemon = True
            overall_watchdog.start()
            qmp = ORACLE.QMP(None, guard, process=process)
            require(qmp.request('query-status')['running'] is False, 'Initial CPU stopped')
            initial_text = qmp.request('human-monitor-command', {'command-line': 'info registers'})
            (output / 'registers-before.txt').write_text(initial_text)
            initial = ORACLE.parse_registers(initial_text)
            report['initial_registers'] = initial
            require(initial['PC'] == layout['entry'] and initial['X00'] == layout['args'] and
                    initial['PSTATE'] & 15 == 9, 'Expected prepared SPTM PC/x0/AArch64 EL2h')
            execution_started = time.monotonic()
            execution_watchdog = threading.Timer(MAX_EXECUTION_SECONDS, kill_owned,
                                                 args=('execution_watchdog_fired',))
            execution_watchdog.daemon = True
            execution_watchdog.start()
            report['execution_requested'] = True
            qmp.request('cont')
            target = execution_started + duration_ms / 1000
            reason = 'requested-duration'
            while time.monotonic() < target:
                guard()
                if any(path.exists() and path.stat().st_size >= CAP for path in log_paths.values()):
                    reason = 'trace-or-log-budget'
                    break
                time.sleep(min(0.002, max(0, target - time.monotonic())))
            qmp.request('stop')
            report['execution_wall_seconds'] = round(time.monotonic() - execution_started, 6)
            execution_watchdog.cancel()
            execution_watchdog.join(timeout=0.1)
            report['execution_end_reason'] = reason
            report['stop_acknowledged'] = True
            status = qmp.request('query-status')
            report['stopped_status'] = status
            require(status['running'] is False, 'Observed CPU stopped')
            final_text = qmp.request('human-monitor-command', {'command-line': 'info registers'})
            (output / 'registers-after.txt').write_text(final_text)
            report['final_registers'] = ORACLE.parse_registers(final_text)
            qmp.request('quit')
            require(process.wait(timeout=min(1, guard())) == 0, 'Clean requested QEMU shutdown')
            report['observation_completed'] = True
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        for watchdog in (execution_watchdog, overall_watchdog):
            if watchdog is not None:
                watchdog.cancel()
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
            report['exit_code'] = process.returncode
            report['child_reaped'] = process.poll() is not None
            if execution_started is not None and 'execution_wall_seconds' not in report:
                report['execution_upper_wall_seconds'] = round(time.monotonic() - execution_started, 6)
        if qmp is not None:
            try:
                qmp.close()
            except Exception as error:
                report['cleanup_error'] = str(error)
                report['observation_completed'] = False
        elif process is not None:
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()
        try:
            after = {name: digest(path, deadline) for name, path in asset_paths.items()}
            report['component_hashes_after'] = after
            report['components_unchanged'] = before == after
            report['binary_unchanged'] = digest(binary, deadline)['sha256'] == report.get('binary_sha256')
            auxiliary_after = {name: digest(path, deadline) for name, path in auxiliary_paths.items()}
            report['auxiliary_hashes_after'] = auxiliary_after
            report['auxiliary_inputs_unchanged'] = auxiliary_before == auxiliary_after
            require(report['components_unchanged'] and report['binary_unchanged'] and
                    report['auxiliary_inputs_unchanged'], 'All inputs stayed immutable')
        except Exception as error:
            report['preservation_error'] = str(error)
            report['observation_completed'] = False
        sizes = {name: path.stat().st_size for name, path in log_paths.items() if path.exists()}
        report['retained_file_sizes'] = sizes
        report['trace_bytes'] = sizes.get('interrupt-trace.log', 0)
        report['trace_budget_reached'] = report['trace_bytes'] >= CAP
        if 'layout' in locals() and log_paths['interrupt-trace.log'].exists():
            with log_paths['interrupt-trace.log'].open('rb') as stream:
                trace = stream.read(CAP).decode('utf-8', errors='replace')
            report.update(exception_observation(trace, layout, blobs))
        report['elapsed_seconds'] = round(time.monotonic() - started, 6)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--provenance', type=Path,
                        help='Defaults to components/../provenance.json')
    parser.add_argument('--output-dir', type=Path, required=True, help='New private output directory')
    parser.add_argument('--execution-ms', type=float, default=50.0)
    args = parser.parse_args()
    require(0 < args.execution_ms <= 100, 'Execution request must be 0 < milliseconds <= 100')
    binary = args.binary.resolve(strict=True)
    components = args.components.resolve(strict=True)
    provenance = (args.provenance or components.parent / 'provenance.json').resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), 'Regular executable supplied')
    require(components.is_dir(), 'Decoded component directory supplied')
    output = args.output_dir.parent.resolve(strict=True) / args.output_dir.name
    previous_umask = os.umask(0o077)
    try:
        output.mkdir(mode=0o700, exist_ok=False)
        result = observe(binary, components, provenance, output, args.execution_ms)
    finally:
        os.umask(previous_umask)
    print(json.dumps({key: result.get(key) for key in
                      ('observation_completed', 'execution_wall_seconds', 'child_reaped',
                       'exit_code', 'components_unchanged', 'binary_unchanged',
                       'modern_guest_boot', 'error')}))
    return 0 if result['observation_completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
