#!/usr/bin/env python3
"""Construct and reset the merged ANS/DCP/MTP profile without executing firmware.

This checks feature coexistence and mapping, not iOS pixels, touch, or encryption.
The separate ANS CPU gate qualifies block I/O and process-crash recovery.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(
        'merged_board_helpers', root / 'test-apple-modern-machine.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    out = args.output.resolve()
    out.mkdir(exist_ok=False)
    binary = args.binary.resolve()
    assets = {name: args.components.resolve() / name for name in helper.ASSETS}
    inputs = {str(path): digest(path) for path in [binary, *assets.values()]}
    backing = out / 'owned-empty.raw'
    backing.write_bytes(bytes(65536))
    disk_hash = digest(backing)
    machine = 'apple-modern,' + ','.join(
        key + '=' + str(assets[name]) for key, name in
        zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), helper.ASSETS))
    machine += (',prepare-only=on,modern-aic=on,modern-ans=on,'
                'modern-mtp-input=on,disp0-probe=dcp-mapper,'
                'dcp-iop=v6-resumed,dcp-attach-cbs=D575+MODES,'
                'modern-pmgr=on,modern-pmgr-storage=on,modern-cpu-dvfm=on,'
                'sep-sim=on,sep-dart=on,modern-mcc-dramcfg=on,'
                'modern-mcc-quota=on,modern-mcc-perf=on,modern-mcc-socni=on,'
                'modern-mcc-socni-command=on,modern-mcc-dcs-perf=on,'
                'modern-mcc-dsid=on,modern-mcc-slc=on,modern-pmp-ptd=on')
    command = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
               '-nodefaults', '-display', 'none', '-serial', 'none',
               '-monitor', 'none', '-S', '-qmp', 'stdio',
               '-blockdev', f'driver=file,filename={backing},node-name=merge-file,read-only=on',
               '-blockdev', 'driver=raw,file=merge-file,node-name=merge-disk,read-only=on',
               '-device', 'nvme-ns,drive=merge-disk,bus=modern-ans-nvme,nsid=1,logical_block_size=4096,physical_block_size=4096']
    report = {'passed': False, 'argv': command, 'inputs_before': inputs,
              'firmware_executed': False, 'guest_executed': False,
              'ios_storage_qualified': False, 'sep_encryption_qualified': False,
              'gui_pixels_qualified': False, 'touch_delivery_qualified': False}
    started = time.monotonic()
    process = None

    def guard():
        remaining = 20 - (time.monotonic() - started)
        assert remaining > 0, 'merged profile deadline'
        assert (out / 'emulator.log').stat().st_size < 4 << 20
        return remaining

    try:
        with (out / 'emulator.log').open('xb') as log:
            process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=log,
                                       bufsize=0, start_new_session=True)
            report['pid'] = process.pid
            qmp = helper.QMP(None, guard, process)
            report['passes'] = []
            for iteration in range(2):
                assert not qmp.request('query-status')['running']
                props = {name: qmp.request('qom-get', {
                    'path': '/machine', 'property': name}) for name in
                    ['prepare-only', 'modern-aic', 'modern-ans',
                     'modern-mtp-input', 'dcp-iop', 'dcp-attach-cbs']}
                assert all(props[name] is True for name in
                           ['prepare-only', 'modern-aic', 'modern-ans', 'modern-mtp-input'])
                assert props['dcp-iop'] == 'v6-resumed'
                assert props['dcp-attach-cbs'] == 'D575+MODES'
                children = {row['name']: row['type'] for row in
                            qmp.request('qom-list', {'path': '/machine'})
                            if row['type'].startswith('child<')}
                for child in ['ans', 'dcp-iop-dev', 'modern-mtp-gpio',
                              'modern-dockchannel-mtp', 'pmgr-storage']:
                    assert child in children, child
                maps = {name: qmp.request('qom-get', {
                    'path': '/machine/pmgr-storage', 'property': name}) for name in
                    ['mapped-window-count', 'sysbus-mmio-count']}
                assert maps == {'mapped-window-count': 56, 'sysbus-mmio-count': 0}
                ans = {name: qmp.request('qom-get', {
                    'path': '/machine/ans', 'property': name}) for name in
                    ['submission-count', 'guest-message-count']}
                assert ans == {'submission-count': 0, 'guest-message-count': 0}
                report['passes'].append({'iteration': iteration, 'properties': props,
                                         'children': children, 'mapping': maps,
                                         'ans': ans})
                if iteration == 0:
                    qmp.request('system_reset')
            qmp.request('quit')
            assert process.wait(timeout=5) == 0
            report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            report['child_reaped'] = process.poll() is not None
            report['qemu_returncode'] = process.returncode
        report['inputs_after'] = {str(path): digest(path) for path in
                                  [binary, *assets.values()]}
        report['inputs_unchanged'] = report['inputs_after'] == inputs
        report['backing_unchanged'] = digest(backing) == disk_hash
        report['script_sha256'] = digest(Path(__file__))
        report['elapsed_seconds'] = time.monotonic() - started
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert report['passed'] and report['inputs_unchanged'] and report['backing_unchanged'], report.get('error')
    print('PASS: merged ANS/DCP mode-push/MTP profile constructs and resets; firmware remains stopped')


if __name__ == '__main__':
    main()
