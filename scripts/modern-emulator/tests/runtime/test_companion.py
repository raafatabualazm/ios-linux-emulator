"""Companion overlay, pin, transport and lifecycle checks; no real guests run."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / 'tools/runtime/companion.py'
spec = importlib.util.spec_from_file_location('companion_fixture', MODULE)
companion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(companion)

FAKE_QEMU = r'''#!/usr/bin/env python3
import json,os,resource,socket,sys,time
mode=os.environ.get('COMPANION_FIXTURE_MODE','normal')
if mode=='early':
 print('fixture-early-stdout',flush=True)
 print('fixture-startup-error',file=sys.stderr,flush=True)
 sys.exit(0)
args=sys.argv[1:]
qmp=args[args.index('-qmp')+1].split(',')[0].removeprefix('unix:')
dev=next(x for x in args if x.startswith('usb-tcp-remote,'))
usb=next(x.split('=',1)[1] for x in dev.split(',') if x.startswith('conn-addr='))
qs=socket.socket(socket.AF_UNIX);qs.bind(qmp);qs.listen(1)
us=socket.socket(socket.AF_UNIX);us.bind(usb);us.listen(1)
if mode=='accepted':
 peer=socket.socket(socket.AF_UNIX);peer.connect(usb)
 accepted,_=us.accept()
print('SIZE_LIMIT='+str(resource.getrlimit(resource.RLIMIT_FSIZE)[1]),flush=True)
if mode=='flood':
 os.write(1,b'x'*(1<<20))
while True:
 connection,_=qs.accept()
 with connection:
  stream=connection.makefile('rwb')
  stream.write(b'{"QMP": {}}\n');stream.flush()
  while True:
   line=stream.readline()
   if not line:break
   request=json.loads(line)
   stream.write((json.dumps({'return':{},'id':request['id']})+'\n').encode());stream.flush()
   if request['execute']=='quit':
    if mode=='unlink-qmp':os.unlink(qmp)
    sys.exit(0)
'''


class CompanionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usb-companion-')
        self.root = Path(self.temp.name)
        self.disk = self.root / 'misleading.raw'
        self.img = Path(shutil.which('qemu-img')).resolve()
        subprocess.run([str(self.img), 'create', '-q', '-f', 'qcow2', str(self.disk), '16M'], check=True)
        self.seed = self.root / 'seed.iso'
        self.seed.write_bytes(b'private-fixture-seed')
        self.binary = self.root / 'fake-qemu'
        self.binary.write_text(FAKE_QEMU)
        self.binary.chmod(0o700)
        self.data = self.root / 'bios'
        self.data.mkdir()
        for name in companion.RESOURCES:
            (self.data / name).write_bytes(('fixture-' + name).encode())
        self.state = self.root / 'companion'
        self.phone = self.root / 'phone'
        self.phone.mkdir(mode=0o700)
        self.usb = self.phone / 'usb.sock'
        self.before = companion.session.file_identity(self.disk)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self):
        return companion.prepare(self.disk, self.seed, self.binary, self.data, self.state, self.img)

    def run_short(self, **kwargs):
        with patch.object(companion, 'MIN_SECONDS', 0.01):
            return companion.run(self.state, self.usb, seconds=0.2, **kwargs)

    def test_listener_remains_ready_when_phone_connects_before_first_poll(self):
        self.prepare()
        real_popen = companion.subprocess.Popen
        def accepted_before_poll(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            if args[0][0] != str(self.binary):
                return process
            # The fixture holds both the listener and an accepted Unix socket
            # before the runner starts inspecting the passive socket table.
            self.assertTrue(process.stdout.readline().startswith(b'SIZE_LIMIT='))
            return process
        with patch.dict(os.environ, COMPANION_FIXTURE_MODE='accepted'), \
                patch.object(companion.subprocess, 'Popen', side_effect=accepted_before_poll):
            record = self.run_short()
        self.assertTrue(record['usb_listener_ready'])
        self.assertFalse(record['usb_enumerated'])
        self.assertEqual(record['status'], 'stopped')
        self.assertFalse(Path('/proc').joinpath(str(record['pid'])).exists())

    def test_child_removing_its_own_qmp_socket_is_successful_cleanup(self):
        self.prepare()
        with patch.dict(os.environ, COMPANION_FIXTURE_MODE='unlink-qmp'):
            record = self.run_short()
        self.assertEqual(record['status'], 'stopped')
        self.assertEqual(record['qmp_cleanup'], 'already absent')
        self.assertTrue(record['originals_unchanged'])
        self.assertFalse((self.state / 'qmp.sock').exists())
        self.assertFalse((self.state / 'live.json').exists())

    def test_preparation_uses_detected_backing_format_and_preserves_original(self):
        manifest = self.prepare()
        info = companion.image_info(self.img, self.state / 'disk.qcow2')
        self.assertEqual(manifest['backing_format'], 'qcow2')
        self.assertEqual(info['backing-filename-format'], 'qcow2')
        self.assertEqual(info['full-backing-filename'], str(self.disk))
        self.assertEqual(self.before, companion.session.file_identity(self.disk))
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertNotEqual((self.state / 'seed.iso').stat().st_ino, self.seed.stat().st_ino)
        companion.load(self.state)

    def test_historical_profile_pins_option_roms_and_matches_retained_hardware(self):
        for name in companion.HARDWARE_PROFILES['historical']:
            if not (self.data / name).exists():
                (self.data / name).write_bytes(('fixture-' + name).encode())
        manifest = companion.prepare(self.disk, self.seed, self.binary, self.data,
                                     self.state, self.img, hardware_profile='historical')
        companion.load(self.state)
        args = companion.argv_for(self.state, manifest, self.usb, self.state / 'runs', 32225)
        self.assertEqual(args[args.index('-cpu') + 1], 'qemu64')
        self.assertEqual(args[args.index('-m') + 1], '3G')
        self.assertEqual(args[args.index('-smp') + 1], '4')
        self.assertIn('-usb', args)
        self.assertNotIn('-nodefaults', args)
        self.assertIn('virtio-net-pci,netdev=isolated', args)
        self.assertIn(',cache=unsafe', args[args.index('-drive') + 1])
        for name in ('vgabios-stdvga.bin', 'efi-virtio.rom'):
            self.assertEqual(manifest['originals'][name]['sha256'],
                             companion.session.sha256(self.data / name))
            private = self.state / 'resources' / name
            self.assertEqual(private.read_bytes(), (self.data / name).read_bytes())
            private.write_bytes(private.read_bytes() + b'changed')
            with self.assertRaises(companion.CompanionError):
                companion.load(self.state)
            private.write_bytes((self.data / name).read_bytes())
        self.assertEqual(self.before, companion.session.file_identity(self.disk))

    def test_existing_profileless_manifest_keeps_the_original_isolated_command(self):
        manifest = self.prepare()
        expected = companion.argv_for(self.state, manifest, self.usb, self.state / 'runs')
        manifest.pop('hardware_profile')
        companion.session.write_json(self.state / 'manifest.json', manifest)
        _, loaded = companion.load(self.state)
        self.assertEqual(companion.argv_for(self.state, loaded, self.usb, self.state / 'runs'), expected)
        self.assertEqual(expected[expected.index('-cpu') + 1], 'max')
        self.assertIn('-nodefaults', expected)

    def test_profile_cannot_be_changed_without_a_complete_matching_resource_set(self):
        manifest = self.prepare()
        manifest['hardware_profile'] = 'historical'
        companion.session.write_json(self.state / 'manifest.json', manifest)
        with self.assertRaises(companion.CompanionError):
            companion.load(self.state)

    def test_missing_historical_rom_and_unknown_profile_refuse_before_creation(self):
        with self.assertRaises(OSError):
            companion.prepare(self.disk, self.seed, self.binary, self.data,
                              self.state, self.img, hardware_profile='historical')
        self.assertFalse(self.state.exists())
        with self.assertRaises(companion.CompanionError):
            companion.prepare(self.disk, self.seed, self.binary, self.data,
                              self.state, self.img, hardware_profile='unknown')
        self.assertFalse(self.state.exists())

    def test_manifest_read_is_bounded(self):
        self.prepare()
        (self.state / 'manifest.json').write_bytes(b'x' * 65537)
        with self.assertRaises(companion.CompanionError):
            companion.load(self.state)

    def test_copy_size_change_is_refused_before_writing(self):
        output = self.root / 'copy.iso'
        for size in (self.seed.stat().st_size - 1, self.seed.stat().st_size + 1):
            with self.assertRaises(companion.CompanionError):
                companion.copy_expected(self.seed, output, size)
            self.assertFalse(output.exists())

    def test_raw_backing_with_qcow_name_is_detected_as_raw(self):
        self.disk.unlink()
        self.disk.write_bytes(b'\0' * 65536)
        self.disk.rename(self.root / 'deceptive.qcow2')
        self.disk = self.root / 'deceptive.qcow2'
        manifest = self.prepare()
        self.assertEqual(manifest['backing_format'], 'raw')
        companion.load(self.state)

    def test_existing_destination_and_source_backing_chain_are_refused(self):
        self.state.mkdir()
        with self.assertRaises(companion.CompanionError):
            self.prepare()
        self.state.rmdir()
        child = self.root / 'child.qcow2'
        subprocess.run([str(self.img), 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(self.disk), str(child)], check=True)
        with self.assertRaises(companion.CompanionError):
            companion.prepare(child, self.seed, self.binary, self.data, self.state, self.img)
        self.assertFalse(self.state.exists())

    def test_original_and_private_pin_changes_are_refused(self):
        self.prepare()
        for path in (self.seed, self.binary, self.data / companion.RESOURCES[0], self.state / 'seed.iso'):
            with self.subTest(path=path.name):
                old = path.read_bytes()
                path.write_bytes(old + b'changed')
                with self.assertRaises(companion.CompanionError):
                    companion.load(self.state)
                path.write_bytes(old)
                # Updating this test manifest restores only the changed fixture identity.
                manifest = json.loads((self.state / 'manifest.json').read_text())
                for value in manifest['originals'].values():
                    if value['path'] == str(path):
                        value['identity'] = companion.session.file_identity(path)
                companion.session.write_json(self.state / 'manifest.json', manifest)

    def test_overlay_retarget_and_hardlink_to_original_are_refused(self):
        self.prepare()
        overlay = self.state / 'disk.qcow2'
        other = self.root / 'other.raw'
        other.write_bytes(b'\0' * (16 << 20))
        subprocess.run([str(self.img), 'rebase', '-u', '-f', 'qcow2', '-F', 'raw', '-b', str(other), str(overlay)], check=True)
        with self.assertRaises(companion.CompanionError):
            companion.load(self.state)
        overlay.unlink()
        os.link(self.disk, overlay)
        with self.assertRaises(companion.CompanionError):
            companion.load(self.state)

    def test_open_original_writer_is_refused_before_preparation(self):
        # A separate process holds a writer; the scanner ignores its own process.
        holder = subprocess.Popen([sys.executable, '-c', 'import sys,time;f=open(sys.argv[1],"r+b");print("ready",flush=True);time.sleep(10)', str(self.disk)], stdout=subprocess.PIPE)
        try:
            self.assertEqual(holder.stdout.readline(), b'ready\n')
            with self.assertRaises(companion.CompanionError):
                self.prepare()
        finally:
            holder.terminate(); holder.wait(timeout=3); holder.stdout.close()

    def test_transport_is_unix_and_network_restricted_to_loopback_forward(self):
        manifest = self.prepare()
        args = companion.argv_for(self.state, manifest, self.usb, self.state / 'runs')
        network = args[args.index('-netdev') + 1]
        self.assertEqual(network, 'user,id=isolated,restrict=on,hostfwd=tcp:127.0.0.1:32222-:22')
        self.assertIn('conn-type=unix,conn-addr=' + str(self.usb), args[-1])
        self.assertIn('readonly=on', next(arg for arg in args if str(self.state / 'seed.iso') in arg))
        self.assertNotIn(str(self.disk), '\n'.join(args))
        args = companion.argv_for(self.state, manifest, self.usb, self.state / 'runs', ssh_port=0)
        self.assertNotIn('hostfwd=', args[args.index('-netdev') + 1])
        for port in (-1, 65536, True):
            with self.assertRaises(companion.CompanionError):
                companion.argv_for(self.state, manifest, self.usb, self.state / 'runs', ssh_port=port)

    def test_bounded_child_is_reaped_endpoints_cleaned_and_originals_preserved(self):
        self.prepare()
        record = self.run_short()
        self.assertEqual(record['status'], 'stopped')
        self.assertEqual(record['exit_code'], 0)
        self.assertTrue(record['usb_listener_ready'])
        self.assertFalse(record['usb_enumerated'])
        self.assertTrue(record['originals_unchanged'])
        self.assertFalse(Path('/proc').joinpath(str(record['pid'])).exists())
        self.assertFalse((self.state / 'live.json').exists())
        self.assertFalse((self.state / 'qmp.sock').exists())
        self.assertFalse(self.usb.exists())
        self.assertIn('SIZE_LIMIT=' + str(companion.MAX_IMAGE_BYTES), (Path(record['run']) / 'console.log').read_text())
        self.assertEqual(self.before, companion.session.file_identity(self.disk))
        companion.load(self.state)

    def test_early_exit_zero_is_failure_and_log_budget_is_enforced(self):
        self.prepare()
        with patch.dict(os.environ, COMPANION_FIXTURE_MODE='early'):
            record = self.run_short()
        self.assertEqual(record['status'], 'unexpected-exit')
        self.assertEqual(record['exit_code'], 0)
        with patch.dict(os.environ, COMPANION_FIXTURE_MODE='flood'), patch.object(companion, 'MAX_LOG_BYTES', 1024):
            record = self.run_short()
        self.assertEqual(record['stop_reason'], 'log size limit')
        self.assertLessEqual(record['log_bytes'], 1024)
        self.assertFalse(Path('/proc').joinpath(str(record['pid'])).exists())

    def test_low_space_and_endpoint_collision_refuse_launch(self):
        self.prepare()
        with patch.object(companion.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(100, 99, 1)):
            with self.assertRaises(companion.CompanionError):
                self.run_short()
        self.usb.write_bytes(b'preserve this collision')
        with self.assertRaises(companion.CompanionError):
            self.run_short()
        self.assertEqual(self.usb.read_bytes(), b'preserve this collision')
        self.assertFalse((self.state / 'live.json').exists())

    def test_result_logging_failure_does_not_leave_child_or_live_endpoints(self):
        self.prepare()
        original_write = companion.session.write_json
        captured = {}
        def fail_result(path, value):
            if path.name == 'live.json':
                captured['pid'] = value['pid']
            if path.name == 'result.json':
                raise OSError('fixture result logging failure')
            return original_write(path, value)
        with patch.object(companion.session, 'write_json', side_effect=fail_result):
            with self.assertRaises(OSError):
                self.run_short()
        self.assertFalse(Path('/proc').joinpath(str(captured['pid'])).exists())
        self.assertFalse((self.state / 'live.json').exists())
        self.assertFalse((self.state / 'qmp.sock').exists())
        self.assertFalse(self.usb.exists())
        self.assertEqual(self.before, companion.session.file_identity(self.disk))

    def test_metadata_capture_failure_regression_reaps_child(self):
        self.prepare()
        original_write = companion.session.write_json
        captured = {}
        def capture_pid(path, value):
            if path.name == 'live.json':
                captured['pid'] = value['pid']
            return original_write(path, value)
        try:
            with patch.object(companion.session, 'write_json', side_effect=capture_pid), \
                    patch.object(companion.session.USBEndpoint, '_capture', side_effect=OSError('fixture USB metadata unavailable')):
                with self.assertRaises(OSError):
                    self.run_short()
            self.assertFalse(Path('/proc').joinpath(str(captured['pid'])).exists())
            self.assertFalse((self.state / 'live.json').exists())
        finally:
            # The red oracle intentionally exposes a missing reap. Stop only
            # this exact disposable fixture if the buggy version leaves it live.
            pid = captured.get('pid')
            command = Path('/proc').joinpath(str(pid), 'cmdline')
            if pid and command.exists() and os.fsencode(str(self.binary)) in command.read_bytes().split(b'\0'):
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

    def test_early_exit_output_regression_is_drained(self):
        self.prepare()
        real_popen = companion.subprocess.Popen
        def already_exited(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            process.wait(timeout=3)
            return process
        with patch.dict(os.environ, COMPANION_FIXTURE_MODE='early'), \
                patch.object(companion.subprocess, 'Popen', side_effect=already_exited):
            record = self.run_short()
        self.assertEqual(record['status'], 'unexpected-exit')
        self.assertIn('fixture-startup-error', (Path(record['run']) / 'stderr.log').read_text())
        self.assertIn('fixture-early-stdout', (Path(record['run']) / 'console.log').read_text())

    def test_interruption_reaps_child_and_cli_reports_signal(self):
        self.prepare()
        runner = subprocess.Popen([sys.executable, str(MODULE), 'run', '--state', str(self.state), '--usb-socket', str(self.usb), '--seconds', '30'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not self.usb.exists() and runner.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(self.usb.exists())
            runner.send_signal(signal.SIGTERM)
            stdout, stderr = runner.communicate(timeout=10)
            self.assertEqual(runner.returncode, 143, stderr.decode())
            output = json.loads(stdout)
            record = json.loads((Path(output['run']) / 'result.json').read_text())
            self.assertEqual(record['status'], 'interrupted')
            self.assertFalse(Path('/proc').joinpath(str(record['pid'])).exists())
            self.assertTrue(record['originals_unchanged'])
            self.assertFalse((self.state / 'live.json').exists())
            self.assertFalse((self.state / 'qmp.sock').exists())
            self.assertFalse(self.usb.exists())
        finally:
            if runner.poll() is None:
                runner.kill();runner.wait(timeout=3)
            runner.stdout.close();runner.stderr.close()


if __name__ == '__main__':
    unittest.main()
