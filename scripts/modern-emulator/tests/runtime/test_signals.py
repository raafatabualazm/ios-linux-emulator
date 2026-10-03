"""Real disposable processes exercise runner interruption and stale recovery."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / 'tools/runtime/session.py'
spec = importlib.util.spec_from_file_location('signal_session', MODULE)
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)

CHILD = '''import json, socket, sys, time
from pathlib import Path
endpoint = sys.argv[sys.argv.index('-qmp') + 1].split(',')[0][5:]
server = socket.socket(socket.AF_UNIX)
server.bind(endpoint)
server.listen(1)
while True:
    connection, _ = server.accept()
    with connection, connection.makefile('rwb') as stream:
        stream.write(b'{"QMP":{}}\\n'); stream.flush()
        while True:
            line = stream.readline()
            if not line: break
            request = json.loads(line)
            if request['execute'] == 'quit':
                Path(endpoint).with_name('quit-received').write_text('fixture cleanup')
                time.sleep(0.3)
            stream.write((json.dumps({'return': {}, 'id': request['id']}) + '\\n').encode())
            stream.flush()
            if request['execute'] == 'quit': sys.exit(0)
'''


class SignalTests(unittest.TestCase):
    def setUp(self):
        # Small Linux-only fixtures live in tmpfs, never opening real guest stores.
        self.temp = tempfile.TemporaryDirectory(prefix='runtime-signals-', dir='/dev/shm')
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'bundle'
        (self.bundle / 'bin').mkdir(parents=True)
        (self.bundle / 'boot-files').mkdir()
        self.binary = self.bundle / 'bin/qemu-system-aarch64'
        # /dev/shm can be mounted noexec; keep the executable in the normal temp area.
        self.executable_temp = tempfile.TemporaryDirectory(prefix='runtime-signal-exec-')
        self.binary = Path(self.executable_temp.name) / 'fixture'
        self.binary.write_text('#!' + sys.executable + '\n' + CHILD)
        self.binary.chmod(0o700)
        for name in session.DISKS:
            (self.bundle / name).write_bytes(bytes(4096))
        for name in session.BOOT_FILES.values():
            (self.bundle / 'boot-files' / name).write_bytes(b'fixture')
        self.state = self.root / 'state'
        session.prepare(self.bundle, self.state, self.binary)

    def tearDown(self):
        self.temp.cleanup()
        self.executable_temp.cleanup()

    def interrupt_runner(self, number, repeat=False):
        runner = subprocess.Popen([sys.executable, str(MODULE), 'run', '--state', str(self.state),
                                   '--seconds', '30'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        guest_pid = None
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and runner.poll() is None:
                live = self.state / 'live.json'
                if live.exists() and (self.state / 'qmp.sock').exists():
                    guest_pid = json.loads(live.read_text())['pid']
                    break
                time.sleep(0.02)
            self.assertIsNotNone(guest_pid, 'Disposable runner failed to start')
            runner.send_signal(number)
            if repeat:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not (self.state / 'quit-received').exists():
                    time.sleep(0.02)
                self.assertTrue((self.state / 'quit-received').exists(), 'Cleanup must begin before repeated signal')
                runner.send_signal(number)
            stdout, stderr = runner.communicate(timeout=8)
            results = list((self.state / 'runs').glob('*/result.json'))
            self.assertEqual(len(results), 1, 'Interruption must retain its result')
            result = json.loads(results[0].read_text())
            self.assertEqual(result['status'], 'interrupted')
            self.assertEqual(result['interruption_signal'], signal.Signals(number).name)
            self.assertEqual(result['interruption_signal_number'], number)
            self.assertEqual(runner.returncode, 128 + number, stderr)
            self.assertEqual(result['exit_code'], 0)  # Clean child exit cannot mask interruption.
            self.assertEqual(result['gui_result'], 'requires visual/semantic evidence')
            self.assertFalse(Path('/proc', str(guest_pid)).exists(), 'Child must be reaped')
            self.assertFalse((self.state / 'live.json').exists())
            self.assertFalse((self.state / 'qmp.sock').exists())
            self.assertTrue(result['original_small_hashes_unchanged'])
        finally:
            if runner.poll() is None:
                runner.kill()
            runner.communicate(timeout=3)
            # Cleanup only our recorded disposable child if the unfixed runner orphaned it.
            if guest_pid and Path('/proc', str(guest_pid)).exists():
                cmdline = Path('/proc', str(guest_pid), 'cmdline').read_bytes()
                if str(self.binary).encode() in cmdline:
                    os.kill(guest_pid, signal.SIGKILL)

    def test_sigterm_reaps_guest_and_is_never_success(self):
        self.interrupt_runner(signal.SIGTERM)

    def test_sigint_reaps_guest_and_is_never_success(self):
        self.interrupt_runner(signal.SIGINT)

    def test_repeated_sigterm_does_not_interrupt_cleanup(self):
        self.interrupt_runner(signal.SIGTERM, repeat=True)

    def stale_markers(self, pid=None):
        if pid is None:
            dead = subprocess.Popen([sys.executable, '-c', 'pass'])
            dead.wait()
            pid = dead.pid
            self.assertFalse(Path('/proc', str(pid)).exists())
        old_run = self.state / 'runs' / ('0' * 32)
        old_run.mkdir(parents=True)
        endpoint = self.state / 'qmp.sock'
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(endpoint))
        live = {'pid': pid, 'run': str(old_run), 'qmp': str(endpoint)}
        session.write_json(self.state / 'live.json', live)
        return old_run, live

    def test_normal_dead_session_recovery_ignores_read_atime_and_retains_markers(self):
        old_run, live = self.stale_markers()
        marker = self.state / 'live.json'
        os.utime(marker, ns=(0, marker.stat().st_mtime_ns))
        session.validate_state(self.state, json.loads((self.state / 'manifest.json').read_text()))
        retained = session.recover_dead_session(self.state)
        self.assertEqual(Path(retained).parent, old_run)
        self.assertEqual(json.loads(Path(retained).read_text())['live'], live)
        self.assertFalse(marker.exists())
        self.assertFalse((self.state / 'qmp.sock').exists())

    def test_recovery_refuses_live_or_reused_pid(self):
        old_run, _ = self.stale_markers(os.getpid())
        with self.assertRaisesRegex(session.SessionError, 'PID exists'):
            session.recover_dead_session(self.state)
        self.assertTrue((self.state / 'live.json').exists())
        self.assertTrue((self.state / 'qmp.sock').exists())
        self.assertEqual(list(old_run.glob('recovery-*.json')), [])

    def test_recovery_refuses_endpoint_symlink(self):
        self.stale_markers()
        endpoint = self.state / 'qmp.sock'
        endpoint.unlink()
        endpoint.symlink_to(self.state / 'manifest.json')
        with self.assertRaisesRegex(session.SessionError, 'not a socket'):
            session.recover_dead_session(self.state)
        self.assertTrue(endpoint.is_symlink())

    def test_recovery_refuses_replaced_marker_after_evidence_write(self):
        self.stale_markers()
        actual_write = session.write_json
        def change(path, value):
            actual_write(path, value)
            actual_write(self.state / 'live.json', {'pid': os.getpid()})
        with patch.object(session, 'write_json', side_effect=change):
            with self.assertRaisesRegex(session.SessionError, 'changed during recovery'):
                session.recover_dead_session(self.state)
        self.assertTrue((self.state / 'live.json').exists())
        self.assertTrue((self.state / 'qmp.sock').exists())

    def test_open_writer_prevents_recovery_and_guest_launch(self):
        old_run, _ = self.stale_markers()
        writer = subprocess.Popen([sys.executable, '-c',
                                   'import sys,time; f=open(sys.argv[1],"r+b"); print("ready",flush=True); time.sleep(30)',
                                   str(self.state / 'sep_nvram')], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(writer.stdout.readline().strip(), 'ready')
            with self.assertRaisesRegex(session.SessionError, 'open writer'):
                session.run(self.state, seconds=30)
            self.assertTrue((self.state / 'live.json').exists())
            self.assertEqual(list(old_run.glob('recovery-*.json')), [])
        finally:
            writer.terminate()
            writer.wait(timeout=3)
            writer.stdout.close()

    def test_low_space_is_rejected_before_launch(self):
        usage = session.shutil.disk_usage(self.state)
        with patch.object(session.shutil, 'disk_usage', return_value=usage._replace(free=1)), \
             patch.object(session, 'argv_for', side_effect=AssertionError('unsafe launch')) as launch:
            with self.assertRaisesRegex(session.SessionError, 'launch refused'):
                session.run(self.state, seconds=30)
            launch.assert_not_called()

    def test_handlers_restored_and_first_signal_wins(self):
        before = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
        with session.RunSignals() as pending:
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGINT)
            self.assertEqual(pending.received, signal.SIGTERM)
        self.assertEqual(before, {number: signal.getsignal(number) for number in before})


if __name__ == '__main__':
    unittest.main()
