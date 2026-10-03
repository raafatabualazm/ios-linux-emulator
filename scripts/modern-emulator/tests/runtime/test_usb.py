"""Passive USB endpoint ownership tests; fixtures never execute a guest."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest


MODULE = Path(__file__).resolve().parents[2] / 'tools/runtime/session.py'
spec = importlib.util.spec_from_file_location('usb_session', MODULE)
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


class USBEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usb-endpoint-')
        self.root = Path(self.temp.name)
        self.state = self.root / 'private state'
        self.state.mkdir(mode=0o700)
        self.path = self.state / 'usb.sock'
        self.sockets = []

    def tearDown(self):
        for server in self.sockets:
            server.close()
        self.temp.cleanup()

    def listener(self, listening=True, kind=socket.SOCK_STREAM):
        server = socket.socket(socket.AF_UNIX, kind)
        self.sockets.append(server)
        server.bind(str(self.path))
        if listening:
            server.listen(1)
        return server

    def identity(self):
        info = self.path.lstat()
        return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid}

    def assert_identity(self, endpoint, expected):
        self.assertIsInstance(endpoint.identity, dict)
        for field, value in expected.items():
            self.assertEqual(endpoint.identity[field], value, field)

    def test_owned_stream_listener_with_spaces_is_ready_without_accepting(self):
        endpoint = session.USBEndpoint(self.state)
        self.assertEqual(endpoint.path, self.path)
        server = self.listener()
        expected = self.identity()
        self.assertTrue(endpoint.wait(session.RunSignals(), timeout=0.2))
        self.assert_identity(endpoint, expected)
        # A readiness connect would consume the companion's accept operation.
        server.settimeout(0.03)
        with self.assertRaises(TimeoutError):
            server.accept()
        self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)
        self.assertFalse(self.path.exists())

    def test_bound_socket_does_not_qualify_as_a_listener(self):
        endpoint = session.USBEndpoint(self.state)
        self.listener(listening=False)
        expected = self.identity()
        started = time.monotonic()
        with self.assertRaises(session.SessionError):
            endpoint.wait(session.RunSignals(), timeout=0.05)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assert_identity(endpoint, expected)
        self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)
        self.assertFalse(self.path.exists())

    def test_sequence_packet_listener_does_not_qualify_as_stream(self):
        endpoint = session.USBEndpoint(self.state)
        self.listener(kind=socket.SOCK_SEQPACKET)
        with self.assertRaises(session.SessionError):
            endpoint.wait(session.RunSignals(), timeout=0.05)
        self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)
        self.assertFalse(self.path.exists())

    def test_existing_file_symlink_and_socket_collisions_are_preserved(self):
        for kind in ('file', 'symlink', 'broken-symlink', 'socket'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    self.path.write_bytes(b'existing unrelated file')
                elif kind == 'symlink':
                    self.path.symlink_to(self.state)
                elif kind == 'broken-symlink':
                    self.path.symlink_to(self.root / 'absent')
                else:
                    self.listener()
                before = self.path.lstat()
                with self.assertRaises(session.SessionError):
                    session.USBEndpoint(self.state)
                after = self.path.lstat()
                self.assertEqual((after.st_dev, after.st_ino, after.st_mode),
                                 (before.st_dev, before.st_ino, before.st_mode))
                self.path.unlink()

    def test_active_unlinked_listener_collision_is_rejected(self):
        self.listener()
        self.path.unlink()
        self.assertFalse(self.path.exists())
        # The old listener remains in /proc/net/unix under the same path.
        with self.assertRaises(session.SessionError):
            session.USBEndpoint(self.state)

    def test_two_companions_claiming_one_path_do_not_qualify(self):
        endpoint = session.USBEndpoint(self.state)
        self.listener()
        self.path.unlink()
        self.listener()
        with self.assertRaises(session.SessionError):
            endpoint.wait(session.RunSignals(), timeout=0.2)
        endpoint.cleanup(child_reaped=True)
        self.assertFalse(self.path.exists())

    def test_public_or_externally_writable_state_is_rejected(self):
        for mode in (0o755, 0o777, 0o720, 0o702):
            with self.subTest(mode=oct(mode)):
                self.state.chmod(mode)
                with self.assertRaises(session.SessionError):
                    session.USBEndpoint(self.state)
                self.assertFalse(self.path.exists())
        self.state.chmod(0o700)

    def test_non_directory_state_is_rejected(self):
        regular = self.root / 'regular'
        regular.write_bytes(b'not a directory')
        with self.assertRaises(session.SessionError):
            session.USBEndpoint(regular)

    def test_private_state_alias_resolves_to_the_canonical_endpoint(self):
        linked = self.root / 'linked'
        linked.symlink_to(self.state)
        endpoint = session.USBEndpoint(linked)
        self.assertEqual(endpoint.path, self.path)
        self.listener()
        self.assertTrue(endpoint.wait(session.RunSignals(), timeout=0.2))
        endpoint.cleanup(child_reaped=True)
        self.assertFalse(self.path.exists())

    def test_timeout_without_endpoint_is_bounded_and_has_nothing_to_remove(self):
        endpoint = session.USBEndpoint(self.state)
        started = time.monotonic()
        with self.assertRaises(session.SessionError):
            endpoint.wait(session.RunSignals(), timeout=0.05)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertIsNone(endpoint.identity)
        self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)
        self.assertFalse(self.path.exists())

    def test_received_signal_stops_wait_without_creating_an_endpoint(self):
        endpoint = session.USBEndpoint(self.state)
        pending = session.RunSignals()
        pending.receive(signal.SIGTERM, None)
        started = time.monotonic()
        self.assertFalse(endpoint.wait(pending, timeout=0.2))
        self.assertLess(time.monotonic() - started, 0.1)
        self.assertIsNone(endpoint.identity)
        self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)

    def test_signal_during_bound_wait_retains_identity_for_cleanup(self):
        endpoint = session.USBEndpoint(self.state)
        self.listener(listening=False)
        expected = self.identity()
        pending = session.RunSignals()
        timer = threading.Timer(0.04, pending.receive, args=(signal.SIGINT, None))
        timer.start()
        try:
            self.assertFalse(endpoint.wait(pending, timeout=0.3))
        finally:
            timer.cancel()
            timer.join(timeout=1)
        self.assert_identity(endpoint, expected)
        self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)
        self.assertFalse(self.path.exists())

    def test_cleanup_refuses_while_phone_is_not_reaped(self):
        endpoint = session.USBEndpoint(self.state)
        self.listener()
        expected = self.identity()
        self.assertTrue(endpoint.wait(session.RunSignals(), timeout=0.2))
        with self.assertRaises(session.SessionError):
            endpoint.cleanup(child_reaped=False)
        self.assertEqual(self.identity(), expected)
        endpoint.cleanup(child_reaped=True)

    def test_cleanup_preserves_replacement_file_symlink_and_socket(self):
        for replacement in ('file', 'symlink', 'socket'):
            with self.subTest(replacement=replacement):
                # Keep prior sockets open so their filesystem identities cannot
                # be reused while a replacement is being tested.
                endpoint = session.USBEndpoint(self.state)
                self.listener()
                self.assertTrue(endpoint.wait(session.RunSignals(), timeout=0.2))
                self.path.unlink()
                if replacement == 'file':
                    self.path.write_bytes(b'new unrelated endpoint')
                elif replacement == 'symlink':
                    self.path.symlink_to(self.state)
                else:
                    self.listener()
                before = self.path.lstat()
                self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)
                after = self.path.lstat()
                self.assertEqual((after.st_dev, after.st_ino, after.st_mode),
                                 (before.st_dev, before.st_ino, before.st_mode))
                self.path.unlink()
                for server in self.sockets:
                    server.close()
                self.sockets.clear()

    def test_cleanup_preserves_uncaptured_late_endpoint(self):
        endpoint = session.USBEndpoint(self.state)
        self.listener()
        before = self.identity()
        self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)
        self.assertEqual(self.identity(), before)

    def test_identity_is_pinned_before_listen_and_rebinding_is_rejected(self):
        endpoint = session.USBEndpoint(self.state)
        self.listener(listening=False)
        original = self.identity()
        with self.assertRaises(session.SessionError):
            endpoint.wait(session.RunSignals(), timeout=0.05)
        self.assert_identity(endpoint, original)
        self.path.unlink()
        self.listener()
        replacement = self.identity()
        self.assertNotEqual(original['inode'], replacement['inode'])
        with self.assertRaises(session.SessionError):
            endpoint.wait(session.RunSignals(), timeout=0.2)
        self.assert_identity(endpoint, original)
        endpoint.cleanup(child_reaped=True)
        self.assertEqual(self.identity(), replacement)

    def test_changed_directory_permissions_preserve_endpoint(self):
        endpoint = session.USBEndpoint(self.state)
        self.listener()
        self.assertTrue(endpoint.wait(session.RunSignals(), timeout=0.2))
        original = self.identity()
        self.state.chmod(0o777)
        try:
            with self.assertRaises(session.SessionError):
                endpoint.wait(session.RunSignals(), timeout=0.2)
            self.assertIsInstance(endpoint.cleanup(child_reaped=True), str)
            self.assertEqual(self.identity(), original)
        finally:
            self.state.chmod(0o700)

    def test_opt_in_changes_only_machine_usb_client_options(self):
        manifest = {'binary': {'path': '/bin/true'}, 'assets': {
            name: {'path': str(self.root / 'assets' / filename)}
            for name, filename in session.BOOT_FILES.items()}}
        run_dir = self.state / 'runs' / ('0' * 32)
        baseline = session.argv_for(self.state, manifest, 'none', run_dir)
        self.assertEqual(baseline, session.argv_for(
            self.state, manifest, 'none', run_dir, usb=False))
        enabled = session.argv_for(self.state, manifest, 'none', run_dir, usb=True)
        machine_index = baseline.index('-M') + 1
        self.assertEqual(enabled[machine_index], baseline[machine_index]
                         + ',usb-conn-type=unix,usb-conn-addr=' + str(self.path))
        enabled[machine_index] = baseline[machine_index]
        self.assertEqual(enabled, baseline)
        self.assertNotIn('-chardev', enabled)


PHONE_FIXTURE = '''import json, os, sys, time
from pathlib import Path
endpoint = sys.argv[sys.argv.index('-qmp') + 1].split(',')[0][5:]
state = Path(endpoint).parent
machine = sys.argv[sys.argv.index('-M') + 1]
expected = ',usb-conn-type=unix,usb-conn-addr=' + str(state / 'usb.sock')
if not machine.endswith(expected): sys.exit(2)
marker = state / 'fixture-started.tmp'
marker.write_text(json.dumps({'pid': os.getpid()}))
marker.replace(state / 'fixture-started.json')
deadline = time.monotonic() + 10
while not (state / 'fixture-stop').exists() and time.monotonic() < deadline:
    time.sleep(0.01)
sys.exit(0 if (state / 'fixture-stop').exists() else 3)
'''

SHORT_WAIT_RUNNER = '''import importlib.util, sys
spec = importlib.util.spec_from_file_location('short_wait_session', sys.argv[1])
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)
actual_wait = session.USBEndpoint.wait
session.USBEndpoint.wait = lambda endpoint, pending: actual_wait(endpoint, pending, timeout=0.05)
sys.argv = sys.argv[1:]
session.main()
'''


class USBRunLifecycleTests(unittest.TestCase):
    """Real runner/child processes, tiny QCOW state and no USB protocol."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usb-lifecycle-')
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'bundle'
        (self.bundle / 'boot-files').mkdir(parents=True)
        (self.bundle / 'bin').mkdir()
        self.binary = self.bundle / 'bin/qemu-system-aarch64'
        self.binary.write_text('#!' + sys.executable + '\n' + PHONE_FIXTURE)
        self.binary.chmod(0o700)
        for name in session.DISKS:
            (self.bundle / name).write_bytes(bytes(4096))
        for filename in session.BOOT_FILES.values():
            (self.bundle / 'boot-files' / filename).write_bytes(b'lifecycle fixture')
        self.state = self.root / 'state'
        session.prepare(self.bundle, self.state)
        self.runner = None
        self.phone_pid = None
        self.companion = None

    def tearDown(self):
        if self.companion is not None:
            self.companion.close()
        marker = self.state / 'fixture-started.json'
        if self.phone_pid is None and marker.exists():
            self.phone_pid = json.loads(marker.read_text())['pid']
        if self.runner is not None:
            if self.runner.poll() is None:
                self.runner.kill()
            self.runner.communicate(timeout=3)
        # Only a recorded disposable fixture child can be cleaned after failure.
        if self.phone_pid and Path('/proc', str(self.phone_pid)).exists():
            try:
                cmdline = Path('/proc', str(self.phone_pid), 'cmdline').read_bytes()
                if str(self.binary).encode() in cmdline:
                    os.kill(self.phone_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.temp.cleanup()

    def start_runner(self, short_wait=False):
        command = ([sys.executable, '-B', '-c', SHORT_WAIT_RUNNER, str(MODULE)]
                   if short_wait else [sys.executable, '-B', str(MODULE)])
        self.runner = subprocess.Popen(
            command + ['run', '--state', str(self.state), '--seconds', '30', '--usb'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def wait_for(self, check, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = check()
            if found:
                return found
            if self.runner.poll() is not None:
                break
            time.sleep(0.01)
        self.fail('Disposable runner did not reach the required lifecycle stage')

    def startup(self):
        paths = list((self.state / 'runs').glob('*/usb-startup.json'))
        return json.loads(paths[0].read_text()) if paths else None

    def result(self):
        stdout, stderr = self.runner.communicate(timeout=8)
        paths = list((self.state / 'runs').glob('*/result.json'))
        self.assertEqual(len(paths), 1, stderr)
        result = json.loads(paths[0].read_text())
        self.assertTrue(result['original_root_metadata_unchanged'])
        self.assertTrue(result['original_small_hashes_unchanged'])
        self.assertEqual(result['ipa_result'], 'not attempted')
        self.assertFalse((self.state / 'live.json').exists())
        self.assertFalse((self.state / 'qmp.sock').exists())
        return result, stdout, stderr

    def test_ready_companion_precedes_phone_and_cleanup_follows_real_reap(self):
        self.start_runner()
        startup = self.wait_for(self.startup)
        self.assertEqual(startup['status'], 'awaiting USB companion')
        self.assertEqual(startup['endpoint'], str(self.state / 'usb.sock'))
        self.assertEqual(startup['wait_limit_seconds'], 30)
        self.assertFalse(startup['companion_managed'])
        self.assertFalse((self.state / 'live.json').exists())
        self.assertFalse((self.state / 'fixture-started.json').exists())
        self.companion = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.companion.bind(startup['endpoint'])
        self.companion.listen(1)
        socket_info = (self.state / 'usb.sock').lstat()
        fixture = self.wait_for(lambda: json.loads((self.state / 'fixture-started.json').read_text())
                                if (self.state / 'fixture-started.json').exists() else None)
        self.phone_pid = fixture['pid']
        live = self.wait_for(lambda: json.loads((self.state / 'live.json').read_text())
                             if (self.state / 'live.json').exists() else None)
        self.assertEqual(live['pid'], self.phone_pid)
        self.assertEqual(live['usb_endpoint'], startup['endpoint'])
        session.write_json(self.state / 'stop-request.json',
                           {'run_id': Path(startup['run']).name})
        (self.state / 'fixture-stop').write_bytes(b'stop disposable child')
        result, _, stderr = self.result()
        self.assertEqual(self.runner.returncode, 0, stderr)
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual(result['stop_reason'], 'explicit stop request')
        self.assertTrue(result['phone_started'])
        self.assertTrue(result['child_reaped'])
        self.assertTrue(result['usb_listener_ready'])
        self.assertFalse(result['usb_companion_managed'])
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['usb_socket_identity'], {
            'device': socket_info.st_dev, 'inode': socket_info.st_ino, 'uid': socket_info.st_uid})
        self.assertEqual(result['usb_endpoint_cleanup'], 'removed captured socket')
        self.assertFalse(Path('/proc', str(self.phone_pid)).exists())
        self.assertFalse((self.state / 'usb.sock').exists())

    def test_startup_timeout_records_failure_without_a_phone_process(self):
        # Use the actual readiness method with a shorter test-only deadline.
        self.start_runner(short_wait=True)
        result, _, _ = self.result()
        self.assertEqual(self.runner.returncode, 1)
        self.assertEqual(result['status'], 'startup-error')
        self.assertEqual(result['stop_reason'], 'startup failed')
        self.assertIn('startup bound', result['startup_error'])
        self.assertFalse(result['phone_started'])
        self.assertTrue(result['child_reaped'])
        self.assertFalse(result['usb_listener_ready'])
        self.assertIsNone(result['exit_code'])
        self.assertIsNone(result['usb_socket_identity'])
        self.assertEqual(result['usb_endpoint_cleanup'], 'not captured')
        self.assertFalse((self.state / 'fixture-started.json').exists())
        self.assertFalse((self.state / 'usb.sock').exists())

    def test_sigterm_during_companion_wait_records_interruption_without_phone(self):
        self.start_runner()
        self.wait_for(self.startup)
        self.runner.send_signal(signal.SIGTERM)
        result, _, _ = self.result()
        self.assertEqual(self.runner.returncode, 128 + signal.SIGTERM)
        self.assertEqual(result['status'], 'interrupted')
        self.assertEqual(result['interruption_signal'], 'SIGTERM')
        self.assertFalse(result['phone_started'])
        self.assertTrue(result['child_reaped'])
        self.assertFalse(result['usb_listener_ready'])
        self.assertIsNone(result['exit_code'])
        self.assertFalse((self.state / 'fixture-started.json').exists())
        self.assertFalse((self.state / 'usb.sock').exists())


if __name__ == '__main__':
    unittest.main()
