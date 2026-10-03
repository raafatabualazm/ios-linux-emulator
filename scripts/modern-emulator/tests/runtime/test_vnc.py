"""Local GUI endpoint checks; optional real RFB handshake without any guest."""
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / 'tools/runtime/session.py'
spec = importlib.util.spec_from_file_location('vnc_session', MODULE)
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise AssertionError('Truncated RFB handshake')
        data.extend(part)
    return bytes(data)


class VNCTests(unittest.TestCase):
    def test_endpoint_validation_rejects_option_injection_and_nonlocal_hosts(self):
        self.assertIsNone(session.checked_vnc(None))
        for value in ('127.0.0.1:0', '127.0.0.1:1', '127.0.0.1:99'):
            self.assertEqual(session.checked_vnc(value), value)
        for value in ('0.0.0.0:1', 'localhost:1', '127.0.0.1:100',
                      '127.0.0.1:01', '127.0.0.1:-1', '127.0.0.1:1,reverse=on',
                      '127.0.0.1:1\n', '', 1, False):
            with self.subTest(value=value), self.assertRaises(session.SessionError):
                session.checked_vnc(value)

    def test_vnc_is_additive_and_original_drive_arguments_are_unchanged(self):
        manifest = {'binary': {'path': '/fixture/qemu'},
                    'assets': {key: {'path': '/fixture/' + key} for key in session.BOOT_FILES}}
        baseline = session.argv_for(Path('/fixture/state'), manifest, 'none', Path('/fixture/run'))
        enabled = session.argv_for(Path('/fixture/state'), manifest, 'none', Path('/fixture/run'),
                                   '127.0.0.1:1')
        self.assertEqual(enabled, baseline + ['-L', str(session.checked_qemu_data()), '-vnc', '127.0.0.1:1'])
        self.assertEqual(enabled.count('-drive'), 9)
        self.assertNotIn('-vnc', baseline)

    def test_invalid_endpoint_is_rejected_before_reading_or_launching_state(self):
        with patch.object(session.subprocess, 'Popen', side_effect=AssertionError('unsafe launch')) as launch:
            with self.assertRaises(session.SessionError):
                session.run(Path('/nonexistent/state'), vnc='127.0.0.1:1,reverse=on')
            launch.assert_not_called()

    @unittest.skipUnless(os.environ.get('MODERN_EMULATOR_TEST_BINARY'), 'real QEMU path not selected')
    def test_actual_qemu_rfb_handshake_and_loopback_query(self):
        binary = Path(os.environ['MODERN_EMULATOR_TEST_BINARY']).resolve(strict=True)
        display = None
        for candidate in range(99, -1, -1):
            with socket.socket() as probe:
                try:
                    probe.bind(('127.0.0.1', 5900 + candidate))
                except OSError:
                    continue
                display = candidate
                break
        self.assertIsNotNone(display)
        with tempfile.TemporaryDirectory(prefix='vnc-wire-') as directory:
            qmp_path = Path(directory) / 'qmp.sock'
            with (Path(directory) / 'emulator.log').open('wb') as log:
                child = subprocess.Popen([str(binary), '-M', 'none', '-nodefaults',
                                          '-display', 'none', '-L', str(session.checked_qemu_data()),
                                          '-vnc', f'127.0.0.1:{display}',
                                          '-qmp', f'unix:{qmp_path},server=on,wait=off'],
                                         stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 8
                    while not qmp_path.exists():
                        self.assertIsNone(child.poll(), 'QEMU exited before QMP became available')
                        self.assertLess(time.monotonic(), deadline, 'QMP startup deadline exceeded')
                        time.sleep(0.05)
                    while True:
                        try:
                            qmp = session.QMP(qmp_path)
                            break
                        except (ConnectionRefusedError, FileNotFoundError):
                            self.assertIsNone(child.poll(), 'QEMU exited before QMP started listening')
                            self.assertLess(time.monotonic(), deadline, 'QMP listen deadline exceeded')
                            time.sleep(0.05)
                    with qmp:
                        server = qmp.request('query-vnc')
                        self.assertTrue(server['enabled'])
                        self.assertEqual(server['host'], '127.0.0.1')
                        self.assertEqual(int(server['service']), 5900 + display)
                        with socket.create_connection(('127.0.0.1', 5900 + display), timeout=5) as viewer:
                            self.assertEqual(exact(viewer, 12), b'RFB 003.008\n')
                            viewer.sendall(b'RFB 003.008\n')
                            types = exact(viewer, exact(viewer, 1)[0])
                            self.assertIn(1, types)
                            viewer.sendall(b'\x01')
                            self.assertEqual(exact(viewer, 4), bytes(4))
                            viewer.sendall(b'\x01')
                            header = exact(viewer, 24)
                            width, height = struct.unpack_from('>HH', header)
                            name_length = struct.unpack_from('>I', header, 20)[0]
                            self.assertLess(name_length, 4096)
                            exact(viewer, name_length)
                            self.assertGreater(width, 0)
                            self.assertGreater(height, 0)
                            self.assertTrue(qmp.request('query-vnc')['clients'])
                        qmp.request('quit')
                    self.assertEqual(child.wait(timeout=5), 0)
                finally:
                    if child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()


if __name__ == '__main__':
    unittest.main()
