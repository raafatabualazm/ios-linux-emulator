import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / 'tools/runtime/session.py'
spec = importlib.util.spec_from_file_location('session', MODULE)
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


class WireServer:
    def __init__(self, directory, response):
        self.path = str(Path(directory) / 'qmp.sock')
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(self.path)
        self.server.listen(1)
        self.response = response
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        connection, _ = self.server.accept()
        with connection, connection.makefile('rwb') as stream:
            stream.write(b'{"QMP":{}}\n')
            stream.flush()
            capabilities = json.loads(stream.readline())
            stream.write((json.dumps({'return': {}, 'id': capabilities['id']}) + '\n').encode())
            stream.flush()
            request = json.loads(stream.readline())
            reply = self.response(request)
            if reply is not None:
                stream.write(reply)
                stream.flush()
        self.server.close()


class FakeChild:
    """A runner lifecycle fixture; it never executes a guest or opens drives."""
    pid = 99999999
    returncode = None

    def __init__(self):
        self.waited = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waited = True
        self.returncode = 0
        return self.returncode


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='session-test-')
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'bundle'
        (self.bundle / 'boot-files').mkdir(parents=True)
        (self.bundle / 'bin').mkdir()
        binary = self.bundle / 'bin/qemu-system-aarch64'
        binary.write_text('#!/bin/sh\nprintf "FAKE_APP_SUCCESS\\n"\nexit 13\n')
        binary.chmod(0o700)
        for name in session.DISKS:
            (self.bundle / name).write_bytes(bytes(4096))
        for filename in session.BOOT_FILES.values():
            (self.bundle / 'boot-files' / filename).write_bytes(b'test fixture')
        self.state = self.root / 'state'

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self):
        return session.prepare(self.bundle, self.state)

    def test_persistent_state_preserves_originals_and_rejects_replacement(self):
        before = {p.name: session.sha256(p) for p in self.bundle.iterdir() if p.is_file()}
        manifest = self.prepare()
        info = json.loads(subprocess.run(['qemu-img', 'info', '--output=json', str(self.state / 'root')],
                                        check=True, capture_output=True, text=True).stdout)
        self.assertEqual(info['format'], 'qcow2')
        self.assertEqual(info['backing-filename'], str(self.bundle / 'root'))
        (self.state / 'sep_nvram').write_bytes(b'changed isolated state')
        self.assertEqual(before, {p.name: session.sha256(p) for p in self.bundle.iterdir() if p.is_file()})
        self.assertFalse(manifest['ipa_qualified'])
        with self.assertRaises(session.SessionError):
            self.prepare()

    def test_actual_source_writer_prevents_copy(self):
        child = subprocess.Popen(['python3', '-c',
                                  'import sys,time; f=open(sys.argv[1],"r+b"); print("ready",flush=True); time.sleep(30)',
                                  str(self.bundle / 'sep_nvram')], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            with self.assertRaisesRegex(session.SessionError, 'open writer'):
                self.prepare()
            self.assertFalse(self.state.exists())
        finally:
            child.terminate()
            child.wait()
            child.stdout.close()

    def test_changed_artifact_and_backing_generation_rejected(self):
        self.prepare()
        path = self.bundle / 'boot-files' / session.BOOT_FILES['kernel']
        path.write_bytes(b'different kernel')
        with self.assertRaisesRegex(session.SessionError, 'artifact changed'):
            session.run(self.state, seconds=30)

    def test_writable_stores_cannot_alias_sources_or_boot_artifacts(self):
        self.prepare()
        isolated = self.state / 'sep_nvram'
        for target, symlink in ((self.bundle / 'sep_nvram', False),
                                (self.bundle / 'root', True),
                                (self.bundle / 'boot-files' / session.BOOT_FILES['kernel'], False),
                                (self.bundle / 'bin/qemu-system-aarch64', False)):
            with self.subTest(target=target.name, symlink=symlink):
                isolated.unlink()
                if symlink:
                    isolated.symlink_to(target)
                else:
                    os.link(target, isolated)
                try:
                    with patch.object(session, 'argv_for', side_effect=AssertionError('unsafe launch')) as launch:
                        with self.assertRaises(session.SessionError):
                            session.run(self.state, seconds=30)
                        launch.assert_not_called()
                finally:
                    isolated.unlink()
                    isolated.write_bytes(bytes(4096))

    def test_writable_stores_cannot_share_an_inode(self):
        self.prepare()
        isolated = self.state / 'sep_nvram'
        isolated.unlink()
        os.link(self.state / 'ctrl_bits', isolated)
        with patch.object(session, 'argv_for', side_effect=AssertionError('unsafe launch')) as launch:
            with self.assertRaises(session.SessionError):
                session.run(self.state, seconds=30)
            launch.assert_not_called()

    def test_root_overlay_must_keep_its_original_raw_backing(self):
        self.prepare()
        other = self.root / 'unrelated-root'
        other.write_bytes(bytes(4096))
        (self.state / 'root').unlink()
        subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'raw',
                        '-b', str(other), str(self.state / 'root')], check=True)
        with patch.object(session, 'argv_for', side_effect=AssertionError('unsafe launch')) as launch:
            with self.assertRaises(session.SessionError):
                session.run(self.state, seconds=30)
            launch.assert_not_called()

    def test_root_overlay_cannot_redirect_writes_to_an_external_data_file(self):
        self.prepare()
        (self.state / 'root').unlink()
        subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'raw',
                        '-b', str(self.bundle / 'root'), '-o', f'data_file={self.root / "external-data"}',
                        str(self.state / 'root')], check=True)
        with patch.object(session, 'argv_for', side_effect=AssertionError('unsafe launch')) as launch:
            with self.assertRaisesRegex(session.SessionError, 'external data file'):
                session.run(self.state, seconds=30)
            launch.assert_not_called()

    def fake_launch(self, child):
        actual_launch = subprocess.Popen
        def launch(*args, **kwargs):
            if args[0][0] == 'qemu-img':
                return actual_launch(*args, **kwargs)
            (self.state / 'qmp.sock').touch()
            return child
        return launch

    def test_live_metadata_failure_reaps_child_and_removes_endpoint(self):
        self.prepare()
        child = FakeChild()
        actual_write = session.write_json
        def fail_live(path, value):
            if path.name == 'live.json':
                raise OSError('live metadata fixture failure')
            return actual_write(path, value)
        with patch.object(session.subprocess, 'Popen', side_effect=self.fake_launch(child)), \
             patch.object(session, 'QMP', side_effect=OSError('no fixture QMP')), \
             patch.object(session, 'write_json', side_effect=fail_live), \
             patch('builtins.print'):
            with self.assertRaisesRegex(OSError, 'live metadata fixture failure'):
                session.run(self.state, seconds=30)
        self.assertTrue(child.waited)
        self.assertFalse((self.state / 'live.json').exists())
        self.assertFalse((self.state / 'qmp.sock').exists())

    def test_output_failure_reaps_child_and_removes_endpoint(self):
        self.prepare()
        child = FakeChild()
        with patch.object(session.subprocess, 'Popen', side_effect=self.fake_launch(child)), \
             patch.object(session, 'QMP', side_effect=OSError('no fixture QMP')), \
             patch('builtins.print', side_effect=BrokenPipeError('output fixture failure')):
            with self.assertRaisesRegex(BrokenPipeError, 'output fixture failure'):
                session.run(self.state, seconds=30)
        self.assertTrue(child.waited)
        self.assertFalse((self.state / 'live.json').exists())
        self.assertFalse((self.state / 'qmp.sock').exists())

    def test_result_logging_failure_still_removes_live_metadata_and_endpoint(self):
        self.prepare()
        child = FakeChild()
        actual_write = session.write_json
        actual_usage = session.shutil.disk_usage(self.state)
        def fail_result(path, value):
            if path.name == 'result.json':
                raise OSError('result logging fixture failure')
            return actual_write(path, value)
        with patch.object(session.subprocess, 'Popen', side_effect=self.fake_launch(child)), \
             patch.object(session, 'QMP', side_effect=OSError('no fixture QMP')), \
             patch.object(session, 'write_json', side_effect=fail_result), \
             patch.object(session.shutil, 'disk_usage', side_effect=[actual_usage, actual_usage._replace(free=1)]), \
             patch('builtins.print'):
            with self.assertRaisesRegex(OSError, 'result logging fixture failure'):
                session.run(self.state, seconds=30)
        self.assertTrue(child.waited)
        self.assertFalse((self.state / 'live.json').exists())
        self.assertFalse((self.state / 'qmp.sock').exists())

    def test_failed_qmp_connect_closes_its_socket(self):
        with patch.object(session.socket, 'socket') as factory:
            sock = factory.return_value
            sock.connect.side_effect = FileNotFoundError('missing fixture endpoint')
            with self.assertRaises(FileNotFoundError):
                session.QMP(self.state / 'qmp.sock')
            sock.close.assert_called_once()

    def test_unexpected_exit_not_hidden_by_success_text(self):
        self.prepare()
        result = session.run(self.state, seconds=30)
        self.assertEqual(result['exit_code'], 13)
        self.assertEqual(result['ipa_result'], 'not attempted')
        self.assertEqual(result['gui_result'], 'requires visual/semantic evidence')
        self.assertFalse((self.state / 'live.json').exists())
        self.assertEqual(result['status'], 'unexpected-exit')

    def test_early_zero_exit_and_stale_stop_marker_are_failures(self):
        binary = self.bundle / 'bin/qemu-system-aarch64'
        binary.write_text('#!/bin/sh\nprintf "FAKE_APP_SUCCESS\\n"\nexit 0\n')
        self.prepare()
        (self.state / 'stop-request.json').write_text('{"run_id":"a-prior-run"}')
        result = session.run(self.state, seconds=30)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['status'], 'unexpected-exit')
        self.assertEqual(result['stop_reason'], 'unexpected emulator exit')
        self.assertEqual(result['ipa_result'], 'not attempted')

    def test_resource_stop_reaps_process_and_preserves_state(self):
        binary = self.bundle / 'bin/qemu-system-aarch64'
        binary.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(60)\n')
        self.prepare()
        original_disk_usage = session.shutil.disk_usage
        actual_usage = original_disk_usage(self.state)
        with patch.object(session.shutil, 'disk_usage', side_effect=[actual_usage, actual_usage._replace(free=1)]):
            result = session.run(self.state, seconds=30)
        self.assertEqual(result['stop_reason'], 'disk space limit')
        self.assertEqual(result['status'], 'stopped')
        self.assertFalse((self.state/'live.json').exists())
        self.assertTrue((self.state/'root').exists())

    def test_qmp_events_are_not_success_and_wrong_id_rejected(self):
        response = lambda request: b'{"event":"FAKE_APP_SUCCESS"}\n' + json.dumps(
            {'return': {}, 'id': request['id'] + 1}).encode() + b'\n'
        server = WireServer(self.root, response)
        with session.QMP(server.path) as client:
            with self.assertRaisesRegex(session.SessionError, 'ID'):
                client.request('query-status')
        server.thread.join(2)

    def test_qmp_eof_rejected_without_waiting_forever(self):
        server = WireServer(self.root, lambda request: None)
        with session.QMP(server.path) as client:
            with self.assertRaisesRegex(session.SessionError, 'closed'):
                client.request('query-status')
        server.thread.join(2)

    def test_touch_rejects_invalid_target_before_contact(self):
        class Recorder:
            def __init__(self):
                self.messages = []
            def request(self, *args):
                self.messages.append(args)
        recorder = Recorder()
        for end in ((828, 5), (-1, 2), (5, 1792)):
            with self.assertRaises(session.SessionError):
                session.gesture(recorder, (414, 600), end)
        self.assertEqual(recorder.messages, [])

    def test_touch_releases_on_mid_gesture_failure(self):
        class BrokenMove:
            def __init__(self):
                self.messages = []
            def request(self, command, args):
                self.messages.append(args)
                if len(self.messages) == 2:
                    raise session.SessionError('device disconnected')
        recorder = BrokenMove()
        with patch.object(session.time, 'sleep'), self.assertRaises(session.SessionError):
            session.gesture(recorder, (414, 1700), (414, 800))
        self.assertEqual(recorder.messages[-1]['events'][0]['data'], {'button': 'left', 'down': False})


if __name__ == '__main__':
    unittest.main()
