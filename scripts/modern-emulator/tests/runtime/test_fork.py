"""Complete generation copying tests using real qcow2 state and process locks."""
import fcntl
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import test_session as base

session = base.session


class ForkTests(unittest.TestCase):
    setUp = base.SessionTests.setUp
    tearDown = base.SessionTests.tearDown
    prepare = base.SessionTests.prepare

    def test_fork_preserves_qcow_progress_and_all_eight_other_stores(self):
        manifest = self.prepare()
        subprocess.run(['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x5a 0 512',
                        str(self.state / 'root')], check=True, capture_output=True)
        for index, name in enumerate(session.DISKS[1:], 1):
            (self.state / name).write_bytes(bytes([index]) * 4096)
        new_binary = self.root / 'new-qemu'
        new_binary.write_text('#!/bin/sh\nexit 0\n')
        new_binary.chmod(0o700)
        destination = self.root / 'fork'
        before = {name: session.file_identity(self.state / name) for name in session.DISKS}
        forked = session.fork_state(self.state, destination, new_binary)
        self.assertEqual(before, {name: session.file_identity(self.state / name) for name in session.DISKS})
        self.assertEqual(manifest, json.loads((self.state / 'manifest.json').read_text()))
        for name in session.DISKS:
            self.assertEqual(session.sha256(self.state / name), session.sha256(destination / name))
            self.assertNotEqual((self.state / name).stat().st_ino, (destination / name).stat().st_ino)
        self.assertEqual(forked['binary']['path'], str(new_binary))
        self.assertEqual(forked['source_root'], manifest['source_root'])
        self.assertFalse(forked['gui_complete'])
        self.assertFalse(forked['ipa_qualified'])
        session.validate_state(destination, forked)
        result = subprocess.run(['qemu-io', '-f', 'qcow2', '-c', 'read -P 0x5a 0 512',
                                 str(destination / 'root')], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_active_lock_and_stale_markers_refuse_fork(self):
        self.prepare()
        destination = self.root / 'fork'
        with (self.state / 'session.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(session.SessionError, 'active runner'):
                session.fork_state(self.state, destination)
        (self.state / 'live.json').write_text('{}')
        with self.assertRaisesRegex(session.SessionError, 'session markers'):
            session.fork_state(self.state, destination)
        self.assertFalse(destination.exists())

    def test_open_source_writer_refuses_fork(self):
        self.prepare()
        child = subprocess.Popen(['python3', '-c',
                                  'import sys,time; f=open(sys.argv[1],"r+b"); print("ready",flush=True); time.sleep(30)',
                                  str(self.state / 'sep_nvram')], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            with self.assertRaisesRegex(session.SessionError, 'open writer'):
                session.fork_state(self.state, self.root / 'fork')
        finally:
            child.terminate()
            child.wait()
            child.stdout.close()

    def test_changed_source_during_copy_leaves_no_usable_manifest(self):
        self.prepare()
        destination = self.root / 'fork'
        actual_run = subprocess.run
        def run(args, **kwargs):
            result = actual_run(args, **kwargs)
            if args[0] == 'cp':
                (self.state / 'sep_nvram').write_bytes(b'changed source generation')
            return result
        with patch.object(session.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(session.SessionError, 'changed during copying'):
                session.fork_state(self.state, destination)
        self.assertFalse((destination / 'manifest.json').exists())

    def test_existing_or_nested_destination_and_low_space_refused(self):
        self.prepare()
        for destination in (self.state, self.state / 'child', self.bundle / 'child'):
            with self.assertRaises(session.SessionError):
                session.fork_state(self.state, destination)
        usage = type('Usage', (), {'free': 0})()
        with patch.object(session.shutil, 'disk_usage', return_value=usage):
            with self.assertRaisesRegex(session.SessionError, 'Insufficient space'):
                session.fork_state(self.state, self.root / 'fork')
        self.assertFalse((self.root / 'fork').exists())

    def test_changed_boot_pin_refuses_fork(self):
        self.prepare()
        (self.bundle / 'boot-files' / session.BOOT_FILES['kernel']).write_bytes(b'changed')
        with self.assertRaisesRegex(session.SessionError, 'artifact changed'):
            session.fork_state(self.state, self.root / 'fork')
