"""Exercise filesystem patch preparation and recovery without an APFS image."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'patch_filesystem', Path(__file__).with_name('patch-filesystem.py'))
patch_filesystem = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patch_filesystem)


def diff_records(path):
    data = path.read_bytes()
    cursor = 0
    while cursor < len(data):
        offset, size = struct.unpack_from('<QI', data, cursor)
        cursor += 12
        yield offset, data[cursor:cursor + size]
        cursor += size


def apply_diff(contents, path, first_only=False):
    result = bytearray(contents)
    for offset, payload in diff_records(path):
        result[offset:offset + len(payload)] = payload
        if first_only:
            break
    return bytes(result)


class PatchFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.ep = ['extent-probe', '-img', 'fixture.img']
        self.backing = {}
        self.commands = []
        self.saved_statuses = []

    def prepare(self, name='fixture', old=b'abcdefghijklmnop',
                new=b'aXXdefghijkYYnop'):
        original, patched = self.work / (name + '.original'), self.work / name
        original.write_bytes(old)
        patched.write_bytes(new)
        stats = patch_filesystem.make_diffs(
            original, patched, self.work / (name + '.diff'),
            self.work / (name + '.undo'))
        item = {'path': '/System/' + name, 'name': name, 'size': len(old),
                'before_sha256': hashlib.sha256(old).hexdigest(),
                'after_sha256': hashlib.sha256(new).hexdigest(), **stats}
        self.backing[item['path']] = old
        return item, old, new

    def fake_run(self, *args):
        args = [str(arg) for arg in args]
        self.commands.append(args)
        if '-patch' in args:
            guest, source = args[args.index('-patch') + 1].split('=', 1)
            self.backing[guest] = apply_diff(self.backing[guest], Path(source))
        elif '-extract' in args:
            guest, destination = args[args.index('-extract') + 1].split('=', 1)
            Path(destination).write_bytes(self.backing[guest])

    def save(self, work, manifest):
        self.assertEqual(work, self.work)
        self.saved_statuses.append(manifest['status'])

    def test_forward_and_reverse_round_trip_across_chunk_boundary(self):
        old, new = b'abcdefghijklmnopq', b'abcdeXXXXXklmnYYq'
        with patch.object(patch_filesystem, 'CHUNK', 8):
            item, _, _ = self.prepare(old=old, new=new)
        self.assertEqual(item['changed_bytes'], 7)
        self.assertEqual(item['records'], 3)
        self.assertEqual(apply_diff(old, self.work / 'fixture.diff'), new)
        self.assertEqual(apply_diff(new, self.work / 'fixture.undo'), old)

    def test_changed_length_rejected_before_output_creation(self):
        original, patched = self.work / 'original', self.work / 'patched'
        original.write_bytes(b'original')
        patched.write_bytes(b'longer original')
        forward, reverse = self.work / 'forward', self.work / 'reverse'
        with self.assertRaises(ValueError):
            patch_filesystem.make_diffs(original, patched, forward, reverse)
        self.assertFalse(forward.exists())
        self.assertFalse(reverse.exists())

    def test_stale_image_is_rejected_before_any_patch(self):
        item, old, _ = self.prepare()
        self.backing[item['path']] = b'!' + old[1:]
        manifest = {'status': 'prepared', 'files': [item]}
        with patch.object(patch_filesystem, 'run', side_effect=self.fake_run), \
                patch.object(patch_filesystem, 'atomic_save_manifest', side_effect=self.save):
            with self.assertRaises(RuntimeError):
                patch_filesystem.apply_patches(self.ep, self.work, manifest)
        self.assertFalse(any('-patch' in command for command in self.commands))
        self.assertEqual(manifest['status'], 'prepared')

    def test_manifest_replace_failure_preserves_previous_valid_manifest(self):
        previous = {'status': 'prepared', 'files': []}
        patch_filesystem.atomic_save_manifest(self.work, previous)
        old_bytes = (self.work / 'manifest.json').read_bytes()
        with patch.object(patch_filesystem.os, 'replace', side_effect=OSError('replace failed')):
            with self.assertRaises(OSError):
                patch_filesystem.atomic_save_manifest(self.work, {'status': 'applying'})
        self.assertEqual((self.work / 'manifest.json').read_bytes(), old_bytes)
        self.assertEqual(list(self.work.glob('.manifest-*')), [])

    def test_successful_apply_verifies_full_files_and_skips_empty_diff(self):
        item, _, new = self.prepare()
        unchanged, unchanged_bytes, _ = self.prepare('unchanged', b'unchanged', b'unchanged')
        manifest = {'status': 'prepared', 'files': [item, unchanged]}
        with patch.object(patch_filesystem, 'run', side_effect=self.fake_run), \
                patch.object(patch_filesystem, 'atomic_save_manifest', side_effect=self.save):
            patch_filesystem.apply_patches(self.ep, self.work, manifest)
        self.assertEqual(manifest['status'], 'verified')
        self.assertEqual(self.backing[item['path']], new)
        self.assertEqual(self.backing[unchanged['path']], unchanged_bytes)
        patch_commands = [command for command in self.commands if '-patch' in command]
        self.assertEqual(len(patch_commands), 1)
        for entry in [item, unchanged]:
            self.assertTrue(any('-extract' in command and
                                command[command.index('-extract') + 1].startswith(entry['path'] + '=')
                                for command in self.commands))
        self.assertIn('verified', self.saved_statuses)

    def test_partial_apply_rolls_back_even_when_error_manifest_save_fails(self):
        item, old, _ = self.prepare()
        manifest = {'status': 'prepared', 'files': [item]}
        failure = RuntimeError('simulated partial patch failure')

        def run(*args):
            if '-patch' in args and str(args[-1]).endswith('.diff'):
                self.commands.append(list(args))
                self.backing[item['path']] = apply_diff(
                    old, self.work / 'fixture.diff', first_only=True)
                raise failure
            self.fake_run(*args)

        def save(work, state):
            self.save(work, state)
            if state['status'] == 'rollback-required':
                raise OSError('manifest write failed')

        with patch.object(patch_filesystem, 'run', side_effect=run), \
                patch.object(patch_filesystem, 'atomic_save_manifest', side_effect=save):
            with self.assertRaises(RuntimeError) as raised:
                patch_filesystem.apply_patches(self.ep, self.work, manifest)
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.backing[item['path']], old)
        self.assertEqual(manifest['status'], 'rolled-back')
        self.assertTrue(any(str(command[-1]).endswith('.undo') for command in self.commands))

    def test_successful_undo_with_wrong_bytes_requires_recovery(self):
        item, old, _ = self.prepare()
        manifest = {'status': 'prepared', 'files': [item]}

        def run(*args):
            self.fake_run(*args)
            if '-patch' in args and str(args[-1]).endswith('.diff'):
                raise RuntimeError('patch failed after mutation')
            if '-patch' in args and str(args[-1]).endswith('.undo'):
                self.backing[item['path']] = b'!' + self.backing[item['path']][1:]

        with patch.object(patch_filesystem, 'run', side_effect=run), \
                patch.object(patch_filesystem, 'atomic_save_manifest', side_effect=self.save):
            with self.assertRaises(RuntimeError):
                patch_filesystem.apply_patches(self.ep, self.work, manifest)
        self.assertNotEqual(self.backing[item['path']], old)
        self.assertEqual(manifest['status'], 'rollback-required')
        self.assertNotIn('rolled-back', self.saved_statuses)

    def test_full_verification_failure_triggers_confirmed_rollback(self):
        item, old, new = self.prepare()
        manifest = {'status': 'prepared', 'files': [item]}

        def run(*args):
            self.fake_run(*args)
            if '-extract' in args and self.backing[item['path']] == new:
                destination = str(args[args.index('-extract') + 1]).split('=', 1)[1]
                Path(destination).write_bytes(b'!' + new[1:])

        with patch.object(patch_filesystem, 'run', side_effect=run), \
                patch.object(patch_filesystem, 'atomic_save_manifest', side_effect=self.save):
            with self.assertRaises(RuntimeError):
                patch_filesystem.apply_patches(self.ep, self.work, manifest)
        self.assertEqual(self.backing[item['path']], old)
        self.assertEqual(manifest['status'], 'rolled-back')
        self.assertTrue(any(str(command[-1]).endswith('.undo') for command in self.commands))


if __name__ == '__main__':
    unittest.main()
