import copy
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

MODULE = Path(__file__).resolve().parents[2] / 'tools/firmware/prepare_firmware.py'
spec = importlib.util.spec_from_file_location('prepare_firmware', MODULE)
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


def der(tag, data):
    length = bytes([len(data)]) if len(data) < 128 else b'\x82' + len(data).to_bytes(2, 'big')
    return bytes([tag]) + length + data


def im4p(typ, payload, extra=b''):
    return der(0x30, der(0x16, b'IM4P') + der(0x16, typ.encode()) + der(0x16, b'test') + der(4, payload) + extra)


def manifest():
    names = {'KernelCache': 'kernel.im4p', 'DeviceTree': 'dtree.im4p',
             'Ap,SecurePageTableMonitor': 'sptm.im4p',
             'Ap,TrustedExecutionMonitor': 'txm.im4p'}
    return {'SupportedProductTypes': ['iPhone17,3'], 'ProductVersion': '27.0',
            'ProductBuildVersion': '24A437', 'BuildIdentities': [
                {'Info': {'DeviceClass': 'd47ap', 'Variant': 'Customer Erase Install (IPSW)',
                          'RestoreBehavior': 'Erase'},
                 'Manifest': {key: {'Info': {'Path': value}} for key, value in names.items()}}]}


class Response(io.BytesIO):
    def __init__(self, data, start, end, total, etag='"fixed"', status=206):
        super().__init__(data)
        self.status = status
        self.headers = {'Content-Range': f'bytes {start}-{end}/{total}',
                        'Content-Length': str(end-start+1), 'ETag': etag}


class FirmwareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='firmware-test-')
        self.root = Path(self.temp.name)
        self.archive = self.root / 'test.ipsw'
        with zipfile.ZipFile(self.archive, 'w', zipfile.ZIP_STORED) as z:
            z.writestr('BuildManifest.plist', plistlib.dumps(manifest()))
            for name, typ in (('kernel', 'krnl'), ('dtree', 'dtre'), ('sptm', 'sptm'), ('txm', 'trxm')):
                z.writestr(name + '.im4p', im4p(typ, b'uncompressed-test-payload'))
            z.writestr('unused-large-root.dmg', b'x' * (2 << 20))
        self.out = self.root / 'prepared'

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, source=None, **kwargs):
        return fw.prepare(source or str(self.archive), self.out, product='iPhone17,3',
                          board='d47ap', version='27.0', build='24A437', **kwargs)

    def add_ramdisk(self, typ='rdsk', payload=b'ordinary-ramdisk-payload', extra=b'',
                    only_manifest=False, omit_member=False):
        with zipfile.ZipFile(self.archive) as z:
            members = {i.filename: z.read(i) for i in z.infolist()}
        m = plistlib.loads(members['BuildManifest.plist'])
        selected = m['BuildIdentities'][0]['Manifest']
        if only_manifest:
            selected.clear()
        selected['RestoreRamDisk'] = {'Info': {'Path': 'restore.dmg'}}
        members['BuildManifest.plist'] = plistlib.dumps(m)
        if not omit_member:
            members['restore.dmg'] = im4p(typ, payload, extra)
        with zipfile.ZipFile(self.archive, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, content in members.items():
                z.writestr(name, content)

    def test_default_selection_and_budget_still_exclude_ramdisk(self):
        self.add_ramdisk(typ='wrong', payload=b'unselected')
        result = self.prepare()
        self.assertEqual(result['component_selection'], 'boot')
        self.assertEqual(result['limit_bytes'], 300 * fw.MIB)
        self.assertEqual(result['maximum_limit_bytes'], 300 * fw.MIB)
        self.assertNotIn('ramdisk', result['selected'])
        self.assertFalse((self.out / 'original/ramdisk.im4p').exists())

    def test_ramdisk_only_prepares_exact_matching_member(self):
        self.add_ramdisk(only_manifest=True)
        result = self.prepare(selection='ramdisk-only', limit=512 * fw.MIB)
        self.assertEqual(set(result['selected']), {'ramdisk'})
        self.assertEqual(result['selected']['ramdisk']['manifest_key'], 'RestoreRamDisk')
        self.assertEqual(result['identity']['DeviceClass'], 'd47ap')
        self.assertEqual((self.out / 'derived/ramdisk').read_bytes(), b'ordinary-ramdisk-payload')
        artifact = result['artifacts'][0]
        self.assertEqual(artifact['image4_type'], 'rdsk')
        self.assertFalse(artifact['filesystem_qualified'])
        self.assertEqual(artifact['original']['sha256'], fw.digest((self.out / 'original/ramdisk.im4p').read_bytes())['sha256'])
        self.assertEqual(artifact['derived']['sha256'], fw.digest((self.out / 'derived/ramdisk').read_bytes())['sha256'])
        actual = sum(p.stat().st_size for p in self.out.rglob('*') if p.is_file())
        self.assertEqual(result['disk_bytes'], actual)

    def test_include_ramdisk_preserves_boot_component_selection(self):
        self.add_ramdisk()
        result = self.prepare(selection='boot-and-ramdisk', limit=600 * fw.MIB)
        self.assertEqual(set(result['selected']), {'bootkc', 'dtree', 'sptm', 'txm', 'ramdisk'})
        self.assertEqual((self.out / 'derived/bootkc').read_bytes(), b'uncompressed-test-payload')
        self.assertEqual(result['maximum_limit_bytes'], 640 * fw.MIB)

    def test_ramdisk_type_and_encrypted_input_are_rejected(self):
        for typ, extra, expected in (('krnl', b'', 'type'), ('rdsk', der(4, b'encrypted-keybag-fixture'), 'encrypted')):
            with self.subTest(typ=typ, expected=expected):
                self.add_ramdisk(typ=typ, extra=extra)
                self.out = self.root / expected
                with self.assertRaisesRegex(fw.FirmwareError, expected), patch.object(fw.subprocess, 'run') as decoder:
                    self.prepare(selection='ramdisk-only', limit=512 * fw.MIB, img4='/fixture/decoder')
                decoder.assert_not_called()
                self.assertFalse((self.out / 'derived/ramdisk').exists())
                report = json.loads((self.out / 'provenance.json').read_text())
                self.assertEqual(report['status'], 'incomplete')
                self.assertIn('original', report['artifacts'][0])

    def test_optional_selection_and_ceiling_are_explicit_and_bounded(self):
        self.add_ramdisk()
        for selection, limit in (('unknown', fw.DEFAULT_LIMIT), ('boot', fw.DEFAULT_LIMIT + 1),
                                 ('ramdisk-only', fw.RAMDISK_LIMIT + 1)):
            with self.subTest(selection=selection, limit=limit), self.assertRaises(fw.FirmwareError):
                self.prepare(selection=selection, limit=limit)
            self.assertFalse(self.out.exists())
        with patch.object(fw.urllib.request, 'urlopen') as fetch, self.assertRaises(fw.FirmwareError):
            fw.RangeReader('https://example.invalid/test', limit=512 * fw.MIB)
        fetch.assert_not_called()

    def test_missing_ramdisk_component_or_member_is_checked(self):
        with self.assertRaisesRegex(fw.FirmwareError, 'required.*ramdisk'):
            self.prepare(selection='ramdisk-only')
        self.add_ramdisk(omit_member=True)
        with self.assertRaisesRegex(fw.FirmwareError, 'missing selected'):
            self.prepare(selection='ramdisk-only')
        self.assertFalse(self.out.exists())

    def test_ramdisk_member_bound_rejected_before_reading_payload(self):
        self.add_ramdisk()
        with patch.object(fw, 'RAMDISK_MEMBER_LIMIT', 8), self.assertRaisesRegex(fw.FirmwareError, 'member bound'):
            self.prepare(selection='ramdisk-only', inspect_only=True)
        self.assertFalse(self.out.exists())

    def test_ramdisk_original_and_decoded_bytes_share_output_budget(self):
        self.add_ramdisk()
        with zipfile.ZipFile(self.archive) as z:
            manifest_size = z.getinfo('BuildManifest.plist').file_size
            original_size = z.getinfo('restore.dmg').file_size
        limit = fw.MAX_REPORT + manifest_size + original_size + len(b'ordinary-ramdisk-payload') - 1
        with self.assertRaisesRegex(fw.FirmwareError, 'decoded.*budget'):
            self.prepare(selection='ramdisk-only', limit=limit)
        self.assertFalse((self.out / 'derived/ramdisk').exists())
        report = json.loads((self.out / 'provenance.json').read_text())
        self.assertEqual(report['status'], 'incomplete')
        actual = sum(p.stat().st_size for p in self.out.rglob('*') if p.is_file())
        self.assertLessEqual(actual, limit)

    def test_remote_ramdisk_selection_remains_range_pinned(self):
        self.add_ramdisk()
        data = self.archive.read_bytes()
        ranges = []
        def fetch(request, timeout):
            first, last = map(int, request.get_header('Range')[6:].split('-'))
            ranges.append((first, last))
            return Response(data[first:last+1], first, last, len(data))
        with patch.object(fw.urllib.request, 'urlopen', side_effect=fetch):
            result = self.prepare('https://example.invalid/test.ipsw', selection='ramdisk-only', limit=512 * fw.MIB)
        self.assertEqual(set(result['selected']), {'ramdisk'})
        self.assertEqual(result['http']['etag'], '"fixed"')
        self.assertTrue(all(last-first+1 <= fw.MAX_REQUEST for first, last in ranges))
        self.assertEqual(result['http']['transferred_bytes'], sum(last-first+1 for first, last in ranges))

    def test_local_preparation_keeps_original_and_excludes_filesystem(self):
        original = self.archive.read_bytes()
        result = self.prepare()
        self.assertEqual(result['status'], 'prepared-unmodified')
        self.assertEqual(self.archive.read_bytes(), original)
        self.assertEqual((self.out/'derived/bootkc').read_bytes(), b'uncompressed-test-payload')
        self.assertFalse((self.out/'unused-large-root.dmg').exists())
        self.assertEqual(result['security_changes'], [])
        actual_output = sum(p.stat().st_size for p in self.out.rglob('*') if p.is_file())
        self.assertEqual(result['disk_bytes'], actual_output)
        with self.assertRaises(fw.FirmwareError):
            self.prepare()

    def test_remote_zip_uses_pinned_bounded_ranges_and_never_reads_root(self):
        data = self.archive.read_bytes()
        headers = []
        def fetch(request, timeout):
            headers.append(dict(request.header_items()))
            first, last = map(int, request.get_header('Range')[6:].split('-'))
            return Response(data[first:last+1], first, last, len(data))
        with patch.object(fw.urllib.request, 'urlopen', side_effect=fetch):
            result = self.prepare('https://example.invalid/test.ipsw')
        self.assertLess(result['http']['transferred_bytes'], 100000)
        self.assertTrue(all(h.get('If-match') == '"fixed"' for h in headers[1:]))
        self.assertEqual(result['status'], 'prepared-unmodified')

    def test_server_ignoring_range_body_is_not_read(self):
        response = Response(b'x'*100, 0, 0, 100, status=200)
        with patch.object(fw.urllib.request, 'urlopen', return_value=response), self.assertRaisesRegex(fw.FirmwareError, 'ignored Range'):
            fw.RangeReader('https://example.invalid/test')
        # BytesIO is closed by the context; read was never invoked.

    def test_changed_entity_and_wrong_ranges_are_rejected(self):
        with patch.object(fw.urllib.request, 'urlopen', side_effect=[Response(b'x', 0, 0, 3), Response(b'y', 1, 1, 3, etag='"changed"')]):
            reader = fw.RangeReader('https://example.invalid/test')
            reader.seek(1)
            with self.assertRaisesRegex(fw.FirmwareError, 'ETag changed'):
                reader.read(1)
        with patch.object(fw.urllib.request, 'urlopen', return_value=Response(b'x', 1, 1, 3)), self.assertRaisesRegex(fw.FirmwareError, 'wrong byte range'):
            fw.RangeReader('https://example.invalid/test')

    def test_truncated_response_and_transfer_budget_rejected(self):
        with patch.object(fw.urllib.request, 'urlopen', return_value=Response(b'', 0, 0, 3)), self.assertRaises(fw.FirmwareError):
            fw.RangeReader('https://example.invalid/test')
        with patch.object(fw.urllib.request, 'urlopen', return_value=Response(b'x', 0, 0, 3)):
            reader = fw.RangeReader('https://example.invalid/test', limit=1)
            with self.assertRaisesRegex(fw.FirmwareError, 'budget'):
                reader.read(1)

    def test_ambiguous_identity_mismatch_and_incomplete_pair_rejected(self):
        m = manifest()
        m['BuildIdentities'].append(copy.deepcopy(m['BuildIdentities'][0]))
        with self.assertRaisesRegex(fw.FirmwareError, 'ambiguous'):
            fw.select_identity(m, product='iPhone17,3', board='d47ap')
        with self.assertRaisesRegex(fw.FirmwareError, 'version'):
            fw.select_identity(manifest(), product='iPhone17,3', board='d47ap', version='18.0')
        m = manifest()
        del m['BuildIdentities'][0]['Manifest']['Ap,TrustedExecutionMonitor']
        with self.assertRaisesRegex(fw.FirmwareError, 'incomplete'):
            fw.select_identity(m, product='iPhone17,3', board='d47ap')

    def test_malformed_plist_shape_and_unsafe_paths_rejected(self):
        for m in ([], {'SupportedProductTypes': []}, {'SupportedProductTypes': ['iPhone17,3'], 'BuildIdentities': [None]}):
            with self.subTest(m=m), self.assertRaises(fw.FirmwareError):
                fw.select_identity(m, product='iPhone17,3', board='d47ap')
        for name in ('../escape', '/absolute', 'a/./b', 'a//b', 'a\x00b', 'a\nb', 'a\\b'):
            with self.subTest(name=name), self.assertRaises(fw.FirmwareError):
                fw.checked_name(name)

    def test_zip_symlink_and_duplicate_are_rejected_before_output(self):
        for symlink in (True, False):
            bad = self.root / ('bad-link.zip' if symlink else 'bad-duplicate.zip')
            with zipfile.ZipFile(bad, 'w') as z:
                member = zipfile.ZipInfo('entry')
                member.external_attr = (stat.S_IFLNK | 0o777) << 16 if symlink else (stat.S_IFREG | 0o600) << 16
                z.writestr(member, b'target')
                if not symlink:
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        z.writestr('entry', b'duplicate')
            with self.assertRaises(fw.FirmwareError), fw.open_archive(str(bad)):
                pass
            self.assertFalse(self.out.exists())

    def test_der_rejects_keys_truncation_and_trailing_bytes(self):
        for data in (im4p('krnl', b'payload', der(4, b'keybag')), im4p('krnl', b'payload')[:-1], im4p('krnl', b'payload') + b'junk'):
            with self.assertRaises(fw.FirmwareError):
                fw.im4p_payload(data)

    def test_budget_prevents_output_and_invalid_timeout_rejected(self):
        with self.assertRaisesRegex(fw.FirmwareError, 'budget'):
            self.prepare(limit=1)
        self.assertFalse(self.out.exists())
        with self.assertRaises(fw.FirmwareError):
            self.prepare(timeout=float('nan'))

    def test_manifest_component_with_wrong_image4_type_is_rejected(self):
        with zipfile.ZipFile(self.archive, 'r') as z:
            members = {i.filename: z.read(i) for i in z.infolist()}
        members['dtree.im4p'] = im4p('krnl', b'wrong-component')
        with zipfile.ZipFile(self.archive, 'w') as z:
            for name, content in members.items():
                z.writestr(name, content)
        with self.assertRaisesRegex(fw.FirmwareError, 'type'):
            self.prepare()
        self.assertFalse((self.out / 'derived/dtree').exists())

    def test_disk_budget_includes_provenance_bytes(self):
        baseline = self.prepare()
        manifest_size = baseline['build_manifest']['size']
        payload_bytes = manifest_size + sum(x[part]['size'] for x in baseline['artifacts']
                                           for part in ('original', 'derived'))
        self.out = self.root / 'tight-budget'
        rejected = False
        try:
            self.prepare(limit=payload_bytes)
        except fw.FirmwareError:
            rejected = True
        self.assertTrue(rejected, 'provenance pushes total output past the stated limit')
        actual = sum(p.stat().st_size for p in self.out.rglob('*') if p.is_file())
        self.assertLessEqual(actual, payload_bytes)

    def test_compressed_decoder_rejects_dangling_output_symlink(self):
        original = self.root / 'compressed.im4p'
        original.write_bytes(im4p('krnl', b'bvx2compressed'))
        output = self.root / 'derived'
        output.symlink_to(self.root / 'victim-does-not-exist')
        with patch.object(fw.subprocess, 'run') as decoder:
            with self.assertRaisesRegex(fw.FirmwareError, 'existing'):
                fw.extract_payload(original.read_bytes(), original, output,
                                   img4='/existing/decoder', limit=1 << 20)
            decoder.assert_not_called()

    def test_non_ascii_image4_type_has_checked_error(self):
        data = im4p('krnl', b'payload').replace(b'krnl', b'\xffrnl')
        with self.assertRaises(fw.FirmwareError):
            fw.im4p_payload(data)

    def test_truncated_and_out_of_bounds_zip_metadata_rejected(self):
        original = self.archive.read_bytes()
        bad_metadata = bytearray(original)
        end = bad_metadata.rfind(b'PK\x05\x06')
        struct.pack_into('<I', bad_metadata, end + 12, 0xfffffffe)
        for content in (original[:-1], bytes(bad_metadata), b'not a zip'):
            self.archive.write_bytes(content)
            with self.subTest(length=len(content)), self.assertRaises(fw.FirmwareError):
                self.prepare()
            self.assertFalse(self.out.exists())

    def test_http_operation_deadline_covers_body_read(self):
        clock = [0]
        class SlowResponse(Response):
            def read(self, size=-1):
                clock[0] = 301
                return super().read(size)
            def read1(self, size=-1):
                return self.read(size)
        with patch.object(fw.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(fw.urllib.request, 'urlopen', return_value=SlowResponse(b'x', 0, 0, 3)), \
             self.assertRaisesRegex(fw.FirmwareError, 'time'):
            fw.RangeReader('https://example.invalid/test')


if __name__ == '__main__':
    unittest.main()
