import datetime as dt
import importlib.util
import io
from pathlib import Path
import plistlib
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

MODULE = Path(__file__).resolve().parents[2] / 'tools/apps/ipa_preflight.py'
spec = importlib.util.spec_from_file_location('ipa_preflight', MODULE)
ipa = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ipa
spec.loader.exec_module(ipa)


def macho(platform=2, minimum=14, cryptid=0, filetype=2, cpu=0x0100000c, subtype=0):
    commands = struct.pack('<6I', 0x32, 24, platform, minimum << 16, 18 << 16, 0)
    commands += struct.pack('<6I', 0x2c, 24, 0, 0, cryptid, 0)
    return struct.pack('<8I', 0xfeedfacf, cpu, subtype, filetype, 2, len(commands), 0, 0) + commands


def archive(binary=None, info=None, extra=()):
    metadata = {'CFBundleIdentifier': 'org.test.App', 'CFBundleExecutable': 'App',
                'CFBundleDisplayName': 'Test', 'CFBundleVersion': '1',
                'MinimumOSVersion': '14.0', 'CFBundleSupportedPlatforms': ['iPhoneOS'], 'UIDeviceFamily': [1]}
    metadata.update(info or {})
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('Payload/Test.app/Info.plist', plistlib.dumps(metadata))
        z.writestr('Payload/Test.app/App', macho() if binary is None else binary)
        for name, value in extra:
            z.writestr(name, value)
    return data.getvalue()


class IPATests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ipa-test-')
        self.root = Path(self.temp.name)
        self.path = self.root / 'owned.ipa'

    def tearDown(self):
        self.temp.cleanup()

    def inspect(self, data=None, **kwargs):
        self.path.write_bytes(archive() if data is None else data)
        return ipa.inspect_ipa(self.path, '14.0', **kwargs)

    def test_valid_metadata_never_claims_install_or_launch(self):
        result = self.inspect()
        self.assertEqual(result.report['status'], 'preflight-passed')
        self.assertFalse(result.report['installed'])
        self.assertFalse(result.report['registered'])
        self.assertFalse(result.report['launched'])
        self.assertEqual(result.report['installation_gate']['status'], 'blocked')

    def test_wrapped_stage_is_byte_identical_and_refuses_replacement(self):
        original = archive()
        wrapper = io.BytesIO()
        with zipfile.ZipFile(wrapper, 'w') as z:
            z.writestr('App.ipa', original)
            z.writestr('__MACOSX/._App.ipa', b'metadata')
        inspected = self.inspect(wrapper.getvalue())
        out = self.root / 'stage'
        report = ipa.stage_ipa(inspected, out)
        self.assertEqual((out/'application.ipa').read_bytes(), original)
        self.assertEqual(report['status'], 'staged-not-installed')
        self.assertFalse(report['installed'])
        with self.assertRaises(FileExistsError):
            ipa.stage_ipa(inspected, out)
        self.assertEqual((out/'application.ipa').read_bytes(), original)

    def test_simulator_minimum_and_encryption_rejected(self):
        for data in (archive(macho(platform=7)), archive(macho(minimum=17)), archive(macho(cryptid=1)), archive(info={'MinimumOSVersion': '18.0'}), archive(info={'UIDeviceFamily': [2]})):
            with self.subTest(data=data[:8]), self.assertRaises(ipa.PreflightError):
                self.inspect(data)

    def test_traversal_symlink_duplicate_and_parent_collision_rejected(self):
        paths = ['../escape', '/absolute', 'a/./b', 'a//b', 'a\\b', 'Payload/Test.app/app', 'Payload/Test.app', 'a\nb']
        for name in paths:
            with self.subTest(name=name), self.assertRaises(ipa.PreflightError):
                self.inspect(archive(extra=[(name, b'bad')]))
        link = zipfile.ZipInfo('link')
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ipa.PreflightError):
            self.inspect(archive(extra=[(link, b'target')]))

    def test_ambiguous_wrapper_and_multiple_apps_rejected(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as z:
            z.writestr('one.ipa', archive())
            z.writestr('two.ipa', archive())
        with self.assertRaises(ipa.PreflightError):
            self.inspect(data.getvalue())
        with self.assertRaises(ipa.PreflightError):
            self.inspect(archive(extra=[('Payload/Second.app/Info.plist', plistlib.dumps({}))]))

    def test_crc_and_uncompressed_budget_are_checked(self):
        data = bytearray(archive())
        # Corrupt the central-directory CRC of the first real member.
        central = data.index(b'PK\x01\x02')
        data[central+16] ^= 1
        with self.assertRaises(ipa.PreflightError):
            self.inspect(data)
        with self.assertRaises(ipa.PreflightError):
            self.inspect(limits=ipa.Limits(uncompressed_bytes=1))

    def test_malformed_deflate_and_xml_fail_as_preflight_rejections(self):
        data = bytearray(archive())
        # Set the first DEFLATE block's BTYPE to the reserved binary value 11.
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            offset = z.infolist()[0].header_offset
        name_size, extra_size = struct.unpack_from('<2H', data, offset + 26)
        data[offset + 30 + name_size + extra_size] = 7
        with self.assertRaisesRegex(ipa.PreflightError, 'integrity'):
            self.inspect(data)
        malformed = io.BytesIO()
        with zipfile.ZipFile(malformed, 'w') as z:
            z.writestr('Payload/Test.app/Info.plist', b'<?xml version="1.0"?><plist><dict>')
            z.writestr('Payload/Test.app/App', macho())
        with self.assertRaisesRegex(ipa.PreflightError, 'Info.plist'):
            self.inspect(malformed.getvalue())

    def test_bad_macho_commands_and_non_executable_rejected(self):
        broken = bytearray(macho())
        struct.pack_into('<I', broken, 36, 4)
        for data in (bytes(broken), macho()[:-1], b'fake executable'):
            with self.assertRaises(ipa.PreflightError):
                self.inspect(archive(data))

    def test_embedded_framework_is_checked_for_target_compatibility(self):
        framework = [('Payload/Test.app/Frameworks/Bad.framework/Info.plist', plistlib.dumps({'CFBundleExecutable': 'Bad'})),
                     ('Payload/Test.app/Frameworks/Bad.framework/Bad', macho(platform=7))]
        with self.assertRaisesRegex(ipa.PreflightError, 'physical-iOS'):
            self.inspect(archive(extra=framework))

    def test_binary_roles_require_executable_or_dynamic_library(self):
        # A dylib renamed to the main executable is not an application binary.
        for filetype in (1, 6, 8):
            with self.subTest(filetype=filetype), self.assertRaisesRegex(ipa.PreflightError, 'file type'):
                self.inspect(archive(macho(filetype=filetype)))
        framework_info = ('Payload/Test.app/Frameworks/Bad.framework/Info.plist',
                          plistlib.dumps({'CFBundleExecutable': 'Bad'}))
        for binary_path, extra in (
            ('Payload/Test.app/Frameworks/Bad.framework/Bad', [framework_info]),
            ('Payload/Test.app/Frameworks/Bad.dylib', []),
            ('Payload/Test.app/PlugIns/Bad.appex/Bad', [
                ('Payload/Test.app/PlugIns/Bad.appex/Info.plist',
                 plistlib.dumps({'CFBundleExecutable': 'Bad', 'MinimumOSVersion': '14.0'}))]),
        ):
            filetype = 6 if binary_path.endswith('.appex/Bad') else 2
            with self.subTest(path=binary_path), self.assertRaisesRegex(ipa.PreflightError, 'file type'):
                self.inspect(archive(extra=extra + [(binary_path, macho(filetype=filetype))]))
        result = self.inspect(archive(extra=[framework_info,
                               ('Payload/Test.app/Frameworks/Bad.framework/Bad', macho(filetype=6))]))
        self.assertEqual(result.report['mach_o'][1]['role'], 'dynamic-library')

    def test_cpu_abi_header_and_arm64_subtype_are_checked(self):
        # A 32-bit Mach-O header cannot declare the 64-bit ARM ABI.
        thin32 = struct.pack('<7I', 0xfeedface, 0x0100000c, 0, 2, 1, 24, 0)
        thin32 += struct.pack('<6I', 0x32, 24, 2, 14 << 16, 18 << 16, 0)
        for binary in (thin32, macho(cpu=12), macho(cpu=0x01000007),
                       macho(subtype=2), macho(subtype=99)):
            with self.subTest(binary=binary[:12]), self.assertRaises(ipa.PreflightError):
                self.inspect(archive(binary))
        self.assertEqual(self.inspect(archive(macho(subtype=1))).report['status'], 'preflight-passed')

    def test_staging_rejects_changed_payload_without_creating_directory(self):
        result = self.inspect()
        result.ipa += b'modified after inspection'
        destination = self.root / 'bad-stage'
        with self.assertRaisesRegex(ipa.PreflightError, 'no longer matches'):
            ipa.stage_ipa(result, destination)
        self.assertFalse(destination.exists())

    def test_device_family_boolean_and_control_paths_are_rejected(self):
        with self.assertRaises(ipa.PreflightError):
            self.inspect(archive(info={'UIDeviceFamily': [True]}))
        with self.assertRaises(ipa.PreflightError):
            self.inspect(archive(extra=[('control\x1bname', b'bad')]))

    def test_profile_report_redacts_identity_and_marks_expiry(self):
        private = {'ExpirationDate': dt.datetime(2025, 12, 25), 'ProvisionedDevices': ['private-device-id'],
                   'Name': 'private-profile-name', 'TeamIdentifier': ['private-team'],
                   'Entitlements': {'get-task-allow': True}}
        completed = type('Completed', (), {'returncode': 0, 'stdout': plistlib.dumps(private)})()
        with patch.object(ipa.shutil, 'which', return_value='/usr/bin/openssl'), patch.object(ipa.subprocess, 'run', return_value=completed):
            result = ipa._safe_profile_metadata(b'profile', dt.datetime(2026, 10, 2, tzinfo=dt.timezone.utc))
        self.assertTrue(result['expired'])
        self.assertEqual(result['udid_count'], 1)
        self.assertEqual(result['profile_type'], 'development')
        self.assertNotIn('private', str(result))


if __name__ == '__main__':
    unittest.main()
