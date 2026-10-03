import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / 'tools/runtime/diagnostics.py'
spec = importlib.util.spec_from_file_location('diagnostics', MODULE)
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


def png_header(width=828, height=1792):
    return b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + struct.pack('>II', width, height) + bytes(9)


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gui-diagnostic-test-')
        self.root = Path(self.temp.name)
        self.run = self.root / 'run'
        self.run.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir()
        (self.state / 'manifest.json').write_text('{}')
        self.live = {'pid': os.getpid(), 'run': str(self.run)}
        (self.state / 'live.json').write_text(json.dumps(self.live))
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        (self.evidence / 'context.json').write_text(json.dumps({
            'state': str(self.state),
            **self.live,
            'manifest_sha256': diagnostics.session.sha256(self.state / 'manifest.json')}))

    def tearDown(self):
        self.temp.cleanup()

    def result(self, **values):
        (self.run / 'result.json').write_text(json.dumps(values))

    def test_unexpected_clean_exit_is_not_success(self):
        self.result(status='unexpected-exit', exit_code=0)
        value = diagnostics.classify(self.run)
        self.assertEqual(value['classification'], 'unexpected-exit')
        self.assertFalse(value['positive_guest_success'])

    def test_runner_interruption_is_distinct_from_guest_crash(self):
        for exit_code in (0, -15):
            with self.subTest(exit_code=exit_code):
                self.result(status='interrupted', exit_code=exit_code)
                value = diagnostics.classify(self.run)
                self.assertEqual(value['classification'], 'runner-interrupted')
                self.assertFalse(value['positive_guest_success'])

    def test_real_panic_precedes_runner_interruption(self):
        self.result(status='interrupted', exit_code=-15)
        (self.run / 'serial.log').write_text('panic(cpu 1 caller 0x123): ordinary panic\n')
        self.assertEqual(diagnostics.classify(self.run)['classification'], 'guest-kernel-panic')

    def test_platform_panic_registration_is_not_a_panic(self):
        (self.run / 'serial.log').write_text('IOPlatformPanicAction -> AppleSEPManager\n')
        self.result(status='stopped', exit_code=0)
        self.assertEqual(diagnostics.classify(self.run)['classification'], 'controlled-stop')

    def test_sep_category_survives_excerpt_budget(self):
        (self.run / 'serial.log').write_text('panic(cpu 1 caller 0x123): ordinary panic\n' * 40 +
                                           'panic(cpu 0 caller 0x321): SEP Panic: observed\n')
        value = diagnostics.classify(self.run)
        self.assertEqual(value['classification'], 'guest-sep-panic')
        self.assertEqual(len(value['matches']), 32)
        self.assertIn('guest-sep-panic', value['observed_categories'])

    def test_sensitive_excerpt_is_omitted(self):
        (self.run / 'serial.log').write_text('panic(cpu 0 caller 0x321): SEP Panic: keybag private-value\n')
        value = diagnostics.classify(self.run)
        self.assertEqual(value['matches'][0]['text'], '[sensitive line omitted]')
        self.assertNotIn('private-value', json.dumps(value))

    def test_tail_bound_and_host_signal(self):
        (self.run / 'serial.log').write_bytes(b'x' * (diagnostics.MAX_LOG + 17))
        self.result(status='unexpected-exit', exit_code=-11)
        value = diagnostics.classify(self.run)
        self.assertEqual(value['classification'], 'host-crash')
        self.assertEqual(value['log_scans'][0]['scanned_bytes'], diagnostics.MAX_LOG)
        self.assertEqual(value['log_scans'][0]['offset'], 17)
        self.assertTrue(value['log_scans'][0]['truncated'])

    def test_changed_manifest_rejected(self):
        (self.state / 'manifest.json').write_text('{"changed":true}')
        with self.assertRaisesRegex(diagnostics.DiagnosticError, 'manifest changed'):
            diagnostics.Recorder(self.evidence)

    def test_recorder_rejects_a_restarted_guest(self):
        recorder = diagnostics.Recorder(self.evidence)
        for changed in ({'run': str(self.root / 'next-run')}, {'pid': os.getpid() + 1}):
            (self.state / 'live.json').write_text(json.dumps({**self.live, **changed}))
            for operation in (lambda: recorder.control('home'),
                              lambda: recorder.capture('stale'), recorder.snapshot):
                with self.subTest(changed=changed), patch.object(diagnostics.session, 'QMP') as qmp:
                    with self.assertRaisesRegex(diagnostics.DiagnosticError, 'stale guest run'):
                        operation()
                    qmp.assert_not_called()
        self.assertFalse(list(self.evidence.glob('*.png')))

    def test_dead_guest_rejected_before_qmp(self):
        recorder = diagnostics.Recorder(self.evidence)
        with patch.object(diagnostics.os, 'kill', side_effect=ProcessLookupError), \
                patch.object(diagnostics.session, 'QMP') as qmp:
            with self.assertRaisesRegex(diagnostics.DiagnosticError, 'no longer alive'):
                recorder.control('home')
            qmp.assert_not_called()

    def test_restart_during_qmp_connect_rejected_before_input(self):
        recorder = diagnostics.Recorder(self.evidence)
        class QMP:
            def __enter__(inner):
                (self.state / 'live.json').write_text(json.dumps(
                    {**self.live, 'run': str(self.root / 'next-run')}))
                return inner
            def __exit__(inner, *_): pass
            def request(inner, *args): self.fail('Input must not reach a different run')
        with patch.object(diagnostics.session, 'QMP', return_value=QMP()):
            with self.assertRaisesRegex(diagnostics.DiagnosticError, 'stale guest run'):
                recorder.control('home')

    def test_observation_rejects_outside_and_symlink(self):
        outside = self.root / 'outside.png'
        outside.write_bytes(png_header())
        (self.evidence / 'alias.png').symlink_to(outside)
        recorder = diagnostics.Recorder(self.evidence)
        for name in ('../outside.png', 'alias.png', str(outside)):
            with self.subTest(name=name):
                with self.assertRaises(diagnostics.DiagnosticError):
                    recorder.observe(name, 'visible observation')

    def test_event_budget_never_exceeded(self):
        recorder = diagnostics.Recorder(self.evidence)
        with patch.object(diagnostics, 'MAX_EVENTS', 1):
            recorder.append({'kind': 'fixture'})
            before = (self.evidence / 'events.jsonl').read_bytes()
            with self.assertRaises(diagnostics.DiagnosticError):
                recorder.append({'kind': 'rejected'})
            self.assertEqual((self.evidence / 'events.jsonl').read_bytes(), before)

    def test_failed_capture_removes_invalid_output(self):
        recorder = diagnostics.Recorder(self.evidence)

        class QMP:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def request(self, command, args=None):
                if command == 'screendump':
                    Path(args['filename']).write_bytes(png_header(640, 480))
                return {'running': True}

        with patch.object(diagnostics.session, 'QMP', return_value=QMP()):
            with self.assertRaisesRegex(diagnostics.DiagnosticError, '828x1792'):
                recorder.capture('invalid-dimensions')
        self.assertFalse(list(self.evidence.glob('*.png')))

    def test_exhausted_event_budget_rejects_control_before_guest_input(self):
        recorder = diagnostics.Recorder(self.evidence)
        with patch.object(diagnostics, 'MAX_EVENTS', 1):
            recorder.append({'kind': 'fixture'})
            with patch.object(diagnostics.session, 'QMP') as qmp:
                with self.assertRaises(diagnostics.DiagnosticError):
                    recorder.control('home')
                qmp.assert_not_called()

    def test_invalid_control_rejected_before_recording_or_qmp(self):
        recorder = diagnostics.Recorder(self.evidence)
        values = [('tap', None, None, .2), ('swipe', (1, 1), None, .2),
                  ('tap', (1, 1), None, float('nan')), ('tap', (828, 1), None, .2)]
        for action, start, end, duration in values:
            with self.subTest(action=action, start=start, duration=duration):
                with patch.object(diagnostics.session, 'QMP') as qmp:
                    with self.assertRaises((diagnostics.DiagnosticError, diagnostics.session.SessionError)):
                        recorder.control(action, start, end, duration)
                    qmp.assert_not_called()
        self.assertFalse((self.evidence / 'events.jsonl').exists())

    def test_screenshot_budget_rejected_before_qmp(self):
        recorder = diagnostics.Recorder(self.evidence)
        for n in range(64):
            (self.evidence / f'{n:03}.png').write_bytes(png_header())
        with patch.object(diagnostics.session, 'QMP') as qmp:
            with self.assertRaises(diagnostics.DiagnosticError):
                recorder.capture('over-budget')
            qmp.assert_not_called()

    def test_screen_and_input_ack_never_claim_semantics(self):
        recorder = diagnostics.Recorder(self.evidence)

        class QMP:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def request(self, command, args=None):
                if command == 'screendump':
                    Path(args['filename']).write_bytes(png_header())
                return {'running': True}

        with patch.object(diagnostics.session, 'QMP', return_value=QMP()):
            self.assertEqual(recorder.capture('fixture')['semantic_result'], 'requires visual observation')
            self.assertEqual(recorder.control('home')['semantic_result'], 'event sent only')

    def test_new_report_cannot_overwrite_evidence(self):
        path = self.root / 'report.json'
        path.write_text('original evidence')
        with self.assertRaises(FileExistsError):
            diagnostics.write_new(path, {'replacement': True})
        self.assertEqual(path.read_text(), 'original evidence')

    def test_runtime_snapshot_does_not_infer_guest_connectivity(self):
        class QMP:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def request(self, command, args=None):
                return 'nic: configured\n' if command == 'human-monitor-command' else {'running': True}

        with patch.object(diagnostics.session, 'QMP', return_value=QMP()), \
             patch.object(diagnostics, 'recognized_fds', return_value={'fixture': True}):
            result = diagnostics.Recorder(self.evidence).snapshot()
        self.assertEqual(result['qemu_network_info'], 'nic: configured\n')
        self.assertFalse(result['guest_connectivity_verified'])


if __name__ == '__main__':
    unittest.main()
