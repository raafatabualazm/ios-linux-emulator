#!/usr/bin/env python3
"""Qualify explicit volume/namespace boundaries using one sparse host fixture."""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import subprocess


def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--exporter', required=True, type=Path)
p.add_argument('--fixture-builder', required=True, type=Path)
p.add_argument('--out', required=True, type=Path)
a = p.parse_args()
a.out.mkdir(exist_ok=False)
env = os.environ.copy()
env['GOMEMLIMIT'] = '512MiB'
base = a.out / 'base.dmg'
subprocess.run([str(a.fixture_builder.resolve()), str(base.resolve())], env=env, check=True)
assert base.stat().st_uid == os.getuid() and base.stat().st_size == 513 << 20
source_hash = digest(base)
m = {'format': 'apple-modern-cow-delta-v1', 'source': str(base.resolve()),
     'source_sha256': source_hash, 'source_size': base.stat().st_size,
     'delta_sha256': hashlib.sha256(b'').hexdigest(), 'saved_bytes': 0,
     'page_size': 4096, 'blocks': []}
zero = a.out / 'zero'
zero.mkdir()
(zero / 'delta.bin').write_bytes(b'')
(zero / 'manifest.json').write_text(json.dumps(m, indent=2) + '\n')
with base.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
    needle = b'DATA-CONTROL-ORDINARY-FILE\n'
    offset = mm.find(needle)
    assert offset >= 0 and mm.find(needle, offset + 1) == -1
    page = offset // 4096 * 4096
    changed_bytes = bytearray(mm[page:page + 4096])
    changed_bytes[offset - page] = ord('X')
changed = a.out / 'changed-data'
changed.mkdir()
(changed / 'delta.bin').write_bytes(changed_bytes)
delta_hash = hashlib.sha256(changed_bytes).hexdigest()
changed_manifest = dict(m, saved_bytes=4096, delta_sha256=delta_hash,
                        blocks=[{'offset': page, 'size': 4096, 'delta_offset': 0, 'sha256': delta_hash}])
(changed / 'manifest.json').write_text(json.dumps(changed_manifest, indent=2) + '\n')
system_id = '11111111-2222-3333-4444-555555555555'
data_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
plans = [
    ('system-default', [], True),
    ('data-role', ['--volume', 'role:data', '--guest-mount', '/private/var'], True),
    ('system-uuid', ['--volume', system_id, '--expected-role', 'system'], True),
    ('data-uuid', ['--volume', data_id, '--expected-role', 'data', '--guest-mount', '/private/var'], True),
    ('changed-data-role', ['--volume', 'role:data', '--guest-mount', '/private/var'], True),
    ('changed-system-default', [], True),
    ('refused-no-mount', ['--volume', 'role:data'], False),
    ('refused-wrong-uuid', ['--volume', '00000000-0000-0000-0000-000000000001'], False),
    ('refused-role-mismatch', ['--volume', system_id, '--expected-role', 'data'], False),
    ('refused-data-guest-path', ['--volume', 'role:data', '--guest-mount', '/private/var', '--dir', '/private/var/db/diagnostics'], False),
    ('refused-system-data-path', ['--dir', '/db/diagnostics'], False),
    ('refused-relative', ['--dir', 'db/diagnostics'], False),
    ('refused-traversal', ['--dir', '/db/../db/diagnostics'], False),
    ('refused-root', ['--dir', '/'], False),
    ('refused-nondirectory', ['--volume', 'role:data', '--guest-mount', '/private/var', '--dir', '/db/diagnostics/probe.tracev3'], False),
    ('refused-budget', ['--max-bytes', '1'], False),
    ('refused-none', ['--volume', 'role:none'], False),
]
cases = []
for name, extra, want in plans:
    manifest = changed / 'manifest.json' if name.startswith('changed-') else zero / 'manifest.json'
    cmd = [str(a.exporter.resolve()), '--manifest', str(manifest.resolve()),
           '--out', str((a.out / name).resolve()), '--require-directories'] + extra
    result = subprocess.run(cmd, capture_output=True, env=env)
    (a.out / (name + '.log')).write_bytes(result.stdout + result.stderr)
    assert (result.returncode == 0) == want, (name, result.stderr)
    cases.append({'name': name, 'argv': cmd, 'returncode': result.returncode,
                  'expected_success': want, 'pass': True})
checks = []
for name, expected, role, uuid in [
    ('system-default', b'SYSTEM-CONTROL-ORDINARY-FILE\n', 'system', system_id),
    ('system-uuid', b'SYSTEM-CONTROL-ORDINARY-FILE\n', 'system', system_id),
    ('data-role', b'DATA-CONTROL-ORDINARY-FILE\n', 'data', data_id),
    ('data-uuid', b'DATA-CONTROL-ORDINARY-FILE\n', 'data', data_id),
    ('changed-data-role', b'XATA-CONTROL-ORDINARY-FILE\n', 'data', data_id),
    ('changed-system-default', b'SYSTEM-CONTROL-ORDINARY-FILE\n', 'system', system_id),
]:
    folder = a.out / name
    report = json.loads((folder / 'export-report.json').read_text())
    prefix = 'private/var' if role == 'system' else ''
    data = (folder / prefix / 'db/diagnostics/probe.tracev3').read_bytes()
    assert data == expected and report['volume_role'] == role and report['volume_uuid'] == uuid
    assert report['files'] == 2
    record = next(r for r in report['records'] if r.get('size') == len(expected))
    assert record['guest_path'] == '/private/var/db/diagnostics/probe.tracev3'
    assert record['sha256'] == hashlib.sha256(expected).hexdigest()
    checks.append({'name': name, 'role': role, 'uuid': uuid, 'volume_path': record['path'],
                   'guest_path': record['guest_path'], 'exact_content_verified': True,
                   'report_sha256': digest(folder / 'export-report.json')})
assert digest(base) == source_hash
report = {'passed': True, 'qualification': 'Owned sparse host fixture only; no guest, fsck-clean, runtime Data mount, separate backing or daemon decoding qualification',
          'exporter_sha256': digest(a.exporter), 'fixture_builder_sha256': digest(a.fixture_builder),
          'fixture': {'source': str(base.resolve()), 'sha256': source_hash,
                      'bytes': base.stat().st_size, 'allocated_bytes': base.stat().st_blocks * 512,
                      'source_unchanged': True, 'two_distinct_role_UUID_namespaces': True},
          'content_and_namespace_checks': checks, 'CLI_cases': cases,
          'Data_page_overlay_leaves_System_unchanged': True}
(a.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'Passed {len(checks)} exact content/UUID/namespace checks and {len(cases)} CLI cases')
