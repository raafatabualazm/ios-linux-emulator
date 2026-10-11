#!/usr/bin/env python3
"""Export a finished qualified root capture; decode only actual tracev3 files."""
import argparse
import collections
import hashlib
import json
import os
import pathlib
import resource
import subprocess
import time

EXPORT_SHA = '1fd6ef5c729a5e93ebfcbc97044e19a75bc6d1e7fe1ec160d7b5ce95c91b7d32'
DECODER_SHA = 'e43dff279d16c96a00b6de0c16a2385bb287f3d6ae257852d6f216f0c907bf8c'

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def bounded_decoder():
    # Applies only to the analysis decoder child, never QEMU, capture or Go export.
    resource.setrlimit(resource.RLIMIT_AS, (4_000_000_000, 4_000_000_000))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--run', type=pathlib.Path, required=True)
p.add_argument('--out', type=pathlib.Path, required=True)
p.add_argument('--exporter', type=pathlib.Path, required=True)
p.add_argument('--decoder', type=pathlib.Path, required=True)
p.add_argument('--wait-seconds', type=int, default=0)
a = p.parse_args()
os.umask(0o077)
if a.wait_seconds < 0:
    p.error('nonnegative wait required')
deadline = time.monotonic() + a.wait_seconds
while not (a.run / 'result.json').exists():
    if time.monotonic() >= deadline:
        raise SystemExit('owned teardown result not available')
    time.sleep(min(30, max(0.1, deadline-time.monotonic())))
result = json.loads((a.run / 'result.json').read_text())
if result.get('capture_returncode') != 0 or result.get('inputs_unchanged') is not True:
    raise SystemExit('capture or source-immutability qualification failed')
manifest = a.run / 'snapshot/manifest.json'
m = json.loads(manifest.read_text())
if m['pid'] != result['qemu_pid']:
    raise SystemExit('capture/run PID mismatch')
if digest(a.exporter) != EXPORT_SHA:
    raise SystemExit('exporter differs from qualified pin')
a.out.mkdir(parents=True, exist_ok=False, mode=0o700)
report = {'run': str(a.run), 'run_result_sha256': digest(a.run/'result.json'),
          'manifest_sha256': digest(manifest), 'source_sha256': m['source_sha256'],
          'exporter_sha256': EXPORT_SHA, 'decoder_invoked': False,
          'filesystem_consistency': 'paused/crash-consistent; not fsck-clean'}
try:
    export = a.out / 'export'
    with (a.out / 'export.log').open('wb') as f:
        subprocess.run([str(a.exporter.resolve()), '--manifest', str(manifest.resolve()),
                        '--out', str(export.resolve())], stdout=f, stderr=subprocess.STDOUT,
                       check=True, timeout=1200)
    er = json.loads((export/'export-report.json').read_text())
    report['export'] = er
    traces = [r for r in er['records'] if r.get('size') is not None and r['path'].endswith('.tracev3')]
    report['tracev3_files'] = len(traces)
    if not traces:
        report['reason'] = 'No actual tracev3 exported; decoder not invoked'
    else:
        if digest(a.decoder) != DECODER_SHA:
            raise RuntimeError('decoder differs from pinned official release')
        archive = a.out/'archive'; archive.mkdir(mode=0o700)
        for r in er['records']:
            if 'sha256' not in r:
                continue
            source = export / r['path'].lstrip('/')
            if digest(source) != r['sha256']:
                raise RuntimeError('exported-file digest changed')
            parts = pathlib.PurePosixPath(r['path']).parts
            if parts[:5] not in [('/', 'private', 'var', 'db', 'diagnostics'),
                                ('/', 'private', 'var', 'db', 'uuidtext')]:
                raise RuntimeError('unexpected archive path')
            target = archive.joinpath(*parts[5:]); target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if target.exists():
                if digest(target) != r['sha256']:
                    raise RuntimeError('archive filename collision')
            else:
                os.link(source, target)  # Reuse exported bytes; no second materialized copy.
        decoded = a.out/'decoded.jsonl'
        with (a.out/'decoder.log').open('wb') as f:
            report['decoder_invoked'] = True
            report['decoder_sha256'] = DECODER_SHA
            command = [str(a.decoder.resolve()), '--mode', 'log-archive', '--input', str(archive.resolve()),
                       '--format', 'jsonl', '--output', str(decoded.resolve())]
            completed = subprocess.run(command, stdout=f, stderr=subprocess.STDOUT,
                                       timeout=600, preexec_fn=bounded_decoder)
            report['decoder_returncode'] = completed.returncode
        counts = collections.Counter(); records = 0; candidates = []
        if decoded.exists():
            with decoded.open() as f:
                for line in f:
                    entry = json.loads(line); records += 1
                    counts[str(entry.get('process', ''))] += 1
                    message = entry.get('message', '')
                    if any(marker in message for marker in ('accelerated backing', 'Skip Display TM',
                                                            'update_surface for IOSurface')):
                        if len(candidates) < 200:
                            candidates.append({k: entry.get(k) for k in ('pid', 'euid', 'process', 'process_uuid',
                                'boot_uuid', 'timestamp', 'library', 'subsystem', 'event_type', 'log_type', 'message', 'evidence')})
            report['decoded_sha256'] = digest(decoded)
        report.update(decoded_records=records, process_counts=dict(counts), ca_candidate_records=candidates,
                      decode_qualification='Parsed records only; retain warnings and partial/missing-message limitations',
                      credential_qualification='Simpledump EUID zero and missing-catalog zero are placeholders; require catalog/process provenance for UID claims')
        if completed.returncode != 0:
            report['error'] = 'decoder failed; any retained records are partial and unqualified'
except Exception as e:
    report['error'] = str(e)
finally:
    (a.out/'observer-report.json').write_text(json.dumps(report, indent=2)+'\n')
if 'error' in report:
    raise SystemExit(report['error'])
print(json.dumps({k: v for k, v in report.items() if k not in ('export', 'ca_candidate_records', 'process_counts')}))
