#!/usr/bin/env python3
"""Prove the owned-ROM transport gate rejects an incorrect PING reply.

Read the exact existing compile/link metadata, build a private single-object
mutant, and run the unchanged transport gate. Production source, build inputs
and immutable executable remain unchanged. No firmware/crypto operation runs.
"""
import argparse
import hashlib
import json
import resource
import shlex
import subprocess
import sys
import time
from pathlib import Path


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
    resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))


def command(argv, cwd, output, label, seconds, build=False):
    with (output / (label + '.stdout')).open('xb') as out, \
         (output / (label + '.stderr')).open('xb') as err:
        result = subprocess.run(argv, cwd=cwd, stdout=out, stderr=err,
                                timeout=seconds,
                                preexec_fn=build_limits if build else None)
    require(all((output / (label + suffix)).stat().st_size < 1 << 20
                for suffix in ('.stdout', '.stderr')), label + ' log bound')
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    binary = args.binary.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    gate = Path(__file__).with_name('test-apple-modern-sep-transport-qemu.py')
    started = time.monotonic()
    report = {'passed': False, 'scope': 'Harmless PING reply mutation oracle',
              'firmware_executed': False, 'cryptographic_operation_sent': False,
              'build_inputs_mutated': False, 'build_dir': str(build),
              'limits': {'compile_seconds': 30, 'link_seconds': 60,
                         'gate_seconds_each': 60, 'log_bytes_each': 1 << 20},
              'script_sha256': digest(Path(__file__))}
    inputs = {}
    source = None
    try:
        report['binary_sha256'] = digest(binary)
        require(digest(build / 'qemu-system-aarch64') == report['binary_sha256'],
                'Existing build executable must match immutable pin')
        database = json.loads((build / 'compile_commands.json').read_text())
        entries = [item for item in database
                   if item['file'] == '../hw/arm/apple-silicon/sep-sim.c']
        require(len(entries) == 1, 'Exactly one SEP compile command')
        entry = entries[0]
        require(Path(entry['directory']).resolve() == build,
                'Compile command belongs to requested build')
        source = (build / entry['file']).resolve()
        report['source_sha256_before'] = digest(source)
        original = source.read_bytes()
        token = b'BOOTSTRAP_OP_PING_ACK, 0, 0);'
        require(original.count(token) == 1, 'Unique harmless PING ACK site')
        (output / 'sep-sim.original.c').write_bytes(original)
        mutant_source = output / 'sep-sim.ping-mutant.c'
        mutant_source.write_bytes(original.replace(
            token, b'BOOTSTRAP_OP_PING_ACK, 0, 1);', 1))
        report['mutation'] = {'site': 'BOOTSTRAP_OP_PING_ACK',
                              'field': 'data', 'before': 0, 'after': 1,
                              'source_sha256': digest(mutant_source)}
        mutant_object = output / 'sep-sim.ping-mutant.o'
        original_compile = shlex.split(entry['command'])
        compile_argv = []
        index = 0
        while index < len(original_compile):
            item = original_compile[index]
            if item in ('-MF', '-MQ', '-MT'):
                index += 2
                continue
            if item in ('-MD', '-MMD'):
                index += 1
                continue
            if item == '-o':
                compile_argv.extend(('-o', str(mutant_object)))
                index += 2
                continue
            compile_argv.append(str(mutant_source) if item == entry['file']
                                else item)
            index += 1
        compile_argv.extend(('-I' + str(source.parent),))
        require(str(mutant_source) in compile_argv and
                str(mutant_object) in compile_argv,
                'Mutant compile writes only private outputs')
        expanded = subprocess.run(['ninja', '-C', str(build), '-t', 'compdb', '-x'],
                                  check=True, capture_output=True, text=True,
                                  timeout=15)
        links = [item for item in json.loads(expanded.stdout)
                 if item.get('output') == 'qemu-system-aarch64']
        require(len(links) == 1, 'Exactly one expanded QEMU link command')
        original_link = shlex.split(links[0]['command'])
        require(original_link.count(entry['output']) == 1,
                'Only one SEP object replaced in exact link command')
        mutant_binary = output / 'qemu-ping-mutant'
        link_argv = [str(mutant_object) if item == entry['output'] else item
                     for item in original_link]
        output_index = link_argv.index('-o') + 1
        require(link_argv[output_index] == 'qemu-system-aarch64',
                'Expected original executable output')
        link_argv[output_index] = str(mutant_binary)
        for item in original_link[1:]:
            path = (build / item).resolve()
            if item != 'qemu-system-aarch64' and path.is_file():
                inputs[str(path)] = digest(path)
        require(str((build / entry['output']).resolve()) in inputs,
                'Original SEP object retained and hashed')
        report['compile_argv'] = compile_argv
        report['link_argv'] = link_argv
        report['link_input_hashes_before'] = inputs
        require(command(compile_argv, build, output, 'compile', 30, True) == 0,
                'Private mutant compile succeeds')
        require(command(link_argv, build, output, 'link', 60, True) == 0,
                'Private mutant link succeeds')
        report['mutant_binary_sha256'] = digest(mutant_binary)
        gate_argv = [sys.executable, '-B', str(gate), '--components',
                     str(args.components.resolve())]
        report['gate_sha256'] = digest(gate)
        baseline_dir = output / 'baseline'
        baseline = gate_argv + ['--binary', str(binary), '--output-dir',
                                str(baseline_dir)]
        report['baseline_argv'] = baseline
        require(command(baseline, build, output, 'baseline', 60) == 0,
                'Unmodified immutable pin passes transport gate')
        baseline_result = json.loads((baseline_dir / 'report.json').read_text())
        require(baseline_result['passed'] and len(baseline_result['passes']) == 2,
                'Baseline executes twice across reset')
        mutant_dir = output / 'mutant'
        mutant = gate_argv + ['--binary', str(mutant_binary), '--output-dir',
                              str(mutant_dir)]
        report['mutant_argv'] = mutant
        code = command(mutant, build, output, 'mutant', 60)
        mutant_result = json.loads((mutant_dir / 'report.json').read_text())
        require(code == 1 and not mutant_result['passed'],
                'Wrong reply must fail the unchanged gate')
        require(mutant_result.get('error', '').startswith('ping_message: expected '),
                'Failure must be the actual PING reply mismatch')
        require(len(mutant_result.get('readonly_rejections', {})) == 14,
                'All original diagnostic properties present and read-only')
        require(not baseline_result['firmware_executed'] and
                not mutant_result['firmware_executed'], 'Only owned ROM executed')
        report['baseline_passes'] = 2
        report['mutant_gate_exit'] = code
        report['mutant_rejection'] = mutant_result['error']
        report['mutant_diagnostics_present'] = True
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
    finally:
        if source is not None:
            report['source_sha256_after'] = digest(source)
            if report['source_sha256_after'] != report['source_sha256_before']:
                report['passed'] = False
                report['error'] = 'Production SEP source changed'
        if inputs:
            after = {name: digest(Path(name)) for name in inputs}
            report['link_input_hashes_after'] = after
            if after != inputs:
                report['passed'] = False
                report['error'] = 'Original build linker inputs changed'
        if binary.is_file() and report.get('binary_sha256') != digest(binary):
            report['passed'] = False
            report['error'] = 'Immutable emulator pin changed'
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in
                      ('passed', 'baseline_passes', 'mutant_rejection', 'error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
