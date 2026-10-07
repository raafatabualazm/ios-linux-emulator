#!/usr/bin/env python3
"""Link and run an owned-data DMA fixture against existing QEMU build objects.

No build is started and no build object is changed. The main.c compile command
and exact response-expanded QEMU link command are read from the build metadata.
Only the main object and output path are replaced. The fixture initializes the
real QEMU object model and tests the DART's actual IOMMU/AddressSpace DMA path.
The supplied immutable emulator pin must match the current built executable.
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
        return {'bytes': path.stat().st_size,
                'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
    resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))


def run_command(argv, cwd, output, label, seconds):
    stdout = output / (label + '.stdout')
    stderr = output / (label + '.stderr')
    with stdout.open('xb') as out, stderr.open('xb') as err:
        result = subprocess.run(argv, cwd=cwd, stdout=out, stderr=err,
                                timeout=seconds, preexec_fn=limits)
    require(stdout.stat().st_size < 1 << 20 and stderr.stat().st_size < 1 << 20,
            label + ' output remains bounded')
    require(result.returncode == 0,
            f'{label} exited {result.returncode}; see {stderr}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    binary = args.binary.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    source = Path(__file__).with_suffix('.c').resolve()
    report = {'scope': 'Actual QEMU DART IOMMU/AddressSpace DMA on owned RAM',
              'passed': False, 'firmware_executed': False, 'guest_executed': False,
              'emulator_build_mutated': False, 'build_dir': str(build),
              'binary': str(binary), 'fixture_source': str(source),
              'limits': {'compile_seconds': 30, 'link_seconds': 60,
                         'fixture_seconds': 30, 'output_bytes_per_stream': 1 << 20}}
    inputs = {}
    try:
        require(binary.is_file() and source.is_file(), 'Pinned binary and owned fixture exist')
        report['binary_digest'] = digest(binary)
        report['fixture_source_digest'] = digest(source)
        report['script_digest'] = digest(Path(__file__))
        source_snapshot = output / 'fixture.c'
        source_snapshot.write_bytes(source.read_bytes())
        report['fixture_source_snapshot'] = str(source_snapshot)
        require(digest(source_snapshot) == report['fixture_source_digest'],
                'Exact fixture source snapshot is preserved')
        built = build / 'qemu-system-aarch64'
        require(digest(built) == report['binary_digest'],
                'Current build executable matches the immutable emulator pin')
        compile_db = json.loads((build / 'compile_commands.json').read_text())
        entries = [entry for entry in compile_db
                   if entry['file'] == '../system/main.c']
        require(len(entries) == 1, 'Exactly one system/main.c compile command exists')
        entry = entries[0]
        require(Path(entry['directory']).resolve() == build,
                'Compile command belongs to the requested build')
        original_compile = shlex.split(entry['command'])
        fixture_object = output / 'owned-dart-dma.o'
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
                compile_argv.extend(('-o', str(fixture_object)))
                index += 2
                continue
            compile_argv.append(str(source_snapshot) if item == entry['file'] else item)
            index += 1
        require(str(source_snapshot) in compile_argv and str(fixture_object) in compile_argv,
                'Only fixture source/object replace the original compile outputs')

        compdb = subprocess.run(['ninja', '-C', str(build), '-t', 'compdb', '-x'],
                                check=True, capture_output=True, text=True, timeout=15)
        links = [item for item in json.loads(compdb.stdout)
                 if item.get('output') == 'qemu-system-aarch64']
        require(len(links) == 1, 'Exactly one response-expanded emulator link command exists')
        original_link = shlex.split(links[0]['command'])
        require(original_link.count(entry['output']) == 1,
                'Original main object appears exactly once in the real link command')
        fixture_binary = output / 'owned-dart-dma'
        link_argv = [str(fixture_object) if item == entry['output'] else item
                     for item in original_link]
        output_index = link_argv.index('-o') + 1
        require(link_argv[output_index] == 'qemu-system-aarch64',
                'Link output is the requested emulator target')
        link_argv[output_index] = str(fixture_binary)
        report['original_main_object'] = entry['output']
        report['compile_argv'] = compile_argv
        report['link_argv'] = link_argv
        for item in original_link[1:]:
            path = (build / item).resolve()
            if item != 'qemu-system-aarch64' and path.is_file():
                inputs[str(path)] = digest(path)
        require(any('dart-t8110' in path for path in inputs),
                'Real DART object is included in the fixture link')
        report['link_input_hashes_before'] = inputs
        run_command(compile_argv, build, output, 'compile', 30)
        run_command(link_argv, build, output, 'link', 60)
        report['fixture_binary_digest'] = digest(fixture_binary)
        run_command([str(fixture_binary)], build, output, 'fixture', 30)
        result = json.loads((output / 'fixture.stdout').read_text())
        require(result.get('passed') is True and result.get('checks', 0) >= 50,
                'Owned fixture reports completed actual DMA/lifecycle checks')
        require(result.get('firmware_executed') is False and
                result.get('guest_executed') is False,
                'The fixture executes no firmware or guest code')
        report['fixture'] = result
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
    finally:
        if inputs:
            after = {path: digest(Path(path)) for path in inputs}
            report['link_input_hashes_after'] = after
            if after != inputs:
                report['passed'] = False
                report['error'] = 'Existing build linker inputs changed during qualification'
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'passed': report['passed'], 'fixture': report.get('fixture'),
                      'error': report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
