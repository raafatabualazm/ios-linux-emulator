#!/usr/bin/env python3
"""Run T8140 DCS performance core gates on owned data; no firmware runs.

The AppleT8140MCC DCS descriptor table (39 slot-2 entries, dumped from the
pinned BootKC) is turned into a C header so the standalone core test replays
the driver's exact configure/enable/poll/disable register sequences with the
real descriptor constants. The core is compiled twice (ASan+UBSan, and the
production -DNDEBUG -O2 profile) and checked against every supplied ADT.
v3: plan_build rejects a present dcs-channel-enable-mask or
amcc-plane-enable-mask that is not exactly 0xf (or not 4 bytes); the test
builds those trees by renaming unvalidated /arm-io/mcc properties in copies.
v4: rejections are matched exactly ("DCS performance: MCC <name> has <n> bytes,
expected 4" before any value; "DCS performance: MCC <name>=<value> is not
modelled"). The v3 claimed-equivalent size mutant is now killed (the wrong-size
message is distinct), and mutants cover both message formats and the prefix.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

PRODUCTION = ['hw/arm/apple-silicon/modern-boot-layout.c',
              'hw/arm/apple-silicon/modern-boot-metadata.c',
              'hw/arm/apple-silicon/modern-mcc-dramcfg.c',
              'hw/arm/apple-silicon/modern-mcc-dcs-perf.c',
              'include/hw/arm/apple-silicon/modern-boot-layout.h',
              'include/hw/arm/apple-silicon/modern-boot-metadata.h',
              'include/hw/arm/apple-silicon/modern-mcc-dramcfg.h',
              'include/hw/arm/apple-silicon/modern-mcc-dcs-perf.h',
              'include/hw/arm/apple-silicon/modern-board-regions.h']
TESTS = ['test-apple-modern-mcc-dcs-perf.c', 'test-apple-modern-mcc-dcs-perf.py',
         'test-apple-modern-mcc-optional-props.h']
DEVICE = 'hw/arm/apple-silicon/modern-mcc-dcs-perf.c'
# Each mutant breaks one declared or attested behaviour; every one must fail.
MUTANTS = [
    ('clear-bits-read-back', '        word &= ~APPLE_MODERN_DCS_PERF_CLEAR_BITS;\n', ''),
    ('clear-wrong-counter', 'core->values[bank][APPLE_MODERN_DCS_PERF_EVENTS + i] = 0;',
     'core->values[bank][APPLE_MODERN_DCS_PERF_EVENTS + (i ^ 1)] = 0;'),
    ('clear-other-bank', 'core->values[bank][APPLE_MODERN_DCS_PERF_EVENTS + i] = 0;',
     'core->values[(bank + 1) % 3][APPLE_MODERN_DCS_PERF_EVENTS + i] = 0;'),
    ('clear-not-counted', '                increment(&core->clears);\n', ''),
    ('clear-at-any-offset', 'if (offset == APPLE_MODERN_DCS_PERF_DURATION_CONTROL) {',
     'if (offset <= APPLE_MODERN_DCS_PERF_DURATION_CONTROL) {'),
    ('counter-writes-accepted', '!valid_access(view, offset, size) || view % 2)',
     '!valid_access(view, offset, size))'),
    ('span-off-by-one', 'offset < view_span(view)', 'offset <= view_span(view)'),
    ('alignment-unchecked', '!(offset & (size - 1)) && ', ''),
    ('width-unchecked', 'size == view_width(view) &&',
     '(size == 4 || size == 8 || size == view_width(view)) &&'),
    ('view-bound', 'return view < APPLE_MODERN_DCS_PERF_VIEWS &&', 'return view <= APPLE_MODERN_DCS_PERF_VIEWS &&'),
    ('read-alias-unchecked', '!valid_access(view, offset, size) ||\n        aliases(core, sizeof(*core), value, sizeof(*value))',
     '!valid_access(view, offset, size)'),
    ('duration-gate-bit', ': 4 * (counter - APPLE_MODERN_DCS_PERF_EVENTS);',
     ': counter - APPLE_MODERN_DCS_PERF_EVENTS;'),
    ('event-gate-register', '(events ? APPLE_MODERN_DCS_PERF_EVENT_ENABLE :',
     '(events ? APPLE_MODERN_DCS_PERF_COMMAND :'),
    ('zero-amount-counted', 'if (amount && (enables & (1U << bit))) {', 'if (enables & (1U << bit)) {'),
    ('event-bank-bound', 'bank >= APPLE_MODERN_DCS_PERF_BANKS ||', 'bank > APPLE_MODERN_DCS_PERF_BANKS ||'),
    ('diagnostics-wrap', '    if (*value != UINT64_MAX) {\n        (*value)++;\n    }', '    (*value)++;'),
    ('reset-keeps-diagnostics', '    core->reads = core->writes = core->clears = core->event_updates = 0;\n', ''),
    ('reset-keeps-controls', '    memset(core->controls, 0, sizeof(core->controls));\n', ''),
    ('control-low-half-only', '    core->controls[bank][offset / 4] = word;',
     '    core->controls[bank][offset / 4] = word & 0xffff;'),
    ('plan-dram-unchecked', '        if (address < dram_base + dram_size && dram_base < address + span) {',
     '        if (0) {'),
    ('plan-exclusion-inclusive', 'exclusions[i].physical_address < address + span) {',
     'exclusions[i].physical_address <= address + span) {'),
    ('plan-wrong-counter-offset', '(view % 2 ? APPLE_MODERN_DCS_PERF_COUNTER_OFFSET :',
     '(view % 2 ? APPLE_MODERN_DCS_PERF_COUNTER_OFFSET + 8 :'),
    ('plan-empty-exclusion', 'if (!exclusions[i].size || exclusions[i].size >',
     'if (exclusions[i].size >'),
    ('plan-shifted-bank', 'geometry.addresses[view / 2] - APPLE_MODERN_MCC_DRAMCFG_OFFSET',
     'geometry.addresses[view / 2 + 1] - APPLE_MODERN_MCC_DRAMCFG_OFFSET'),
    ('reset-value-ignored', 'core->values[bank][i] = core->reset_value;',
     'core->values[bank][i] = 0;'),
    ('read-wrong-bank', 'core->values[view / 2][offset / 8]', 'core->values[0][offset / 8]'),
    ('plan-alias-unchecked', 'if (!output || aliases(output, sizeof(*output), tree.data, tree.size) ||',
     'if (!output ||'),
    # v3 optional-property guards (re-anchored on the v4 call sites).
    ('optional-dcs-mask-unchecked',
     '        !optional_property(tree, "DCS performance", "dcs-channel-enable-mask",\n'
     '                           0xf, true, errp) ||\n', ''),
    ('optional-amcc-mask-unchecked',
     ' ||\n        !optional_property(tree, "DCS performance", "amcc-plane-enable-mask",\n'
     '                           0xf, true, errp)) {', ') {'),
    ('optional-dcs-mask-limit', '"dcs-channel-enable-mask",\n                           0xf, true',
     '"dcs-channel-enable-mask",\n                           0x7, true'),
    ('optional-amcc-mask-not-exact', '"amcc-plane-enable-mask",\n                           0xf, true',
     '"amcc-plane-enable-mask",\n                           0xf, false'),
    ('optional-inexact', 'exact ? value != limit : value > limit',
     'exact ? value > limit : value > limit'),
    ('optional-absent-rejected', '        error_free(absent);\n        return true;',
     '        error_free(absent);\n        return false;'),
    ('optional-low-byte-only', 'for (size_t i = 0; i < 4; i++) {', 'for (size_t i = 0; i < 1; i++) {'),
    ('optional-big-endian', 'value |= (uint32_t)property.data[i] << (8 * i);',
     'value |= (uint32_t)property.data[i] << (8 * (3 - i));'),
    ('optional-other-node', 'apple_modern_adt_property(tree, "/arm-io/mcc", name, &property, &absent)',
     'apple_modern_adt_property(tree, "/arm-io/pmp", name, &property, &absent)'),
    # v4 message formats. The size test was a claimed-equivalent mutant in v3
    # (a short property decoded as 0); v4 reports sizes separately, so
    # removing it is now observable and must be killed.
    ('optional-size-unchecked', '    if (property.size != 4) {\n', '    if (0) {\n'),
    ('optional-size-8-accepted', 'if (property.size != 4) {',
     'if (property.size != 4 && property.size != 8) {'),
    ('optional-size-message-size', 'expected 4", device, name,\n                   property.size);',
     'expected 4", device, name,\n                   property.size + 1);'),
    ('optional-size-message-unprefixed', '"%s: MCC %s has %zu bytes, expected 4", device, name,',
     '"MCC %s has %zu bytes, expected 4", name,'),
    ('optional-value-message-unprefixed', '"%s: MCC %s=%#x is not modelled", device, name, value',
     '"MCC %s=%#x is not modelled", name, value'),
    ('optional-value-message-decimal', '"%s: MCC %s=%#x is not modelled"',
     '"%s: MCC %s=%u is not modelled"'),
    ('optional-dcs-mask-device-prefix', '"DCS performance", "dcs-channel-enable-mask"',
     '"MCC DSID", "dcs-channel-enable-mask"'),
    ('optional-amcc-mask-device-prefix', '"DCS performance", "amcc-plane-enable-mask"',
     '"MCC SLC", "amcc-plane-enable-mask"'),
]
# Mutants that must SURVIVE: they change no observable behaviour, and the run
# proves it (built, gate passes). v4: none. v3's 'optional-size-unchecked'
# claim (a short property decodes as 0, already != 0xf, same error text) no
# longer holds because the wrong-size message is distinct; it is a killed
# mutant above.
EQUIVALENT_MUTANTS = []
DEFAULT_DESCRIPTORS = ('modern-emulator/evidence/features-20261008/mcc-provider-review/'
                       'dcs-dsid-review/descriptors.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise SystemExit(message)


def descriptor_header(path):
    """Slot-2 descriptors as C data; raw desc words are the driver's fields."""
    entries = [item for item in json.loads(path.read_text()) if item['slot'] == 2]
    require(len(entries) == 39, 'Expected 39 DCS descriptors')
    rows = []
    for position, item in enumerate(entries):
        words = {int(key, 16): int(value, 16) for key, value in item['words'].items()}
        field = {'enable_reg': 0x20, 'enable': 0x28, 'request': 0x30, 'command_reg': 0x34,
                 'command_value': 0x38, 'select_reg': 0x40, 'select_mask': 0x44,
                 'select_value': 0x48, 'data_reg': 0x58, 'counter': 0x5c,
                 'param_count': 0x6c}
        row = {name: words[offset] & 0xffffffff for name, offset in field.items()}
        # The top-level JSON fields are a second decoding of the same words.
        for name, key in (('enable', 'enable_mask'), ('command_reg', 'command_offset'),
                          ('command_value', 'command_value'), ('select_reg', 'filter_offset'),
                          ('select_mask', 'filter_mask'), ('select_value', 'filter_value'),
                          ('data_reg', 'parameter_offset'), ('counter', 'counter_offset'),
                          ('param_count', 'parameter_words')):
            value = item[key]
            require((int(value, 16) if isinstance(value, str) else value) == row[name],
                    f'Descriptor {position} {key} disagrees with its raw word')
        require(item['index'] == position, 'Descriptor table order')
        params = [words[0x70 + 8 * i] & 0xffffffff for i in range(6)]
        rows.append('    {%u, %u, %u, %u, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, '
                    '0x%x, 0x%x, %u, {%s}}, /* %s */' % (
                        position, item['kind'], item['bank'], item['channel'],
                        row['enable_reg'], row['enable'], row['request'], row['command_reg'],
                        row['command_value'], row['select_reg'], row['select_mask'],
                        row['select_value'], row['data_reg'], row['counter'],
                        row['param_count'], ', '.join('0x%x' % v for v in params),
                        item['name'].replace('*/', '')))
    return '\n'.join([
        '/* Generated from %s (sha256 %s); do not edit. */' % (path.name, digest(path)),
        '#include <stdbool.h>', '#include <stdint.h>',
        'typedef struct DCSDescriptor {',
        '    unsigned index, kind, bank, channel;',
        '    uint32_t enable_reg, enable, request, command_reg, command_value;',
        '    uint32_t select_reg, select_mask, select_value, data_reg, counter;',
        '    unsigned param_count;', '    uint32_t params[6];', '} DCSDescriptor;',
        '#define DCS_DESCRIPTOR_COUNT %u' % len(rows),
        'static const DCSDescriptor dcs_descriptors[DCS_DESCRIPTOR_COUNT] = {',
        *rows, '};', ''])


def build_and_run(root, script_dir, temp, mode, flags, trees, device=None):
    binary = Path(temp) / mode
    sources = [str(root / name) for name in PRODUCTION if name.endswith('.c')]
    if device is not None:
        sources[sources.index(str(root / DEVICE))] = str(device)
    command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-DAPPLE_MODERN_LAYOUT_STANDALONE', '-I' + temp, '-I' + str(root / 'include'),
               *flags, *sources, str(script_dir / TESTS[0]), '-o', str(binary)]
    built = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if built.returncode:
        return {'mode': mode, 'built': False, 'exit': None,
                'stdout': built.stdout, 'stderr': built.stderr[-4000:]}
    executed = subprocess.run([str(binary), *map(str, trees)], capture_output=True,
                              text=True, timeout=300,
                              env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1',
                                       UBSAN_OPTIONS='halt_on_error=1'))
    return {'mode': mode, 'built': True, 'flags': flags, 'exit': executed.returncode,
            'stdout': executed.stdout, 'stderr': executed.stderr[-4000:]}


MODES = [('sanitizers', ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                         '-fno-omit-frame-pointer', '-g']),
         ('production-ndebug', ['-DNDEBUG', '-O2'])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dtree', type=Path, action='append', required=True,
                        help='matched T8140 ADT; repeat to check several trees')
    parser.add_argument('--descriptors', type=Path)
    parser.add_argument('--source-root', type=Path,
                        help='tree holding hw/ and include/ (default: this checkout)')
    parser.add_argument('--mutants', action='store_true',
                        help='also require every listed device mutant to fail the gate')
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    script_dir = Path(__file__).resolve().parent
    root = (args.source_root or script_dir.parent).resolve()
    workspace = next(parent for parent in script_dir.parents
                     if (parent / 'modern-emulator' / 'evidence').is_dir())
    descriptors = (args.descriptors or workspace / DEFAULT_DESCRIPTORS).resolve()
    trees = [tree.resolve() for tree in args.dtree]

    def snapshot():
        return ({name: digest(root / name) for name in PRODUCTION} |
                {'scripts/' + name: digest(script_dir / name) for name in TESTS} |
                {str(path): digest(path) for path in [descriptors, *trees]})

    before = snapshot()
    pinned = workspace / 'modern-emulator/evidence/features-20261008/mcc-dcs-perf/source-v4'
    pin_match = {name: digest(pinned / Path(name).name) == before[name]
                 for name in PRODUCTION if 'dcs-perf' in name}
    runs, mutants, equivalent = [], [], []
    with tempfile.TemporaryDirectory(prefix='modern-mcc-dcs-perf-core-') as temp:
        header = Path(temp) / 'dcs-perf-descriptors.h'
        header.write_text(descriptor_header(descriptors))
        for mode, flags in MODES:
            run = build_and_run(root, script_dir, temp, mode, flags, trees)
            runs.append(run)
            if not run['built'] or run['exit']:
                raise SystemExit(json.dumps(run, indent=2))
        header_sha256 = digest(header)
        if args.mutants:
            original = (root / DEVICE).read_text()
            for name, old, new in MUTANTS:
                require(original.count(old) == 1, 'Mutant anchor is unique: ' + name)
                mutated = Path(temp) / 'modern-mcc-dcs-perf.c'
                mutated.write_text(original.replace(old, new))
                run = build_and_run(root, script_dir, temp, 'mutant', MODES[0][1], trees,
                                    mutated)
                failure = (run['stderr'] or run['stdout']).strip().splitlines()
                # A mutant only counts when it compiles and the gate itself fails.
                mutants.append({'mutant': name, 'built': run['built'], 'exit': run['exit'],
                                'rejected': run['built'] and run['exit'] != 0,
                                'first_failure': next((line for line in failure
                                                       if 'FAIL' in line or 'ERROR' in line
                                                       or 'error' in line),
                                                      failure[0] if failure else '')})
                mutated.unlink()
            require(all(item['rejected'] for item in mutants),
                    'Surviving mutant(s): ' + ', '.join(item['mutant'] for item in mutants
                                                       if not item['rejected']))
            for name, old, new in EQUIVALENT_MUTANTS:
                require(original.count(old) == 1, 'Mutant anchor is unique: ' + name)
                mutated = Path(temp) / 'modern-mcc-dcs-perf.c'
                mutated.write_text(original.replace(old, new))
                run = build_and_run(root, script_dir, temp, 'equivalent', MODES[0][1], trees,
                                    mutated)
                equivalent.append({'mutant': name, 'built': run['built'], 'exit': run['exit'],
                                   'survived_as_claimed': run['built'] and run['exit'] == 0})
                mutated.unlink()
            require(all(item['survived_as_claimed'] for item in equivalent),
                    'Claimed-equivalent mutant was killed or failed to build')
    results = [json.loads(run['stdout']) for run in runs]
    require(all(result['passed'] for result in results) and
            results[0]['checks'] == results[1]['checks'] and
            all(result['trees'] == len(trees) for result in results),
            'Both builds pass the same number of checks on every tree')
    require(before == snapshot(), 'Inputs changed during qualification')
    require(len({(result['optional_property_accepts'], result['optional_property_rejects'],
                  result['optional_property_size_rejects']) for result in results}) == 1,
            'Same optional-property oracle on every build')
    report = {'passed': True, 'checks_per_build': results[0]['checks'],
              'optional_property_accepts': results[0]['optional_property_accepts'],
              'optional_property_rejects': results[0]['optional_property_rejects'],
              'optional_property_size_rejects': results[0]['optional_property_size_rejects'],
              'max_exclusions_compiled': results[0]['max_exclusions'],
              'source_root': str(root), 'script_dir': str(script_dir),
              'sha256': before, 'device_sources_match_pinned_source_v4': pin_match,
              'runs': runs, 'dtrees': {str(tree): before[str(tree)] for tree in trees},
              'descriptors': str(descriptors), 'descriptors_sha256': before[str(descriptors)],
              'generated_descriptor_header_sha256': header_sha256,
              'mutation_oracle': {'mutants': len(mutants),
                                  'rejected': sum(item['rejected'] for item in mutants),
                                  'results': mutants,
                                  'equivalent_mutants_surviving_as_claimed': equivalent}
                                 if args.mutants else None,
              'firmware_executed': False, 'qemu_mmio_wrapper_exercised': False,
              'scope': ('T8140 DCS performance core: reset, driver configure/enable/'
                        'clear-poll/disable replay with the 39 BootKC descriptors, '
                        'declared clear/injection profile, rejected accesses, saturating '
                        'diagnostics, the matched sparse DCS0-2 layout (DCS3 unmapped) and '
                        'the optional dcs-channel-enable-mask / amcc-plane-enable-mask guards '
                        '(exact 0xf, size 4) on renamed-property tree copies, with the exact v4 '
                        'wrong-size and unmodelled-value messages'),
              'declared_not_attested': ['clear bits zero their duration counter',
                                        'clear bits complete at once',
                                        'virtual reset value of counters',
                                        'event injection gating (no producer connected)',
                                        'modulo-2^64 accumulation',
                                        'controls store all 32 bits']}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        with (args.evidence / 'core-result.json').open('x') as fp:
            json.dump(report, fp, indent=2)
            fp.write('\n')
    print(json.dumps({key: report[key] for key in ('passed', 'checks_per_build',
                                                   'max_exclusions_compiled', 'dtrees',
                                                   'firmware_executed')} |
                     {'mutants_rejected': report['mutation_oracle'] and
                      [report['mutation_oracle']['rejected'],
                       report['mutation_oracle']['mutants']]}, indent=2))


if __name__ == '__main__':
    main()
