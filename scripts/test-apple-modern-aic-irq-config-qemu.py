#!/usr/bin/env python3
"""Actual-CPU gate for the aic-record-irq-config board option (owned ROM).

An owned ROM at EL2 drives the modern AIC the way the BootKC's
AppleInterruptControllerV3 would on a tree that carries aic-ext-intr-cfg:
it stores nonzero IRQ_CFG words, reads them back, performs the driver's
read-modify-write (keep bits [31:8], replace bits [7:0]), then raises an
interrupt whose recorded target is a CPU this one-CPU board does not have.
The gate checks that the store completes, the word reads back exactly, the
interrupt is still taken by CPU0 and acknowledged, and that a system reset
returns every word to zero (two passes).

Negative oracles:
  * default board (option off): the first nonzero store takes a synchronous
    external abort; the ROM records ESR_EL2 and never reaches completion;
  * option on without modern-aic: clean startup refusal;
  * the option is creation-only (qom-set is refused);
  * run the same command with the previous pin and the option is unknown.

The ROM owns its range and firmware code is never executed (the board stays
preparation-only). Run under the shared QEMU lock.
"""
import argparse
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


delivery = module('aic_delivery_gate', 'test-apple-modern-aic-qemu.py')
board = delivery.board
require = delivery.require

BASE, SCRATCH = delivery.BASE, delivery.SCRATCH
AIC_BASE, GLBCFG = delivery.AIC_BASE, delivery.GLBCFG
IRQ_CONFIG = delivery.IRQ_CONFIG
MASK_CLEAR, SW_SET, SW_CLEAR = delivery.MASK_CLEAR, delivery.SW_SET, delivery.SW_CLEAR
EVENT, EVENT_IRQ = delivery.EVENT, delivery.EVENT_IRQ
TEST_IRQ = delivery.TEST_IRQ              # 42; recorded target 5, a CPU this board lacks
MAX_WALL = 60
FAULT_COUNT, FAULT_ESR = 0x500, 0x508

# Values the ROM stores (declared expectations, independent of the model code).
ROUTE_42 = 0x00000005                     # target 5, delay index 0
SEED_1092 = 0xabcdef00                    # upper bits that the driver must preserve
ENTRY_1092 = 0xa3                         # the aic-ext-intr-cfg byte: delay 5, target 3
LAST_IRQ, ROUTE_LAST = 4095, 0xffffffff   # every bit, last word of the window


def cfg(irq):
    return IRQ_CONFIG + irq * 4


class ConfigROM(delivery.ROM):
    def alu(self, opcode, rd, rn, rm):
        self.emit(opcode | (rm << 16) | (rn << 5) | rd)

    def build(self):
        word, bit = TEST_IRQ // 32 * 4, 1 << (TEST_IRQ & 31)
        self.mov(20, SCRATCH)
        self.mov(21, 0)                        # interrupts taken
        self.mov(22, 0)                        # acknowledged event value
        self.mov(24, 0)                        # unexpected exceptions
        self.mov(0, delivery.NORMAL_SP)
        self.emit(0x9100001f)                  # mov sp,x0
        self.set('HCR_EL2', (1 << 31) | (1 << 34) | (1 << 4))
        self.set('VBAR_EL2', BASE + 0x4000)

        # A reset leaves every recorded word at zero (second pass proves it).
        self.mmio_read(cfg(TEST_IRQ), 2)
        self.trace('reset_value_42', 0, register=2)
        self.mmio_read(cfg(1092), 2)
        self.trace('reset_value_1092', 0, register=2)

        # Plain nonzero store, then readback: the original model aborted here.
        self.mmio_write(cfg(TEST_IRQ), ROUTE_42)
        self.mmio_read(cfg(TEST_IRQ), 2)
        self.trace('readback_42', ROUTE_42, register=2)

        # The driver's read-modify-write at irq 1092 (attested behaviour).
        self.mmio_write(cfg(1092), SEED_1092)
        self.mov(1, AIC_BASE + cfg(1092))
        self.emit(0xb9400000 | (1 << 5) | 2)   # ldr w2,[x1]
        self.mov(3, 0xffffff00)
        self.alu(0x0a000000, 2, 2, 3)          # and w2,w2,w3
        self.mov(4, ENTRY_1092)
        self.alu(0x2a000000, 2, 2, 4)          # orr w2,w2,w4
        self.emit(0xb9000000 | (1 << 5) | 2)   # str w2,[x1]
        self.mmio_read(cfg(1092), 2)
        self.trace('rmw_1092', (SEED_1092 & 0xffffff00) | ENTRY_1092, register=2)

        # Last word of the window stores all bits; its neighbour (SW_SET word 0)
        # is a different register and is untouched.
        self.mmio_write(cfg(LAST_IRQ), ROUTE_LAST)
        self.mmio_read(cfg(LAST_IRQ), 2)
        self.trace('readback_last', ROUTE_LAST, register=2)
        self.mmio_read(SW_SET, 2)
        self.trace('sw_set_bank_untouched', 0, register=2)

        # Delivery still goes to CPU0 for an interrupt whose target is CPU5.
        self.mmio_write(GLBCFG, 1)
        self.trace('enabled_no_interrupt', 0, register=21)
        self.mmio_write(MASK_CLEAR + word, bit)
        self.mmio_write(SW_SET + word, bit)
        self.emit(0xd50342ff)                  # msr daifclr,#2
        self.await_count(1)
        self.emit(0xd503425f)                  # msr daifset,#2
        self.trace('delivered_count', 1, register=21)
        self.trace('acknowledged_event', EVENT_IRQ | TEST_IRQ, register=22)
        self.mmio_read(cfg(TEST_IRQ), 2)
        self.trace('route_kept_after_ack', ROUTE_42, register=2)
        self.mmio_write(SW_CLEAR + word, bit)

        self.mov(0, 0xfeedfacecafebeef)
        self.trace('completion', 0xfeedfacecafebeef)
        terminal = len(self.words)
        self.branch(terminal)

        def fault(offset, record):
            self.at(offset)
            if record:
                self.emit(delivery.sysreg('ESR_EL2', 25, True))   # mrs x25,esr_el2
                self.store(25, FAULT_ESR)
            self.emit(0x91000718)              # add x24,x24,#1
            self.store(24, FAULT_COUNT)
            self.emit(0x14000000)              # b .

        for offset in (0x4000, 0x4080, 0x4100, 0x4180):
            fault(offset, False)
        fault(0x4200, True)                    # synchronous, current EL, SP_ELx
        self.at(0x4280)
        self.mmio_read(EVENT, 22)
        self.emit(0x910006b5)                  # add x21,x21,#1
        self.emit(0xd69f03e0)                  # eret
        for offset in (0x4300, 0x4380):
            fault(offset, False)
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < FAULT_COUNT,
                'Owned ROM and scratch ranges remain separate')
        return b''.join(struct.pack('<I', w) for w in self.words)


def start(binary, components, extra, rom_path, scratch_log, started, extra_args=()):
    asset_paths = {name: components / name for name in board.ASSETS}
    machine = 'apple-modern,' + ','.join(
        name + '=' + str(asset_paths[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true,boot-command-line=' + board.COMMAND_LINE + extra
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1', '-nodefaults',
            '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rom_path},addr={BASE},cpu-num=0,force-raw=true',
            '-S', '-qmp', 'stdio', *extra_args]
    with scratch_log.open('xb') as log:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=log, bufsize=0, preexec_fn=delivery.child_limits)

    def guard():
        remaining = MAX_WALL - (time.monotonic() - started)
        require(remaining > 0 and scratch_log.stat().st_size <= delivery.MAX_LOG,
                'gate wall/log bound exceeded')
        return remaining

    return process, board.QMP(None, guard, process), argv, guard


def read_scratch(qmp, scratch, size, offset=0):
    dump = scratch / 'scratch.bin'
    qmp.request('pmemsave', {'val': SCRATCH + offset, 'size': size, 'filename': str(dump)})
    data = dump.read_bytes()
    dump.unlink()
    return data


def wait_pc(qmp, expected):
    deadline = time.monotonic() + 3
    while True:
        values = board.parse_registers(qmp.request(
            'human-monitor-command', {'command-line': 'info registers'}))
        if values['PC'] == expected:
            return values
        require(time.monotonic() < deadline, 'Loader did not select owned PC')
        time.sleep(0.02)


def run_to_completion(qmp, scratch, rom, guard):
    qmp.request('cont')
    deadline = time.monotonic() + 10
    while True:
        guard()
        qmp.request('stop')
        raw = read_scratch(qmp, scratch, len(rom.expected) * 8)
        if struct.unpack_from('<Q', raw, (len(rom.expected) - 1) * 8)[0] == 0xfeedfacecafebeef:
            return raw
        require(time.monotonic() < deadline, 'Owned ROM did not complete')
        qmp.request('cont')
        time.sleep(0.05)


def run_case(binary, components, output, label, extra, expect_fault, passes,
             qemu_args=()):
    started = time.monotonic()
    rom = ConfigROM()
    content = rom.build()
    rom_path = output / f'{label}.rom'
    rom_path.write_bytes(content)
    log_path = output / f'{label}-emulator.log'
    result = {'label': label, 'extra': extra, 'rom_sha256': delivery.digest(rom_path)['sha256'],
              'passes': [], 'expect_fault': expect_fault}
    process = qmp = None
    try:
        with tempfile.TemporaryDirectory(prefix='aic-cfg-gate-') as temporary:
            scratch = Path(temporary)
            process, qmp, argv, guard = start(binary, components, extra, rom_path,
                                              log_path, started, qemu_args)
            result['argv'] = argv
            require(qmp.request('qom-get', {'path': '/machine', 'property': 'prepare-only'}) is True,
                    'Board remains preparation-only')
            result['option'] = qmp.request('qom-get', {'path': '/machine',
                                                       'property': 'aic-record-irq-config'})
            for iteration in range(passes):
                if iteration:
                    qmp.request('system_reset')
                values = wait_pc(qmp, BASE)
                require(values['PSTATE'] & 15 == 9, 'Owned ROM starts at AArch64 EL2h')
                require(qmp.request('query-status')['running'] is False, 'CPU stopped before cont')
                verify = scratch / 'owned-before.bin'
                qmp.request('pmemsave', {'val': BASE, 'size': len(content),
                                         'filename': str(verify)})
                require(verify.read_bytes() == content, 'Owned ROM bytes are exact before cont')
                verify.unlink()
                if expect_fault:
                    qmp.request('cont')
                    deadline = time.monotonic() + 10
                    while True:
                        guard()
                        qmp.request('stop')
                        count = struct.unpack('<Q', read_scratch(qmp, scratch, 8, FAULT_COUNT))[0]
                        if count:
                            break
                        require(time.monotonic() < deadline, 'Expected abort never taken')
                        qmp.request('cont')
                        time.sleep(0.05)
                    esr = struct.unpack('<Q', read_scratch(qmp, scratch, 8, FAULT_ESR))[0]
                    raw = read_scratch(qmp, scratch, len(rom.expected) * 8)
                    # Nothing past the abort ran: no readback, no completion.
                    require(struct.unpack_from('<Q', raw, (len(rom.expected) - 1) * 8)[0] == 0,
                            'ROM must not complete when the store is refused')
                    result['passes'].append({'iteration': iteration, 'fault_count': count,
                                             'esr_el2': hex(esr),
                                             'ec': hex(esr >> 26), 'dfsc': hex(esr & 0x3f),
                                             'write_not_read': bool(esr & 0x40)})
                    continue
                raw = run_to_completion(qmp, scratch, rom, guard)
                observed = {}
                for index, (name, expect) in enumerate(rom.expected.items()):
                    value = struct.unpack_from('<Q', raw, index * 8)[0]
                    observed[name] = hex(value)
                    require(expect is None or value == expect,
                            f'{name}: expected {expect:#x}, observed {value:#x}')
                count = struct.unpack('<Q', read_scratch(qmp, scratch, 8, FAULT_COUNT))[0]
                require(count == 0, 'No unexpected exception was taken')
                result['passes'].append({'iteration': iteration,
                                         'after_system_reset': bool(iteration),
                                         'observed': observed})
            if label == 'record-on':
                qmp.sequence += 1
                request = {'execute': 'qom-set', 'id': qmp.sequence,
                           'arguments': {'path': '/machine', 'property': 'aic-record-irq-config',
                                         'value': False}}
                deadline = time.monotonic() + 3
                qmp.send(json.dumps(request).encode() + b'\n', deadline)
                while time.monotonic() < deadline:
                    response = qmp.receive(deadline)
                    if 'event' in response:
                        continue
                    require('error' in response and 'return' not in response,
                            'aic-record-irq-config is creation-only')
                    require(response['error']['desc'] ==
                            'apple-modern properties are fixed after initialization',
                            'exact immutability message')
                    result['creation_only'] = response['error']['desc']
                    break
            qmp.request('quit')
            result['exit_code'] = process.wait(timeout=10)
            process = None
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
    result['log'] = log_path.read_text(errors='replace')
    return result


def refused(binary, components, output, label, extra, needle):
    asset_paths = {name: components / name for name in board.ASSETS}
    machine = 'apple-modern,' + ','.join(
        name + '=' + str(asset_paths[asset])
        for name, asset in zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
    machine += ',prepare-only=true' + extra
    argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1', '-nodefaults',
            '-display', 'none', '-serial', 'none', '-monitor', 'none', '-S']
    run = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    (output / f'{label}-emulator.log').write_text(run.stdout + run.stderr)
    require(run.returncode != 0, f'{label}: startup refused')
    require(needle in run.stderr, f'{label}: refusal names the reason')
    return {'exit_code': run.returncode, 'stderr': run.stderr.strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--previous-binary', type=Path,
                        help='pin without the option: it must reject the property')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    assets = {name: args.components / name for name in board.ASSETS}
    before = {name: delivery.digest(path) for name, path in assets.items()}
    report = {'binary': str(args.binary), 'binary_sha256': delivery.digest(args.binary)['sha256'],
              'component_hashes_before': before, 'passed': False,
              'firmware_executed': False, 'ios_boot_claim': False}
    try:
        on = run_case(args.binary, args.components, args.output_dir, 'record-on',
                      ',modern-aic=on,aic-record-irq-config=on', False, 2)
        require(on['option'] is True, 'Option reads back true')
        require('AIC records IRQ_CFG words and delivers every interrupt to CPU0' in on['log'],
                'Board states the CPU0 delivery policy')
        traced = run_case(args.binary, args.components, args.output_dir, 'record-on-trace',
                          ',modern-aic=on,aic-record-irq-config=on,aic-trace=on', False, 1,
                          ('-d', 'unimp'))
        for needle in ('apple-modern-aic: irq-config irq 42 value 0x00000005 target 5 delay-index 0',
                       'apple-modern-aic: irq-config irq 1092 value 0xabcdef00 target 0 delay-index 0',
                       'apple-modern-aic: irq-config irq 1092 value 0xabcdefa3 target 3 delay-index 5',
                       'apple-modern-aic: irq-config irq 4095 value 0xffffffff target 15 delay-index 7'):
            require(needle in traced['log'], 'aic-trace decodes: ' + needle)
        require('(not recorded)' not in traced['log'], 'recorded stores are not flagged')
        off = run_case(args.binary, args.components, args.output_dir, 'record-off',
                       ',modern-aic=on', True, 1)
        require(off['option'] is False, 'Option defaults to false')
        require('records IRQ_CFG' not in off['log'], 'Default board is silent about the option')
        for entry in off['passes']:
            # Synchronous external abort on a store: EC 0x25, DFSC 0x10, WnR set.
            require(entry['ec'] == '0x25' and entry['dfsc'] == '0x10' and
                    entry['write_not_read'], 'default board aborts the nonzero store')
        report['record_on'] = {k: on[k] for k in ('passes', 'creation_only', 'argv', 'rom_sha256')}
        report['record_off'] = {k: off[k] for k in ('passes', 'argv', 'rom_sha256')}
        report['record_on_trace'] = {'argv': traced['argv'], 'config_log_lines': [
            l for l in traced['log'].splitlines() if 'irq-config irq' in l]}
        report['without_modern_aic'] = refused(
            args.binary, args.components, args.output_dir, 'without-modern-aic',
            ',aic-record-irq-config=on',
            'aic-record-irq-config needs modern-aic=on')
        if args.previous_binary:
            report['previous_pin_binary_sha256'] = delivery.digest(args.previous_binary)['sha256']
            report['previous_pin'] = refused(
                args.previous_binary, args.components, args.output_dir, 'previous-pin',
                ',modern-aic=on,aic-record-irq-config=on', 'aic-record-irq-config')
        report['passed'] = True
    except BaseException as error:
        report['error'] = repr(error)
    after = {name: delivery.digest(path) for name, path in assets.items()}
    report['component_hashes_after'] = after
    report['components_unchanged'] = before == after
    report['passed'] = report['passed'] and report['components_unchanged']
    (args.output_dir / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps({k: report.get(k) for k in ('passed', 'error', 'components_unchanged')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
