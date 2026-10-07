#!/usr/bin/env python3
"""Qualify SEP transport diagnostics with an owned AArch64 ROM.

The ROM uses the AP mailbox offsets measured in XNU, drains the simulator's
reset announcement, exchanges harmless PING and GET_STATUS messages, sends an
unsupported bootstrap opcode, and checks a subsequent status round trip still
works. Read-only QOM counters establish accepted frames, dispatch, reply and
unsupported-message handling without recording message payloads or key data.
The sequence repeats across system reset, including counter reset checks.

Only this owned ROM executes. Firmware components are preparation inputs and
remain unchanged. This gate establishes transport behaviour, not sepOS boot,
cryptography, an Apple driver handshake or a complete iOS boot. OOL DMA errors
must remain zero here; no keystore or firmware-validation operation is sent.
The existing sep-mailbox gate separately qualifies CPU IRQ delivery.
"""
import argparse
import importlib.util
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    'sep_mailbox_gate_helpers',
    Path(__file__).with_name('test-apple-modern-sep-mailbox-qemu.py'))
mailbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mailbox)
board = mailbox.board
require = mailbox.require
digest = mailbox.digest

COUNTERS = (
    'transport-ap-send-count', 'transport-ap-recv-count',
    'sim-dispatch-count', 'sim-reply-count', 'sim-unsupported-count',
    'sim-ool-error-count', 'wrapper-mmio-read-count',
    'wrapper-mmio-write-count', 'ap-mmio-read-count', 'ap-mmio-write-count',
)
LAST = ('sim-last-endpoint', 'sim-last-opcode',
        'sim-last-unsupported-endpoint', 'sim-last-unsupported-opcode')
RESET = dict.fromkeys(COUNTERS + LAST, 0) | {'sim-reply-count': 1}
FINAL = {
    'transport-ap-send-count': 4, 'transport-ap-recv-count': 4,
    'sim-dispatch-count': 4, 'sim-reply-count': 4,
    'sim-unsupported-count': 1, 'sim-ool-error-count': 0,
    'wrapper-mmio-read-count': 1, 'wrapper-mmio-write-count': 0,
    'ap-mmio-write-count': 8,
    'sim-last-endpoint': 255, 'sim-last-opcode': 2,
    'sim-last-unsupported-endpoint': 255,
    'sim-last-unsupported-opcode': 127,
}
COMPLETION = 0xfeedfacecafebeef


class QMP(board.QMP):
    def require_readonly(self, path, property_name):
        """Expect a QMP error without desynchronising the shared client."""
        self.guard()
        self.sequence += 1
        request = {'execute': 'qom-set', 'id': self.sequence,
                   'arguments': {'path': path, 'property': property_name,
                                 'value': 0}}
        deadline = time.monotonic() + 3
        self.send(json.dumps(request).encode() + b'\n', deadline)
        while time.monotonic() < deadline:
            response = self.receive(deadline)
            if 'event' in response:
                self.events.append(response['event'])
                require(len(self.events) <= 64, 'QMP event count bound')
                continue
            require(response.get('id') == self.sequence, 'QMP response ID')
            require('error' in response and 'return' not in response,
                    property_name + ' must reject qom-set')
            return response['error']
        raise RuntimeError('QMP readonly-property deadline')


class ROM(mailbox.ROM):
    def wait_reply(self):
        poll = len(self.words)
        self.read32(mailbox.I2A_CTRL, 23)
        self.mov(24, mailbox.CTRL_ENABLE | mailbox.ctrl_count(1))
        self.emit(0x6b1802ff)  # cmp w23,w24
        self.branch(poll, 1)   # b.ne

    def send(self, tag, opcode):
        message = int.from_bytes(struct.pack('<BBBBI', 255, tag, opcode, 0, 0),
                                 'little')
        self.write64(mailbox.A2I_SEND, message)
        self.write64(mailbox.A2I_SEND + 8, 0)

    def receive(self, label, tag, opcode, data):
        expected = int.from_bytes(struct.pack('<BBBBI', 255, tag, opcode, 0, data),
                                  'little')
        self.read64(mailbox.I2A_RECV, 23)
        self.trace(label + '_message', expected, register=23)
        self.read64(mailbox.I2A_RECV + 8, 23)
        self.trace(label + '_count_stamp', mailbox.stamped(0, 1), register=23)

    def build(self):
        self.mov(20, mailbox.SCRATCH)
        self.mov(0, mailbox.NORMAL_SP)
        self.emit(0x9100001f)  # mov sp,x0
        self.emit(0xd5034fdf)  # msr daifset,#15
        self.set('VBAR_EL2', mailbox.BASE + 0x4000)
        self.read32(mailbox.IDLE_STATUS, 23)
        self.trace('idle_status', 3, register=23)
        self.read32(mailbox.A2I_CTRL, 23)
        self.trace('inbox_reset', mailbox.CTRL_ENABLE | mailbox.CTRL_EMPTY,
                   register=23)
        self.read32(mailbox.I2A_CTRL, 23)
        self.trace('outbox_reset_announcement',
                   mailbox.CTRL_ENABLE | mailbox.ctrl_count(1), register=23)
        self.receive('announcement', 0, 210, 1)
        self.read32(mailbox.I2A_CTRL, 23)
        self.trace('outbox_after_announcement',
                   mailbox.CTRL_ENABLE | mailbox.CTRL_EMPTY, register=23)

        self.send(0x31, 1)  # PING
        self.wait_reply()
        self.receive('ping', 0x31, 101, 0)
        self.send(0x32, 2)  # GET_STATUS
        self.wait_reply()
        self.receive('status', 0x32, 102, 1)
        self.send(0x33, 127)  # Deliberately unsupported; must produce no reply.
        self.send(0x34, 2)    # Ordered barrier after the unsupported message.
        self.wait_reply()
        self.receive('status_after_unsupported', 0x34, 102, 1)

        # Empty receive cannot count as a successful AP frame or wedge the FIFO.
        self.read64(mailbox.I2A_RECV, 23)
        self.trace('empty_receive', 0, register=23)
        self.read32(mailbox.I2A_CTRL, 23)
        self.trace('outbox_final', mailbox.CTRL_ENABLE | mailbox.CTRL_EMPTY,
                   register=23)
        self.mov(0, COMPLETION)
        self.trace('completion', COMPLETION)
        self.branch(len(self.words))

        # Any unexpected exception records ESR and stops instead of returning
        # into an uninitialised vector table. The runner rejects the fault word.
        for offset in range(0x4000, 0x4800, 0x80):
            self.at(offset)
            self.mov(0, 1)
            self.store(0, 0x500)
            self.emit(mailbox.sysreg('ESR_EL2', 0, True))
            self.store(0, 0x508)
            self.emit(0x14000000)
        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < 0x500,
                'Owned ROM, result and fault ranges remain separate')
        return b''.join(struct.pack('<I', value) for value in self.words)


def find_sep(qmp):
    children = qmp.request('qom-list', {'path': '/machine/unattached'})
    found = [child['name'] for child in children
             if child['type'] == 'child<apple-sep-sim>']
    require(len(found) == 1, 'Exactly one SEP simulator is present')
    return '/machine/unattached/' + found[0]


def values(qmp, path, names):
    result = {name: qmp.request('qom-get', {'path': path, 'property': name})
              for name in names}
    require(all(isinstance(value, int) and not isinstance(value, bool) and
                0 <= value < 1 << 64 for value in result.values()),
            'Diagnostics are bounded unsigned integers')
    return result


def run(binary, components, output):
    started = time.monotonic()
    assets = {name: components / name for name in board.ASSETS}
    before = {name: digest(path) for name, path in assets.items()}
    layout = board.expected_layout({name: path.read_bytes()
                                    for name, path in assets.items()})
    for name, (address, size) in layout['regions'].items():
        require(mailbox.PROBE_END <= address or mailbox.BASE >= address + size,
                'Owned ROM/scratch overlaps reserved component: ' + name)
    require(mailbox.DRAM <= mailbox.BASE < mailbox.PROBE_END <=
            mailbox.DRAM + board.RAM_SIZE, 'Owned range lies within modern DRAM')
    require(shutil.disk_usage(output).free >= 64 << 20,
            'Minimum evidence free space')
    rom = ROM()
    content = rom.build()
    rom_path = output / 'sep-transport.rom'
    rom_path.write_bytes(content)
    # RAM normally survives system_reset. A separate owned loader clears result
    # and fault words at each reset so a stale completion cannot satisfy pass 2.
    result_path = output / 'zero-results.bin'
    zero_results = bytes(0x510)
    result_path.write_bytes(zero_results)
    report = {
        'scope': 'Owned-ROM SEP transport diagnostics; no sepOS/crypto operation',
        'binary': str(binary), 'binary_sha256': digest(binary)['sha256'],
        'script_sha256': digest(Path(__file__))['sha256'],
        'rom_sha256': digest(rom_path)['sha256'],
        'zero_results_sha256': digest(result_path)['sha256'],
        'component_hashes_before': before,
        'firmware_executed': False, 'ios_boot_claim': False,
        'guest_driver_exercised': False, 'ool_dma_exercised': False,
        'counter_payload_recorded': False,
        'unsupported_message': {'endpoint': 255, 'opcode': 127},
        'ap_apertures_measured_in_xnu': {
            'inbox_ctrl': hex(mailbox.A2I_CTRL),
            'outbox_ctrl': hex(mailbox.I2A_CTRL),
            'send': hex(mailbox.A2I_SEND), 'receive': hex(mailbox.I2A_RECV)},
        'empty_read_semantics_is_apple_documented': False,
        'owned_range': {'start': hex(mailbox.BASE), 'end': hex(mailbox.PROBE_END)},
        'limits': {'wall_seconds': mailbox.MAX_WALL, 'cpu_seconds': 30,
                   'log_bytes': mailbox.MAX_LOG},
        'passes': [], 'passed': False,
    }
    process = qmp = None
    log_path = output / 'emulator.log'
    try:
        with tempfile.TemporaryDirectory(prefix='sep-transport-gate-') as temporary:
            scratch = Path(temporary)
            machine = 'apple-modern,' + ','.join(
                name + '=' + str(assets[asset]) for name, asset in
                zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
            machine += (',prepare-only=true,modern-aic=on,sep-sim=on,'
                        'boot-command-line=' + board.COMMAND_LINE)
            argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
                    '-nodefaults', '-display', 'none', '-serial', 'none',
                    '-monitor', 'none', '-device',
                    f'loader,file={rom_path},addr={mailbox.BASE},cpu-num=0,force-raw=true',
                    '-device', f'loader,file={result_path},addr={mailbox.SCRATCH},force-raw=true',
                    '-S', '-qmp', 'stdio']
            report['argv'] = argv
            with log_path.open('xb') as log:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=log,
                                           bufsize=0, preexec_fn=mailbox.child_limits)

                def guard():
                    remaining = mailbox.MAX_WALL - (time.monotonic() - started)
                    require(remaining > 0 and log_path.stat().st_size <= mailbox.MAX_LOG,
                            'SEP transport gate wall/log bound exceeded')
                    return remaining

                qmp = QMP(None, guard, process)
                for property_name in ('prepare-only', 'modern-aic', 'sep-sim'):
                    require(qmp.request('qom-get', {'path': '/machine',
                                                   'property': property_name}) is True,
                            property_name + ' is enabled for this gate')
                path = find_sep(qmp)
                report['device_path'] = path
                properties = {item['name']: item['type'] for item in
                              qmp.request('qom-list', {'path': path})}
                require(all(properties.get(name) == 'uint64' for name in COUNTERS),
                        'Every transport counter is a uint64 QOM property')
                report['readonly_rejections'] = {
                    name: qmp.require_readonly(path, name) for name in COUNTERS + LAST}

                for iteration in range(2):
                    if iteration:
                        qmp.request('system_reset')
                    deadline = time.monotonic() + 3
                    while True:
                        registers = board.parse_registers(qmp.request(
                            'human-monitor-command', {'command-line': 'info registers'}))
                        if registers['PC'] == mailbox.BASE:
                            break
                        require(time.monotonic() < deadline,
                                'Owned PC not selected; no cont issued')
                        time.sleep(0.02)
                    require(registers['PSTATE'] & 15 == 9,
                            'Owned ROM starts at AArch64 EL2h')
                    require(qmp.request('query-status')['running'] is False,
                            'CPU remains stopped before owned cont')
                    reset = values(qmp, path, COUNTERS + LAST)
                    require(reset == RESET,
                            'Reset counters must be zero plus one announcement: ' + str(reset))
                    verify = scratch / 'rom.bin'
                    qmp.request('pmemsave', {'val': mailbox.BASE, 'size': len(content),
                                             'filename': str(verify)})
                    require(verify.read_bytes() == content,
                            'Exact owned ROM bytes verified before cont')
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH,
                                             'size': len(zero_results),
                                             'filename': str(verify)})
                    require(verify.read_bytes() == zero_results,
                            'Result and fault words cleared before each owned cont')
                    qmp.request('cont')
                    deadline = time.monotonic() + 10
                    dump = scratch / 'result.bin'
                    while True:
                        guard()
                        qmp.request('stop')
                        qmp.request('pmemsave', {'val': mailbox.SCRATCH,
                                                 'size': len(rom.expected) * 8,
                                                 'filename': str(dump)})
                        raw = dump.read_bytes()
                        if struct.unpack_from('<Q', raw,
                                              (len(rom.expected) - 1) * 8)[0] == COMPLETION:
                            break
                        require(time.monotonic() < deadline, 'Owned ROM did not complete')
                        qmp.request('cont')
                        time.sleep(0.05)

                    observed = {}
                    for index, (label, expected) in enumerate(rom.expected.items()):
                        actual = struct.unpack_from('<Q', raw, index * 8)[0]
                        observed[label] = hex(actual)
                        require(actual == expected,
                                f'{label}: expected {expected:#x}, observed {actual:#x}')
                    faults = scratch / 'faults.bin'
                    qmp.request('pmemsave', {'val': mailbox.SCRATCH + 0x500, 'size': 16,
                                             'filename': str(faults)})
                    require(struct.unpack('<2Q', faults.read_bytes()) == (0, 0),
                            'No unexpected exception occurred')
                    counters = values(qmp, path, COUNTERS + LAST)
                    for name, expected in FINAL.items():
                        require(counters[name] == expected,
                                f'{name}: expected {expected}, observed {counters[name]}')
                    require(counters['ap-mmio-read-count'] >= 16,
                            'AP mailbox MMIO reads are recorded')
                    require(values(qmp, path, COUNTERS + LAST) == counters,
                            'Reading diagnostics does not change counters')
                    report['passes'].append({'iteration': iteration,
                                             'after_system_reset': bool(iteration),
                                             'reset_counters': reset,
                                             'observed': observed, 'counters': counters,
                                             'completed': True})
                qmp.request('quit')
                code = process.wait(timeout=10)
                require(code == 0, f'Emulator exited {code}')
                process = None
        report['passed'] = len(report['passes']) == 2
    except Exception as error:
        report['error'] = str(error)
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
        if qmp is not None:
            qmp.close()
        after = {name: digest(path) for name, path in assets.items()}
        report['component_hashes_after'] = after
        if after != before:
            report['passed'] = False
            report['error'] = 'Firmware preparation components changed'
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'passed': report['passed'], 'transport_passes': len(report['passes']),
                      'binary_sha256': report['binary_sha256'],
                      'error': report.get('error')}))
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    return run(args.binary.resolve(), args.components.resolve(), args.output_dir.resolve())


if __name__ == '__main__':
    sys.exit(main())
