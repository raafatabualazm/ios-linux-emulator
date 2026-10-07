#!/usr/bin/env python3
"""Qualify the SEP ASC mailbox with an owned ROM.

This gate isolates the hardware transport from firmware and SEP protocol
behaviour. Earlier zero-access restore observations were superseded by later
AppleSEPManager startup; firmware access needs device counters measured on the
exact supplied device tree.

An owned ROM plays both ends. As the AP it uses exactly the apertures measured in
XNU's AppleA7IOP driver (INBOX0_CTRL +0x8110, OUTBOX0_CTRL +0x8114, a 16-byte
send at +0x8800, a 16-byte receive at +0x8830, IDLE_STATUS at +0x8000). As the
coprocessor it uses the IOP-side mailbox at one AKF stride, which no AP code
touches and which is therefore declared, not measured. It checks:

  - reset CONTROL words and IDLE_STATUS;
  - the enable handshake XNU performs;
  - provider interrupt index 1 (IOP_EMPTY, AIC 343): high while the coprocessor
    inbox is empty, LOW while a message waits, and HIGH again once the
    coprocessor drains it -- the line XNU uses to wake a blocked sender;
  - provider interrupt index 2 (AP_NONEMPTY, AIC 346): the message doorbell;
  - both message directions round-trip, with the remaining-count stamp in
    bytes 12-15 that XNU's getMailboxBulk relies on;
  - an empty receive returns zero and wedges nothing.

The CPU takes real IRQ exceptions through the modern AIC, at the acknowledge
offset the board publishes. The whole sequence repeats across a system reset.
Firmware is never executed. This qualifies THIS model; several pieces are
declared rather than Apple-sourced, and report.json says which.
"""
import argparse
import hashlib
import importlib.util
import json
import resource
import shutil
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


board = module('board_preparation_gate', 'test-apple-modern-machine.py')
metadata = module('board_metadata_oracle', 'test-apple-modern-boot-metadata.py')

DRAM = 1 << 40
BASE = DRAM + 0x100000
SCRATCH = BASE + 0x10000
NORMAL_SP = BASE + 0x20000
PROBE_END = NORMAL_SP + 0x1000
MAX_LOG = 1024 * 1024
MAX_WALL = 60

# Controller placement, from the served ADT: /arm-io ranges parent 0x210000000
# plus the aic "reg" child offset 0xf1000000, and extint-baseaddress 0x10000.
AIC_BASE = 0x301000000
GLBCFG = 0x14
IRQ_CONFIG = 0x10000
NUM_IRQS = 4096
SW_SET = IRQ_CONFIG + NUM_IRQS * 4
SW_CLEAR = SW_SET + NUM_IRQS // 32 * 4
MASK_SET = SW_CLEAR + NUM_IRQS // 32 * 4
MASK_CLEAR = MASK_SET + NUM_IRQS // 32 * 4
EVENT = 0x2000               # declared by this model; not an Apple-documented offset
EVENT_IRQ = 0x00010000       # event type field for a hardware/software IRQ
TEST_IRQ = 42

SEP_WRAP = 0x282600000       # ADT /arm-io/sep reg[0], translated
AP_MBOX = SEP_WRAP + 0x8100  # AP-side mailbox block
IOP_MBOX = SEP_WRAP + 0x4100 # coprocessor-side block (declared aperture)
A2I_CTRL = AP_MBOX + 0x10    # Apple's INBOX0_CTRL  (+0x8110)
I2A_CTRL = AP_MBOX + 0x14    # Apple's OUTBOX0_CTRL (+0x8114)
A2I_SEND = AP_MBOX + 0x700   # +0x8800, XNU's 16-byte stp
I2A_RECV = AP_MBOX + 0x730   # +0x8830, XNU's 16-byte ldp
IDLE_STATUS = SEP_WRAP + 0x8000
IOP_A2I_RECV = IOP_MBOX + 0x710
IOP_I2A_SEND = IOP_MBOX + 0x720
LINE_IOP_EMPTY = 343         # provider index 1, used by XNU
LINE_AP_NONEMPTY = 346       # provider index 2, used by XNU: the doorbell
CTRL_ENABLE = 1
CTRL_EMPTY = 1 << 17
CTRL_UNDERFLOW = 1 << 19
def ctrl_count(n):
    return (n & 0xf) << 20
LO1, HI1 = 0x1111222233334444, 0x5555666677778888
LO2, HI2 = 0x0123456789abcdef, 0xfedcba9876543210
def stamped(hi, remaining):
    """Upper 64 bits after the core writes the remaining count at byte 12."""
    return (hi & 0xffffffff) | (ctrl_count(remaining) << 32)

REGS = {
    'HCR_EL2': (3, 4, 1, 1, 0), 'VBAR_EL2': (3, 4, 12, 0, 0),
    'ESR_EL2': (3, 4, 5, 2, 0), 'CurrentEL': (3, 0, 4, 2, 2),
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sysreg(name, register, read):
    op0, op1, crn, crm, op2 = REGS[name]
    return (0xd5000000 | (int(read) << 21) | (op0 << 19) | (op1 << 16)
            | (crn << 12) | (crm << 8) | (op2 << 5) | register)


class ROM:
    """Minimal AArch64 emitter; the same shape the timer gate uses."""

    def __init__(self):
        self.words, self.expected = [], {}

    def emit(self, word):
        self.words.append(word)

    def at(self, offset):
        require(len(self.words) * 4 <= offset, 'Owned ROM blocks overlap')
        self.words.extend([0] * (offset // 4 - len(self.words)))

    def mov(self, register, value):
        for half in range(4):
            self.emit((0xd2800000 if half == 0 else 0xf2800000)
                      | (half << 21) | (((value >> (half * 16)) & 0xffff) << 5)
                      | register)

    def set(self, name, value):
        self.mov(0, value)
        self.emit(sysreg(name, 0, False))

    def store(self, register, offset):
        require(offset % 8 == 0 and 0 <= offset < 32768, 'Owned scratch store bounds')
        self.emit(0xf9000000 | ((offset // 8) << 10) | (20 << 5) | register)

    def trace(self, label, expected, name=None, register=0):
        if name:
            self.emit(sysreg(name, register, True))
        self.store(register, len(self.expected) * 8)
        self.expected[label] = expected

    def write32(self, address, value):
        self.mov(1, address)
        self.mov(0, value)
        self.emit(0xb9000020)                  # str w0,[x1]

    def write64(self, address, value):
        self.mov(1, address)
        self.mov(0, value)
        self.emit(0xf9000020)                  # str x0,[x1]

    def read32(self, address, register):
        self.mov(1, address)
        self.emit(0xb9400000 | (1 << 5) | register)  # ldr w<reg>,[x1]

    def read64(self, address, register):
        self.mov(1, address)
        self.emit(0xf9400000 | (1 << 5) | register)  # ldr x<reg>,[x1]

    def unmask(self, line):
        self.write32(AIC_BASE + MASK_CLEAR + line // 32 * 4, 1 << (line & 31))

    def window(self):
        """Open the IRQ window long enough for a level to be taken."""
        self.emit(0xd50342ff)                  # msr daifclr,#2
        for _ in range(64):
            self.emit(0xd503201f)              # nop
        self.emit(0xd503425f)                  # msr daifset,#2

    def branch(self, target_index, condition=None):
        displacement = target_index - len(self.words)
        if condition is None:
            self.emit(0x14000000 | (displacement & 0x3ffffff))
        else:
            self.emit(0x54000000 | ((displacement & 0x7ffff) << 5) | condition)

    def await_count(self, count):
        poll = len(self.words)
        self.emit(0xf10002bf | (count << 10))  # cmp x21,#count
        self.branch(poll, 1)                   # b.ne

    def build(self):
        self.mov(20, SCRATCH)
        self.mov(21, 0)                        # interrupts taken
        self.mov(22, 0)                        # last acknowledged event
        self.mov(24, 0)                        # unexpected exceptions
        self.mov(0, NORMAL_SP)
        self.emit(0x9100001f)                  # mov sp,x0
        self.set('HCR_EL2', (1 << 31) | (1 << 34) | (1 << 4))
        self.set('VBAR_EL2', BASE + 0x4000)

        self.write32(AIC_BASE + GLBCFG, 1)
        self.trace('enabled_no_interrupt', 0, register=21)

        # Reset state, as XNU would first read it.
        self.read32(A2I_CTRL, 23)
        self.trace('inbox_ctrl_reset', CTRL_ENABLE | CTRL_EMPTY, register=23)
        self.read32(I2A_CTRL, 23)
        self.trace('outbox_ctrl_reset', CTRL_ENABLE | CTRL_EMPTY, register=23)
        self.read32(IDLE_STATUS, 23)
        self.trace('idle_status', 3, register=23)

        # XNU's enable handshake: write OUTBOX0_CTRL bit 0, poll INBOX0_CTRL bit 0.
        self.write32(I2A_CTRL, 1)
        self.read32(A2I_CTRL, 23)
        self.trace('handshake_inbox_ctrl', CTRL_ENABLE | CTRL_EMPTY, register=23)

        # Index 1 (IOP_EMPTY) is high while the coprocessor inbox is empty.
        self.unmask(LINE_IOP_EMPTY)
        self.emit(0xd50342ff)
        self.await_count(1)
        self.emit(0xd503425f)
        self.trace('iop_empty_count', 1, register=21)
        self.trace('iop_empty_event', EVENT_IRQ | LINE_IOP_EMPTY, register=22)

        # AP posts A2I exactly as XNU does. While the message waits, IOP_EMPTY
        # must be LOW, so re-unmasking it must not deliver.
        self.write64(A2I_SEND, LO1)
        self.write64(A2I_SEND + 8, HI1)
        self.read32(A2I_CTRL, 23)
        self.trace('inbox_ctrl_one_queued', CTRL_ENABLE | ctrl_count(1), register=23)
        self.unmask(LINE_IOP_EMPTY)
        self.window()
        self.trace('iop_empty_low_while_queued', 1, register=21)

        # The coprocessor drains it: payload intact, remaining count stamped,
        # and IOP_EMPTY rises again -- the sender-wake XNU depends on.
        self.read64(IOP_A2I_RECV, 23)
        self.trace('a2i_rx_lo', LO1, register=23)
        self.read64(IOP_A2I_RECV + 8, 23)
        self.trace('a2i_rx_hi', stamped(HI1, 1), register=23)
        self.emit(0xd50342ff)
        self.await_count(2)
        self.emit(0xd503425f)
        self.trace('iop_empty_after_drain_count', 2, register=21)
        self.trace('iop_empty_after_drain_event', EVENT_IRQ | LINE_IOP_EMPTY, register=22)

        # The coprocessor sends I2A; index 2 (AP_NONEMPTY) is the doorbell.
        self.write64(IOP_I2A_SEND, LO2)
        self.write64(IOP_I2A_SEND + 8, HI2)
        self.read32(I2A_CTRL, 23)
        self.trace('outbox_ctrl_one_queued', CTRL_ENABLE | ctrl_count(1), register=23)
        self.unmask(LINE_AP_NONEMPTY)
        self.emit(0xd50342ff)
        self.await_count(3)
        self.emit(0xd503425f)
        self.trace('doorbell_count', 3, register=21)
        self.trace('doorbell_event', EVENT_IRQ | LINE_AP_NONEMPTY, register=22)

        # AP receives exactly as XNU does; the single message carries count 1.
        self.read64(I2A_RECV, 23)
        self.trace('i2a_rx_lo', LO2, register=23)
        self.read64(I2A_RECV + 8, 23)
        self.trace('i2a_rx_hi', stamped(HI2, 1), register=23)
        self.read32(I2A_CTRL, 23)
        self.trace('outbox_ctrl_drained', CTRL_ENABLE | CTRL_EMPTY, register=23)
        self.unmask(LINE_AP_NONEMPTY)
        self.window()
        self.trace('doorbell_quiet_after_drain', 3, register=21)

        # A stray empty receive must return zero and wedge nothing: no
        # underflow bit, and no doorbell storm afterwards.
        self.read64(I2A_RECV, 23)
        self.trace('empty_read_value', 0, register=23)
        self.read32(I2A_CTRL, 23)
        self.trace('outbox_ctrl_after_empty_read', CTRL_ENABLE | CTRL_EMPTY, register=23)
        self.unmask(LINE_AP_NONEMPTY)
        self.window()
        self.trace('no_storm_after_empty_read', 3, register=21)

        self.mov(0, 0xfeedfacecafebeef)
        self.trace('completion', 0xfeedfacecafebeef)
        terminal = len(self.words)
        self.branch(terminal)

        # Vector table, emitted in ascending order. Every entry other than the
        # IRQ one records that an unexpected exception was taken and stops.
        def fault(offset):
            self.at(offset)
            self.emit(0x91000718)              # add x24,x24,#1
            self.store(24, 0x500)
            self.emit(0x14000000)

        for offset in (0x4000, 0x4080, 0x4100, 0x4180, 0x4200):
            fault(offset)
        # IRQ, current EL with SP_ELx.
        self.at(0x4280)
        self.read32(AIC_BASE + EVENT, 22)
        self.emit(0x910006b5)                  # add x21,x21,#1
        self.emit(0xd69f03e0)                  # eret
        for offset in (0x4300, 0x4380):
            fault(offset)

        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < 0x500,
                'Owned ROM and scratch ranges remain separate')
        return b''.join(struct.pack('<I', w) for w in self.words)


def digest(path):
    with path.open('rb') as stream:
        return {'bytes': path.stat().st_size,
                'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
    resource.setrlimit(resource.RLIMIT_AS, (16 << 30, 16 << 30))


def run(binary, components, output):
    started = time.monotonic()
    asset_paths = {name: components / name for name in board.ASSETS}
    before = {name: digest(path) for name, path in asset_paths.items()}
    blobs = {name: path.read_bytes() for name, path in asset_paths.items()}
    layout = board.expected_layout(blobs)
    reserved = [{'name': name, 'physical_address': address, 'size': size}
                for name, (address, size) in layout['regions'].items()]
    for region in reserved:
        require(PROBE_END <= region['physical_address'] or
                BASE >= region['physical_address'] + region['size'],
                'Owned ROM/scratch range overlaps boot reservation: ' + region['name'])
    require(DRAM <= BASE < PROBE_END <= DRAM + board.RAM_SIZE,
            'Owned probe lies inside modern DRAM')
    require(shutil.disk_usage(output).free >= 64 * 1024 * 1024,
            'Minimum evidence free space')

    rom = ROM()
    content = rom.build()
    rom_path = output / 'sep-mailbox.rom'
    rom_path.write_bytes(content)
    report = {'scope': 'SEP ASC v6 mailbox transport and doorbells; owned ROM only',
              'binary': str(binary), 'binary_sha256': digest(binary)['sha256'],
              'rom_sha256': digest(rom_path)['sha256'],
              'component_hashes_before': before, 'passes': [], 'passed': False,
              'firmware_executed': False, 'ios_boot_claim': False,
              'declared_event_offset': hex(EVENT),
              'event_offset_is_apple_documented': False,
              'sep_wrapper': hex(SEP_WRAP),
              'ap_apertures_measured_in_xnu': {
                  'INBOX0_CTRL': hex(A2I_CTRL), 'OUTBOX0_CTRL': hex(I2A_CTRL),
                  'send': hex(A2I_SEND), 'receive': hex(I2A_RECV),
                  'IDLE_STATUS': hex(IDLE_STATUS)},
              'coprocessor_aperture_is_apple_documented': False,
              'lines_used_by_xnu': {'index1_iop_empty': LINE_IOP_EMPTY,
                                    'index2_doorbell': LINE_AP_NONEMPTY},
              'unused_line_assignment_is_apple_documented': False,
              'empty_read_semantics_is_apple_documented': False,
              'guest_driver_exercised': False,
              'owned_range': {'start': hex(BASE), 'end': hex(PROBE_END)},
              'limits': {'wall_seconds': MAX_WALL, 'cpu_seconds': 30,
                         'log_bytes': MAX_LOG}}
    process = qmp = None
    log_path = output / 'emulator.log'
    try:
        with tempfile.TemporaryDirectory(prefix='sep-mailbox-gate-') as temporary:
            scratch = Path(temporary)
            machine = 'apple-modern,' + ','.join(
                name + '=' + str(asset_paths[asset]) for name, asset in
                zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
            machine += ',prepare-only=true,modern-aic=on,sep-mailbox=on,boot-command-line=' + board.COMMAND_LINE
            argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
                    '-nodefaults', '-display', 'none', '-serial', 'none',
                    '-monitor', 'none',
                    '-device', f'loader,file={rom_path},addr={BASE},cpu-num=0,force-raw=true',
                    '-S', '-qmp', 'stdio']
            report['argv'] = argv
            with log_path.open('xb') as log:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=log,
                                           bufsize=0, preexec_fn=child_limits)

                def guard():
                    remaining = MAX_WALL - (time.monotonic() - started)
                    require(remaining > 0 and log_path.stat().st_size <= MAX_LOG,
                            'AIC gate wall/log bound exceeded')
                    return remaining

                qmp = board.QMP(None, guard, process)
                require(qmp.request('qom-get', {'path': '/machine',
                                                'property': 'prepare-only'}) is True,
                        'Board remains preparation-only')
                require(qmp.request('qom-get', {'path': '/machine',
                                                'property': 'modern-aic'}) is True,
                        'Controller is enabled for this gate')
                for iteration in range(2):
                    if iteration:
                        qmp.request('system_reset')
                    deadline = time.monotonic() + 3
                    while True:
                        registers = qmp.request('human-monitor-command',
                                                {'command-line': 'info registers'})
                        values = board.parse_registers(registers)
                        if values['PC'] == BASE:
                            break
                        require(time.monotonic() < deadline,
                                'Loader did not select owned PC; no cont issued')
                        time.sleep(0.02)
                    require(values['PSTATE'] & 15 == 9, 'Owned ROM starts at AArch64 EL2h')
                    require(qmp.request('query-status')['running'] is False,
                            'CPU is stopped before owned cont')
                    verify = scratch / 'owned-before.bin'
                    qmp.request('pmemsave', {'val': BASE, 'size': len(content),
                                             'filename': str(verify)})
                    require(verify.read_bytes() == content,
                            'Owned ROM bytes are exact before cont')
                    verify.unlink()
                    qmp.request('cont')

                    deadline = time.monotonic() + 10
                    dump = scratch / 'scratch.bin'
                    while True:
                        guard()
                        qmp.request('stop')
                        qmp.request('pmemsave', {'val': SCRATCH,
                                                 'size': len(rom.expected) * 8,
                                                 'filename': str(dump)})
                        raw = dump.read_bytes()
                        done = len(raw) >= len(rom.expected) * 8 and struct.unpack_from(
                            '<Q', raw, (len(rom.expected) - 1) * 8)[0] == 0xfeedfacecafebeef
                        if done:
                            break
                        require(time.monotonic() < deadline, 'Owned ROM did not complete')
                        qmp.request('cont')
                        time.sleep(0.05)

                    observed = {}
                    for index, (label, expect) in enumerate(rom.expected.items()):
                        value = struct.unpack_from('<Q', raw, index * 8)[0]
                        observed[label] = hex(value)
                        require(expect is None or value == expect,
                                f'{label}: expected {expect!r}, observed {value:#x}')
                    faults = scratch / 'faults.bin'
                    qmp.request('pmemsave', {'val': SCRATCH + 0x500, 'size': 8,
                                             'filename': str(faults)})
                    require(struct.unpack('<Q', faults.read_bytes())[0] == 0,
                            'No unexpected exception was taken')
                    report['passes'].append({'iteration': iteration,
                                             'after_system_reset': bool(iteration),
                                             'observed': observed,
                                             'completed': True})
                qmp.request('quit')
                code = process.wait(timeout=10)
                require(code == 0, f'Emulator exited {code}')
                process = None
        after = {name: digest(path) for name, path in asset_paths.items()}
        require(after == before, 'Firmware components are unchanged')
        report['component_hashes_after'] = after
        report['passed'] = len(report['passes']) == 2
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps({'passed': report['passed'],
                      'cpu_delivery_passes': len(report['passes']),
                      'binary_sha256': report['binary_sha256'],
                      'event_offset_is_apple_documented': False}))
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    return run(args.binary, args.components, args.output_dir)


if __name__ == '__main__':
    sys.exit(main())
