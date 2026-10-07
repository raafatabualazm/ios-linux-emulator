#!/usr/bin/env python3
"""Qualify the modern AIC's HARDWARE input path with a real device line.

A bug lived in this path for the whole life of the controller:
apple_modern_aic_set_irq() recorded each input level inside an assert(), this
tree is built with -DNDEBUG, and so the controller never recorded a single
hardware interrupt. The AIC delivery gate missed it because it raises its test
interrupt through the software-set register, which never touches that path. The
SEP mailbox gate now covers it, but it is a poor sentinel: it also depends on a
device model we wrote, and no firmware boot has ever driven an input.

This gate drives the line the restore boot actually configures -- uart0, ADT
interrupt 1092 -- through the stock Apple UART model, with the host injecting
one received byte over a pipe. An owned ROM enables the controller, unmasks the
line, checks it stays quiet with no data, and then requires exactly one IRQ
exception whose acknowledge value names 1092, a status read showing data ready,
and the injected byte. The sequence repeats across a system reset.

Two behaviours of the UART model itself are ASSERTED, in BOTH directions. They
were first measured here as quirks and recorded only (the gate passed against the
quirky model, which hid them), and each is now behind an opt-in property, off by
default and off on every shipped board:

  * `drain-refresh`: the line must fall once the receive FIFO is drained. Off
    (the historical model) the URXH read leaves the line high, so re-unmasking
    delivers a second interrupt: the gate requires the count to be 2 and the raw
    line to stay high after a FIFO-disabled read. On, it requires 1 and a low line.
  * `ucon-store`: a UCON write must read back as written. Off (the historical
    model) the write is dropped and UCON reads back 0, which the gate requires, so
    an accidental flip of the default fails.

`--uart-drain-refresh on` and `--uart-ucon-store on` add the matching
`-global apple-uart.<name>=on`. The four combinations are independent and each is
pinned. A second sequence feeds two bytes at once: the pop that leaves data must
keep the level high (one more delivery on re-unmask), and only the pop that empties
the FIFO lowers it. A third disables the FIFO, receives one byte and drains it
through URXH, then reads the raw line level (the FIFO-disabled branch of the same
refresh).
Guest RAM survives system_reset, so the scratch words are rewritten with zeros on
every reset; otherwise the second iteration would compare the first one's results.
Firmware is never executed. This qualifies THIS model only.
"""
import argparse
import hashlib
import importlib.util
import errno
import json
import os
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

UART_BASE = 0x385200000      # ADT /arm-io/uart0 reg[0], translated
UART_IRQ = 1092              # ADT /arm-io/uart0 interrupts[0]
UFCON, UCON, UTRSTAT, UFSTAT, URXH = 0x08, 0x04, 0x10, 0x18, 0x24
UFCON_FIFO_ENABLE = 1
UCON_TXTHRESH_ENA = 1 << 13
UCON_WRITTEN = 0x2005        # TX-threshold enable | TX mode IRQ | RX mode IRQ
UCON_TXMODE_IRQ = 1 << 2
UCON_RXMODE_IRQ = 1
UTRSTAT_RESET = 0x6          # Tx_EMPTY | Tx_BUFFER_EMPTY, per the model
INJECTED = 0x5a
PHASE_A_MARK = 0x600d        # ROM -> host: quiet check done, inject now
PHASE_B_MARK = 0x600e        # ROM -> host: first sequence done, inject two bytes at once
PHASE_C_MARK = 0x600f        # ROM -> host: FIFO disabled, inject one byte
TWO_BYTES = bytes([0x41, 0x42])
FIFO_OFF_BYTE = 0x43
HW_STATE = MASK_CLEAR + NUM_IRQS // 32 * 4   # raw input levels, masking ignored
LINE_BIT = 1 << (UART_IRQ & 31)
LINE_WORD = AIC_BASE + HW_STATE + UART_IRQ // 32 * 4
# msr daifset,#2. The value 0xd503425f that this gate used to emit (the AIC delivery and SEP
# mailbox gates still emit it) disassembles as `msr dit,#2`, so IRQs were never masked again
# after the first window. 0xd50342df is DAIFSet (op2 = 6).
DAIFSET_2 = 0xd50342df

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

    def __init__(self, ucon_expected=0, drain_refresh=False):
        self.words, self.expected = [], {}
        self.ucon_expected = ucon_expected
        self.drain_refresh = drain_refresh

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
        self.emit(DAIFSET_2)                   # msr daifset,#2

    def and1(self, register):
        self.emit(0x12000000 | (register << 5) | register)   # and w<r>,w<r>,#1

    def movz(self, register, value):
        require(0 <= value < 0x10000, 'movz immediate')
        self.emit(0xd2800000 | (value << 5) | register)

    def and_mask(self, register, mask):
        """w<register> &= mask, through x1 (clobbered)."""
        self.movz(1, mask)
        self.emit(0x0a000000 | (1 << 16) | (register << 5) | register)  # and w<r>,w<r>,w1

    def line(self, register=23):
        """The raw uart0 input level from AIC HW_STATE, masked to the line's bit."""
        self.read32(LINE_WORD, register)
        self.and_mask(register, LINE_BIT)

    def cbz_back(self, register, target_index):
        displacement = target_index - len(self.words)
        self.emit(0xb4000000 | ((displacement & 0x7ffff) << 5) | register)  # cbz x<r>

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

        # Reset state of the status register, as the model defines it.
        self.read32(UART_BASE + UTRSTAT, 23)
        self.trace('utrstat_reset', UTRSTAT_RESET, register=23)

        # Is a UCON write stored? Asserted: 0 by default (the legacy model drops
        # the write; an accidental default flip must fail) and UCON_WRITTEN with
        # ucon-store on. Written back to zero straight away. With the store on,
        # the write latches the TX-threshold request and raises the line while
        # AIC input 1092 is still masked, and the following zero write lowers it
        # again before the unmask below, so no delivery is expected before data.
        # A -trace 'apple_uart_*' run showed the raise and the lower; the assertion
        # that pins the absence of a delivery is quiet_before_data.
        self.write32(UART_BASE + UFCON, UFCON_FIFO_ENABLE)
        self.write32(UART_BASE + UCON, UCON_WRITTEN)
        self.read32(UART_BASE + UCON, 23)
        self.trace('ucon_readback', self.ucon_expected, register=23)
        self.write32(UART_BASE + UCON, 0)

        # No data yet: unmasking the line must not deliver anything.
        self.unmask(UART_IRQ)
        self.window()
        self.trace('quiet_before_data', 0, register=21)
        self.mov(0, PHASE_A_MARK)
        self.trace('phase_a_done', PHASE_A_MARK)

        # The host now injects one byte; the line must raise exactly one IRQ.
        self.emit(0xd50342ff)                  # msr daifclr,#2
        self.await_count(1)
        self.emit(DAIFSET_2)                   # msr daifset,#2
        self.trace('irq_count', 1, register=21)
        self.trace('irq_event', EVENT_IRQ | UART_IRQ, register=22)

        self.read32(UART_BASE + UTRSTAT, 23)
        self.and1(23)
        self.trace('data_ready_bit', 1, register=23)
        self.read32(UART_BASE + UFSTAT, 23)
        self.emit(0x12000c00 | (23 << 5) | 23)  # and w23,w23,#0xf
        self.trace('rx_fifo_count', 1, register=23)
        self.read32(UART_BASE + URXH, 23)
        self.trace('rx_byte', INJECTED, register=23)
        self.read32(UART_BASE + UTRSTAT, 23)
        self.and1(23)
        self.trace('data_ready_after_drain', 0, register=23)

        # With the FIFO drained the line must have fallen. If the model never
        # refreshed it (as before the URXH refresh), re-unmasking delivers a
        # second IRQ, which this requires not to happen: the count stays at 1.
        # With drain-refresh off the historical model leaves the line high and the
        # count reaches 2: that is pinned too, so a default that silently starts
        # refreshing fails here.
        self.unmask(UART_IRQ)
        self.window()
        self.trace('irq_count_after_drain', 1 if self.drain_refresh else 2, register=21)

        # Two bytes at once. A single os.write is not guaranteed to arrive in one
        # chardev callback, so the ROM waits until the FIFO count reads 2 (IRQs are
        # masked at the CPU meanwhile). Popping the first byte leaves data, so the
        # level must stay high and re-unmasking must deliver exactly once more; only
        # the pop that empties the FIFO lowers it.
        self.mov(0, PHASE_B_MARK)
        self.trace('phase_b_done', PHASE_B_MARK)
        poll = len(self.words)
        self.read32(UART_BASE + UFSTAT, 23)
        self.emit(0x12000c00 | (23 << 5) | 23)  # and w23,w23,#0xf
        self.emit(0x71000aff)                   # cmp w23,#2
        self.branch(poll, 1)                    # b.ne
        self.read32(UART_BASE + URXH, 23)
        self.trace('two_first_byte', TWO_BYTES[0], register=23)
        self.read32(UART_BASE + UTRSTAT, 23)
        self.and1(23)
        self.trace('two_data_ready_after_first_pop', 1, register=23)
        self.window()
        self.trace('two_irq_count_first', 2, register=21)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('two_irq_count_after_reunmask', 3, register=21)
        self.read32(UART_BASE + URXH, 23)
        self.trace('two_second_byte', TWO_BYTES[1], register=23)
        self.read32(UART_BASE + UTRSTAT, 23)
        self.and1(23)
        self.trace('two_data_ready_after_second_pop', 0, register=23)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('two_irq_count_after_final_drain', 3 if self.drain_refresh else 4,
                   register=21)

        # FIFO disabled: a byte received now is held in URXH alone, and the URXH read
        # that clears data-ready is the other branch of the refresh. The raw level is
        # read from the AIC HW_STATE bank (masking is irrelevant to it).
        self.write32(UART_BASE + UFCON, 0)
        self.mov(0, PHASE_C_MARK)
        self.trace('phase_c_done', PHASE_C_MARK)
        poll = len(self.words)
        self.read32(UART_BASE + UTRSTAT, 23)
        self.and1(23)
        self.cbz_back(23, poll)                 # until data-ready
        self.read32(UART_BASE + URXH, 23)
        self.trace('fifooff_byte', FIFO_OFF_BYTE, register=23)
        self.read32(UART_BASE + UTRSTAT, 23)
        self.and1(23)
        self.trace('fifooff_data_ready_after_read', 0, register=23)
        self.line()
        self.trace('fifooff_line_after_read', 0 if self.drain_refresh else LINE_BIT,
                   register=23)
        # system_reset does not lower a device's output line, and with the refresh off
        # the line is still high here: a UCON write refreshes it (a stored zero or a
        # dropped write both call apple_uart_update_irq()), so the next iteration
        # starts low.
        self.write32(UART_BASE + UCON, 0)
        self.line()
        self.trace('fifooff_line_after_cleanup', 0, register=23)

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


def run(binary, components, output, ucon_store='off', drain_refresh='off'):
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

    rom = ROM(UCON_WRITTEN if ucon_store == 'on' else 0, drain_refresh == 'on')
    content = rom.build()
    rom_path = output / 'aic-hardware-input.rom'
    rom_path.write_bytes(content)
    # Guest RAM survives system_reset (MEASURED: the second iteration used to see the
    # first run's marks and completion word before the ROM had executed a single
    # instruction, so its "pass" compared stale values). A second loader blob rewrites
    # zeros over the scratch words and the fault counter on every reset.
    zero_path = output / 'scratch-zero.bin'
    zero_path.write_bytes(bytes(0x508))
    report = {'scope': 'Modern AIC hardware input path via the uart0 line; owned ROM only',
              'binary': str(binary), 'binary_sha256': digest(binary)['sha256'],
              'rom_sha256': digest(rom_path)['sha256'],
              'component_hashes_before': before, 'passes': [], 'passed': False,
              'firmware_executed': False, 'ios_boot_claim': False,
              'declared_event_offset': hex(EVENT),
              'event_offset_is_apple_documented': False,
              'line': {'device': '/arm-io/uart0', 'adt_interrupt': UART_IRQ,
                       'base': hex(UART_BASE)},
              'uart_ucon_store': ucon_store,
              'uart_drain_refresh': drain_refresh,
              'uart_model_quirks_are_measured_not_asserted': False,
              'asserted_uart_behaviours': {
                  'irq_count_after_drain': 1 if drain_refresh == 'on' else 2,
                  'two_irq_count_after_final_drain': 3 if drain_refresh == 'on' else 4,
                  'fifooff_line_after_read': 0 if drain_refresh == 'on' else hex(LINE_BIT),
                  'ucon_readback': hex(UCON_WRITTEN if ucon_store == 'on' else 0)},
              'guest_driver_exercised': False,
              'owned_range': {'start': hex(BASE), 'end': hex(PROBE_END)},
              'limits': {'wall_seconds': MAX_WALL, 'cpu_seconds': 30,
                         'log_bytes': MAX_LOG}}
    process = qmp = None
    log_path = output / 'emulator.log'
    try:
        with tempfile.TemporaryDirectory(prefix='aic-hw-input-gate-') as temporary:
            scratch = Path(temporary)
            uart_pipe = scratch / 'uart'
            os.mkfifo(str(uart_pipe) + '.in')
            os.mkfifo(str(uart_pipe) + '.out')
            machine = 'apple-modern,' + ','.join(
                name + '=' + str(asset_paths[asset]) for name, asset in
                zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
            machine += ',prepare-only=true,modern-aic=on,boot-command-line=' + board.COMMAND_LINE
            argv = [str(binary), '-M', machine, '-m', '8G', '-smp', '1',
                    '-nodefaults', '-display', 'none', '-serial', 'pipe:' + str(uart_pipe),
                    '-monitor', 'none',
                    '-device', f'loader,file={rom_path},addr={BASE},cpu-num=0,force-raw=true',
                    '-device', f'loader,file={zero_path},addr={SCRATCH},force-raw=true',
                    '-S', '-qmp', 'stdio']
            for name, value in (('ucon-store', ucon_store), ('drain-refresh', drain_refresh)):
                if value == 'on':
                    argv[1:1] = ['-global', 'apple-uart.' + name + '=on']
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
                injector = None
                for _ in range(100):
                    try:
                        injector = os.open(str(uart_pipe) + '.in',
                                           os.O_WRONLY | os.O_NONBLOCK)
                        break
                    except OSError as error:
                        require(error.errno == errno.ENXIO, 'UART pipe open')
                        time.sleep(0.05)     # emulator has not opened its end yet
                require(injector is not None, 'UART pipe reader appeared')
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
                    qmp.request('pmemsave', {'val': SCRATCH, 'size': 0x508,
                                             'filename': str(verify)})
                    require(verify.read_bytes() == bytes(0x508),
                            'Scratch is zero before cont (no stale first-run values)')
                    verify.unlink()
                    qmp.request('cont')

                    deadline = time.monotonic() + 10
                    dump = scratch / 'scratch.bin'
                    labels = list(rom.expected)
                    marks = {'phase_a_done': (PHASE_A_MARK, bytes([INJECTED])),
                             'phase_b_done': (PHASE_B_MARK, TWO_BYTES),
                             'phase_c_done': (PHASE_C_MARK, bytes([FIFO_OFF_BYTE]))}
                    injected = set()
                    while True:
                        guard()
                        qmp.request('stop')
                        qmp.request('pmemsave', {'val': SCRATCH,
                                                 'size': len(rom.expected) * 8,
                                                 'filename': str(dump)})
                        raw = dump.read_bytes()
                        # Our own stop/cont polling is what produces these events;
                        # the 10 s deadline bounds the loop, so drain them instead
                        # of tripping the harness's 64-event cap, which would
                        # replace the stalled-step diagnostic with a generic error.
                        qmp.events.clear()
                        for label, (mark, payload) in marks.items():
                            if label not in injected and len(raw) >= len(rom.expected) * 8 and \
                                    struct.unpack_from('<Q', raw, labels.index(label) * 8)[0] == mark:
                                # phase_a: the ROM has proven the line quiet with no data.
                                os.write(injector, payload)
                                injected.add(label)
                        done = len(raw) >= len(rom.expected) * 8 and struct.unpack_from(
                            '<Q', raw, (len(rom.expected) - 1) * 8)[0] == 0xfeedfacecafebeef
                        if done:
                            break
                        if time.monotonic() >= deadline:
                            progress = ', '.join(
                                '%s=%#x' % (label, struct.unpack_from('<Q', raw, i * 8)[0])
                                for i, label in enumerate(labels)
                                if len(raw) >= (i + 1) * 8 and
                                struct.unpack_from('<Q', raw, i * 8)[0])
                            require(False, 'Owned ROM did not complete (injected=%s); '
                                    'nonzero progress: %s' % (sorted(injected), progress))
                        qmp.request('cont')
                        time.sleep(0.05)

                    observed, failed = {}, []
                    for index, (label, expect) in enumerate(rom.expected.items()):
                        value = struct.unpack_from('<Q', raw, index * 8)[0]
                        observed[label] = hex(value)
                        # Collect every mismatch rather than stopping at the first,
                        # so a negative oracle shows exactly which checks it trips.
                        if expect is not None and value != expect:
                            shown = repr(expect) if expect < 10 else hex(expect)
                            failed.append(f'{label}: expected {shown}, observed {value:#x}')
                    faults = scratch / 'faults.bin'
                    qmp.request('pmemsave', {'val': SCRATCH + 0x500, 'size': 8,
                                             'filename': str(faults)})
                    require(struct.unpack('<Q', faults.read_bytes())[0] == 0,
                            'No unexpected exception was taken')
                    ucon = int(observed['ucon_readback'], 16)
                    drained = int(observed['irq_count_after_drain'], 16)
                    report['passes'].append({'iteration': iteration,
                                             'measured_ucon_write_stored': ucon != 0,
                                             'measured_line_stuck_after_drain': drained > 1,
                                             'after_system_reset': bool(iteration),
                                             'observed': observed,
                                             'failed_checks': failed,
                                             'completed': not failed})
                    require(not failed, '; '.join(failed))
                qmp.request('quit')
                code = process.wait(timeout=10)
                require(code == 0, f'Emulator exited {code}')
                process = None
        after = {name: digest(path) for name, path in asset_paths.items()}
        require(after == before, 'Firmware components are unchanged')
        report['component_hashes_after'] = after
        report['passed'] = (len(report['passes']) == 2 and
                            all(item['completed'] for item in report['passes']))
    except Exception as error:
        # A failing run still leaves its evidence: which checks failed, and the
        # emulator's last words (an unknown property, for one, stops it at creation).
        report['error'] = str(error)
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
    if not report['passed'] and log_path.exists():
        report['emulator_log_tail'] = log_path.read_text(errors='replace')[-600:]
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps({'passed': report['passed'],
                      'cpu_delivery_passes': len(report['passes']),
                      'binary_sha256': report['binary_sha256'],
                      'uart_ucon_store': ucon_store,
                      'uart_drain_refresh': drain_refresh,
                      'failed_checks': [check for item in report['passes']
                                        for check in item['failed_checks']],
                      'error': report.get('error'),
                      'event_offset_is_apple_documented': False}))
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--uart-ucon-store', choices=('off', 'on'), default='off',
                        help='off: the shipped default, UCON must read back 0; on: '
                             'pass -global apple-uart.ucon-store=on, UCON must read '
                             'back as written')
    parser.add_argument('--uart-drain-refresh', choices=('off', 'on'), default='off',
                        help='off: the shipped default, the line stays high after a '
                             'drain (second delivery on re-unmask, count 2); on: pass '
                             '-global apple-uart.drain-refresh=on, the line falls '
                             '(count 1)')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    return run(args.binary, args.components, args.output_dir, args.uart_ucon_store,
               args.uart_drain_refresh)


if __name__ == '__main__':
    sys.exit(main())
