#!/usr/bin/env python3
"""Qualify the Apple UART's two opt-in behaviours against storms, hangs and drift.

Two qdev properties exist, both default off, both off on every shipped board:

  * `ucon-store`: store UCON writes, so for the first time a guest can enable the
    TX-threshold, RX-threshold and RX-timeout interrupts. Neither validated guest
    ever does (UCON is written 0x405 only), so this gate is the only thing that
    exercises those paths.
  * `drain-refresh`: re-evaluate the interrupt line when a URXH read empties the
    receive FIFO (or on any FIFO-disabled read).

`--mode on` (the default) passes both and ASSERTS the contained behaviour (cases (a)
to (j), plus the recorded probes (l)). `--mode legacy` passes neither, runs only the
probes (l), and requires every observation and the RX-timeout trace to equal the record
taken from the pinned v10 binary and from the rebuilt base tree. That is a pin on the
default, not an endorsement of it: the historical model drops UCON word writes and
leaves a line stale, and this mode exists so a default that drifts from v10 FAILS
instead of being argued unreachable (a halfword store to UART+6 reaches UCON without
any property, case (l), so "unreachable" was false). Cases (a) to (j) are not run in
legacy mode on purpose: on the historical model a stale data-ready bit satisfies every
wait, so the ROM races the host's byte injections and the observations would be
timing-dependent (measured: bytes read one case late). The probes (l) start from a reset
FIFO and wait for each byte, so they are deterministic.

The risks the `on` mode guards:

  * a TX storm: with Tx_EMPTY and Tx_BUFFER_EMPTY in the interrupt mask, enabling
    bit 13 raised the line at once and the kernel's acknowledge (UTRSTAT <- 0x20)
    could not clear them, so a driver that acks through UTRSTAT only and
    re-unmasks every time was delivered the interrupt forever;
  * a stuck RX timeout: the timeout latched with an EMPTY FIFO and held the line,
    and a timeout latched WITH data outlived the drain;
  * a stale level after a drain, or a refresh that drops another pending source.

The owned ROM acts like a naive driver on uart0 (ADT interrupt 1092): its IRQ
handler reads the AIC event register (which masks the line), counts the delivery
against a hard cap, optionally acknowledges through UTRSTAT, and RE-UNMASKS the
line every time. The line level itself is read from the AIC HW_STATE bank, which
reports the raw input regardless of masking. Cases, in order:

  (a) TX threshold: UCON <- 0x2405 raises the line and delivers exactly once; the
      level stays high until acknowledged; UTRSTAT <- 0x20 with bit 13 STILL SET
      clears bit 5 and lowers the line; re-unmasking delivers nothing; clearing
      and re-enabling bit 13 delivers exactly one more (the request is
      edge-latched on the enable) and the naive handler's ack ends it. The
      edge-latch checks (a_no_second_delivery, a_rearm_delivery) pin a DECLARED
      choice, not a measurement: real hardware may be level-based on FIFO fill, in
      which case a faithful model would fail them for the right reason, and a
      guest that relies on a re-interrupt per refill would stall after one burst.
  (b) RX timeout enable plus one injected byte, drained: the timer is made long
      (about 109 ms of virtual time) so it fires AFTER the drain, with no data.
      The ROM waits 250 ms of virtual time with the line unmasked and a naive
      handler, and requires no delivery, a clear Rx_TIMEOUT bit and a low line. The
      emulator's own apple_uart_rx_timeout trace proves the timer fired late
      (UTRSTAT then reads 0x6, no data-ready).
  (c) UCON <- 0x405, the only value guests write: one delivery for one byte.
  (d) RX-threshold enable plus a byte: Rx_THRESH is RECORDED, not asserted (the
      minimum trigger level, 32, exceeds the 15-entry FIFO, so it is unreachable).
  (e) UFCON Rx-FIFO reset with a byte pending: RECORDED, not asserted (a residual the
      model keeps: the reset empties the FIFO but leaves data-ready set and the line
      high, and an empty-FIFO read does not refresh it).
  (f) the realistic timeout: the timer fires WITH data pending (status 0x9, line
      high), then the guest drains: Rx_TIMEOUT must clear and the line must fall.
      Case (b) cannot see this, because its timer fires after the drain.
  (g) the same, but the guest acknowledges the timeout through UTRSTAT <- 0x8 first:
      bit 3 clears, data-ready keeps the line high, the drain lowers it.
  (h) TX threshold: rewriting UCON while bit 13 is already set must NOT re-arm.
  (i) TX threshold: bit 13 with the FIFO disabled is not armed; enabling the FIFO
      arms it once; rewriting UFCON while enabled does not re-arm.
  (j) a drain while the TX request is pending must keep the line high (the refresh
      re-evaluates the whole mask; a bare lower would drop the TX request), and the
      acknowledge then lowers it.
  (l) legacy probes, RECORDED (asserted only: the line is low at the end). A halfword
      store to UART+6 reaches UCON through the generic register path with or without
      `ucon-store`. (l1) bit 13 that way: whether enabling the FIFO arms the TX request,
      the line after a UCON word write, and whether UTRSTAT <- 0x20 clears bit 5. (l2) a
      late timeout through the same path (timeout enable, one byte received and drained
      at once): the historical rule latches Rx_TIMEOUT with the enable alone and the
      line follows. (l3) one more byte received and drained with the timer off: whether
      Rx_TIMEOUT survives the drain. Each ungated behaviour changes at least one of these
      values, which is what proves it really is gated.

Two iterations with a system_reset between them. The scratch words are zeroed on
every reset by a second loader blob (guest RAM otherwise survives reset, which
would hand the second iteration the first one's results). Cases (f) to (l) keep
CPU interrupts closed and read the raw line level, so they do not depend on AIC mask
state left by earlier cases. Firmware is never executed. This qualifies THIS model only.
"""
import argparse
import errno
import importlib.util
import json
import os
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


hw = module('aic_hardware_input_gate', 'test-apple-modern-aic-hardware-input-qemu.py')
board = hw.board
require = hw.require

BASE, SCRATCH = hw.BASE, hw.SCRATCH
AIC_BASE, UART_BASE, UART_IRQ = hw.AIC_BASE, hw.UART_BASE, hw.UART_IRQ
UCON, UFCON, UTRSTAT, UFSTAT, URXH = hw.UCON, hw.UFCON, hw.UTRSTAT, hw.UFSTAT, hw.URXH
ULCON, UBRDIV = 0x00, 0x28
HW_STATE = hw.MASK_CLEAR + hw.NUM_IRQS // 32 * 4      # raw input levels, masking ignored
LINE_BIT = 1 << (UART_IRQ & 31)
LINE_WORD = AIC_BASE + HW_STATE + UART_IRQ // 32 * 4
ACK_TX_THRESH = 0x20          # what XNU writes to UTRSTAT to acknowledge the TX threshold
CAP = 8                       # hard cap on deliveries counted by the handler
EVENT_UART = hw.EVENT_IRQ | UART_IRQ
MAX_LOG, MAX_WALL = 1024 * 1024, 60
ITERATION_SECONDS = 25
CLEAR_STATUS = 0x38           # UTRSTAT bits 3-5: Rx timeout, Rx threshold, Tx threshold
UTRSTAT_BIT5 = 0x20

# Host injections: label of the ROM's "ready" mark -> byte to inject.
MARKS = {'phase_b_ready': (0x600d0b, 0x62), 'phase_c_ready': (0x600d0c, 0x63),
         'phase_d_ready': (0x600d0d, 0x64), 'phase_e_ready': (0x600d0e, 0x65),
         'phase_f_ready': (0x600d0f, 0x66), 'phase_g_ready': (0x600d10, 0x67),
         'phase_j_ready': (0x600d11, 0x6a), 'phase_l_ready': (0x600d12, 0x6c),
         'phase_m_ready': (0x600d13, 0x6d)}

# `--mode legacy` requires every label of every iteration, and the RX-timeout trace
# states, to equal the record below. It was taken from the pinned v10 binary (b498aa9b...)
# and from the rebuilt base tree, which behave identically; see the evidence README for
# provenance. Iteration 0 (a fresh start) is recorded in full. Iteration 1 differs only
# in the delta: system_reset leaves the UART line high (MEASURED), so the first window of
# the second iteration takes a delivery the first did not.
# BEGIN LEGACY RECORD (regenerated by the recording step; do not edit by hand)
LEGACY_TIMEOUT_STATES = ['0x26', '0x26']
LEGACY_ITERATION_0 = {
    'completion': '0xfeedfacecafebeef',
    'enabled_no_interrupt': '0x0',
    'l_bit5_after_ack': '0x20',
    'l_bit5_after_ucon_word_write': '0x20',
    'l_bit5_after_ufcon_enable': '0x0',
    'l_late_byte': '0x6c',
    'l_line_after_ack': '0x10',
    'l_line_after_late_timer': '0x10',
    'l_line_after_ucon_word_write': '0x10',
    'l_line_after_ufcon_enable': '0x0',
    'l_line_low_after_cleanup': '0x0',
    'l_second_byte': '0x6d',
    'l_status_after_late_timer': '0x8',
    'l_status_after_second_drain': '0x8',
    'l_ucon_after_halfword_store': '0x2000',
    'l_ucon_after_word_write': '0x2000',
    'phase_l_ready': '0x600d12',
    'phase_m_ready': '0x600d13',
}
LEGACY_ITERATION_1_DELTA = {

}
LEGACY_OBSERVED = [LEGACY_ITERATION_0, {**LEGACY_ITERATION_0, **LEGACY_ITERATION_1_DELTA}]
# END LEGACY RECORD

# Why a failing check might fail for a reason other than the model.
HINTS = {'b_status_before_drain':
         ' (timeout fired before the drain: the case did not exercise a late timer; '
         'the host or guest stalled, rerun)',
         'f_status_timeout_pending':
         ' (the timeout did not fire within a second of virtual time while data was '
         'pending: either the model or a stalled host; rerun before believing it)',
         'g_status_timeout_pending':
         ' (the timeout did not fire within a second of virtual time while data was '
         'pending: either the model or a stalled host; rerun before believing it)'}

hw.REGS.update({'CNTPCT_EL0': (3, 3, 14, 0, 1), 'CNTFRQ_EL0': (3, 3, 14, 0, 0)})


class StormROM(hw.ROM):
    """Adds the few instructions the storm program needs to the shared emitter."""

    def __init__(self, legacy=False):
        super().__init__()
        self.legacy = legacy

    def status(self, mask, register=23):
        self.read32(UART_BASE + UTRSTAT, register)
        self.and_mask(register, mask)

    def cbz_forward(self, register, nonzero=False):
        index = len(self.words)
        self.emit((0xb5000000 if nonzero else 0xb4000000) | register)
        return index

    def bcond_forward(self, condition):
        index = len(self.words)
        self.emit(0x54000000 | condition)
        return index

    def bind(self, index):
        self.words[index] |= ((len(self.words) - index) & 0x7ffff) << 5

    def open_irq(self):
        self.emit(0xd50342ff)                  # msr daifclr,#2

    def close_irq(self):
        self.emit(hw.DAIFSET_2)                # msr daifset,#2

    def deadline(self, shift):
        """x27 = CNTPCT + CNTFRQ >> shift (a virtual-time deadline)."""
        self.emit(hw.sysreg('CNTFRQ_EL0', 27, True))
        self.emit(0xd340fc00 | (shift << 16) | (27 << 5) | 27)  # lsr x27,x27,#shift
        self.emit(hw.sysreg('CNTPCT_EL0', 28, True))
        self.emit(0x8b000000 | (28 << 16) | (27 << 5) | 27)     # add x27,x27,x28

    def await_at_least(self, count):
        """IRQs open until x21 >= count or half a second of virtual time passes. The
        bound keeps a model that never delivers from hanging the ROM, so the failing
        checks are named instead of the run timing out."""
        self.deadline(1)
        self.open_irq()
        poll = len(self.words)
        self.emit(0xf10002bf | (count << 10))  # cmp x21,#count
        reached = self.bcond_forward(2)        # b.hs: delivered
        self.emit(hw.sysreg('CNTPCT_EL0', 28, True))
        self.emit(0xeb00001f | (27 << 16) | (28 << 5))          # cmp x28,x27
        self.branch(poll, 3)                   # b.lo poll
        self.bind(reached)
        self.close_irq()

    def await_status(self, mask, shift):
        """Poll UTRSTAT with CPU interrupts closed until any bit of `mask` is set, or
        CNTFRQ >> shift of virtual time passes. Bounded, so a model that never sets it
        fails a named check instead of hanging the ROM."""
        self.deadline(shift)
        poll = len(self.words)
        self.read32(UART_BASE + UTRSTAT, 23)
        self.and_mask(23, mask)
        done = self.cbz_forward(23, nonzero=True)
        self.emit(hw.sysreg('CNTPCT_EL0', 28, True))
        self.emit(0xeb00001f | (27 << 16) | (28 << 5))          # cmp x28,x27
        self.branch(poll, 3)                                    # b.lo poll
        self.bind(done)

    def wait_closed(self, shift):
        """Spin with CPU interrupts closed for CNTFRQ >> shift of virtual time."""
        self.deadline(shift)
        loop = len(self.words)
        self.emit(hw.sysreg('CNTPCT_EL0', 28, True))
        self.emit(0xeb00001f | (27 << 16) | (28 << 5))          # cmp x28,x27
        self.branch(loop, 3)                                    # b.lo loop

    def halfword(self, address, value):
        """strh w0,[x1]: a 2-byte store, which the model's switch sends to its
        generic register path whatever the offset."""
        self.mov(1, address)
        self.mov(0, value)
        self.emit(0x79000020)

    def policy(self, ack, naive):
        """Handler behaviour: x25 = UTRSTAT acknowledge value (0 = none), x26 = re-unmask."""
        self.mov(25, ack)
        self.mov(26, 1 if naive else 0)

    def wait_virtual(self):
        """IRQs open for a quarter of a second of VIRTUAL time (CNTPCT, which follows
        the same clock as the UART's timer and stands still while the host has the
        machine stopped)."""
        self.deadline(2)
        self.open_irq()
        loop = len(self.words)
        self.emit(hw.sysreg('CNTPCT_EL0', 28, True))
        self.emit(0xeb00001f | (27 << 16) | (28 << 5))          # cmp x28,x27
        self.branch(loop, 3)                                    # b.lo loop
        self.close_irq()

    def mark(self, label):
        value = MARKS[label][0]
        self.mov(0, value)
        self.trace(label, value)

    def cases_a_to_e(self):
        # ---- (a) TX threshold -------------------------------------------------
        self.write32(UART_BASE + UFCON, hw.UFCON_FIFO_ENABLE)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('a_quiet_before_enable', 0, register=21)
        self.status(CLEAR_STATUS)
        self.trace('a_status_bits_clear', 0, register=23)
        self.write32(UART_BASE + UCON, 0x2405)
        self.line()
        self.trace('a_line_high_on_enable', LINE_BIT, register=23)
        self.status(UTRSTAT_BIT5)
        self.trace('a_tx_thresh_latched', UTRSTAT_BIT5, register=23)
        self.policy(0, False)
        self.window()
        self.trace('a_first_delivery', 1, register=21)
        self.trace('a_event', EVENT_UART, register=22)
        self.line()
        self.trace('a_level_high_until_acked', LINE_BIT, register=23)
        # The kernel-style acknowledge, with bit 13 still set.
        self.write32(UART_BASE + UTRSTAT, ACK_TX_THRESH)
        self.status(UTRSTAT_BIT5)
        self.trace('a_bit5_cleared_by_ack', 0, register=23)
        self.line()
        self.trace('a_line_low_after_ack', 0, register=23)
        self.read32(UART_BASE + UCON, 23)
        self.trace('a_ucon_unchanged_by_ack', 0x2405, register=23)
        # A naive driver: acknowledges through UTRSTAT only and re-unmasks every time.
        self.policy(ACK_TX_THRESH, True)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('a_no_second_delivery', 1, register=21)
        self.write32(UART_BASE + UCON, 0x0405)  # disable ...
        self.window()
        self.trace('a_quiet_while_disabled', 1, register=21)
        self.write32(UART_BASE + UCON, 0x2405)  # ... and re-enable: one more request
        self.window()
        self.trace('a_rearm_delivery', 2, register=21)
        self.status(UTRSTAT_BIT5)
        self.trace('a_bit5_after_rearm', 0, register=23)
        self.line()
        self.trace('a_line_low_after_rearm', 0, register=23)
        self.window()
        self.trace('a_no_storm_after_rearm', 2, register=21)

        # ---- (b) RX timeout, firing after the drain ---------------------------
        self.write32(UART_BASE + ULCON, 3)
        self.write32(UART_BASE + UBRDIV, 0x7ff)  # model word time ~13.7 ms
        self.write32(UART_BASE + UTRSTAT, CLEAR_STATUS)
        self.policy(0, False)
        self.write32(UART_BASE + UCON, 0x8205)   # timeout enable; interval nibble 8
        self.line()
        self.trace('b_line_low_before_data', 0, register=23)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('b_quiet_before_data', 2, register=21)
        self.mark('phase_b_ready')
        self.await_at_least(3)
        self.trace('b_delivery', 3, register=21)
        self.status(0x9)
        self.trace('b_status_before_drain', 1, register=23)
        self.read32(UART_BASE + URXH, 23)
        self.trace('b_byte', MARKS['phase_b_ready'][1], register=23)
        self.status(0x9)
        self.trace('b_status_after_drain', 0, register=23)
        self.line()
        self.trace('b_line_low_after_drain', 0, register=23)
        self.policy(0, True)
        self.unmask(UART_IRQ)
        self.wait_virtual()
        self.trace('b_no_delivery_after_drain', 3, register=21)
        self.status(0x8)
        self.trace('b_timeout_bit_after_wait', 0, register=23)
        self.line()
        self.trace('b_line_low_after_wait', 0, register=23)

        # ---- (c) the only value guests write ----------------------------------
        self.write32(UART_BASE + UCON, 0x0405)
        self.write32(UART_BASE + UTRSTAT, CLEAR_STATUS)
        self.read32(UART_BASE + UCON, 23)
        self.trace('c_ucon_readback', 0x405, register=23)
        self.line()
        self.trace('c_line_low', 0, register=23)
        self.policy(0, False)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('c_quiet_before_data', 3, register=21)
        self.mark('phase_c_ready')
        self.await_at_least(4)
        self.trace('c_delivery', 4, register=21)
        self.status(0x39)
        self.trace('c_status_after_delivery', 1, register=23)
        self.read32(UART_BASE + URXH, 23)
        self.trace('c_byte', MARKS['phase_c_ready'][1], register=23)
        self.line()
        self.trace('c_line_low_after_drain', 0, register=23)
        self.policy(0, True)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('c_no_second_delivery', 4, register=21)

        # ---- (d) RX threshold enable: recorded --------------------------------
        self.write32(UART_BASE + UCON, 0x1405)
        self.line()
        self.trace('d_line_low', 0, register=23)
        self.policy(0, False)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('d_quiet_before_data', 4, register=21)
        self.mark('phase_d_ready')
        self.await_at_least(5)
        self.trace('d_delivery', 5, register=21)
        self.status(0x10)
        self.trace('d_rx_thresh_bit', None, register=23)   # recorded, not asserted
        self.read32(UART_BASE + UFSTAT, 23)
        self.and_mask(23, 0xf)
        self.trace('d_rx_fifo_count', 1, register=23)
        self.read32(UART_BASE + URXH, 23)
        self.trace('d_byte', MARKS['phase_d_ready'][1], register=23)
        self.line()
        self.trace('d_line_low_after_drain', 0, register=23)

        # ---- (e) UFCON Rx-FIFO reset with data pending: RECORDED, not asserted ----
        # A residual the model keeps: the reset empties the FIFO but leaves data-ready
        # set, and nothing refreshes the line. Inferred from the source, recorded here.
        self.write32(UART_BASE + UCON, 0x0405)
        self.policy(0, False)
        self.unmask(UART_IRQ)
        self.window()
        self.mark('phase_e_ready')
        self.await_at_least(6)
        self.write32(UART_BASE + UFCON, 0x3)    # FIFO enable | Rx FIFO reset
        self.read32(UART_BASE + UFSTAT, 23)
        self.and_mask(23, 0xf)
        self.trace('e_fifo_count_after_reset', None, register=23)
        self.status(0x1)
        self.trace('e_data_ready_after_reset', None, register=23)
        self.line()
        self.trace('e_line_after_reset', None, register=23)
        self.read32(UART_BASE + URXH, 23)       # empty FIFO: the error branch, no refresh
        self.trace('e_empty_read_value', None, register=23)
        self.status(0x1)
        self.trace('e_data_ready_after_empty_read', None, register=23)
        self.unmask(UART_IRQ)
        self.window()
        self.trace('e_count_after_reunmask', None, register=21)
        # Leave the line low. system_reset does not lower a device's output (MEASURED: the
        # AIC input stayed high into the next iteration, which then took a delivery before
        # it had enabled anything), so the ROM must not end with the line high. With the
        # FIFO disabled a URXH read clears data-ready and refreshes the line.
        self.write32(UART_BASE + UFCON, 0x0)
        self.read32(UART_BASE + URXH, 23)
        self.line()
        self.trace('e_line_low_after_cleanup', 0, register=23)

    def cases_f_to_j(self):
        # Cases (f) to (l) keep CPU interrupts closed and read the raw line level
        # (the AIC HW_STATE bank ignores masking), so they do not depend on what
        # earlier cases left masked in the AIC. The delivery counter is restarted so
        # an earlier case's count cannot leak into a later expectation.
        self.mov(21, 0)
        self.policy(0, False)
        self.write32(UART_BASE + UFCON, hw.UFCON_FIFO_ENABLE)
        self.write32(UART_BASE + UCON, 0x0405)  # no enable bits: also deletes any timer
        self.write32(UART_BASE + UTRSTAT, CLEAR_STATUS)

        # ---- (f) the RX timeout fires WITH data pending, then a drain ---------
        # Interval nibble 8 of UBRDIV 0x7ff's word time, as in (b): about 109 ms. The
        # ROM waits for the timeout BIT (bounded to a second of virtual time), not for
        # a fixed delay, so a slow host cannot make it look at the wrong moment.
        self.write32(UART_BASE + UCON, 0x8205)
        self.line()
        self.trace('f_line_low_before_data', 0, register=23)
        self.mark('phase_f_ready')
        self.await_status(0x8, 0)
        self.status(0x9)
        self.trace('f_status_timeout_pending', 0x9, register=23)
        self.line()
        self.trace('f_line_high_timeout_pending', LINE_BIT, register=23)
        self.read32(UART_BASE + URXH, 23)
        self.trace('f_byte', MARKS['phase_f_ready'][1], register=23)
        self.status(0x9)
        self.trace('f_status_after_drain', 0, register=23)
        self.line()
        self.trace('f_line_low_after_drain', 0, register=23)

        # ---- (g) the same, acknowledged through UTRSTAT before the drain ------
        self.mark('phase_g_ready')
        self.await_status(0x8, 0)
        self.status(0x9)
        self.trace('g_status_timeout_pending', 0x9, register=23)
        self.write32(UART_BASE + UTRSTAT, 0x8)  # acknowledge the timeout only
        self.status(0x8)
        self.trace('g_timeout_bit_cleared_by_ack', 0, register=23)
        self.status(0x1)
        self.trace('g_data_ready_survives_ack', 1, register=23)
        self.line()
        self.trace('g_line_high_data_pending', LINE_BIT, register=23)
        self.read32(UART_BASE + URXH, 23)
        self.trace('g_byte', MARKS['phase_g_ready'][1], register=23)
        self.line()
        self.trace('g_line_low_after_drain', 0, register=23)

        # ---- (h) TX threshold: a UCON rewrite while enabled does not re-arm ---
        self.write32(UART_BASE + UCON, 0x0405)
        self.write32(UART_BASE + UTRSTAT, CLEAR_STATUS)
        self.line()
        self.trace('h_line_low_before', 0, register=23)
        self.write32(UART_BASE + UCON, 0x2405)
        self.status(UTRSTAT_BIT5)
        self.trace('h_armed_on_enable', UTRSTAT_BIT5, register=23)
        self.write32(UART_BASE + UTRSTAT, ACK_TX_THRESH)
        self.status(UTRSTAT_BIT5)
        self.trace('h_cleared_by_ack', 0, register=23)
        self.line()
        self.trace('h_line_low_after_ack', 0, register=23)
        self.write32(UART_BASE + UCON, 0x2405)  # bit 13 already set: no new edge
        self.status(UTRSTAT_BIT5)
        self.trace('h_no_rearm_on_ucon_rewrite', 0, register=23)
        self.line()
        self.trace('h_line_low_after_rewrite', 0, register=23)

        # ---- (i) TX threshold and the FIFO enable -----------------------------
        self.write32(UART_BASE + UFCON, 0)       # FIFO disabled, bit 13 still set
        self.status(UTRSTAT_BIT5)
        self.trace('i_clear_with_fifo_off', 0, register=23)
        self.write32(UART_BASE + UCON, 0x2405)
        self.status(UTRSTAT_BIT5)
        self.trace('i_not_armed_with_fifo_off', 0, register=23)
        self.line()
        self.trace('i_line_low_with_fifo_off', 0, register=23)
        self.write32(UART_BASE + UFCON, hw.UFCON_FIFO_ENABLE)   # the enable arms it
        self.status(UTRSTAT_BIT5)
        self.trace('i_armed_on_fifo_enable', UTRSTAT_BIT5, register=23)
        self.line()
        self.trace('i_line_high_on_fifo_enable', LINE_BIT, register=23)
        self.write32(UART_BASE + UTRSTAT, ACK_TX_THRESH)
        self.line()
        self.trace('i_line_low_after_ack', 0, register=23)
        self.write32(UART_BASE + UFCON, hw.UFCON_FIFO_ENABLE)   # already enabled
        self.status(UTRSTAT_BIT5)
        self.trace('i_no_rearm_on_ufcon_rewrite', 0, register=23)
        self.line()
        self.trace('i_line_low_after_ufcon_rewrite', 0, register=23)

        # ---- (j) a drain while the TX request is pending ----------------------
        self.write32(UART_BASE + UCON, 0x0405)
        self.write32(UART_BASE + UTRSTAT, CLEAR_STATUS)
        self.write32(UART_BASE + UCON, 0x2405)
        self.line()
        self.trace('j_line_high_tx_pending', LINE_BIT, register=23)
        self.mark('phase_j_ready')
        self.await_status(0x1, 0)
        self.status(0x1)
        self.trace('j_data_ready', 1, register=23)
        self.read32(UART_BASE + URXH, 23)
        self.trace('j_byte', MARKS['phase_j_ready'][1], register=23)
        self.status(0x1)
        self.trace('j_data_ready_after_drain', 0, register=23)
        self.line()
        self.trace('j_line_high_tx_still_pending', LINE_BIT, register=23)
        self.write32(UART_BASE + UTRSTAT, ACK_TX_THRESH)
        self.line()
        self.trace('j_line_low_after_ack', 0, register=23)

    def probes_l(self):
        # ---- (l) RECORDED: a halfword store reaches UCON without any property ---
        # The model's switch sends every offset it does not name, 2-byte stores to
        # UART+6 included, to the generic register path, which stores the value into
        # the UCON slot whether or not `ucon-store` is on. So the legacy UCON-dependent
        # code is reachable in the DEFAULT model, and "unreachable while UCON stays 0"
        # was never true. Everything here is RECORDED, not asserted, except the final
        # cleanup; `--mode legacy` pins it to the v10 values, which is what proves each
        # gated behaviour really is gated: a mutant that ungates any of them changes at
        # least one recorded value below.
        #
        # Start from an empty receive FIFO and data-ready clear, so the legacy and the
        # contained model begin the probes from the same state.
        self.write32(UART_BASE + UFCON, 0)
        self.read32(UART_BASE + URXH, 23)                  # FIFO disabled: clears data-ready
        self.write32(UART_BASE + UFCON, 0x3)               # FIFO enable | Rx FIFO reset
        self.write32(UART_BASE + UCON, 0x0405)
        self.write32(UART_BASE + UTRSTAT, CLEAR_STATUS)
        # (l1) bit 13 through the generic path: the TX arm, the line, the acknowledge.
        self.write32(UART_BASE + UFCON, 0)
        self.halfword(UART_BASE + 6, 0x2000)
        self.read32(UART_BASE + UCON, 23)
        self.trace('l_ucon_after_halfword_store', None, register=23)
        self.write32(UART_BASE + UFCON, hw.UFCON_FIFO_ENABLE)
        self.status(UTRSTAT_BIT5)
        self.trace('l_bit5_after_ufcon_enable', None, register=23)
        self.line()
        self.trace('l_line_after_ufcon_enable', None, register=23)
        self.write32(UART_BASE + UCON, 0)        # a word write refreshes the line
        self.status(UTRSTAT_BIT5)
        self.trace('l_bit5_after_ucon_word_write', None, register=23)
        self.line()
        self.trace('l_line_after_ucon_word_write', None, register=23)
        self.read32(UART_BASE + UCON, 23)
        self.trace('l_ucon_after_word_write', None, register=23)
        self.write32(UART_BASE + UTRSTAT, ACK_TX_THRESH)
        self.status(UTRSTAT_BIT5)
        self.trace('l_bit5_after_ack', None, register=23)
        self.line()
        self.trace('l_line_after_ack', None, register=23)
        self.halfword(UART_BASE + 6, 0)
        self.write32(UART_BASE + UCON, 0)
        # (l2) a LATE timeout through the generic path: timeout enable (bit 9), interval
        # nibble 8, one byte received and drained at once, the timer firing after the
        # drain with no data. The legacy rule latches Rx_TIMEOUT with the enable bit
        # alone and the line follows; the contained rule needs data.
        self.halfword(UART_BASE + 6, 0x8200)
        self.mark('phase_l_ready')
        self.await_status(0x1, 0)
        self.read32(UART_BASE + URXH, 23)
        self.trace('l_late_byte', None, register=23)
        self.wait_closed(2)
        self.status(0x9)
        self.trace('l_status_after_late_timer', None, register=23)
        self.line()
        self.trace('l_line_after_late_timer', None, register=23)
        # (l3) with the timer off, receive and drain one more byte: the contained model
        # clears Rx_TIMEOUT on a drain to empty, the legacy model leaves it set.
        self.halfword(UART_BASE + 6, 0)
        self.mark('phase_m_ready')
        self.await_status(0x1, 0)
        self.read32(UART_BASE + URXH, 23)
        self.trace('l_second_byte', None, register=23)
        self.status(0x9)
        self.trace('l_status_after_second_drain', None, register=23)
        # Leave the line low and UCON zero, in either mode.
        self.write32(UART_BASE + UCON, 0)
        self.write32(UART_BASE + UTRSTAT, CLEAR_STATUS)
        self.line()
        self.trace('l_line_low_after_cleanup', 0, register=23)

    def build(self):
        self.mov(20, hw.SCRATCH)
        self.mov(21, 0)                        # deliveries
        self.mov(22, 0)                        # last acknowledged event
        self.mov(24, 0)                        # unexpected exceptions
        self.mov(25, 0)                        # handler: UTRSTAT acknowledge value
        self.mov(26, 0)                        # handler: re-unmask the line
        self.mov(0, hw.NORMAL_SP)
        self.emit(0x9100001f)                  # mov sp,x0
        self.set('HCR_EL2', (1 << 31) | (1 << 34) | (1 << 4))
        self.set('VBAR_EL2', BASE + 0x4000)
        self.write32(AIC_BASE + hw.GLBCFG, 1)
        self.trace('enabled_no_interrupt', 0, register=21)

        if self.legacy:
            # The default-pin ROM runs only the (l) probes. Cases (a) to (j) inject bytes at
            # marks and, on the legacy model, race those injections against a ROM that never
            # waits for them (stale data-ready satisfies every wait), so they would make a
            # flaky pin. The (l) probes start from a reset FIFO and wait for each byte.
            self.probes_l()
        else:
            self.cases_a_to_e()
            self.cases_f_to_j()
            self.probes_l()

        self.mov(0, 0xfeedfacecafebeef)
        self.trace('completion', 0xfeedfacecafebeef)
        terminal = len(self.words)
        self.branch(terminal)

        def fault(offset):
            self.at(offset)
            self.emit(0x91000718)              # add x24,x24,#1
            self.store(24, 0x500)
            self.emit(0x14000000)

        for offset in (0x4000, 0x4080, 0x4100, 0x4180, 0x4200):
            fault(offset)
        # IRQ, current EL with SP_ELx: a naive driver's handler.
        self.at(0x4280)
        self.read32(AIC_BASE + hw.EVENT, 22)   # acknowledge; the AIC masks the line
        self.emit(0x910006b5)                  # add x21,x21,#1
        skip_ack = self.cbz_forward(25)
        self.mov(1, UART_BASE + UTRSTAT)
        self.emit(0xb9000039)                  # str w25,[x1]
        self.bind(skip_ack)
        done_a = self.cbz_forward(26)
        self.emit(0xf10002bf | (CAP << 10))    # cmp x21,#CAP
        done_b = self.bcond_forward(2)         # b.hs: the cap is reached, stop re-arming
        self.unmask(UART_IRQ)
        self.bind(done_a)
        self.bind(done_b)
        self.emit(0xd69f03e0)                  # eret
        for offset in (0x4300, 0x4380):
            fault(offset)

        require(len(self.words) * 4 < 0x10000 and len(self.expected) * 8 < 0x500,
                'Owned ROM and scratch ranges remain separate')
        return b''.join(struct.pack('<I', word) for word in self.words)


def run(binary, components, output, mode='on'):
    started = time.monotonic()
    asset_paths = {name: components / name for name in board.ASSETS}
    before = {name: hw.digest(path) for name, path in asset_paths.items()}
    blobs = {name: path.read_bytes() for name, path in asset_paths.items()}
    layout = board.expected_layout(blobs)
    for name, (address, size) in layout['regions'].items():
        require(hw.PROBE_END <= address or BASE >= address + size,
                'Owned ROM/scratch range overlaps boot reservation: ' + name)
    require(shutil.disk_usage(output).free >= 64 * 1024 * 1024, 'Minimum evidence free space')

    rom = StormROM(legacy=(mode == 'legacy'))
    content = rom.build()
    rom_path = output / 'uart-ucon-storm.rom'
    rom_path.write_bytes(content)
    zero_path = output / 'scratch-zero.bin'
    zero_path.write_bytes(bytes(0x508))
    trace_path = output / 'uart-trace.log'
    report = {'scope': 'Apple UART opt-in UCON store and drain refresh: storm, stuck-line '
                       'and hang cases, and a pin of the default; owned ROM only',
              'mode': mode,
              'binary': str(binary), 'binary_sha256': hw.digest(binary)['sha256'],
              'rom_sha256': hw.digest(rom_path)['sha256'],
              'component_hashes_before': before, 'passes': [], 'passed': False,
              'firmware_executed': False, 'ios_boot_claim': False,
              'uart_ucon_store': 'on' if mode == 'on' else 'off',
              'uart_drain_refresh': 'on' if mode == 'on' else 'off',
              'delivery_cap': CAP,
              'declared_event_offset': hex(hw.EVENT),
              'limits': {'wall_seconds': MAX_WALL, 'cpu_seconds': 30, 'log_bytes': MAX_LOG}}
    process = None
    log_path = output / 'emulator.log'
    try:
        with tempfile.TemporaryDirectory(prefix='uart-storm-gate-') as temporary:
            scratch = Path(temporary)
            uart_pipe = scratch / 'uart'
            os.mkfifo(str(uart_pipe) + '.in')
            os.mkfifo(str(uart_pipe) + '.out')
            machine = 'apple-modern,' + ','.join(
                name + '=' + str(asset_paths[asset]) for name, asset in
                zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), board.ASSETS))
            machine += ',prepare-only=true,modern-aic=on,boot-command-line=' + board.COMMAND_LINE
            argv = [str(binary)]
            if mode == 'on':
                argv += ['-global', 'apple-uart.ucon-store=on',
                         '-global', 'apple-uart.drain-refresh=on']
            argv += ['-M', machine, '-m', '8G', '-smp', '1',
                    '-nodefaults', '-display', 'none', '-serial', 'pipe:' + str(uart_pipe),
                    '-monitor', 'none',
                    '-device', f'loader,file={rom_path},addr={BASE},cpu-num=0,force-raw=true',
                    '-device', f'loader,file={zero_path},addr={SCRATCH},force-raw=true',
                    '-trace', 'apple_uart_rx_timeout', '-D', str(trace_path),
                    '-S', '-qmp', 'stdio']
            report['argv'] = argv
            with log_path.open('xb') as log:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=log,
                                           bufsize=0, preexec_fn=hw.child_limits)

                def guard():
                    remaining = MAX_WALL - (time.monotonic() - started)
                    require(remaining > 0 and log_path.stat().st_size <= MAX_LOG and
                            (not trace_path.exists() or trace_path.stat().st_size <= MAX_LOG),
                            'Storm gate wall/log bound exceeded')
                    return remaining

                qmp = board.QMP(None, guard, process)
                injector = None
                for _ in range(100):
                    try:
                        injector = os.open(str(uart_pipe) + '.in', os.O_WRONLY | os.O_NONBLOCK)
                        break
                    except OSError as error:
                        require(error.errno == errno.ENXIO, 'UART pipe open')
                        time.sleep(0.05)
                require(injector is not None, 'UART pipe reader appeared')
                for iteration in range(2):
                    if iteration:
                        qmp.request('system_reset')
                    deadline = time.monotonic() + 3
                    while True:
                        values = board.parse_registers(qmp.request(
                            'human-monitor-command', {'command-line': 'info registers'}))
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
                    require(verify.read_bytes() == content, 'Owned ROM bytes are exact before cont')
                    verify.unlink()
                    qmp.request('pmemsave', {'val': SCRATCH, 'size': 0x508,
                                             'filename': str(verify)})
                    require(verify.read_bytes() == bytes(0x508),
                            'Scratch is zero before cont (no stale first-run values)')
                    verify.unlink()
                    qmp.request('cont')

                    labels = list(rom.expected)
                    size = len(labels) * 8
                    dump = scratch / 'scratch.bin'
                    injected = set()
                    deadline = time.monotonic() + ITERATION_SECONDS
                    while True:
                        guard()
                        qmp.request('stop')
                        qmp.request('pmemsave', {'val': SCRATCH, 'size': size,
                                                 'filename': str(dump)})
                        raw = dump.read_bytes()
                        qmp.events.clear()   # our own stop/cont polling makes these events

                        def slot(label):
                            return struct.unpack_from('<Q', raw, labels.index(label) * 8)[0]
                        for label, (mark, byte) in MARKS.items():
                            if label in labels and label not in injected and \
                                    len(raw) >= size and slot(label) == mark:
                                os.write(injector, bytes([byte]))   # while stopped
                                injected.add(label)
                        if len(raw) >= size and slot('completion') == 0xfeedfacecafebeef:
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

                    observed, failed, primary = {}, [], {}
                    for index, (label, expect) in enumerate(rom.expected.items()):
                        value = struct.unpack_from('<Q', raw, index * 8)[0]
                        observed[label] = hex(value)
                        if mode == 'on' and expect is not None and value != expect:
                            # A hint only when the case got that far on its own: after an
                            # earlier failure in the same case it would be a misleading echo.
                            hint = '' if label[:2] in primary else HINTS.get(label, '')
                            shown = repr(expect) if expect < 10 else hex(expect)
                            failed.append(f'{label}: expected {shown}, observed {value:#x}'
                                          + hint)
                            primary.setdefault(label[:2], failed[-1])
                    if mode == 'legacy':
                        # The default is PINNED to the recorded v10 observations. A
                        # label that is absent from the record is itself a failure, so
                        # a ROM change cannot silently pass.
                        recorded = LEGACY_OBSERVED[iteration]
                        for label, value in observed.items():
                            if recorded.get(label) != value:
                                failed.append('%s: v10 recorded %s, observed %s'
                                              % (label, recorded.get(label), value))
                                primary.setdefault(label[:2], failed[-1])
                        for label in recorded:
                            if label not in observed:
                                failed.append(label + ': recorded for v10, not observed')
                                primary.setdefault(label[:2], failed[-1])
                    faults = scratch / 'faults.bin'
                    qmp.request('pmemsave', {'val': SCRATCH + 0x500, 'size': 8,
                                             'filename': str(faults)})
                    if struct.unpack('<Q', faults.read_bytes())[0] != 0:
                        failed.append('an unexpected exception was taken')
                        primary.setdefault('!!', failed[-1])
                    # Later checks of a case cascade from its first failure (a stuck line
                    # leaves the cap hit and every later count wrong), so name the first
                    # failure of each case separately.
                    primary = list(primary.values())
                    report['passes'].append({'iteration': iteration,
                                             'after_system_reset': bool(iteration),
                                             'observed': observed, 'failed_checks': failed,
                                             'first_failure_per_case': primary,
                                             'completed': not failed})
                    if mode == 'on':
                        require(not failed, 'first failure per case: ' + '; '.join(primary))
                    # Legacy mode runs both iterations before judging, so the record can be
                    # taken from a run that would otherwise stop at the first mismatch.
                qmp.request('quit')
                code = process.wait(timeout=10)
                require(code == 0, f'Emulator exited {code}')
                process = None
        # On: per iteration the timer fires four times, in order: after the drain with no
        # data (case (b), stat 0x6, so a late timeout was really exercised), twice with data
        # pending (cases (f) and (g), stat 0x7: data-ready plus the idle Tx bits), and once
        # more late through the generic UCON path (case (l2)). Legacy: UCON word writes are
        # dropped, so only the (l2) halfword probe ever arms the timer.
        text = trace_path.read_text(errors='replace') if trace_path.exists() else ''
        timeouts = [line for line in text.splitlines() if 'Rx timeout stat=' in line]
        report['timeout_trace_lines'] = timeouts
        # The (l2) trace value is compared with the data-ready bit (bit 0) masked off: the
        # byte is drained a few instructions after it arrives, but a host that starves the
        # vCPU thread for more than the 109 ms timer interval lets the timer fire in between
        # (MEASURED: 2 of 15 repeats under a loaded host showed 0x27 for 0x26). The recorded
        # labels do not depend on which side wins, so the trace is not allowed to flake the
        # gate. (b), (f) and (g) keep exact values: (f) and (g) wait for the timeout bit with
        # data pending, and (b) is checked by b_status_before_drain as well.
        states = [int(line.split('stat=')[1].split()[0], 16) for line in timeouts]
        if mode == 'on':
            expected = [0x6, 0x7, 0x7, 0x6] * 2
            ok = len(states) == len(expected) and all(
                (got & ~1) == (want & ~1) if index % 4 == 3 else got == want
                for index, (got, want) in enumerate(zip(states, expected)))
            require(ok, 'RX timeout fired as (b) late, (f) and (g) with data, (l2) late, per '
                    'iteration (observed %r)' % ([hex(v) for v in states],))
        else:
            recorded = [int(v, 16) for v in LEGACY_TIMEOUT_STATES]
            require([v & ~1 for v in states] == [v & ~1 for v in recorded],
                    'Legacy default: the timer fires only for the (l2) halfword probe '
                    '(v10 recorded %r, observed %r)'
                    % (LEGACY_TIMEOUT_STATES, [hex(v) for v in states]))
        after = {name: hw.digest(path) for name, path in asset_paths.items()}
        require(after == before, 'Firmware components are unchanged')
        report['component_hashes_after'] = after
        report['passed'] = (len(report['passes']) == 2 and
                            all(item['completed'] for item in report['passes']))
        require(report['passed'], 'first failure per case: ' + '; '.join(
            check for item in report['passes'] for check in item['first_failure_per_case']))
    except Exception as error:
        report['error'] = str(error)
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
    if not report['passed'] and log_path.exists():
        report['emulator_log_tail'] = log_path.read_text(errors='replace')[-600:]
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps({'passed': report['passed'],
                      'cpu_passes': len(report['passes']),
                      'binary_sha256': report['binary_sha256'],
                      'failed_checks': [check for item in report['passes']
                                        for check in item['first_failure_per_case']
                                        ] if report['passes'] and
                      'first_failure_per_case' in report['passes'][-1] else [],
                      'error': report.get('error')}))
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--components', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--mode', choices=('on', 'legacy'), default='on',
                        help='on: pass -global apple-uart.ucon-store=on and '
                             '-global apple-uart.drain-refresh=on and assert the contained '
                             'behaviour; legacy: pass neither and require the recorded '
                             'v10 observations (pins the default)')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    return run(args.binary, args.components, args.output_dir, args.mode)


if __name__ == '__main__':
    sys.exit(main())
