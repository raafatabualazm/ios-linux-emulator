#!/usr/bin/env python3
"""Owned CPU SKS wire/DMA gate. No firmware, keys or encryption operation.

Client-terminate exercises a neutral existing compatibility handler. Python's
hashlib constructs independent versioned wire vectors and exact reply oracles.
Invalid messages must leave the output marker unchanged and allow the following
bootstrap status barrier to complete. Repeat after reset without reusing OOL state.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location('sep_transport',
    Path(__file__).with_name('test-apple-modern-sep-transport-qemu.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
m, b = t.mailbox, t.board
IN = m.BASE + 0x80000
OUT = m.BASE + 0x82000
END = m.BASE + 0x84000
FAULT = 0x1800
VECTOR = 0xc000
MARKER = 0x12345678aabbccdd
DONE = 0xfedcba9876543210


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def frame(version, body, flags=0):
    header = bytearray(72 if version == 1 else 80)
    struct.pack_into('<IQIQQI', header, 16, version, 0x123456789a,
                     flags, 0x8877665544332211, 0x1234abcde, 0xaabbccdd)
    header[52:72] = bytes(range(20))
    header[:16] = hashlib.sha256(header[16:] + body).digest()[:16]
    return struct.pack('<I', len(header)) + header + body


class ROM(t.ROM):
    def __init__(self, valid_only):
        super().__init__()
        self.valid_only = valid_only
        self.sent = self.received = self.rejected = self.unsupported = self.ool_errors = 0
        self.cases = []

    def send_raw(self, packet):
        self.write64(m.A2I_SEND, int.from_bytes(packet, 'little'))
        self.write64(m.A2I_SEND + 8, 0)
        self.sent += 1

    def recv_raw(self, label, packet):
        self.wait_reply()
        self.read64(m.I2A_RECV, 23)
        self.trace(label, int.from_bytes(packet, 'little'), register=23)
        self.read64(m.I2A_RECV + 8, 23)
        self.trace(label + '_stamp', m.stamped(0, 1), register=23)
        self.received += 1

    def control(self, op, value, ep=18, ack=True):
        self.send_raw(struct.pack('<BBBBI', 0, 0x31, op, ep, value))
        if ack:
            self.recv_raw(f'control_{self.sent}', struct.pack('<BBBBI', 0, 0x31, 1, 0, 0))

    def barrier(self, label):
        self.send_raw(struct.pack('<BBBBI', 255, 0x32, 2, 0, 0))
        self.recv_raw(label + '_status', struct.pack('<BBBBI', 255, 0x32, 102, 0, 1))

    def request(self, label, data, op=0x1b, reject=False, unsupported=False, wire_size=None):
        for offset in range(0, len(data), 4):
            self.write32(IN + offset, int.from_bytes(data[offset:offset + 4].ljust(4, b'\0'),
                                                   'little'))
        self.write64(OUT, MARKER)
        self.write64(OUT + 128, MARKER)
        size = len(data) if wire_size is None else wire_size
        self.send_raw(struct.pack('<BBBBHH', 18, op, 0x42, 0, 0, size))
        if reject or unsupported:
            self.barrier(label)
            self.read64(OUT, 23)
            self.trace(label + '_no_output', MARKER, register=23)
            self.rejected += int(reject)
            self.unsupported += int(unsupported)
        else:
            version = struct.unpack_from('<I', data, 20)[0]
            expected = frame(version, struct.pack('<I', 0))
            self.recv_raw(label + '_reply', struct.pack('<BBBBHH', 18, op | 0x80,
                                                       0x42, 0, 0, len(expected)))
            for offset in range(0, len(expected), 8):
                self.read64(OUT + offset, 23)
                self.trace(f'{label}_wire_{offset}',
                           struct.unpack_from('<Q', expected, offset)[0], register=23)
        self.read64(OUT + 128, 23)
        self.trace(label + '_tail_guard', MARKER, register=23)
        self.cases.append(label)

    def build(self):
        self.mov(20, m.SCRATCH)
        self.mov(0, m.NORMAL_SP)
        self.emit(0x9100001f)
        self.emit(0xd5034fdf)
        self.set('VBAR_EL2', m.BASE + VECTOR)
        self.recv_raw('announcement', struct.pack('<BBBBI', 255, 0, 210, 0, 1))
        body = struct.pack('<I', 0x76543210)
        if not self.valid_only:
            self.request('unconfigured_after_reset', frame(1, body), reject=True)
        self.control(2, IN >> 12)
        self.control(3, OUT >> 12)
        self.control(4, 4096)
        self.control(5, 4096)
        self.request('v1', frame(1, body))
        self.request('v2', frame(2, body))
        if not self.valid_only:
            for size in (0, 23, 24, 75):
                self.request(f'truncated_{size}', frame(1, body), wire_size=size, reject=True)
            for op, minimum in ((0x02, 16), (0x04, 16), (0x19, 20), (0x1b, 4)):
                self.request(f'short_body_{op:x}', frame(1, bytes(minimum - 1)),
                             op=op, reject=True)
            wrong = bytearray(frame(1, body))
            struct.pack_into('<I', wrong, 0, 80)
            self.request('legacy_v1_prefix', wrong, reject=True)
            wrong = bytearray(frame(1, body))
            struct.pack_into('<I', wrong, 20, 3)
            self.request('unknown_version', wrong, reject=True)
            wrong = bytearray(frame(1, body))
            wrong[-1] ^= 1
            self.request('bad_digest', wrong, reject=True)
            self.request('encrypted_not_supported', frame(1, body, flags=1), reject=True)
            self.control(4, 79)
            self.request('input_capacity', frame(1, body), reject=True)
            self.control(4, 4096)
            self.control(5, 79)
            self.request('output_capacity', frame(1, body), reject=True)
            self.control(5, 4096)
            self.request('unknown_operation_no_echo', frame(1, body), op=0x70,
                         unsupported=True)
            for op, request_body in ((0x01, b''), (0x03, b''), (0x08, b''),
                                     (0x0c, b''), (0x0d, b''), (0x19, bytes(20))):
                self.request(f'unimplemented_key_service_{op:x}', frame(1, request_body),
                             op=op, unsupported=True)
            self.control(2, IN >> 12, ep=255, ack=False)
            self.ool_errors += 1
            self.barrier('invalid_ool_endpoint')
            self.request('valid_after_rejections', frame(1, body))
        self.mov(0, DONE)
        self.trace('completed', DONE)
        self.branch(len(self.words))
        for offset in range(VECTOR, VECTOR + 0x800, 0x80):
            self.at(offset)
            self.mov(0, 1)
            self.store(0, FAULT)
            self.emit(m.sysreg('ESR_EL2', 0, True))
            self.store(0, FAULT + 8)
            self.branch(len(self.words))
        t.require(len(self.expected) * 8 < FAULT, 'Result words overlap fault record')
        t.require(len(self.words) * 4 < 0x10000, 'ROM overlaps scratch')
        return b''.join(struct.pack('<I', w) for w in self.words)


def run(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assets = {name: args.components.resolve() / name for name in b.ASSETS}
    before = {name: digest(p) for name, p in assets.items()}
    layout = b.expected_layout({name: p.read_bytes() for name, p in assets.items()})
    for name, (address, size) in layout['regions'].items():
        t.require(END <= address or m.BASE >= address + size, 'Owned range overlap: ' + name)
    rom = ROM(args.valid_only)
    content = rom.build()
    rp, zp = out / 'owned.rom', out / 'zero.bin'
    rp.write_bytes(content)
    zp.write_bytes(bytes(FAULT + 16))
    machine = 'apple-modern,' + ','.join(
        name + '=' + str(assets[asset]) for name, asset in
        zip(('bootkc', 'sptm', 'txm', 'dtree', 'tc'), b.ASSETS))
    machine += ',prepare-only=on,modern-aic=on,sep-sim=on'
    argv = [str(args.binary.resolve()), '-M', machine, '-m', '8G', '-smp', '1',
            '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-device', f'loader,file={rp},addr={m.BASE},cpu-num=0,force-raw=true',
            '-device', f'loader,file={zp},addr={m.SCRATCH},force-raw=true', '-S', '-qmp', 'stdio']
    report = {'passed': False, 'argv': argv, 'binary_sha256': digest(args.binary),
              'script_sha256': digest(Path(__file__)), 'rom_sha256': digest(rp),
              'component_hashes_before': before, 'passes': [], 'cases': rom.cases,
              'scope': 'Owned CPU framing, DMA bounds, SHA256 and reset; no key service',
              'firmware_executed': False, 'encrypted_storage_qualified': False,
              'valid_only': args.valid_only}
    process = qmp = None
    started = time.monotonic()
    log_path = out / 'qemu.log'
    try:
        with tempfile.TemporaryDirectory(prefix='sks-dma-') as name, log_path.open('xb') as log:
            scratch = Path(name) / 'readback'
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=log, bufsize=0, preexec_fn=m.child_limits)
            def guard():
                left = 60 - (time.monotonic() - started)
                t.require(left > 0 and log_path.stat().st_size < (1 << 20), 'Time/log bound')
                return left
            qmp = t.QMP(None, guard, process)
            path = t.find_sep(qmp)
            names = ('sim-sks-rejected-count', 'sim-unsupported-count', 'sim-ool-error-count')
            if not args.valid_only:
                for key in names:
                    qmp.require_readonly(path, key)
            for iteration in range(2):
                if iteration:
                    qmp.request('system_reset')
                regs = b.parse_registers(qmp.request('human-monitor-command',
                                                    {'command-line': 'info registers'}))
                t.require(regs['PC'] == m.BASE and regs['PSTATE'] & 15 == 9,
                          'Owned PC at EL2 before execution')
                t.require(not qmp.request('query-status')['running'], 'CPU starts stopped')
                if not args.valid_only:
                    t.require(t.values(qmp, path, names) == dict.fromkeys(names, 0),
                              'Reset diagnostic state')
                qmp.request('pmemsave', {'val': m.BASE, 'size': len(content), 'filename': str(scratch)})
                t.require(scratch.read_bytes() == content, 'Exact ROM before execution')
                qmp.request('pmemsave', {'val': m.SCRATCH, 'size': FAULT + 16,
                                         'filename': str(scratch)})
                t.require(scratch.read_bytes() == bytes(FAULT + 16), 'Zero result and fault state')
                qmp.request('cont')
                deadline = time.monotonic() + 10
                while True:
                    guard()
                    qmp.request('stop')
                    qmp.request('pmemsave', {'val': m.SCRATCH, 'size': len(rom.expected) * 8,
                                             'filename': str(scratch)})
                    raw = scratch.read_bytes()
                    if struct.unpack_from('<Q', raw, len(raw) - 8)[0] == DONE:
                        break
                    t.require(time.monotonic() < deadline, 'Owned SKS sequence did not complete')
                    qmp.request('cont')
                    time.sleep(.03)
                observed = dict(zip(rom.expected, struct.unpack('<' + 'Q' * len(rom.expected), raw)))
                for label, expected in rom.expected.items():
                    t.require(observed[label] == expected,
                              f'{label}: expected {expected:#x}, observed {observed[label]:#x}')
                qmp.request('pmemsave', {'val': m.SCRATCH + FAULT, 'size': 16,
                                         'filename': str(scratch)})
                t.require(scratch.read_bytes() == bytes(16), 'No guest exception')
                counters = {}
                if not args.valid_only:
                    counters = t.values(qmp, path, names)
                    t.require(counters == dict(zip(names, (rom.rejected, rom.unsupported,
                                                          rom.ool_errors))), 'Refusal counts')
                report['passes'].append({'iteration': iteration, 'checks': len(observed),
                                         'observed': observed, 'counters': counters})
            qmp.request('quit')
            t.require(process.wait(timeout=10) == 0, 'Clean QEMU exit')
            process = None
            report['passed'] = True
    except Exception as e:
        report['error'] = str(e)
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
        if qmp:
            qmp.close()
        report['child_reaped'] = True
        report['component_hashes_after'] = {name: digest(p) for name, p in assets.items()}
        report['inputs_unchanged'] = (before == report['component_hashes_after'] and
                                      digest(args.binary) == report['binary_sha256'])
        report['passed'] &= report['inputs_unchanged']
        report['elapsed_seconds'] = time.monotonic() - started
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report.get(k) for k in ('passed', 'error', 'elapsed_seconds')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--components', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--valid-only', action='store_true', help='Behavioral negative control on old pins')
    raise SystemExit(run(p.parse_args()))
