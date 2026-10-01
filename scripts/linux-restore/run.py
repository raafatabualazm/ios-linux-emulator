#!/usr/bin/env python3
"""Launch an iPhone 11 or its Linux USB companion with explicit asset paths."""
import argparse
import os
from pathlib import Path
import shlex


def existing(value):
    try:
        path = Path(value).expanduser().resolve(strict=True)
    except OSError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not path.is_file():
        raise argparse.ArgumentTypeError(f'Not a file: {path}')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    phone = sub.add_parser('iphone', help='iPhone 11, iOS 14.0b5 (18A5351d)')
    phone.add_argument('--qemu', required=True, type=existing)
    phone.add_argument('--data', required=True, type=Path)
    phone.add_argument('--restore', action='store_true', help='Use erase ramdisk and enter recovery')
    phone.add_argument('--snapshot', action='store_true',
                       help='Write device disks through disposable QEMU overlays')
    phone.add_argument('--ecid', help='ECID matching your tickets; otherwise the upstream default')
    phone.add_argument('--display', choices=['vnc', 'gtk', 'none'], default='vnc')
    phone.add_argument('--vnc', default='127.0.0.1:6', help='VNC address:display (default TCP 5906)')
    phone.add_argument('--usb-socket', type=Path, help='Same socket path as the companion')
    companion = sub.add_parser('companion', help='Existing USB-capable x86_64 Linux guest')
    companion.add_argument('--qemu', required=True, type=existing)
    companion.add_argument('--disk', required=True, type=existing)
    companion.add_argument('--usb-socket', required=True, type=Path)
    companion.add_argument('--ssh-port', type=int, default=32222)
    companion.add_argument('--tcg', action='store_true', help='Use TCG if x86_64 KVM is unavailable (slower)')
    for p in (phone, companion):
        p.add_argument('--print-command', action='store_true')
    args = parser.parse_args()
    if not os.access(args.qemu, os.X_OK):
        parser.error(f'QEMU is not executable: {args.qemu}')
    if args.usb_socket:
        args.usb_socket = args.usb_socket.expanduser().resolve()
        if len(os.fsencode(args.usb_socket)) > 100 or any(c in str(args.usb_socket) for c in ',\n'):
            parser.error('Use a short USB socket path without commas or newlines')
        if not args.usb_socket.parent.is_dir():
            parser.error('The USB socket parent directory must exist')
    if args.mode == 'companion':
        if not 1 <= args.ssh_port <= 65535:
            parser.error('SSH port must be in 1..65535')
        argv = [str(args.qemu), '-M', 'q35', '-m', '4G', '-smp', '4',
                '-accel', 'tcg' if args.tcg else 'kvm', '-cpu', 'max' if args.tcg else 'host',
                '-drive', f'file={str(args.disk).replace(",", ",,")},if=virtio,format=qcow2',
                '-nic', f'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{args.ssh_port}-:22',
                '-usb', '-device', 'usb-ehci,id=ehci', '-device',
                f'usb-tcp-remote,bus=ehci.0,conn-type=unix,conn-addr={args.usb_socket}', '-nographic']
    else:
        try:
            data = args.data.expanduser().resolve(strict=True)
        except OSError as error:
            parser.error(str(error))
        if not data.is_dir() or any(c in str(data) for c in ',\n'):
            parser.error('Use an existing data directory without commas or newlines')
        assets = {
            'trustcache': data / 'Restore/Firmware/038-44135-124.dmg.trustcache',
            'ticket': data / 'root_ticket.der',
            'sep-fw': data / 'sep-firmware.n104.RELEASE.new.img4',
            'sep-rom': data / 'AppleSEPROM-Cebu-B1',
        }
        kernel = data / 'Restore/kernelcache.research.iphone12b'
        dtb = data / 'Restore/Firmware/all_flash/DeviceTree.n104ap.im4p'
        ramdisk = data / 'Restore/038-44135-124.dmg'
        disks = ['sep_nvram', 'sep_ssc', 'root', 'firmware', 'syscfg',
                 'ctrl_bits', 'nvram', 'effaceable', 'panic_log']
        for path in list(assets.values()) + [kernel, dtb] + [data / n for n in disks] + ([ramdisk] if args.restore else []):
            if not path.is_file():
                parser.error(f'Missing prepared asset: {path}')
        machine = 't8030,' + ','.join(f'{k}={v}' for k, v in assets.items()) + ',kaslr-off=true'
        if args.restore:
            machine += ',boot-mode=enter_recovery'
        if args.ecid:
            try:
                ecid = int(args.ecid, 0)
                if not 0 <= ecid < 1 << 64:
                    raise ValueError()
            except ValueError:
                parser.error('ECID must be a 64-bit decimal or 0x-prefixed integer')
            machine += f',ecid={ecid}'
        if args.usb_socket:
            machine += f',usb-conn-type=unix,usb-conn-addr={args.usb_socket}'
        bootargs = 'tlto_us=-1 mtxspin=-1 agm-genuine=1 agm-authentic=1 agm-trusted=1 serial=3 wdt=-1 -vm_compressor_wk_sw'
        if not args.restore:
            bootargs += ' launchd_unsecure_cache=1'
        argv = [str(args.qemu), '-M', machine, '-kernel', str(kernel), '-dtb', str(dtb),
                '-append', bootargs, '-smp', '7', '-m', '4G',
                '-serial', f'file:{data}/serial.log',
                '-qmp', f'unix:{data}/qmp.sock,server=on,wait=off', '-display',
                'gtk,zoom-to-fit=on,show-cursor=on' if args.display == 'gtk' else 'none']
        if args.restore:
            argv += ['-initrd', str(ramdisk)]
        if args.snapshot:
            argv += ['-snapshot']
        if args.display == 'vnc':
            argv += ['-vnc', args.vnc]
        for name in disks[:2]:
            argv += ['-drive', f'file={data / name},if=pflash,format=raw']
        for nsid, (name, nstype) in enumerate(zip(disks[2:], [1, 2, 3, 4, 5, 6, 8]), 1):
            dev = 'apple-nvram' if name == 'nvram' else 'nvme-ns'
            device_id = ',id=nvram' if name == 'nvram' else ''
            argv += ['-drive', f'file={data / name},if=none,format=raw,id={name}',
                     '-device', f'{dev},drive={name},bus=nvme-bus.0,nsid={nsid},nstype={nstype}{device_id},logical_block_size=4096,physical_block_size=4096']
    print(shlex.join(argv), flush=True)
    if not args.print_command:
        os.execv(args.qemu, argv)


if __name__ == '__main__':
    main()
