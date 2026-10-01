# Restore and boot iPhone 11 on Linux

This guide covers the tested iPhone 11 (`t8030`, `n104ap`) with iOS 14.0 beta 5,
build `18A5351d`. Prepare firmware and matching tickets using upstream's
[file setup](https://chefkiss.dev/guides/inferno/file-setup/), then follow the Linux
build, restore, filesystem patch, and GUI steps below.

Two QEMU processes run during restore. The ARM process runs the iPhone; an
x86_64 Linux companion runs `usbmuxd` and `idevicerestore`. A UNIX socket connects
their USB devices. Afterwards, an offline APFS tool extracts the dyld cache,
patches it, and writes back same-size changes. This replaces the macOS
mount/write step; no macOS VM or writable Linux APFS mount is needed for it.

## Build

Install these development packages on Debian/Kali. Nettle must meet the source
tree's minimum version (3.10 or later); older distributions may need newer
packages. Reduce the build parallelism on machines with less memory.

```sh
sudo apt-get update
sudo apt-get install build-essential ninja-build pkg-config python3-venv \
  libglib2.0-dev libpixman-1-dev libgnutls28-dev nettle-dev libpng-dev \
  liblzfse-dev libslirp-dev git unzip
git clone --branch linux-restore --recurse-submodules \
  https://github.com/raafatabualazm/ios-linux-emulator.git
cd ios-linux-emulator
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install meson
./configure --target-list=aarch64-softmmu,x86_64-softmmu \
  --enable-lzfse --enable-nettle --enable-gnutls --enable-slirp \
  --disable-werror --disable-qom-cast-debug --disable-debug-info
ninja -C build -j8
build/qemu-system-aarch64 --version
build/qemu-system-x86_64 -netdev help
python3 scripts/test-a13-ipi.py
export EMULATOR="$PWD"
```

The network backends must include `user`. This fork's x86_64 binary supplies
`usb-tcp-remote`, which stock QEMU lacks. `--disable-werror` avoids a bundled
device-tree compiler warning becoming a failure on GCC 15. For GTK, install
`libgtk-3-dev` and add `--enable-gtk` before building; VNC works without GTK.

## Device assets and disks

Keep the device directory outside the checkout. Use the upstream file setup
instructions for extracting the matching IPSW, generating tickets, and preparing
SEP firmware and ROM. The launcher expects these filenames:

```text
iphone-data/
  Restore/kernelcache.research.iphone12b
  Restore/038-44135-124.dmg
  Restore/Firmware/038-44135-124.dmg.trustcache
  Restore/Firmware/all_flash/DeviceTree.n104ap.im4p
  root_ticket.der
  sep-firmware.n104.RELEASE.new.img4
  AppleSEPROM-Cebu-B1
  root  firmware  syscfg  ctrl_bits  nvram  effaceable  panic_log
  sep_nvram  sep_ssc
```

Set the directory and ticket ECID. For a **new device directory only**, create
blank disks. The loop refuses existing disk names; never recreate restored disks.

```sh
export IPHONE_DATA="$HOME/iphone-data"
export ECID=0x1122334455667788   # replace if your tickets use another ECID
mkdir -p "$IPHONE_DATA"
python3 - "$IPHONE_DATA" <<'PY'
from pathlib import Path
import sys
directory = Path(sys.argv[1])
sizes = {'root': 32 << 30, 'firmware': 8 << 20, 'syscfg': 128 << 10,
         'ctrl_bits': 8 << 10, 'nvram': 8 << 10, 'effaceable': 4 << 10,
         'panic_log': 1 << 20, 'sep_nvram': 64 << 10, 'sep_ssc': 128 << 10}
if any((directory / name).exists() for name in sizes):
    raise SystemExit('Existing device disks found; choose a new directory')
for name, size in sizes.items():
    with (directory / name).open('xb') as stream:
        stream.truncate(size)
PY
```

## Companion and restore

Configure an x86_64 Linux qcow2 guest with SSH and the restore tools from the
[upstream companion guide](https://chefkiss.dev/guides/inferno/companion-setup/).
Apply upstream's `idevicerestore` patch before building it; the ordinary distro
executable is insufficient. Its source libraries must match that patched revision.

The companion needs a USB-capable kernel. In the tested Debian cloud image,
the cloud kernel omitted USB. Install the generic kernel and boot that entry
through GRUB's advanced menu:

```sh
sudo apt-get install linux-image-amd64 usbutils
uname -r                       # check again AFTER rebooting to the generic kernel
lsusb -t
ls /sys/bus/usb/devices
```

Configure GRUB's default if unattended boot keeps choosing the cloud kernel,
then verify the selected kernel after reboot. Socket connectivity alone does
not establish USB enumeration.

On the host, start this already configured companion **before** the iPhone:

```sh
export COMPANION_DISK="$HOME/companion/debian.qcow2"
export USB_SOCKET=/tmp/ios-linux-usb.sock
python3 "$EMULATOR/scripts/linux-restore/run.py" companion \
  --qemu "$EMULATOR/build/qemu-system-x86_64" \
  --disk "$COMPANION_DISK" --usb-socket "$USB_SOCKET"
```

Keep it running. KVM is used on an x86_64 host; `--tcg` is available elsewhere,
but restore timing under TCG is unvalidated. In another terminal, copy the IPSW
and ticket into the companion. Replace `student` with your configured account.

```sh
scp -P 32222 "$IPHONE_DATA/"*18A5351d_Restore.ipsw \
  "$IPHONE_DATA/root_ticket.der" student@127.0.0.1:
ssh -p 32222 student@127.0.0.1
```

Have `usbmuxd` running and the patched restore command ready. In another host
terminal, start the iPhone with its erase ramdisk:

```sh
python3 "$EMULATOR/scripts/linux-restore/run.py" iphone \
  --qemu "$EMULATOR/build/qemu-system-aarch64" --data "$IPHONE_DATA" \
  --ecid "$ECID" --usb-socket "$USB_SOCKET" --restore
```

Immediately start restore **inside the companion**, using the matching ECID:

```sh
cd "$HOME"
sudo systemd-run --unit="ios-restore-$(date +%s)" --collect \
  --working-directory="$PWD" /usr/local/bin/idevicerestore \
  --erase --restore-mode --no-input --plain-progress -i 0x1122334455667788 \
  "$PWD/iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw" \
  -T "$PWD/root_ticket.der"
exit
```

The service keeps running after SSH closes. The tested ramdisk's restore-start
wait was about 120 seconds. Avoid continuous SSH polling during restore. Check
`lsusb` in the companion when diagnosing enumeration.

Afterwards inspect `$IPHONE_DATA/serial.log` and the companion's
`restore_<ECID>_<timestamp>.log`. The systemd journal can omit details written
to the restore executable's own log. Quiet serial output does not establish a
stalled transfer. A successful restore sets `auto-boot`; QEMU detects the
transition and exits for filesystem patching. A received filesystem alone is
not proof that the subsequent bootloader update succeeded. Back up **all nine
writable disks together**, including NVRAM and SEP state, before patching.

## Filesystem patch on Linux

Stop every process using these disks. Install Go 1.26.5 or later (64-bit) and
Python 3.11 or later. Build the extent tool; Go downloads dependencies on its
first build. Build the canonical external patcher at the validated revision:

```sh
cd "$EMULATOR/scripts/linux-apfs"
go build -o extent-probe .
git clone https://git.chefkiss.dev/AppleHax/InfernoFSPatcher "$HOME/InfernoFSPatcher"
git -C "$HOME/InfernoFSPatcher" checkout 3008aaaa0909824a71ee3040c9edc58703c250f5
g++ -std=c++17 -O2 -o "$HOME/InfernoFSPatcher/inferno_fs_patcher" \
  "$HOME/InfernoFSPatcher/src/main.cpp"
python3 "$EMULATOR/scripts/linux-apfs/patch-filesystem.py" "$IPHONE_DATA/root" \
  --extent-probe "$EMULATOR/scripts/linux-apfs/extent-probe" \
  --patcher "$HOME/InfernoFSPatcher/inferno_fs_patcher" \
  --workdir "$IPHONE_DATA/fs-patch-$(date +%s)"
```

The helper selects `role:system` at container offset 24576, verifies extent
reads, and prepares originals plus forward/reverse diffs before writing.
It runs the patcher with its default software-rendering settings. **Do not
use `--no-swr`**, which disables the needed rendering patches. File sizes must
remain identical; this tool cannot resize files or allocate APFS blocks.
Full-file hashes are checked after application, with verified rollback on
failure. Keep recovery data and the full device backup. Read the
[tool reference](../scripts/linux-apfs/README.md) for limitations and recovery.

The validated image has a binary `launchd.plist` and reached GUI without
disabling launch services. Only the dyld patch is applied here; the older
XML-only service workaround is excluded.

## GUI boot and validation

Use the same restored disk set without `--restore`. The launcher omits the
erase ramdisk and adds `launchd_unsecure_cache=1` to the normal boot args:

```sh
python3 "$EMULATOR/scripts/linux-restore/run.py" iphone \
  --qemu "$EMULATOR/build/qemu-system-aarch64" \
  --data "$IPHONE_DATA" --ecid "$ECID"
```

Connect VNC to `127.0.0.1:5906`. Add `--display gtk` if built with GTK, or
`--display none` for headless operation. Hello/setup is the tested endpoint;
it does not establish that every app or hardware feature works. Normal GUI
boot does not provide Bash. The optional AFL branch documents the lab shell
ramdisk separately.

For an optional boot test that discards guest disk changes on exit, add
`--snapshot`:

```sh
python3 "$EMULATOR/scripts/linux-restore/run.py" iphone \
  --qemu "$EMULATOR/build/qemu-system-aarch64" \
  --data "$IPHONE_DATA" --ecid "$ECID" --snapshot
```

QEMU writes to disposable overlays for this test; serial output and the QMP
socket still use the data directory. Use a separate prepared staging directory
if you want to keep its existing log. Omit `--snapshot` for a restore whose
result you intend to retain.

The display now scans out at 60 Hz even without a viewer. Previously completion
interrupts depended on viewer activity, leaving restore waiting after filesystem
transfer; a headless comparison identified this fix. A13 interrupt delivery now
handles senders in another CPU cluster, with a regression check in the build steps.

NVMe changes retain the single-vector MSI fallback, completion re-notification,
and INTx workaround in the combined tested build. Earlier NVMe experiments did
not resolve the stall alone; they are not independently established as its fix.
They affect the generic NVMe controller, so other configurations need testing.

The laboratory build completed a local Linux restore in 13 minutes 58 seconds
and booted the patched image to Hello/setup. That disk set also booted to GUI on
the course host. A **fresh course-host restore remains unresolved**: filesystem
transfer finishes, then `update_iBoot` crashes and a DART panic follows. Its GUI
validation used the successful local disk set. The dyld patch and boot argument
were tested together, without isolating their individual effects. Old snapshots
and cross-version migration have not been validated with these state changes.

See the [upstream manual](https://chefkiss.dev/guides/inferno/) for device setup
and [upstream repository](https://github.com/ChefKissInc/Inferno) for attribution.
