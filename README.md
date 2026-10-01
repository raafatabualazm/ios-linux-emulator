# iOS Linux Emulator

A Linux-focused fork of [ChefKissInc/Inferno](https://github.com/ChefKissInc/Inferno),
which extends QEMU with Apple ARM device support. This fork starts from upstream
commit `cc4302a99167abec69b714cfd00c38caece7e7de` and publishes the changes used in
our iPhone 11 / iOS 14 laboratory.

## Start here

Follow the [Linux restore and GUI guide](docs/linux-restore.md) to build both
emulators, connect the Linux companion, restore the device, patch its APFS image
on Linux, and boot to Hello/setup. The [APFS tool reference](scripts/linux-apfs/README.md)
explains verification and recovery. Firmware, tickets, and device disk images
are supplied by the user and are not distributed here.

The default `linux-restore` branch contains:

- A display scanout timer that lets restore progress without an attached viewer.
- An A13 fix for interprocessor interrupts sent between CPU clusters.
- NVMe interrupt compatibility changes present in the validated lab build.
- Linux tools to apply same-size dyld cache changes to an offline raw APFS image,
  with verification and recovery data.
- Portable iPhone and companion launch commands.

The optional [afl-persistent branch](https://github.com/raafatabualazm/ios-linux-emulator/tree/afl-persistent)
adds the lab's Linux AFL integration. It requires an explicit `--enable-afl`
build; see that branch's [AFL guide](https://github.com/raafatabualazm/ios-linux-emulator/blob/afl-persistent/docs/afl.md).

The APFS tools replace the macOS mounting/copy-back step in the
[upstream filesystem instructions](https://chefkiss.dev/guides/inferno/fs-patches/).
They do not implement general APFS write support. The tested target is iPhone 11
(`t8030`, `n104ap`), iOS 14.0 beta 5 (`18A5351d`). See the guide for validation
results and the unresolved fresh-restore failure on the course machine.

## Attribution and licensing

Credit for the emulator and filesystem patcher belongs to their upstream
authors. This fork is independently maintained and uses the neutral product
name **iOS Linux Emulator**. The restricted upstream splash artwork has been
removed in accordance with the [branding notice](ui/icons/CKBrandingNotice.md).
Support upstream development at [ChefKiss's donation page](https://ko-fi.com/chefkiss).

The source retains its original copyright notices and licenses; see [LICENSE](LICENSE).
Upstream's derivative project uses GPLv3, with its own code under AGPLv3;
individual QEMU components retain their applicable original licenses. The
external filesystem patcher has its own license. This software is provided as
is, without warranty. QEMU is a trademark of Fabrice Bellard; iOS is a trademark
of Apple Inc. Neither is affiliated with this fork.

Some changes and documentation were prepared with AI assistance and reviewed
against the laboratory results.
