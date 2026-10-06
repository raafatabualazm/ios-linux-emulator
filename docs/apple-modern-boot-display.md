# Modern Apple boot framebuffer

`apple-modern` now has optional scanout of a bootloader framebuffer in guest
RAM. The default is off. This is a fixed BootVideo console; DCP display services,
IOMobileFramebuffer user clients, touch and SpringBoard remain separate work.

## Layout and interface

Enable `boot-display=on`. Geometry properties are `boot-display-width` (default
1024), `boot-display-height` (768), and `boot-display-stride` (0 selects width
times four). Width/height must be 1..4096. Stride must cover the visible row and
be divisible by four. The reservation, rounded to 2 MiB, cannot exceed 64 MiB.

The framebuffer occupies the final usable DRAM tail. BootVideo and an existing
`/vram/reg` describe its physical address, and `/chosen/memory-map/PurpleGfxMem`
describes the same reservation. Bootargs `memSize` excludes it, while
`memSizeActual` retains physical memory size. MTE's 31/32 adjustment precedes
the carveout. Boot blob addresses and `topOfKernelData` remain unchanged. Reset
clears the entire reservation, including padding.

The normal handoff follows the [Darwin display fork at b0f7bc6](https://github.com/d0lb33/qemu-sptm/blob/b0f7bc6/hw/arm/xnuboot_sptm.c#L42).
Apple's [BootVideo ABI](https://github.com/apple-oss-distributions/xnu/blob/main/pexpert/pexpert/arm64/boot.h)
and [console initialization](https://github.com/apple-oss-distributions/xnu/blob/main/pexpert/arm/pe_init.c)
define the fields and text mode. Depth is32; display is0. XRGB scanout is qualified
on this Linux little-endian host. `serial=2` retains UART input and routes XNU
console output to the framebuffer; `serial=3` routes output to UART.

## Verified local checkpoint

Immutable executable `qemu-system-aarch64-modern-boot-display-v3`:
SHA-256 `528c681c4b2f740ea1f890194853f0926605df4806ade0a1d3c1cdc70352ebdf`.
It continues the retained source baseline39278a1.

- 44 layout and55 metadata semantic checks pass under ASan/UBSan.
- Two actual owned A64 ROM runs, across reset, verify all851 visible RGB
  pixels, real CPU stores, guest row padding, framebuffer clearing, BootVideo,
  managed/physical memory sizes and ADT/vram reservation.
- The complete stopped board preparation/reset gate passes with display off.
- A bounded60s iOS27 restore boot produces actual XNU text, including ACM
  endpoint retry messages:107,335 nonblack pixels in a1024x768 screenshot.
  Inputs retain their hashes; QEMU exits0 and its child is reaped. That capture
  establishes the boot console, not a new interactive-shell or SpringBoard result.

Runtime evidence is private and outside source:
`modern-emulator/evidence/features-20261006/{modern-display-tail-layout-v1,modern-display-owned-rom-tail-v1,modern-display-disabled-preparation-tail-v1,modern-display-xnu-console-tail-v1}/`.

The first appended reservation failed SPTM's bootstrap typing check. Its evidence
is retained. Moving the framebuffer to the normal tail carveout fixes the layout
without changing guest checks. The odd-width pixel fixture also exposed an
existing QMP PPM writer error: it wrote pixman padding into every row. The writer
now emits exactly width times three bytes per RGB row.

## Observe the boot console

`scripts/observe-apple-modern-display.py` accepts the executable, matched decoded
components, served ADT, ramdisk and trustcache explicitly. It starts stopped,
checks the prepared entry/BootVideo, runs for at most60s, captures a PNG and
records limits, source hashes and shutdown. The inherited
`--img4-ignition-compat` and `--pauth-compat` flags default off and are recorded.
The shell recipe uses both: private BootKC ignition patch and PAC sign/auth no-ops.
The original firmware files are unchanged. No additional guest patch is part of
the framebuffer implementation.

`scripts/test-apple-modern-display-qemu.py` executes only its owned pixel writer.
The firmware components supply normal metadata and their code is never selected.
The stopped preparation script verifies the default configuration independently.

The built executable offers VNC via `-vnc 127.0.0.1:1`; a local VNC viewer supplies
the desktop window. GTK/SDL are not included in this build. The framebuffer has
no swap/fence protocol and needs no fabricated device-completion flags.
