# Fork publication checks — 2026-10-01

The published source starts from upstream
`cc4302a99167abec69b714cfd00c38caece7e7de`. These checks were run on 64-bit
Linux with GCC 15, separately from the already installed course runtime.
Firmware, tickets, complete guest disks, private machine paths, and raw logs
are not included in the fork.

## Emulator and Linux tools

- A fresh standard build linked both `qemu-system-aarch64` and
  `qemu-system-x86_64`. The neutral version banner, `t8030` machine,
  `usb-tcp-remote` options, and `user` network backend were checked.
- The A13 cross-cluster IPI regression check passed.
- Nine Go tests and eight Python tests passed for malformed diffs, sparse
  extents, physical/logical bounds, short reads, aliases, recovery, and
  failed manifest writes. The Go tool built for AMD64 and cross-built for
  ARM64; the pinned APFS dependency currently prevents 32-bit builds.
- Read-only verification of the real restored image passed for the
  2,052,489,216-byte dyld cache at container offset 24576, `role:system`.
  Its current file mapping has one uncompressed, unencrypted extent.
  The original same-size write and full-file hash verification were performed
  during the earlier GUI setup; no new full-image write was run for publication.
- Portable launch commands and QMP status, side-button, screenshot, and quit
  controls were exercised. The fresh standard binary reached Hello/setup
  using temporary disk overlays on the previously restored disk set.
  That successful retry ran under GDB. One earlier solo startup exited with
  host SIGSEGV before usable guest logs; no core or causal stack was available.
  Two earlier tests were stopped before a GUI result. The old validated binary
  also reached Hello using the same overlay profile. Reliable startup is not
  established by this successful retry, and the host fault remains unresolved.

Standard AArch64 executable SHA-256:
`93daa7781d799bbc74c2d1c9bf37c0c339f600cdafbc645eaa3240766494c56b`.
Standard x86_64 executable SHA-256:
`8e98213c2267cd8de2e2e05d031ac916eeae611476a6710c666ab98a3c79db40`.
These identify the tested local builds; binaries are not distributed here.

## Optional AFL branch

See the [AFL guide](https://github.com/raafatabualazm/ios-linux-emulator/blob/afl-persistent/docs/afl.md).

- A fresh `--enable-afl` build linked successfully. An independent build with
  `--disable-afl` also linked, with `CONFIG_AFL` undefined and no forkserver
  marker or AFL runtime/helper functions. Enabling AFL without TCG was rejected.
- Focused C checks exercised bounded HINT reads, inactive/privileged calls,
  thread-stop failure, and exception nesting deeper than the saved stack.
- Actual forkserver replay with seven guest CPUs completed 407 boundaries,
  including 200 repeats each of `getpid` and `getppid`. Every repeated input
  consumed its 14 bytes and stopped at the boundary. Each syscall's 106-bucket
  coverage map was byte-identical across all its repeats, and the two maps
  differed. Empty input had no coverage beyond the AFL live-map marker.
- A 50-second AFL 2.57b run with the 30-second testcase timeout completed
  cleanly: 20 executions, two paths, 0.17% bitmap occupancy, 100% stability,
  zero crashes, and one hang. Its serial log showed the harness exiting with
  SIGSYS after a syscall-number mutation. This is not a confirmed kernel panic.
  The earlier 10-second boot-timeout run aborted under concurrent load; the
  helper now makes that timeout configurable and reports early aborts as failures.
- The separate shell image built with the documented helper reached root Bash.
  `id` returned `uid=0(root)`, `uname -a` identified Darwin 20 / iPhone12,1,
  and `echo SHELL_OK` completed. The normal GUI profile does not supply Bash.

The pinned wrapper scope is `0x1e7c:0x1e14`, with ramdisk SHA-256
`dfda491c79438ddd87b519747bbdc697d29c3d706b046ae9c57930178dcd7ab5`.
Map SHA-256 values:

| Input | Map SHA-256 |
| --- | --- |
| getpid | `a8dda5133c0b760ad7760dff4edb4f8d0c1ab3a8e95bb44116e999612a528013` |
| getppid | `8d05e77e4ada0e08cbea32eebf90801e5504e1751b8a55623d863dd1f85d79b6` |

The final enabled executable's SHA-256 is
`4b3ef42a44f6458310483093ea5bf9724440589100ed2b5e0d4afa3592d68110`.
The repeat test preceded an attribution-comment-only rebuild; the smoke and
shell checks used this final executable. Narrow-scope repeatability and a short
smoke run do not establish whole-kernel coverage or long-run stability.

## Earlier restore results and remaining gaps

The preceding laboratory build completed a local Linux restore in 13m58s.
Its patched raw disk booted Hello/setup locally and on the course host,
including the course GTK desktop. No full restore was rerun for publication.
The course host's independent fresh restore still fails during `update_iBoot`
after filesystem transfer, with a later DART panic. Its working GUI disk came
from the local restore. Setup Assistant completion, a configured home screen,
other iOS releases/devices, and old snapshot/migration compatibility remain
unvalidated. The newly published hardening changes have not been installed
over either existing lab runtime.
