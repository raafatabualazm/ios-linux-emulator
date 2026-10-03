# Private GUI diagnostics

`diagnostics.py` records evidence for an already running isolated `session.py` state. It does not start guests, change firmware, or install apps. Keep recorder directories in ignored private evidence storage.

```sh
python3 tools/runtime/diagnostics.py init --state /path/to/state --evidence /path/to/new-evidence
python3 tools/runtime/diagnostics.py capture --evidence /path/to/new-evidence --label awake
python3 tools/runtime/diagnostics.py observe --evidence /path/to/new-evidence --screen 000-awake.png --description 'Describe the visible screen after viewing it'
python3 tools/runtime/diagnostics.py control --evidence /path/to/new-evidence tap --x 414 --y 1000
python3 tools/runtime/diagnostics.py snapshot --evidence /path/to/new-evidence
python3 tools/runtime/diagnostics.py classify --run /path/to/state/runs/RUN --output /path/to/new-report.json
python3 tools/runtime/diagnostics.py originals --state /path/to/state --output /path/to/new-original-check.json
```

View every screenshot before deciding the next control. Input and QMP acknowledgements are recorded as events sent; they do not prove a screen transition or app execution. The legacy display must be 828 by 1792 pixels. `home` sends F6 and `side` sends F5. `swipe` additionally takes `--to-x`, `--to-y`, and `--duration` from 0.02 to 5 seconds.

`snapshot` records QEMU run status, its network configuration text (at most 4 KiB), and recognized live drive descriptors. A configured QEMU network does not prove guest connectivity.

The recorder allows 64 PNGs, at most 8 MiB each and 64 MiB total, and 256 events with a 256 KiB JSONL limit. A screenshot budget is reserved before asking QEMU to write; its fixed display dimensions are checked afterwards. The PNG header check establishes size and dimensions, not full image integrity. Run manifest changes reject later recorder operations. Init records original root metadata, all eight ancillary-store hashes, and recognized live file descriptors. The large original root hash is not recomputed. Run `originals` after the guest stops for a second check.

The classifier reads at most the final 4 MiB of each serial/emulator log and records at most 32 short excerpts. It distinguishes real `panic(cpu...)` lines from registration strings such as `IOPlatformPanicAction`; SEP panic takes precedence even after the excerpt limit. Negative process signals and host assertion text are crash evidence. An unrequested clean exit remains an unexpected exit. Absence of these patterns does not establish guest health, Home, or IPA success. Logs outside the scanned tail may contain earlier evidence. Lines containing keybag, IV key, ticket, or password markers are omitted from excerpts.

Live operations are bound to the recorder's run ID and PID. A stopped guest or a restarted state rejects capture, input and runtime snapshots. Create a fresh evidence directory for each run; historical observations remain readable.

Verification: `python3 -m unittest discover -s tests/runtime -p test_diagnostics.py -v` uses temporary fixtures and mock QMP; it runs no guest.

## Optional USB companion endpoint

The iOS 14 `t8030` USB controller connects to a companion's Unix listener through
the machine properties `usb-conn-type` and `usb-conn-addr`. Enable its private
endpoint with:

```sh
python3 tools/runtime/session.py run --state /path/to/private-state --seconds 900 --usb
```

The runner holds the state lock, requires an owned mode-0700 directory, and
rejects an existing `usb.sock` or an active Linux socket using that pathname.
It writes `runs/RUN/usb-startup.json` and prints the generated endpoint before
waiting up to 30 seconds for the companion. Start the companion during this
waiting phase; the phone QEMU starts automatically after the listener is ready.
The startup wait counts towards `--seconds`. Default runs keep their existing
arguments and do not enter this waiting phase.

Use a pinned custom x86 QEMU with `usb-tcp-remote`, a USB-capable Linux kernel,
and an already prepared disposable companion overlay. In a second terminal:

```sh
/path/to/custom-qemu-system-x86_64 -M q35 -m 3G -smp 2 \
  -drive file=/path/to/disposable-companion.qcow2,if=virtio,format=qcow2 \
  -usb -device usb-ehci,id=ehci \
  -device usb-tcp-remote,bus=ehci.0,conn-type=unix,conn-addr=/path/to/private-state/usb.sock \
  -nic none -display none -serial mon:stdio
```

Readiness uses a bounded passive `/proc/net/unix` read, requires a single stream
listener, and rechecks the captured filesystem device/inode/owner. It does not
connect to the listener or consume its USB accept. `usb_listener_ready` means
only that the companion listener is ready; USB enumeration, normal-mode
lockdown pairing, AFC and installation_proxy require separate observations.
The endpoint uses the Unix USB bridge directly; no USB chardev is added.

After the phone is reaped, cleanup removes only the captured socket identity;
replacement files/sockets are preserved. Cleanup is inode checked within the
private state directory, not an atomic guarantee against concurrent same-user
pathname replacement. Unreaped phone processes retain their live/QMP metadata
and USB endpoint. The runner does not manage or stop the external companion;
stop it separately after the phone run, including startup timeout/interruption.
Unlinking its endpoint does not terminate the companion listener process.

Pairing material stays private in the companion. The uploaded IPA has an
expired profile; this transport option performs no installation. Normal
installation requires a freshly signed app accepted by the guest, followed by
independent registration and GUI launch evidence.

Verification: `python3 -m unittest discover -s tests/runtime -p test_usb.py -v`
uses owned disposable Unix sockets and process fixtures, with no iOS guest.
