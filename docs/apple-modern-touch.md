# apple-modern touch input (branch claude/touch-attach)

Architecture note for the multi-touch path of the `apple-modern` machine (T8140 / iPhone17,3, iOS 27 24A437).
Everything here is default-off. The goal is a device model that plays the multi-touch coprocessor's end of
the HID transport, so the unmodified iOS kernel publishes a digitizer.

## Options

| option | effect |
| --- | --- |
| `adt-compat-restore=...+hid-mtp` | restore the stock `compatible` strings of the MTP nodes (the served tree strips them) |
| `modern-mtp-input=on` | map `/arm-io/mtp-gpio`, the DockChannel FIFO of `/arm-io/dockchannel-mtp`, and a declared T8110 DART for `/arm-io/dart-mtp`; needs `modern-aic=on` |
| `hid-static-config=on` | in-memory kernel-cache edit so `AppleHIDTransportDeviceFIFO::getStaticConfig` returns the real `MTP_SYS[0].Config` (Protocol `SCMFIFO`, 4 interfaces) instead of waiting for a firmware download; serves `use-static-config` on `mtp-transport` |
| `modern-mtp-peer=on` | attach the device-side stand-in (needs `modern-mtp-input`) |
| `mtp-peer-descriptor=firmware` | HID descriptor served for interface 1. Only the firmware's own opaque-frame descriptor is supported: the multitouch service does not understand a generic digitizer report |
| boot args `agm-authentic=1 agm-trusted=1` | satisfy AppleGenericMultitouchDecider's authenticity/trust gate (no AuthCP relay on this board) |
| boot args `mt-strings=1 mt-bytes=1` | make the transport print its log and every byte it reads and writes on the console |

Diagnostics and test hooks, all on the QOM object `/machine/modern-dockchannel-mtp`:

* `x-push-rx` (write-only hex bytes queued as device-to-AP data).
* `x-touch` (write-only, needs `modern-mtp-peer`): `tap X Y [HOLD_MS]` or `swipe X0 Y0 X1 Y1 [DURATION_MS [HOLD_MS]]`, pixel
  coordinates of the 1024x768 framebuffer. The gesture is generated on the guest's virtual clock, one frame every 16 ms,
  so its timing does not depend on host scheduling. The lift-off (BreakTouch) frame is the last step of the motion and keeps
  its velocity, as a real controller's does; a HOLD_MS keeps the finger at the end point and lifts with zero velocity.
  Example: `qom-set ... x-touch "swipe 512 745 512 300 250"`.
* A pointer drag (VNC, QMP `input-send-event`) is one finger: absolute X/Y move it, the left button is touch down / up. A frame is generated every 16 ms while the
  button is down; frames are never closer than 8 ms (a release a millisecond after a periodic frame is delayed), and the lift-off frame carries the average velocity of the
  last 100 ms of the contact, because a flick is judged by the velocity at release.
* Bounded logs of every RX arm and IRQ transition, `sysreg-trace`.

## Protocol (confirmed against the guest's own byte dumps)

DockChannel carries SCMFIFO frames. Frame = 8-byte header `{hdr_len=8, type, length, transfer_id, interface, b6, b7}`,
8-byte sub-header `{flags, 0, payload_len, retcode}`, payload, zero pad to 4, `u32 = ~sum` of the little-endian words
before it. `length = round_up(8 + payload_len, 4)` with a sub-header, 0 without. type `0x11` command / response,
`0x12` device report. flags: bit 0 = GET, bits 7:6 = report type (2 = feature).

Start-up, as the emulated device plays it:

1. The AP arms a 12-byte asynchronous receive (the minimum frame: header + checksum) and sends nothing until the
   device speaks. The first device frame makes it create the other interfaces and arm a 100 ms handshake.
2. Device: descriptor packet, report `0xf0` on interface 0: `{0xf0, u16 version <= 1, u8 interface, char name[16],
   u16 more}` + sections `{u16 type 0..7, u16 length < 0x800, body}`. Type 0 is the HID report descriptor, type 4 the
   ready status (0 = HID), `more = 0` completes the interface. Parsed by `comm::parseDescriptor` (0xfffffff008e5e36c).
3. AP: SET feature `c1 02` (system awake) on interface 0; device acks (same transfer id, empty payload). Transport logs
   `Handshake done: SW FIFOs registered`.
4. AP: SET `b4 <interface>` (enable); device acks, then reports READY: `f1 <interface> 00 00` on interface 0.
   READY ahead of the descriptor is ignored, and a non-zero status marks the interface inactive. The transport then logs
   `multi-touch::ready: Registering interface` and `AppleHIDTransportHIDDevice::start: interface 1`.
5. AP configures the interface: SET/GET `0x41` (interface power; the GET wants `[0x41, interface, state, 0]`), GETs of
   `0xdb 0xd1 0xd3 0xd0 0xa1 0xd9 0x7f 0x73` on interface 1, SETs `0x40`, `0x9d`, `0xbf`, `0xaf`.
   The peer answers with the controller bytes the kernel itself caches (BootKC personality `GetReportCachedResponse`,
   variant ExpectedVersion 896), except the sensor-surface report `0xd9` (and its copy inside the `0xdb` composite),
   which describes this machine's 100.00 x 75.00 mm surface: whole multiples of 100 units, because the HID plug-in
   normalises with `floor(size / 100)`. The `0xbf` GET (touch mode command words) answers eight zero bytes.
6. Device: one `60 11` report on interface 1 ("Power on Reset and InitDone") shortly after the first `0xdb` GET.

The firmware's multi-touch HID descriptor (29 bytes at 0x8a194 of the retained MTP images) is one Digitizer / Touch Screen
collection with a single vendor-page buffered-bytes input of 0x1ffff bits and no report id: every input report is an
opaque Apple multitouch frame whose first byte is the multitouch report id.

## Multitouch frame (decoded from MultitouchSupport; same bytes as the t8030 model in mt-spi.c)

Input report on interface 1, report id `0x44`, little endian:

| offset | size | field |
| --- | --- | --- |
| 0 | 1 | `0x44` |
| 1 | 1 | frame counter (wraps; a repeated counter with a repeated timestamp is dropped) |
| 2 | 1 | header length, 28 |
| 3 | 1 | header version, 0 |
| 4 | 4 | timestamp in milliseconds: non-zero, strictly increasing |
| 8..15 | 8 | flags, reserved, image length 0 |
| 16 | 1 | path count (<= 32) |
| 17 | 1 | path stride, 20 |
| 18..27 | 10 | reserved |
| 28 + 20 i | 20 | path: `id, stage, finger, hand, s16 x, s16 y, s16 vx, s16 vy, u16 major, u16 minor, s16 angle, u16 zTotal` |

Positions are 0.01 mm from the bottom-left of the sensor, velocities 1/8 mm/s, radii 0.01 mm, `angle * pi / 32768`,
`zTotal / 256`. Stages: 3 MakeTouch, 4 Touching, 5 BreakTouch, 6 LingerInRange, 7 OutOfRange. The kernel service only
forwards the frame; MultitouchSupport and `MultitouchHID.plugin` (parser type 1) turn it into digitizer events. Frames
are dropped while the touch mode is Off (the guest sets it to On with `SET 0xbf` by itself).

## What stops a swipe from opening Setup (not a touch problem)

SpringBoard's key bag state on this guest is "passcode set, not unlocked since boot" (read live: `SBFMobileKeyBag` `hasPasscodeSet = 1`, `hasUnlockedSinceBoot = 0`), because the
guest has no SEP and the AppleKeyStore user client is deliberately unsupported (`sks-open-wait-skip` candidate), so MobileKeyBag's `aks_get_lock_state` / `aks_get_configuration`
fail and SpringBoard keeps its fail-secure defaults. A swipe lifts the cover sheet and shows only the Emergency button; Setup is alive but never presented. A fresh,
never-set-up device reports no passcode and unlocked since boot; modelling that answer in the key store is the next step.

## Pointer-driven flicks

A pointer tap (QMP `input-send-event`, a VNC click) works like a scripted tap, and a pointer drag that is released while still moving lifts the cover sheet like the scripted
`x-touch swipe` (the decoded frame logs of the two match number for number). A drag that pauses before the release does not: the frames before the lift-off are stationary, so the
velocity at release is near zero and the system does not treat it as a flick (the test script of the first boots paused 16 ms before releasing). A human flick with a VNC client
releases while moving.

## Not done

* HID descriptors for `nova` (interface 3) and `mtp` (interface 2). The retained `D47_MtpFirmware` image has one digitizer descriptor, the multi-touch one; `D47S1` and `wftm` are not in it. The peer now announces those two interfaces Inactive (ready status 1, no invented descriptor) so a READY can clear AsyncRegistration. That announcement is codec-tested only; a guest replay of tip `d72897a` has not been run.
* the memory FIFOs (no IOMapper: `AppleT8110DART` never starts for `dart-mtp`
  here), the MTP coprocessor itself, wftm provisioning, more than one finger.
* Verified on the guest: sensor x to the right and sensor y up from the bottom edge map to the framebuffer without any flip
  (a tap at the carousel's information button opened its information view). One finger only.
