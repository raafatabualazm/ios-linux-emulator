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
| `mtp-peer-descriptor=firmware\|digitizer` | HID descriptor served for interface 1: the firmware's own opaque-frame one (default) or a generic touch screen |
| boot args `agm-authentic=1 agm-trusted=1` | satisfy AppleGenericMultitouchDecider's authenticity/trust gate (no AuthCP relay on this board) |
| boot args `mt-strings=1 mt-bytes=1` | make the transport print its log and every byte it reads and writes on the console |

Diagnostics: `x-push-rx` (QOM property of `/machine/modern-dockchannel-mtp`, write-only hex bytes queued as
device-to-AP data), bounded logs of every RX arm and IRQ transition, `sysreg-trace`.

## Protocol (confirmed against the guest's own byte dumps)

DockChannel carries SCMFIFO frames. Frame = 8-byte header `{hdr_len=8, type, length, transfer_id, interface, b6, b7}`,
8-byte sub-header `{flags, 0, payload_len, retcode}`, payload, zero pad to 4, `u32 = ~sum` of the little-endian words
before it. `length = round_up(8 + payload_len, 4)` with a sub-header, 0 without. type `0x11` command / response,
`0x12` device report. flags: bit 0 = GET, bits 7:6 = report type (2 = feature).

Start-up, as the emulated device plays it:

1. The AP arms a 12-byte asynchronous receive (the minimum frame: header + checksum) and sends nothing.
2. Device: READY report on interface 0, payload `f1 <interface> <status>`.
3. AP: SET feature `c1 02` (system awake) on interface 0; device acks (same transfer id, empty payload).
   Transport logs `Handshake done: SW FIFOs registered`.
4. Device: descriptor packet, report `0xf0` on interface 0: `{0xf0, u16 version <= 1, u8 interface, char name[16],
   u16 more}` + sections `{u16 type 0..7, u16 length < 0x800, body}`; type 0 is the HID report descriptor, `more = 0`
   completes the interface. Parsed by `comm::parseDescriptor` (0xfffffff008e5e36c).
5. AP: SET `b4 01`; ack; `multi-touch::ready: Registering interface`; `AppleHIDTransportHIDDevice::start`.
6. AP configures the interface: SET/GET `0x41` (interface power; the GET wants `[0x41, interface, state, 0]`), GETs of
   `0xdb 0xd1 0xd3 0xd0 0xa1 0xd9 0x7f 0x73` on interface 1 (answered with the controller bytes the kernel itself caches,
   BootKC personality `GetReportCachedResponse`), SETs `0x40`, `0x9d`, `0xbf`, `0xaf`.

The firmware's multi-touch HID descriptor (29 bytes at 0x8a194 of the retained MTP images) is one Digitizer / Touch Screen
collection with a single vendor-page buffered-bytes input of 0x1ffff bits: an opaque multitouch frame.

## Not done

* the multitouch frame layout (and so real touch reports), the other three interfaces' descriptors, the memory FIFOs
  (no IOMapper: `AppleT8110DART` never starts for `dart-mtp` here), the MTP coprocessor itself, wftm provisioning.
