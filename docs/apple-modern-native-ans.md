# Initial native ANS block adapter

`apple-modern,modern-aic=on,modern-ans=on` creates a default-off, firmware-free
ANS/RTKit peer and an Apple linear-tag adapter around the ordinary QEMU NVMe
backend. It does not execute ANS or SEP firmware. For an owned 4 KiB-sector disk:

```sh
-blockdev driver=file,filename=/path/to/owned.raw,node-name=native-file,cache.no-flush=off \
-blockdev driver=raw,file=native-file,node-name=native-disk \
-device nvme-ns,drive=native-disk,bus=modern-ans-nvme,nsid=1,logical_block_size=4096,physical_block_size=4096
```

The matched T8140 ADT supplies the ASC wrapper, main/secure BARs and interrupts.
The internal PCI host exists to reuse the NVMe engine; it is not enumerated by
the guest. RTKit negotiation must complete before the ANS boot-status word
reports ready. Commands use 64-byte SQEs, 128-byte TCBs, one global pool of 64
tags and normal NVMe completions/interrupts. The authoritative TCB PRPs are
validated page by page before submission, including list bounds and lengths.
DMA can reach only the configured main RAM; this is not a full CoastGuard model.

The adapter explicitly refuses unsupported crypto, metadata and SGL requests.
A successful plaintext command is not evidence of SEP encryption. Native iOS
storage discovery and encrypted Data mounting remain separate integration gates.
Migration is blocked. The adapter and its diagnostics reset with the machine.
Existing NVMe controllers retain their original queue-entry behavior; 64-byte
linear entries are enabled only for this controller.

```sh
python3 scripts/test-apple-modern-ans-qemu.py \
  --binary /path/to/pinned/qemu --components /path/to/derived \
  --output-dir /new/evidence
```

The owned ARM64 fixture executes real MMIO and DMA. It tests write/flush,
process crash after the flush acknowledgement, fresh-process old-data readback,
a distinct read-only write refusal, invalid second-page DMA without partial
writes, TCB length disagreement, crypto refusal, tag reuse, CQ phase wrap,
mailbox/NVMe interrupt delivery and a complete second sequence after reset.
This is process-crash persistence on the host backend, not host power-loss proof.

With `prepare-only=off`, the board also maps the declared core-loaded register,
SART register storage and segment SRAM, and supplies the ANS nub metadata. The
SART bank stores 32-bit words; QEMU splits valid 64-bit accesses into two words
so the high half is retained. These registers do not enforce SART DMA permissions
and the loaded/running metadata does not mean an ANS firmware core executes.
The matched SART node has three apertures (0xc000, 0x4000, 0x4000); the current
adapter covers only the first 0x4000 bytes of reg[0]. The other ranges remain
unimplemented and the width/reset test covers only the mapped subset.

`scripts/test-apple-modern-ans-sart-qemu.py` uses normal board mappings and an
owned ARM64 ROM. It verifies the exact PC/code before execution, tests mixed
32/64-bit accesses, neighbor preservation, the bank end and reset. The older
block-I/O fixture uses `prepare-only=on` and therefore cannot qualify this bank.

## Quiet PMP command receipt

For platform investigation, the existing opt-in PTD board can additionally use:

```sh
-M apple-modern,...,modern-pmp-ptd=on \
-global apple-modern-pmp-ptd.command-responder=on
```

The property defaults off and is fixed after realization. The recovered T8140
PMP firmware commits the two-word MCC command at Update[432], after word1 at
433; a nonzero 12-bit sequence is acknowledged at Dashboard[448]. The quiet
stand-in publishes only that receipt and its new_data bit. It supplies no PMP
online status, power acknowledgement, cache grants, thermal policy or firmware
execution. The absence of those services is intentional and remains visible.
Read-only command-count, ack-count and command-word0/1 diagnostics distinguish
an actual guest command from a dormant device. The existing MMIO counters keep
their meaning. Reset clears receipts and counters and retains the QOM profile.

Protocol provenance is the retained, hash-pinned AP/PMP disassembly in
`modern-emulator/evidence/features-20261009/w2-pmp/README.md` (profile Q), at
workspace level. `test-apple-modern-pmp-command-qemu.py` checks default-off and
quiet behavior with real ARM64 loads/stores across reset. It also requires
PMP-status and quota-response slots to remain zero.

## PMGR accounting register continuation

The native-storage lane also extends the existing opt-in PMGR storage profile
with the five ADT cluster-control registers, the original ADT's non-event counter
control/data words and the bounded ACC accounting ranges recovered from
AppleT8140PMGR slot0xb88. These are zero-reset storage without event producers.
They do not enforce voltage, frequency or thermal policy.

The wrapper maps validated sparse MemoryRegions directly. More than32 windows
must never be passed to sysbus_init_mmio: SysBusDevice has a fixed32-entry array,
and NDEBUG hides its overflow assertion. The actual CPU gate caught that old
wrapper defect and now checks all57 mapped regions and zero SysBus slots across
reset. The ACC accounting-enable register at +0x178 in each cluster accepts the
recovered 64-bit read-modify-write without generating hardware events. Missing
words, holes and window boundaries still fault. Core and CPU
qualification is recorded under the workspace native-storage evidence directory.

The additional eight-byte P-cluster region at `0x211e440f8` follows the matched
AppleT8140PMGR slot0x9b8/0xe08 call chain and ACC mapping table at `0x77b2000`.
The actual native fault instruction at linked `0x92ae918` stores the value 1.
E-cluster's corresponding address already lies in cpm-impl RAM. This narrow
region provides zero-reset storage with no power/status acknowledgement; both
adjacent holes still fault. Gemini's optional permissive callback cannot extend
the mapped address space and is not enabled for this qualification.
