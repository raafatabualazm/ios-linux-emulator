# Recording AIC IRQ_CFG words (`aic-record-irq-config`)

By default the modern AIC accepts only a zero store to an `IRQ_CFG` word and
answers any nonzero store with an access error, which the guest sees as a
synchronous external abort (`ESR_EL2` `0x96000250`). With
`apple-modern,modern-aic=on,aic-record-irq-config=on` every `IRQ_CFG` store is
accepted and recorded, reads return what was stored, and a device or `RESET`
register reset returns every word to zero. The property is fixed after board
initialization and the board refuses it without `modern-aic`.

## What the register layout rests on

* **Attested (pinned BootKC, `AppleInterruptControllerV3`).** The only
  `IRQ_CFG` writer is the loop over the ADT property `aic-ext-intr-cfg`
  (three-byte entries: `u16` die-and-irq, `u8` value). For each entry it reads
  the word, keeps bits `[31:8]` and replaces bits `[7:0]` with the entry byte.
  The address helper is `0x10000 + die * 0x4a00 + irq * 4` unless
  `extint-baseaddress` and `extintrcfg-stride` say otherwise, which the stock
  tree does (`0x10000`, `0x4a00`). The driver also writes `-1` to every
  `MASK_SET` word at start.
* **Attested absence.** The stock iPhone17,3 ADT has no `aic-ext-intr-cfg` and
  the iBoot image holds no such string. A stock boot therefore writes no
  `IRQ_CFG` word at all, and the abort only matters for trees that carry the
  property.
* **Analogy (m1n1 `aic.c`/`aic_regs.h`, Linux `irq-apple-aic.c`).** Bits
  `[3:0]` are the target CPU number and bits `[7:5]` a delay-group index. Linux
  names the delay field and never writes it on AIC2/AIC3.
* **Declared.** Bit 4 and bits `[31:8]` have no public meaning; they are stored
  and returned verbatim because the driver's read-modify-write needs to read
  back what it wrote. Delay groups are not modelled (delivery is immediate) and
  the board has one CPU, so every interrupt is delivered to CPU0 whatever
  target is recorded. Reset clearing the words is declared, not measured.

## Qualified scope

```sh
python3 scripts/test-apple-modern-aic-irq-config.py --evidence /new/dir
python3 scripts/test-apple-modern-aic-irq-config-qemu.py --binary /pinned/qemu \
  --components /path/to/derived --output-dir /new/dir --previous-binary /older/qemu
```

The core test checks every one of the 4,096 words, a full register-window sweep
(nothing outside the window changes), the XNU read-modify-write, delivery of
interrupts whose recorded target is a missing CPU, reset, size/alignment
refusals and the default-off refusal. It runs under ASan/UBSan and `NDEBUG` and
rejects eight deliberately broken variants of the model. The actual-CPU gate
runs an owned ROM twice across a system reset and also shows the default board
taking the external abort, the refusal without `modern-aic`, creation-only
mutability and rejection by the previous pin. `aic-trace=on` additionally logs
the first 200 `IRQ_CFG` stores with their decoded target and delay index.

No guest iOS interrupt-driven path is claimed by this option.
