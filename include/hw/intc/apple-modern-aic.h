/*
 * Scoped single-CPU Apple AIC2/AIC3 compatibility controller.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Register layout and interrupt semantics follow the Asahi Linux reference
 * drivers (Copyright The Asahi Linux Contributors) and m1n1's GPL-2.0-or-later
 * src/aic.c and src/aic_regs.h. This model does not describe exact silicon.
 */
#ifndef HW_INTC_APPLE_MODERN_AIC_H
#define HW_INTC_APPLE_MODERN_AIC_H

#include <stdbool.h>
#include <stdint.h>

#define APPLE_MODERN_AIC_MAX_IRQS 4096
#define APPLE_MODERN_AIC_MAX_WORDS (APPLE_MODERN_AIC_MAX_IRQS / 32)
/* Defaults for the ADT-named rev-offset and aicglbcfg-offset properties. */
#define APPLE_MODERN_AIC_VERSION_OFFSET 0x0000
/*
 * Declared: the ADT names no reset register and XNU's own driver never reads
 * this offset. It sits in the hole between the Apple-named cap0 (0x4) and
 * aicglbcfg (0x14) registers.
 */
#define APPLE_MODERN_AIC_RESET_OFFSET 0x0010
#define APPLE_MODERN_AIC_CONFIG_OFFSET 0x0014
/*
 * Declared acknowledge offset. Apple documents no value; the ADT property
 * aic-iack-offset supplies it and the firmware treats zero as fatal. 0x1000
 * must not be used: that is Apple's own pubstampcfg0-offset, which the same
 * driver both reads and writes.
 */
#define APPLE_MODERN_AIC_EVENT_OFFSET 0x2000
#define APPLE_MODERN_AIC_EVENT_IRQ 0x00010000

/*
 * IRQ_CFG word layout, one 32-bit register per interrupt at
 * extint-baseaddress + 4 * irq (+ die stride, one die here).
 *
 * Provenance of each statement:
 *  - attested (pinned BootKC, AppleInterruptControllerV3::start and the helper
 *    at 0xfffffff0090189b4): the only IRQ_CFG writer in the driver is the
 *    loop over the ADT property "aic-ext-intr-cfg" (3-byte entries: u16
 *    irq+die, u8 value). Per entry it reads the word, keeps bits [31:8] and
 *    replaces bits [7:0] with the entry byte. The stock iPhone17,3 ADT has no
 *    such property, and the iBoot image carries no such string, so a stock
 *    boot writes no IRQ_CFG at all. The driver also writes -1 to every
 *    MASK_SET word at start (the 128 words at +0x14400 seen in boot traces).
 *  - analogy (m1n1 src/aic.c and aic_regs.h AIC23_IRQ_CFG_TARGET, Linux
 *    irq-apple-aic.c AIC2_IRQ_CFG_TARGET / AIC2_IRQ_CFG_DELAY_IDX): bits [3:0]
 *    are the target CPU number and bits [7:5] a delay-group index. Linux names
 *    the delay field but never writes it on AIC2/AIC3.
 *  - declared: bit 4 and bits [31:8] have no public meaning. They are stored
 *    and returned verbatim and never interpreted, because the driver's
 *    read-modify-write preserves [31:8] and so needs to read back what it
 *    wrote. Delay groups (AIC2_DELAY_GROUPS) are not modelled: delivery is
 *    immediate. This model has one CPU, so every interrupt is delivered to
 *    CPU0 whatever target is recorded.
 */
#define APPLE_MODERN_AIC_IRQ_CFG_TARGET_MASK 0x0000000fu
#define APPLE_MODERN_AIC_IRQ_CFG_DELAY_MASK 0x000000e0u
#define APPLE_MODERN_AIC_IRQ_CFG_DELAY_SHIFT 5

/* All offsets are relative to MMIO0, including the AP event register. */
typedef struct AppleModernAICGeometry {
    uint32_t revision;
    uint32_t num_irqs;
    uint32_t max_irqs;
    uint32_t version_offset;
    uint32_t config_offset;
    uint32_t cap0_offset;
    uint32_t maxnumirq_offset;
    uint32_t irq_config_offset;
    uint32_t event_offset;
    /*
     * Shared timestamp block (ADT pubstampcfg0-offset, #shared-timestamps and
     * pubstampstride-mask). Reads return zero and writes are discarded: the
     * timestamp counters are not modelled. A zero count disables the window.
     */
    uint32_t timestamp_offset;
    uint32_t timestamp_size;
    uint32_t mmio_size;
    /*
     * Opt-in, default false. When false IRQ_CFG accepts only zero (the
     * declared default CPU0 route) and a nonzero store fails, which is the
     * guest-visible external abort the original model produced. When true
     * every IRQ_CFG store is accepted and recorded; see the layout above.
     */
    bool record_irq_config;
} AppleModernAICGeometry;

typedef struct AppleModernAICCore {
    AppleModernAICGeometry geometry;
    uint32_t sw_set_offset;
    uint32_t sw_clear_offset;
    uint32_t mask_set_offset;
    uint32_t mask_clear_offset;
    uint32_t hw_state_offset;
    uint32_t hardware[APPLE_MODERN_AIC_MAX_WORDS];
    uint32_t software[APPLE_MODERN_AIC_MAX_WORDS];
    uint32_t masked[APPLE_MODERN_AIC_MAX_WORDS];
    /* Recorded IRQ_CFG words; all zero unless record_irq_config is set. */
    uint32_t irq_config[APPLE_MODERN_AIC_MAX_IRQS];
    bool enabled;
} AppleModernAICCore;

/* A failed initialization or unsupported write leaves state unchanged. */
bool apple_modern_aic_core_init(AppleModernAICCore *s,
                                const AppleModernAICGeometry *geometry,
                                const char **reason);
/* Preserve externally held hardware levels; mask all, clear SW and enable. */
void apple_modern_aic_core_reset(AppleModernAICCore *s);
bool apple_modern_aic_core_set_level(AppleModernAICCore *s, uint32_t irq,
                                    bool level);
bool apple_modern_aic_core_output(const AppleModernAICCore *s);
uint32_t apple_modern_aic_core_ack(AppleModernAICCore *s);
/* Recorded IRQ_CFG word for an interrupt below max_irqs, else zero. */
uint32_t apple_modern_aic_core_irq_config(const AppleModernAICCore *s,
                                          uint32_t irq);
bool apple_modern_aic_core_read(AppleModernAICCore *s, uint64_t offset,
                               unsigned size, uint32_t *value);
bool apple_modern_aic_core_write(AppleModernAICCore *s, uint64_t offset,
                                unsigned size, uint32_t value);

#ifndef APPLE_MODERN_AIC_STANDALONE
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_APPLE_MODERN_AIC "apple-modern-aic"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernAICState, APPLE_MODERN_AIC)

struct AppleModernAICState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    qemu_irq irq;
    AppleModernAICGeometry geometry;
    AppleModernAICCore core;
    /*
     * Bounded delivery diagnostic (trace=on). Logs output transitions and the
     * accesses that follow the first assertion, so interrupt delivery and the
     * guest's acknowledge path can be observed without unbounded output.
     */
    bool trace;
    bool asserted;
    uint32_t traced;
    /* Separate bound for IRQ_CFG stores, logged whenever trace=on. */
    uint32_t config_traced;
};
#endif

#endif /* HW_INTC_APPLE_MODERN_AIC_H */
