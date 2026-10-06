/*
 * Scoped single-CPU Apple AIC2/AIC3 compatibility controller.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Reference register layout and observable interrupt behavior:
 *   Linux drivers/irqchip/irq-apple-aic.c
 *   Copyright The Asahi Linux Contributors
 *   Based on irq-lpc32xx: Copyright 2015-2016 Vladimir Zapolskiy
 *   Based on irq-bcm2836: Copyright 2015 Broadcom
 *   m1n1 src/aic.c and src/aic_regs.h (GPL-2.0-or-later)
 *
 * https://github.com/torvalds/linux/blob/master/drivers/irqchip/irq-apple-aic.c
 * https://github.com/AsahiLinux/m1n1/blob/main/src/aic.c
 * https://github.com/AsahiLinux/m1n1/blob/main/src/aic_regs.h
 *
 * One CPU, one die, level inputs ORed with independent software latches.
 * Event reads select the lowest active IRQ and automatically mask it.
 * IRQ_CFG accepts only zero (the declared default CPU0 route). Nonzero routes,
 * delay groups, reserved registers, fast IPIs and timer routing are unsupported.
 * The declared revision value and SW/MASK alias readback are compatibility
 * interfaces, not claims about undocumented hardware revision/reset bits.
 * No target IRQ count or event-register location is inferred here.
 */
#ifndef APPLE_MODERN_AIC_STANDALONE
#include "qemu/osdep.h"
#else
#include <stddef.h>
#include <string.h>
#endif
#include "hw/intc/apple-modern-aic.h"
#ifndef APPLE_MODERN_AIC_STANDALONE
#include "migration/vmstate.h"
#endif

static bool aic_ranges_overlap(uint64_t a, uint64_t a_size,
                            uint64_t b, uint64_t b_size)
{
    return a < b + b_size && b < a + a_size;
}

bool apple_modern_aic_core_init(AppleModernAICCore *s,
                                const AppleModernAICGeometry *geometry,
                                const char **reason)
{
    uint64_t bank_size, total_size;
    uint32_t registers[6];
    const char *problem = NULL;

    if (!s || !geometry) {
        problem = "missing controller state or geometry";
        goto invalid;
    }
    if (geometry->revision != 2 && geometry->revision != 3) {
        problem = "only declared AIC2/AIC3 compatibility revisions are supported";
        goto invalid;
    }
    if (!geometry->num_irqs || geometry->num_irqs > geometry->max_irqs ||
        geometry->max_irqs > APPLE_MODERN_AIC_MAX_IRQS ||
        (geometry->num_irqs & 31) || (geometry->max_irqs & 31)) {
        problem = "IRQ counts must be multiples of 32 with 0 < num <= max <= 4096";
        goto invalid;
    }
    if (geometry->mmio_size < 0x18 || geometry->mmio_size > 0x4000000 ||
        (geometry->mmio_size & 3) || (geometry->irq_config_offset & 3)) {
        problem = "MMIO geometry must be aligned and bounded to 64 MiB";
        goto invalid;
    }
    bank_size = geometry->max_irqs / 32 * 4;
    total_size = (uint64_t)geometry->max_irqs * 4 + bank_size * 5;
    if ((uint64_t)geometry->irq_config_offset + total_size >
        geometry->mmio_size) {
        problem = "IRQ configuration and bitmap banks exceed the MMIO aperture";
        goto invalid;
    }
    registers[0] = APPLE_MODERN_AIC_VERSION_OFFSET;
    registers[1] = APPLE_MODERN_AIC_RESET_OFFSET;
    registers[2] = APPLE_MODERN_AIC_CONFIG_OFFSET;
    registers[3] = geometry->cap0_offset;
    registers[4] = geometry->maxnumirq_offset;
    registers[5] = geometry->event_offset;
    for (unsigned i = 0; i < 6; i++) {
        if ((registers[i] & 3) ||
            (uint64_t)registers[i] + 4 > geometry->mmio_size ||
            aic_ranges_overlap(registers[i], 4, geometry->irq_config_offset,
                           total_size)) {
            problem = "capability/control/event register is outside or overlaps IRQ banks";
            goto invalid;
        }
        for (unsigned j = 0; j < i; j++) {
            if (registers[i] == registers[j]) {
                problem = "capability/control/event registers overlap";
                goto invalid;
            }
        }
    }

    memset(s, 0, sizeof(*s));
    s->geometry = *geometry;
    s->sw_set_offset = geometry->irq_config_offset + geometry->max_irqs * 4;
    s->sw_clear_offset = s->sw_set_offset + bank_size;
    s->mask_set_offset = s->sw_clear_offset + bank_size;
    s->mask_clear_offset = s->mask_set_offset + bank_size;
    s->hw_state_offset = s->mask_clear_offset + bank_size;
    apple_modern_aic_core_reset(s);
    if (reason) {
        *reason = NULL;
    }
    return true;

invalid:
    if (reason) {
        *reason = problem;
    }
    return false;
}

void apple_modern_aic_core_reset(AppleModernAICCore *s)
{
    memset(s->software, 0, sizeof(s->software));
    memset(s->masked, 0xff, sizeof(s->masked));
    s->enabled = false;
}

bool apple_modern_aic_core_set_level(AppleModernAICCore *s, uint32_t irq,
                                    bool level)
{
    uint32_t bit;

    if (irq >= s->geometry.num_irqs) {
        return false;
    }
    bit = UINT32_C(1) << (irq & 31);
    if (level) {
        s->hardware[irq / 32] |= bit;
    } else {
        s->hardware[irq / 32] &= ~bit;
    }
    return true;
}

static int pending_irq(const AppleModernAICCore *s)
{
    if (!s->enabled) {
        return -1;
    }
    for (unsigned word = 0; word < s->geometry.num_irqs / 32; word++) {
        uint32_t pending = (s->hardware[word] | s->software[word]) &
                           ~s->masked[word];
        if (pending) {
            return word * 32 + __builtin_ctz(pending);
        }
    }
    return -1;
}

bool apple_modern_aic_core_output(const AppleModernAICCore *s)
{
    return pending_irq(s) >= 0;
}

uint32_t apple_modern_aic_core_ack(AppleModernAICCore *s)
{
    int irq = pending_irq(s);

    if (irq < 0) {
        return 0;
    }
    s->masked[irq / 32] |= UINT32_C(1) << (irq & 31);
    return APPLE_MODERN_AIC_EVENT_IRQ | irq;
}

static bool valid_access(const AppleModernAICCore *s, uint64_t offset,
                         unsigned size)
{
    return s->geometry.num_irqs && size == 4 && !(offset & 3) &&
           offset < s->geometry.mmio_size &&
           s->geometry.mmio_size - offset >= 4;
}

static bool bank_word(const AppleModernAICCore *s, uint64_t offset,
                      uint32_t base, unsigned *word)
{
    uint64_t size = s->geometry.max_irqs / 32 * 4;

    if (offset < base || offset - base >= size) {
        return false;
    }
    *word = (offset - base) / 4;
    return true;
}

bool apple_modern_aic_core_read(AppleModernAICCore *s, uint64_t offset,
                               unsigned size, uint32_t *value)
{
    unsigned word;

    if (!value || !valid_access(s, offset, size)) {
        return false;
    }
    if (offset == APPLE_MODERN_AIC_VERSION_OFFSET) {
        *value = s->geometry.revision;
    } else if (offset == s->geometry.cap0_offset) {
        *value = s->geometry.num_irqs; /* last die = 0 */
    } else if (offset == s->geometry.maxnumirq_offset) {
        *value = s->geometry.max_irqs | UINT32_C(1) << 24; /* one die */
    } else if (offset == APPLE_MODERN_AIC_RESET_OFFSET) {
        *value = 0;
    } else if (offset == APPLE_MODERN_AIC_CONFIG_OFFSET) {
        *value = s->enabled;
    } else if (offset == s->geometry.event_offset) {
        *value = apple_modern_aic_core_ack(s);
    } else if (offset >= s->geometry.irq_config_offset &&
               offset - s->geometry.irq_config_offset <
               (uint64_t)s->geometry.max_irqs * 4) {
        *value = 0; /* only declared default CPU0 routing is supported */
    } else if (bank_word(s, offset, s->sw_set_offset, &word) ||
               bank_word(s, offset, s->sw_clear_offset, &word)) {
        *value = s->software[word];
    } else if (bank_word(s, offset, s->mask_set_offset, &word) ||
               bank_word(s, offset, s->mask_clear_offset, &word)) {
        *value = s->masked[word];
    } else if (bank_word(s, offset, s->hw_state_offset, &word)) {
        *value = s->hardware[word];
    } else {
        return false; /* no fabricated reserved-register success */
    }
    return true;
}

bool apple_modern_aic_core_write(AppleModernAICCore *s, uint64_t offset,
                                unsigned size, uint32_t value)
{
    unsigned word;

    if (!valid_access(s, offset, size)) {
        return false;
    }
    if (offset == APPLE_MODERN_AIC_RESET_OFFSET) {
        if (value & ~UINT32_C(1)) {
            return false;
        }
        if (value & 1) {
            apple_modern_aic_core_reset(s);
        }
    } else if (offset == APPLE_MODERN_AIC_CONFIG_OFFSET) {
        if (value & ~UINT32_C(1)) {
            return false;
        }
        s->enabled = value & 1;
    } else if (offset >= s->geometry.irq_config_offset &&
               offset - s->geometry.irq_config_offset <
               (uint64_t)s->geometry.max_irqs * 4) {
        return value == 0; /* refuse unsupported routing/delay/reserved bits */
    } else if (bank_word(s, offset, s->sw_set_offset, &word)) {
        if (word < s->geometry.num_irqs / 32) {
            s->software[word] |= value;
        }
    } else if (bank_word(s, offset, s->sw_clear_offset, &word)) {
        if (word < s->geometry.num_irqs / 32) {
            s->software[word] &= ~value;
        }
    } else if (bank_word(s, offset, s->mask_set_offset, &word)) {
        if (word < s->geometry.num_irqs / 32) {
            s->masked[word] |= value;
        }
    } else if (bank_word(s, offset, s->mask_clear_offset, &word)) {
        if (word < s->geometry.num_irqs / 32) {
            s->masked[word] &= ~value;
        }
    } else {
        return false; /* capability, event, HW_STATE and reserved are not RW */
    }
    return true;
}

#ifndef APPLE_MODERN_AIC_STANDALONE
#include "qapi/error.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qemu/log.h"
#include "qemu/module.h"

static void apple_modern_aic_update(AppleModernAICState *s)
{
    qemu_set_irq(s->irq, apple_modern_aic_core_output(&s->core));
}

static MemTxResult apple_modern_aic_read(void *opaque, hwaddr offset,
                                        uint64_t *value, unsigned size,
                                        MemTxAttrs attrs)
{
    AppleModernAICState *s = opaque;
    uint32_t result;

    if (!apple_modern_aic_core_read(&s->core, offset, size, &result)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "apple-modern-aic: unsupported read at 0x%" HWADDR_PRIx
                      " size %u\n", offset, size);
        *value = 0;
        return MEMTX_ERROR;
    }
    *value = result;
    apple_modern_aic_update(s);
    return MEMTX_OK;
}

static MemTxResult apple_modern_aic_write(void *opaque, hwaddr offset,
                                         uint64_t value, unsigned size,
                                         MemTxAttrs attrs)
{
    AppleModernAICState *s = opaque;

    if (!apple_modern_aic_core_write(&s->core, offset, size, value)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "apple-modern-aic: unsupported write at 0x%" HWADDR_PRIx
                      " size %u value 0x%" PRIx64 "\n", offset, size, value);
        return MEMTX_ERROR;
    }
    apple_modern_aic_update(s);
    return MEMTX_OK;
}

static const MemoryRegionOps apple_modern_aic_ops = {
    .read_with_attrs = apple_modern_aic_read,
    .write_with_attrs = apple_modern_aic_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
    .impl = { .min_access_size = 4, .max_access_size = 4, .unaligned = false },
};

static void apple_modern_aic_set_irq(void *opaque, int irq, int level)
{
    AppleModernAICState *s = opaque;

    assert(apple_modern_aic_core_set_level(&s->core, irq, level));
    apple_modern_aic_update(s);
}

static void apple_modern_aic_reset(DeviceState *dev)
{
    AppleModernAICState *s = APPLE_MODERN_AIC(dev);

    apple_modern_aic_core_reset(&s->core);
    apple_modern_aic_update(s);
}

static void apple_modern_aic_realize(DeviceState *dev, Error **errp)
{
    AppleModernAICState *s = APPLE_MODERN_AIC(dev);
    const char *reason;

    if (!apple_modern_aic_core_init(&s->core, &s->geometry, &reason)) {
        error_setg(errp, "apple-modern-aic: %s", reason);
        return;
    }
    memory_region_init_io(&s->mmio, OBJECT(s), &apple_modern_aic_ops, s,
                          TYPE_APPLE_MODERN_AIC, s->geometry.mmio_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);
    qdev_init_gpio_in(dev, apple_modern_aic_set_irq, s->geometry.num_irqs);
    apple_modern_aic_update(s);
}

static void apple_modern_aic_init(Object *obj)
{
    AppleModernAICState *s = APPLE_MODERN_AIC(obj);

    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq);
}

static const Property apple_modern_aic_properties[] = {
    DEFINE_PROP_UINT32("revision", AppleModernAICState, geometry.revision, 2),
    DEFINE_PROP_UINT32("num-irqs", AppleModernAICState, geometry.num_irqs, 0),
    DEFINE_PROP_UINT32("max-irqs", AppleModernAICState, geometry.max_irqs, 0),
    DEFINE_PROP_UINT32("cap0-offset", AppleModernAICState, geometry.cap0_offset, 4),
    DEFINE_PROP_UINT32("maxnumirq-offset", AppleModernAICState,
                       geometry.maxnumirq_offset, 12),
    DEFINE_PROP_UINT32("irq-config-offset", AppleModernAICState,
                       geometry.irq_config_offset, 0x2000),
    DEFINE_PROP_UINT32("event-offset", AppleModernAICState, geometry.event_offset, 0),
    DEFINE_PROP_UINT32("mmio-size", AppleModernAICState, geometry.mmio_size, 0),
};

/* Interrupt-controller state is not migrated by this compatibility model. */
static const VMStateDescription vmstate_apple_modern_aic = {
    .name = TYPE_APPLE_MODERN_AIC,
    .unmigratable = 1,
};

static void apple_modern_aic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_modern_aic_realize;
    device_class_set_legacy_reset(dc, apple_modern_aic_reset);
    device_class_set_props(dc, apple_modern_aic_properties);
    dc->vmsd = &vmstate_apple_modern_aic;
    dc->desc = "Scoped single-CPU Apple AIC2/AIC3 compatibility controller";
}

static const TypeInfo apple_modern_aic_info = {
    .name = TYPE_APPLE_MODERN_AIC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernAICState),
    .instance_init = apple_modern_aic_init,
    .class_init = apple_modern_aic_class_init,
};

static void apple_modern_aic_register_types(void)
{
    type_register_static(&apple_modern_aic_info);
}

type_init(apple_modern_aic_register_types)
#endif /* !APPLE_MODERN_AIC_STANDALONE */
