/*
 * Darwin-VM-compatible AMCC aperture (CTRR bank bounds only).
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Port of qemu-sptm 2867d847 hw/arm/apple_amcc.c. Compatibility model only:
 * the real AMCC enforces CTRR memory protection, this one only remembers the
 * bank lower/upper limits at the offsets named by the served ADT. All other
 * offsets read zero and ignore writes, as in Darwin; in particular offset 0
 * (the served enable/write-disable/lock registers) never reads back as set.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/arm/apple-silicon/modern-amcc.h"

static uint64_t amcc_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleModernAMCC *s = opaque;

    if (offset == 0) {
        return 0;
    }
    for (unsigned bank = 0; bank < APPLE_MODERN_AMCC_BANKS; bank++) {
        if (offset == s->lwr_reg[bank]) {
            return s->ctrr_lwr[bank];
        }
        if (offset == s->upr_reg[bank]) {
            return s->ctrr_upr[bank];
        }
    }
    return 0;
}

static void amcc_write(void *opaque, hwaddr offset, uint64_t value,
                       unsigned size)
{
    AppleModernAMCC *s = opaque;

    if (offset == 0) {
        return;
    }
    for (unsigned bank = 0; bank < APPLE_MODERN_AMCC_BANKS; bank++) {
        if (offset == s->lwr_reg[bank]) {
            s->ctrr_lwr[bank] = value;
        }
        if (offset == s->upr_reg[bank]) {
            s->ctrr_upr[bank] = value;
        }
    }
}

static const MemoryRegionOps amcc_ops = {
    .read = amcc_read,
    .write = amcc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 8 },
};

bool apple_modern_amcc_init(AppleModernAMCC *amcc, MemoryRegion *parent,
                            uint64_t base, uint64_t size,
                            const uint32_t lwr_reg[APPLE_MODERN_AMCC_BANKS],
                            const uint32_t upr_reg[APPLE_MODERN_AMCC_BANKS],
                            Error **errp)
{
    if (!size || size > 0x100000 || (base & 0xfff) || (size & 0xfff) ||
        base > UINT64_MAX - size) {
        error_setg(errp, "invalid AMCC aperture");
        return false;
    }
    for (unsigned bank = 0; bank < APPLE_MODERN_AMCC_BANKS; bank++) {
        const uint32_t regs[2] = { lwr_reg[bank], upr_reg[bank] };
        if (!regs[0] != !regs[1]) {
            error_setg(errp, "AMCC bank %u has only one bound register", bank);
            return false;
        }
        for (unsigned i = 0; i < 2; i++) {
            if (regs[i] && ((regs[i] & 7) || regs[i] > size - 8)) {
                error_setg(errp, "AMCC bank %u bound register outside the "
                           "aperture", bank);
                return false;
            }
        }
        if (regs[0] && regs[0] == regs[1]) {
            error_setg(errp, "AMCC bank %u bound registers overlap", bank);
            return false;
        }
    }
    amcc->base = base;
    amcc->size = size;
    memcpy(amcc->lwr_reg, lwr_reg, sizeof(amcc->lwr_reg));
    memcpy(amcc->upr_reg, upr_reg, sizeof(amcc->upr_reg));
    apple_modern_amcc_reset(amcc);
    memory_region_init_io(&amcc->iomem, NULL, &amcc_ops, amcc,
                          "apple-modern.amcc", size);
    memory_region_add_subregion(parent, base, &amcc->iomem);
    return true;
}

void apple_modern_amcc_reset(AppleModernAMCC *amcc)
{
    memset(amcc->ctrr_lwr, 0, sizeof(amcc->ctrr_lwr));
    memset(amcc->ctrr_upr, 0, sizeof(amcc->ctrr_upr));
}

void apple_modern_amcc_set_bounds(AppleModernAMCC *amcc, unsigned bank,
                                  uint64_t lower, uint64_t upper)
{
    assert(bank < APPLE_MODERN_AMCC_BANKS);
    amcc->ctrr_lwr[bank] = lower;
    amcc->ctrr_upr[bank] = upper;
}
