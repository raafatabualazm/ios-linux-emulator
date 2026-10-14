/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_APPLE_MODERN_ANS_H
#define HW_APPLE_MODERN_ANS_H
#include "hw/sysbus.h"

/* Firmware-free platform controller model, not ANS firmware execution or SEP
 * crypto. The board supplies checked ADT apertures and a RAM-only DMA space. */
#define TYPE_APPLE_MODERN_ANS "apple-modern-ans"
SysBusDevice *apple_modern_ans_create(Object *parent, MemoryRegion *ram,
                                     uint64_t ram_base, uint64_t wrapper_size,
                                     Error **errp);
#endif
