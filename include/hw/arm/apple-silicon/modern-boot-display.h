/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_BOOT_DISPLAY_H
#define HW_ARM_APPLE_MODERN_BOOT_DISPLAY_H

#include "system/memory.h"
#include "qapi/error.h"
#include "chardev/char.h"

/*
 * Scan out an already reserved boot framebuffer in system RAM. This is the
 * bootloader's fixed 32-bit XRGB surface, not a DCP/IOMobileFramebuffer device.
 * The board owns the RAM and clears the reservation on machine reset.
 */
bool apple_modern_boot_display_create(MemoryRegion *ram, uint64_t offset,
                                      uint32_t width, uint32_t height,
                                      uint32_t stride, Chardev *uart,
                                      Error **errp);

#endif
