/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_PMGR_VOLTAGE_H
#define HW_ARM_APPLE_MODERN_PMGR_VOLTAGE_H
#include <string.h>
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/* Board option value selecting the measured MacBook Neo (J700) tables. */
#define APPLE_MODERN_PMGR_VOLTAGE_J700 "j700"

/* Returns the override list for a profile name, or NULL (count 0) when the
 * name is unknown. The list has static storage. */
const AppleModernAdtOverride *apple_modern_pmgr_voltage_profile(
    const char *name, size_t *count);
#endif
