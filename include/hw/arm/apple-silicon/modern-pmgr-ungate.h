/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_PMGR_UNGATE_H
#define HW_ARM_APPLE_MODERN_PMGR_UNGATE_H
#include <stddef.h>
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/*
 * The declared "ungate" ADT overrides: /arm-io no-clock-gate and
 * no-power-gate.
 *
 * Attested, BootKC a36b9241..., com.apple.driver.AppleT8140,
 * AppleH17PPlatformIO::start at 0xfffffff00979775c. The driver reads
 * "no-clock-gate" (string at 0xfffffff00779a069) and "no-power-gate" (string
 * at 0xfffffff00779a077) off its own /arm-io node; when a property is present
 * it branches over the matching "function-clock_gate" / "function-power_gate"
 * lookup and never records a gate action. When neither the escape hatch nor
 * the function property is present it panics:
 *   "AppleH17PPlatformIO::start: can't find 'function-clock_gate', update
 *    Device Tree" @AppleH17PPlatformIO.cpp:94   (and :100 for power)
 * Only presence is tested (csel after a getProperty), so the value carries no
 * meaning; a single nonzero byte is used because the override ABI has no
 * zero-length form.
 *
 * WHAT THIS REMOVES: the guest kernel can no longer clock-gate or power-gate
 * any /arm-io device through /arm-io/pmgr, and the two panics above no longer
 * guard a tree that lacks the function properties. It is a declared
 * modification of Apple's device tree, not Apple fidelity.
 */
#define APPLE_MODERN_PMGR_UNGATE_COUNT 2

/* Static storage; *count is always APPLE_MODERN_PMGR_UNGATE_COUNT. */
const AppleModernAdtOverride *apple_modern_pmgr_ungate_overrides(size_t *count);
#endif
