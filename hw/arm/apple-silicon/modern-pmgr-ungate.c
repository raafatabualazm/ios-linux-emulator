/*
 * Declared /arm-io clock- and power-gate escape hatches (pmgr-ungate).
 * See include/hw/arm/apple-silicon/modern-pmgr-ungate.h for the attested
 * BootKC code this mirrors and for what the option removes.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/modern-pmgr-ungate.h"

/* Presence-only marker: AppleH17PPlatformIO::start only tests for non-NULL. */
static const uint8_t present[1] = { 1 };

static const AppleModernAdtOverride ungate[APPLE_MODERN_PMGR_UNGATE_COUNT] = {
    { "/arm-io", "no-clock-gate", present, sizeof(present) },
    { "/arm-io", "no-power-gate", present, sizeof(present) },
};

const AppleModernAdtOverride *apple_modern_pmgr_ungate_overrides(size_t *count)
{
    if (count) {
        *count = APPLE_MODERN_PMGR_UNGATE_COUNT;
    }
    return ungate;
}
