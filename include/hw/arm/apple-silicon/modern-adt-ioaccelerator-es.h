/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_ADT_IOACCELERATOR_ES_H
#define HW_ARM_APPLE_MODERN_ADT_IOACCELERATOR_ES_H
#include "hw/arm/apple-silicon/modern-boot-metadata.h"

/*
 * /arm-io/IOAcceleratorES -- a minimal AppleARMIODevice nub whose registry
 * name matches QuartzCore's CAMetalContextCreate wait:
 *   IOServiceNameMatching("IOAcceleratorES") + IOServiceGetMatchingServices
 * (QC 24A437 @ 0x1847c3500; see Grok/gui-20261017/re/METAL-WAIT-SKIP.md).
 *
 * WHY A STUB NODE, NOT A DSC PATCH.  Poking the wait counter in the dyld
 * shared cache (gui-v2) makes AMFI kill backboardd with OS_REASON_CODESIGNING.
 * Publishing a real IORegistry entry named IOAcceleratorES makes the once-wait
 * observe a non-empty iterator on the first poll and exit without touching
 * userspace text.  The once block only checks presence (IteratorNext +
 * Release); it does not open the service, so a plain AppleARMIODevice nub is
 * enough for fail-fast.  Metal device creation then proceeds with a nil
 * accelerator and AccelServer's SW fallback (angr 7/7).
 *
 * SHAPE.  Stock smallest /arm-io leaves are {name, AAPL,phandle} (e.g.
 * aop2-exclave-ioreporting).  Phandle 0x10b is the stock /arm-io/sgx value and
 * is unused in the Darwin-derived tree that deletes sgx (measured free in
 * dtree-no-routes-noeapfs).  Mutually exclusive with sgx=on: both consume the
 * single synthesized-node slot (metadata_input.added_node).
 *
 * WHAT IS NOT CLAIMED: that AGX matches, that IOServiceOpen for a Metal user
 * client succeeds, or that the nub is a real IOAcceleratorES subclass.  The
 * only attested effect is clearing the ~30s NameMatching wait CS-safely.
 */
const AppleModernAdtNode *apple_modern_adt_ioaccelerator_es_node(void);

#endif
