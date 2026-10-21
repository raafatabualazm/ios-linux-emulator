/*
 * Apple SEP.
 *
 * Copyright (c) 2023-2026 Visual Ehrmanntraut (VisualEhrmanntraut).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef HW_ARM_APPLE_SILICON_SEP_SIM_H
#define HW_ARM_APPLE_SILICON_SEP_SIM_H

#include "qemu/osdep.h"
#include "hw/arm/apple-silicon/dt.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_APPLE_SEP_SIM "apple-sep-sim"
OBJECT_DECLARE_TYPE(AppleSEPSimState, AppleSEPSimClass, APPLE_SEP_SIM)

struct AppleSEPSimClass {
    /*< private >*/
    SysBusDeviceClass base_class;

    DeviceRealize parent_realize;
    ResettablePhases parent_phases;
};

#define SEP_ENDPOINT_MAX 0x20

typedef struct {
    uint8_t in_min_pages;
    uint8_t in_max_pages;
    uint8_t out_min_pages;
    uint8_t out_max_pages;
} QEMU_PACKED AppleSEPSimOOLInfo;

typedef struct {
    uint64_t in_addr;
    uint32_t in_size;
    uint64_t out_addr;
    uint32_t out_size;
} AppleSEPSimOOLState;

struct AppleSEPSimState {
    /*< private >*/
    AppleA7IOP parent_obj;

    MemoryRegion *dma_mr;
    AddressSpace *dma_as;
    QemuMutex lock;
    bool rsep;
    /* V6 (apple-modern) uses T8140 wire framing; V2/V4 keep the legacy container. */
    bool sks_modern;
    /* When true, unimplemented SKS opcodes stop the VM instead of silent drop. */
    bool sks_fail_closed;
    /*
     * Opt-in "already booted" SEP, declared emulator behaviour, default 0:
     *   1: announce the ROM status (BOOTSTRAP), then NOTIFY_ALIVE and the
     *      endpoint list at reset, with no bootstrap dialogue;
     *   2: as 1, but the first status announcement already says ACTIVE;
     *   3: announce ACTIVE only (no NOTIFY_ALIVE, no endpoints): observation.
     */
    uint32_t preboot;
    /*
     * TXM-owned secure channel page as the ADT describes it on the SEP DART
     * (txm-secure-channel-base / -size): the IOVA and length at which the SEP
     * sees the page TXM reads SEP-provided device state from. Zero disables
     * the diagnostic probe below. Read-only observation of what TXM leaves there.
     */
    uint64_t txm_sc_base;
    uint64_t txm_sc_size;
    unsigned txm_sc_probes;
    /*
     * Diagnostic writer for the same page, for black-box experiments on what TXM accepts: txm_sc_hex is a hex string
     * written at page offset 0, txm_sc_fill (0x100 | byte value, or 0 for none) fills the rest first. Both default off.
     */
    char *txm_sc_hex;
    uint32_t txm_sc_fill;
    uint32_t status;
    /* Read-only host diagnostics; never contain message payloads or keys. */
    uint64_t diagnostic_dispatches;
    uint64_t diagnostic_unsupported;
    uint64_t diagnostic_ool_errors;
    uint64_t diagnostic_sks_rejected;
    uint64_t diagnostic_sks_replies;
    uint32_t diagnostic_last_ep;
    uint32_t diagnostic_last_op;
    uint32_t diagnostic_last_unsupported_ep;
    uint32_t diagnostic_last_unsupported_op;
    AppleSEPSimOOLInfo ool_info[SEP_ENDPOINT_MAX];
    AppleSEPSimOOLState ool_state[SEP_ENDPOINT_MAX];
};

AppleSEPSimState *apple_sep_sim_new(const char *role, uint64_t mmio_size,
                                    AppleA7IOPVersion version,
                                    AddressSpace *dma_as);
AppleSEPSimState *apple_sep_sim_from_node(AppleDTNode *node, bool modern);

#endif /* HW_ARM_APPLE_SILICON_SEP_SIM_H */
