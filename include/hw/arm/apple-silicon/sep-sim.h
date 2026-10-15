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
    bool sks_modern;
    uint32_t status;
    /* Read-only host diagnostics; never contain message payloads or keys. */
    uint64_t diagnostic_dispatches;
    uint64_t diagnostic_unsupported;
    uint64_t diagnostic_ool_errors;
    uint64_t diagnostic_sks_rejected;
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
