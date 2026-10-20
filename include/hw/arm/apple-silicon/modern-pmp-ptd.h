/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_PMP_PTD_H
#define HW_ARM_APPLE_MODERN_PMP_PTD_H
#include "hw/arm/apple-silicon/modern-board-regions.h"

/*
 * PMP "PTD" hardware message board, as the T8140 memory-cache controller driver
 * uses it (pinned BootKC a36b9241): the MCC maps /arm-io/mcc reg[6]
 * (pmp_ptd_db_reg_idx, the Dashboard) and reg[7] (pmp_ptd_update_reg_idx, the
 * Update port), 0x4000 bytes each.
 *   Dashboard: 1024 entries of 16 bytes {msg, metadata}, read as two 8-byte
 *              loads (QEMU splits the driver's 16-byte LDP).
 *   Update:    2048 eight-byte slots written by 64-bit stores at index * 8
 *              (writePTD: str x, [update + idx * 8]).
 * ATTESTED by the driver: those widths and strides; the command words are
 * written at indices 433 then 432; quota requests are read back from the
 * Dashboard before the Update rewrite.
 * DECLARED by this model: an Update store to slot i < 1024 latches into the
 * Dashboard msg of entry i (the quota read-back requires the mirror, but who
 * performs it, the board or the PMP firmware, is not known); metadata stays
 * zero; slots >= 1024 are stored and not visible.
 * Optional command-responder (default off): on the command commit at slot 432,
 * publish its nonzero low 12-bit sequence to Dashboard[448], with new_data.
 * This is the quiet PMP stand-in described by the retained T8140 firmware/AP
 * disassembly in evidence/features-20261009/w2-pmp/README.md, profile Q. It
 * acknowledges receipt only: no cache quota grant, power-status, power ack,
 * thermal control or PMP firmware execution is supplied. In particular it
 * does not claim that a power transition or a key operation succeeded.
 * The Update port is write-only and the Dashboard read-only; every other
 * access width, alignment or offset is rejected.
 */
#define APPLE_MODERN_PTD_VIEWS 2
#define APPLE_MODERN_PTD_DASHBOARD 0
#define APPLE_MODERN_PTD_UPDATE 1
#define APPLE_MODERN_PTD_SPAN 0x4000
#define APPLE_MODERN_PTD_ENTRIES (APPLE_MODERN_PTD_SPAN / 16)
#define APPLE_MODERN_PTD_SLOTS (APPLE_MODERN_PTD_SPAN / 8)

typedef struct AppleModernPTDPlan {
    uint64_t addresses[APPLE_MODERN_PTD_VIEWS];
} AppleModernPTDPlan;
typedef struct AppleModernPTDCore {
    uint64_t msg[APPLE_MODERN_PTD_ENTRIES];
    uint64_t meta[APPLE_MODERN_PTD_ENTRIES];
    uint64_t hidden[APPLE_MODERN_PTD_SLOTS - APPLE_MODERN_PTD_ENTRIES];
    uint64_t reads, writes;
    bool command_responder;
    uint64_t command_count, ack_count, command_word0, command_word1;
} AppleModernPTDCore;

bool apple_modern_pmp_ptd_plan_build(AppleModernBlob tree,
    uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *exclusions, size_t exclusion_count,
    AppleModernPTDPlan *output, Error **errp);
void apple_modern_pmp_ptd_core_reset(AppleModernPTDCore *core);
bool apple_modern_pmp_ptd_core_read(AppleModernPTDCore *core, unsigned view,
    uint64_t offset, unsigned size, uint64_t *value);
bool apple_modern_pmp_ptd_core_write(AppleModernPTDCore *core, unsigned view,
    uint64_t offset, unsigned size, uint64_t value);

#ifndef APPLE_MODERN_LAYOUT_STANDALONE
#include "hw/sysbus.h"
#define TYPE_APPLE_MODERN_PMP_PTD "apple-modern-pmp-ptd"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernPTDState, APPLE_MODERN_PMP_PTD)
DeviceState *apple_modern_pmp_ptd_new(void);
#endif
#endif
