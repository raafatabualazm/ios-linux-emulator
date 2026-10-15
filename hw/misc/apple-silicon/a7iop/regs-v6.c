/*
 * Apple A7IOP V6 wrapper registers ("ascwrap-v6").
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Deliberately lean: it decodes only what XNU's AppleA7IOP driver was measured
 * to touch in the pinned iOS 27 boot kernel collection, and logs everything
 * else under LOG_UNIMP so a future access is visible instead of silently
 * answered. The complete AP-side offset inventory recovered from that driver is
 *
 *   reads   0x40, 0x44, 0x8000, 0x8110, 0x8114, and 0x8180 + 4k for k < 128
 *   writes  0x44, 0x1004, 0x1014, 0x8114
 *   128-bit store at 0x8800, 128-bit load at 0x8830
 *
 * of which 0x8110/0x8114/0x8800/0x8830 belong to the mailbox subregion mapped
 * at 0x8100. Nothing in 0x4000-0x7FFF is touched, so the coprocessor-side
 * mirror at one AKF stride is retained unmodelled rather than removed:
 * the absence of AP-side access is not evidence that the aperture is absent.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "private.h"
#include "trace.h"

#define REG_UNKNOWN_40 (0x40)
#define REG_CPU_CTRL (0x44)
#define REG_CPU_STATUS (0x48)
/*
 * Apple's own name, from the driver's format string. It is the first word of
 * the AKF block that also holds the mailbox, and the only predicate applied to
 * it is "(value & 3) != 0 means idle".
 */
#define REG_IDLE_STATUS (AKF_STRIDE * 2)
#define IDLE_STATUS_IDLE (0x3)

#define AKF_MAILBOX_OFF (0x100)

static void apple_a7iop_v6_reg_write(void *opaque, hwaddr addr,
                                     const uint64_t data, unsigned size)
{
    AppleA7IOP *s = opaque;

    s->diagnostic_mmio_writes++;
    trace_apple_a7iop_wrapper_write(s->role, 6, addr, size, data);
    switch (addr) {
    case REG_CPU_CTRL:
        /*
         * /arm-io/sep carries cpu-ctrl-filtered, which makes XNU skip both this
         * register and the idle poll entirely, so no modelled state may depend
         * on the guest writing it. Retained because the driver does write it on
         * nodes without that property.
         */
        apple_a7iop_set_cpu_ctrl(s, (uint32_t)data);
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "A7IOP_V6(%s): unhandled write @ 0x" HWADDR_FMT_plx
                      " value 0x%" PRIx64 "\n",
                      s->role, addr, data);
        break;
    }
}

static uint64_t apple_a7iop_v6_reg_read(void *opaque, hwaddr addr,
                                        unsigned size)
{
    AppleA7IOP *s = opaque;

    s->diagnostic_mmio_reads++;
    trace_apple_a7iop_wrapper_read(s->role, 6, addr, size);
    switch (addr) {
    case REG_UNKNOWN_40:
        /*
         * /arm-io/dcp carries idle-ctrl-check and AppleA7IOP bit-tests offset
         * 0x40 when polling for idle on power-down (see modern-dcp-asc.h).
         */
        return 1;
    case REG_CPU_CTRL:
        return apple_a7iop_get_cpu_ctrl(s);
    case REG_CPU_STATUS:
        /*
         * Declared. XNU never reads this register on any path reachable from
         * its start(), so neither our CPU_STATUS_IDLE = bit 0 nor m1n1's
         * "bit 0 RUNNING, bit 5 IDLE" is confirmed by the firmware.
         */
        return apple_a7iop_get_cpu_status(s);
    case REG_IDLE_STATUS:
        return (apple_a7iop_get_cpu_status(s) & CPU_STATUS_IDLE) ?
               IDLE_STATUS_IDLE : 0;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "A7IOP_V6(%s): unhandled read @ 0x" HWADDR_FMT_plx "\n",
                      s->role, addr);
        return 0;
    }
}

static const MemoryRegionOps apple_a7iop_v6_reg_ops = {
    .write = apple_a7iop_v6_reg_write,
    .read = apple_a7iop_v6_reg_read,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.unaligned = false,
};

void apple_a7iop_init_mmio_v6(AppleA7IOP *s, uint64_t mmio_size)
{
    SysBusDevice *sbd;
    char name[32];

    sbd = SYS_BUS_DEVICE(s);

    snprintf(name, sizeof(name), TYPE_APPLE_A7IOP ".%s.regs", s->role);
    memory_region_init_io(&s->mmio, OBJECT(s), &apple_a7iop_v6_reg_ops, s, name,
                          mmio_size);
    sysbus_init_mmio(sbd, &s->mmio);

    /*
     * Mailbox blocks at one and two AKF strides, offset by 0x100 inside the
     * block. That places the AP mailbox CONTROL pair at 0x8110/0x8114, its
     * send frame at 0x8800 and its receive frame at 0x8830 -- the four
     * apertures measured in the driver -- while leaving 0x8000 itself to the
     * wrapper for IDLE_STATUS.
     */
    memory_region_add_subregion_overlap(&s->mmio, AKF_STRIDE + AKF_MAILBOX_OFF,
                                        &s->iop_mailbox->mmio, 1);
    memory_region_add_subregion_overlap(
        &s->mmio, (AKF_STRIDE * 2) + AKF_MAILBOX_OFF, &s->ap_mailbox->mmio, 1);
}
