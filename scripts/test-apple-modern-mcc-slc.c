/* AMCC system-level-cache way/flush cells and matched sparse layout qualification.
 * v3: 12-way boot state (requested 0x8000000c, status 0x0c000c00), the
 * neutral +0x82c cell, public view offsets, the AMCC-window bound and the
 * optional amcc-plane-enable-mask / max-way-count guards.
 * v4: apple_modern_mcc_slc_view_offset() returns UINT64_MAX for every view
 * >= 11, and optional-property rejections are matched exactly with the
 * "MCC SLC" prefix (separate wrong-size and unmodelled-value messages).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-mcc-slc.h"
static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

#define PLANES APPLE_MODERN_MCC_SLC_PLANES
#define STATUS APPLE_MODERN_MCC_SLC_STATUS_VIEW
#define FLUSH APPLE_MODERN_MCC_SLC_FLUSH_VIEW
#define VIEWS APPLE_MODERN_MCC_SLC_VIEWS
enum { WAYS_VIEW, CTRL_82C_VIEW, FLUSH_REQUEST_VIEW };
#define RESET_WAYS UINT32_C(0x8000000c)
#include "test-apple-modern-mcc-optional-props.h"

static const uint64_t amcc = UINT64_C(0x220000000);
/* Darwin's served compatibility aperture (/chosen/lock-regs/amcc). */
static const uint64_t aperture = UINT64_C(0x220000000), aperture_size = 0x4000;

static void clear_error(Error **error)
{
    CHECK(*error != NULL);
    error_free(*error);
    *error = NULL;
}

static uint64_t expected_address(unsigned view)
{
    static const uint64_t global[] = {0x2800, 0x82c, 0x2844};
    if (view < STATUS) {
        return amcc + 0x100000 + global[view];
    }
    if (view < FLUSH) {
        return amcc + (view - STATUS) * UINT64_C(0x40000) + 0x2804;
    }
    return amcc + (view - FLUSH) * UINT64_C(0x40000) + 0x2844;
}

static uint64_t expected_offset(unsigned view)
{
    return expected_address(view) - amcc;
}

static uint32_t status_for(uint32_t ways)
{
    return ((ways & 0x7f) << 24) | ((ways & 0x7f) << 8);
}

static void expect_planes(AppleModernMCCSLCCore *core, uint32_t ways)
{
    for (unsigned plane = 0; plane < PLANES; plane++) {
        uint64_t value = UINT64_MAX;
        CHECK(apple_modern_mcc_slc_core_read(core, STATUS + plane, 0, 4, &value));
        CHECK(value == status_for(ways));
        value = UINT64_MAX;
        CHECK(apple_modern_mcc_slc_core_read(core, FLUSH + plane, 0, 4, &value));
        CHECK(value == 0);
    }
}

static uint64_t plan_dram_base = UINT64_C(0x10000000000), plan_dram_size = UINT64_C(8) << 30;

static bool slc_plan(AppleModernBlob tree, void *plan, Error **errp)
{
    return apple_modern_mcc_slc_plan_build(tree, plan_dram_base, plan_dram_size, NULL, 0,
                                           plan, errp);
}

int main(int argc, char **argv)
{
    AppleModernMCCSLCCore core;
    uint64_t value;
    CHECK(VIEWS == 11 && STATUS == 3 && FLUSH == 7 && APPLE_MODERN_MCC_SLC_SPAN == 4);
    CHECK(APPLE_MODERN_MCC_SLC_GLOBAL_VIEWS == 3 && APPLE_MODERN_MAX_BOARD_EXCLUSIONS == 96);
    CHECK(APPLE_MODERN_MCC_SLC_RESET_WAYS == RESET_WAYS && APPLE_MODERN_MCC_SLC_WAY_MASK == 0x7f);
    CHECK(APPLE_MODERN_MCC_SLC_CTRL_82C == 0x82c && APPLE_MODERN_MCC_SLC_WAYS == 0x2800 &&
          APPLE_MODERN_MCC_SLC_WAY_STATUS == 0x2804 && APPLE_MODERN_MCC_SLC_FLUSH == 0x2844);
    CHECK(APPLE_MODERN_MCC_SLC_GLOBAL_OFFSET == 0x100000 &&
          APPLE_MODERN_MCC_SLC_PLANE_STRIDE == 0x40000 && APPLE_MODERN_MCC_AMCC_SPAN == 0x140000);
    /* Public view offsets, and the AMCC-window bound every view satisfies
     * (plan_build's bound check is unreachable with these constants). */
    uint64_t highest = 0;
    for (unsigned view = 0; view < VIEWS; view++) {
        CHECK(apple_modern_mcc_slc_view_offset(view) == expected_offset(view));
        CHECK(apple_modern_mcc_slc_view_offset(view) + APPLE_MODERN_MCC_SLC_SPAN <=
              APPLE_MODERN_MCC_AMCC_SPAN);
        if (expected_offset(view) > highest) {
            highest = expected_offset(view);
        }
        for (unsigned other = 0; other < view; other++) {
            CHECK(apple_modern_mcc_slc_view_offset(other) + 4 <=
                      apple_modern_mcc_slc_view_offset(view) ||
                  apple_modern_mcc_slc_view_offset(view) + 4 <=
                      apple_modern_mcc_slc_view_offset(other));
        }
    }
    CHECK(highest == 0x102844 && highest + 4 == 0x102848);
    /* v4: an invalid view has no offset. Every valid view's offset is a real
     * one (never the UINT64_MAX sentinel), and every view from 11 up to
     * UINT32_MAX, sampled densely above the boundary, returns UINT64_MAX. */
    for (unsigned view = 0; view < VIEWS; view++) {
        CHECK(apple_modern_mcc_slc_view_offset(view) != UINT64_MAX);
    }
    for (unsigned view = VIEWS; view < VIEWS + 4096; view++) {
        CHECK(apple_modern_mcc_slc_view_offset(view) == UINT64_MAX);
    }
    {
        static const unsigned invalid[] = {
            VIEWS, VIEWS + 1, 12, 15, 16, 31, 32, 63, 64, 255, 256, 0x10000, 0x7fffffffU,
            0x80000000U, 0xc0000000U, 0xfffffff0U, 0xfffffffeU, 0xffffffffU,
        };
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
            CHECK(apple_modern_mcc_slc_view_offset(invalid[i]) == UINT64_MAX);
        }
        for (unsigned shift = 4; shift < 32; shift++) {
            CHECK(apple_modern_mcc_slc_view_offset(1U << shift) == UINT64_MAX);
            CHECK(apple_modern_mcc_slc_view_offset((1U << shift) - 1) == UINT64_MAX);
        }
    }

    /* Reset: the 12-way handover state (PR #664 readback, analogy) is requested
     * and reported powered; nothing pending, diagnostics clear. */
    memset(&core, 0xa5, sizeof(core));
    apple_modern_mcc_slc_core_reset(&core);
    CHECK(core.ways == RESET_WAYS && !core.ctrl_82c && !core.flush && !core.reads &&
          !core.writes);
    CHECK(status_for(RESET_WAYS) == UINT32_C(0x0c000c00));
    expect_planes(&core, RESET_WAYS);
    for (unsigned plane = 0; plane < PLANES; plane++) {
        CHECK(apple_modern_mcc_slc_core_read(&core, STATUS + plane, 0, 4, &value));
        CHECK(value == UINT32_C(0x0c000c00));
    }
    CHECK(core.reads == 12 && !core.writes && core.ways == RESET_WAYS);

    /* mccEnableCacheMode: global +0x2800 = 12 ways, then mccWaitForWaysPwrOn
     * polls every plane's +0x2804 for bits [30:24] == 12, then bits [14:8] ==
     * 12, then global +0x82c = 0. */
    CHECK(apple_modern_mcc_slc_core_write(&core, WAYS_VIEW, 0, 4, 0xc));
    for (unsigned plane = 0; plane < PLANES; plane++) {
        CHECK(apple_modern_mcc_slc_core_read(&core, STATUS + plane, 0, 4, &value));
        CHECK(((value >> 24) & 0x7f) == 12);
        CHECK(apple_modern_mcc_slc_core_read(&core, STATUS + plane, 0, 4, &value));
        CHECK(((value >> 8) & 0x7f) == 12);
        CHECK(value == UINT32_C(0x0c000c00));
    }
    CHECK(apple_modern_mcc_slc_core_write(&core, CTRL_82C_VIEW, 0, 4, 0));
    CHECK(core.ways == 12 && core.ctrl_82c == 0 && core.reads == 20 && core.writes == 2);
    /* cacheFlush: global +0x82c = 1, +0x2844 = 1, then each plane's +0x2844
     * bit 0 reads clear (declared immediate completion). */
    CHECK(apple_modern_mcc_slc_core_write(&core, CTRL_82C_VIEW, 0, 4, 1));
    CHECK(apple_modern_mcc_slc_core_write(&core, FLUSH_REQUEST_VIEW, 0, 4, 1));
    for (unsigned plane = 0; plane < PLANES; plane++) {
        value = UINT64_MAX;
        CHECK(apple_modern_mcc_slc_core_read(&core, FLUSH + plane, 0, 4, &value));
        CHECK(!(value & 1) && value == 0);
    }
    CHECK(core.ctrl_82c == 1 && core.flush == 1 && core.ways == 12);
    CHECK(core.reads == 24 && core.writes == 4);
    /* A flush request leaves the way status untouched, and vice versa. */
    expect_planes(&core, 12);

    /* Requested ways are stored whole; each status field reports bits [6:0]. */
    static const uint32_t ways[] = {0, 1, 0x7f, 0x80, 0x81, 0xff, 0x100c,
                                    0x7fffff8c, 0x80000000, 0x8000000c, 0xffffffff, 0xc};
    for (unsigned i = 0; i < sizeof(ways) / sizeof(ways[0]); i++) {
        CHECK(apple_modern_mcc_slc_core_write(&core, WAYS_VIEW, 0, 4, ways[i]));
        CHECK(core.ways == ways[i] && core.ctrl_82c == 1 && core.flush == 1);
        expect_planes(&core, ways[i]);
    }
    CHECK(status_for(0xffffffff) == UINT32_C(0x7f007f00));
    CHECK(status_for(0x80) == 0 && status_for(0x100c) == UINT32_C(0x0c000c00));
    /* A 32-bit transaction stores only its 32 bits. */
    CHECK(apple_modern_mcc_slc_core_write(&core, WAYS_VIEW, 0, 4, UINT64_C(0xffffffff0000000c)));
    CHECK(core.ways == 12);
    for (uint32_t flush = 0; flush < 4; flush++) {
        CHECK(apple_modern_mcc_slc_core_write(&core, FLUSH_REQUEST_VIEW, 0, 4, flush));
        CHECK(apple_modern_mcc_slc_core_write(&core, CTRL_82C_VIEW, 0, 4, flush ^ 3));
        CHECK(core.flush == flush && core.ctrl_82c == (flush ^ 3) && core.ways == 12);
        expect_planes(&core, 12);
    }
    CHECK(apple_modern_mcc_slc_core_write(&core, FLUSH_REQUEST_VIEW, 0, 4, UINT32_MAX));
    CHECK(apple_modern_mcc_slc_core_write(&core, CTRL_82C_VIEW, 0, 4, UINT32_MAX));
    CHECK(core.flush == UINT32_MAX && core.ctrl_82c == UINT32_MAX);
    expect_planes(&core, 12);

    /* Rejected operations leave the core byte-identical and the output
     * untouched: global loads, plane stores, widths, offsets, views. */
    AppleModernMCCSLCCore before = core;
    value = UINT64_C(0x123456789abcdef0);
    for (unsigned view = 0; view < STATUS; view++) {
        CHECK(!apple_modern_mcc_slc_core_read(&core, view, 0, 4, &value));
    }
    for (unsigned view = STATUS; view < VIEWS; view++) {
        CHECK(!apple_modern_mcc_slc_core_write(&core, view, 0, 4, 0));
        CHECK(!apple_modern_mcc_slc_core_write(&core, view, 0, 4, 0xc));
    }
    for (unsigned view = 0; view < VIEWS + 3; view++) {
        for (unsigned size = 0; size <= 16; size++) {
            if (size != 4 || view >= VIEWS) {
                CHECK(!apple_modern_mcc_slc_core_read(&core, view, 0, size, &value));
                CHECK(!apple_modern_mcc_slc_core_write(&core, view, 0, size, 1));
            }
        }
        static const uint64_t offsets[] = {1, 2, 3, 4, 8, 0x40, 0x40000,
                                           UINT64_C(1) << 32, UINT64_MAX - 3, UINT64_MAX};
        for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
            CHECK(!apple_modern_mcc_slc_core_read(&core, view, offsets[i], 4, &value));
            CHECK(!apple_modern_mcc_slc_core_write(&core, view, offsets[i], 4, 1));
        }
    }
    CHECK(!apple_modern_mcc_slc_core_read(&core, UINT32_MAX, 0, 4, &value));
    CHECK(!apple_modern_mcc_slc_core_write(&core, UINT32_MAX, 0, 4, 1));
    CHECK(!apple_modern_mcc_slc_core_read(NULL, STATUS, 0, 4, &value));
    CHECK(!apple_modern_mcc_slc_core_write(NULL, WAYS_VIEW, 0, 4, 1));
    CHECK(!apple_modern_mcc_slc_core_read(&core, STATUS, 0, 4, NULL));
    CHECK(!apple_modern_mcc_slc_core_read(&core, STATUS, 0, 4, &core.reads));
    CHECK(!apple_modern_mcc_slc_core_read(&core, STATUS, 0, 4, &core.writes));
    CHECK(!apple_modern_mcc_slc_core_read(&core, STATUS, 0, 4,
                                          (uint64_t *)(void *)&core.ways));
    CHECK(value == UINT64_C(0x123456789abcdef0));
    CHECK(!memcmp(&core, &before, sizeof(core)));

    /* Saturating diagnostics. */
    core.reads = core.writes = UINT64_MAX;
    CHECK(apple_modern_mcc_slc_core_read(&core, STATUS + 3, 0, 4, &value));
    CHECK(apple_modern_mcc_slc_core_write(&core, WAYS_VIEW, 0, 4, 5));
    CHECK(value == UINT32_C(0x0c000c00) && core.ways == 5);
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX);
    apple_modern_mcc_slc_core_reset(&core);
    CHECK(core.ways == RESET_WAYS && !core.ctrl_82c && !core.flush && !core.reads &&
          !core.writes);
    expect_planes(&core, RESET_WAYS);
    /* Reset restores the boot request even after the driver lowered it. */
    CHECK(apple_modern_mcc_slc_core_write(&core, WAYS_VIEW, 0, 4, 0));
    CHECK(apple_modern_mcc_slc_core_write(&core, CTRL_82C_VIEW, 0, 4, 1));
    CHECK(apple_modern_mcc_slc_core_write(&core, FLUSH_REQUEST_VIEW, 0, 4, 1));
    expect_planes(&core, 0);
    apple_modern_mcc_slc_core_reset(&core);
    CHECK(core.ways == RESET_WAYS && !core.ctrl_82c && !core.flush && !core.reads &&
          !core.writes);
    expect_planes(&core, RESET_WAYS);

    /* Matched sparse layout. */
    CHECK(argc == 2);
    FILE *file = fopen(argv[1], "rb"); CHECK(file);
    CHECK(!fseek(file, 0, SEEK_END)); long length = ftell(file);
    CHECK(length > 0 && length < 1 << 20); rewind(file);
    uint8_t *tree = malloc(length); CHECK(tree);
    CHECK(fread(tree, 1, length, file) == (size_t)length); fclose(file);
    AppleModernBlob blob = {tree, length}, property;
    AppleModernMCCSLCPlan plan, zero, saved;
    memset(&zero, 0, sizeof(zero));
    Error *error = NULL;
    const uint64_t dram = UINT64_C(0x10000000000), size = UINT64_C(8) << 30;
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(!error);
    for (unsigned view = 0; view < VIEWS; view++) {
        CHECK(plan.addresses[view] == expected_address(view));
        CHECK(plan.addresses[view] == amcc + apple_modern_mcc_slc_view_offset(view));
        /* Inside the matched reg[2] AMCC window [amcc, amcc + 0x140000). */
        CHECK(plan.addresses[view] >= amcc &&
              plan.addresses[view] + 4 <= amcc + APPLE_MODERN_MCC_AMCC_SPAN);
    }
    CHECK(plan.addresses[0] == UINT64_C(0x220102800) && plan.addresses[1] == UINT64_C(0x22010082c) &&
          plan.addresses[2] == UINT64_C(0x220102844) && plan.addresses[3] == UINT64_C(0x220002804) &&
          plan.addresses[6] == UINT64_C(0x2200c2804) && plan.addresses[7] == UINT64_C(0x220002844) &&
          plan.addresses[10] == UINT64_C(0x2200c2844));
    for (unsigned view = 0; view < VIEWS; view++) {
        uint64_t address = expected_address(view);
        AppleModernAddressRange first = {address, 1}, last = {address + 3, 1};
        AppleModernAddressRange wide = {address - 0x10, 0x20};
        AppleModernAddressRange *bad[] = {&first, &last, &wide};
        for (unsigned i = 0; i < 3; i++) {
            memset(&plan, 0x5a, sizeof(plan));
            CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, bad[i], 1, &plan, &error));
            clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        }
        memset(&plan, 0x5a, sizeof(plan));
        CHECK(!apple_modern_mcc_slc_plan_build(blob, address, 1, NULL, 0, &plan, &error));
        clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        CHECK(!apple_modern_mcc_slc_plan_build(blob, address + 3, 1, NULL, 0, &plan, &error));
        clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        CHECK(!apple_modern_mcc_slc_plan_build(blob, address, 4, NULL, 0, &plan, &error));
        clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        AppleModernAddressRange adjacent[] = {{address - 4, 4}, {address + 4, 4}};
        CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, adjacent, 2, &plan, &error));
        CHECK(!error && plan.addresses[view] == address);
        CHECK(apple_modern_mcc_slc_plan_build(blob, address - 4, 4, NULL, 0, &plan, &error));
        CHECK(apple_modern_mcc_slc_plan_build(blob, address + 4, 4, NULL, 0, &plan, &error));
    }
    /* The whole compatibility aperture collides with plane 0's cells; the
     * board's carve (three pieces around +0x2804 and +0x2844) does not. */
    AppleModernAddressRange whole = {aperture, aperture_size};
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, &whole, 1, &plan, &error));
    clear_error(&error);
    AppleModernAddressRange carved[] = {
        {aperture, 0x2804}, {aperture + 0x2808, 0x3c},
        {aperture + 0x2848, aperture_size - 0x2848},
    };
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, carved, 3, &plan, &error));
    for (unsigned i = 0; i < 3; i++) {
        AppleModernAddressRange grown = carved[i];
        if (i < 2) {
            grown.size++;                                     /* into the next cell */
        } else {
            grown.physical_address--, grown.size++;           /* into +0x2844 */
        }
        AppleModernAddressRange variant[3] = {carved[0], carved[1], carved[2]};
        variant[i] = grown;
        CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, variant, 3, &plan, &error));
        clear_error(&error);
    }
    AppleModernAddressRange grown_down = {aperture + 0x2807, 0x3d};
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, &grown_down, 1, &plan, &error));
    clear_error(&error);
    /* Served CTRR bound registers (A..D lower/upper at +0x10/+0x20 + 0x100 *
     * bank) are ordinary exclusions that never meet a view. */
    for (unsigned bank = 0; bank < 4; bank++) {
        AppleModernAddressRange bounds[] = {{aperture + 0x10 + 0x100 * bank, 8},
                                            {aperture + 0x20 + 0x100 * bank, 8}};
        CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, bounds, 2, &plan, &error));
    }

    /* ADT mutations of the matched T8140 AMCC schema. */
    const char *names[] = {"compatible", "amcc-reg-idx", "amcc-count",
                           "dcs-count-per-amcc", "reg", "reg"};
    const size_t offsets[] = {0, 0, 0, 0, 2 * 16, 2 * 16 + 8};
    for (unsigned i = 0; i < 6; i++) {
        CHECK(apple_modern_adt_property(blob, "/arm-io/mcc", names[i], &property, &error));
        for (unsigned bit = 0; bit < (i >= 4 ? 3U : 1U); bit++) {
            uint8_t *byte = (uint8_t *)property.data + offsets[i] + (i >= 4 ? bit : 0);
            uint8_t mask = i >= 4 ? (uint8_t)(1U << (bit + 2)) : 1;
            *byte ^= mask;
            memset(&plan, 0x5a, sizeof(plan));
            CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
            clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
            *byte ^= mask;
        }
    }
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(apple_modern_adt_property(blob, "/arm-io", "ranges", &property, &error));
    CHECK(property.size >= 48);
    uint8_t ranges[24]; memcpy(ranges, property.data + 24, 24);
    memcpy((uint8_t *)property.data + 24, property.data, 24);   /* ambiguous */
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
    memcpy((uint8_t *)property.data + 24, ranges, 24);
    memcpy(ranges, property.data, 24);
    ((uint8_t *)property.data)[8] ^= 1;                        /* translation */
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, ranges, 24);
    memset((uint8_t *)property.data + 16, 0xff, 8);            /* wraps */
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, ranges, 24);
    memset((uint8_t *)property.data + 16, 0, 8);               /* empty */
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, ranges, 24);
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));

    /* Exclusion budget, wrap/empty/NULL, DRAM extent, output aliasing. */
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1];
    for (unsigned i = 0; i < APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1; i++) {
        exclusions[i] = (AppleModernAddressRange){UINT64_C(0x1000) + i * 8, 8};
    }
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, exclusions,
                                          APPLE_MODERN_MAX_BOARD_EXCLUSIONS, &plan, &error));
    saved = plan;
    exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS - 1] =
        (AppleModernAddressRange){expected_address(VIEWS - 1) + 3, 1};
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, exclusions,
                                           APPLE_MODERN_MAX_BOARD_EXCLUSIONS, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
    exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS - 1] =
        (AppleModernAddressRange){UINT64_C(0x1000) + (APPLE_MODERN_MAX_BOARD_EXCLUSIONS - 1) * 8, 8};
    plan = saved;
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, exclusions,
                                           APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &saved, sizeof(plan)));
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &saved, sizeof(plan)));
    AppleModernAddressRange wrap = {UINT64_MAX, 8}, top = {UINT64_MAX - 3, 3},
                            empty = {expected_address(STATUS), 0};
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, &wrap, 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, &top, 1, &plan, &error));
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, &empty, 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
    CHECK(!apple_modern_mcc_slc_plan_build(blob, UINT64_MAX, size, NULL, 0, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, 0, NULL, 0, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, NULL, &error));
    clear_error(&error);
    uint8_t *tree_before = malloc(length); CHECK(tree_before); memcpy(tree_before, tree, length);
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0,
              (AppleModernMCCSLCPlan *)(void *)(tree + (length / 16) * 8), &error));
    clear_error(&error); CHECK(!memcmp(tree, tree_before, length));
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    saved = plan;
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size,
              (AppleModernAddressRange *)(void *)&plan.addresses[4], 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &saved, sizeof(plan)));
    CHECK(!apple_modern_mcc_slc_plan_build(blob, dram, size, &wrap, 1, &plan, NULL));
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(!memcmp(&plan, &saved, sizeof(plan)) && !error);

    /* Optional /arm-io/mcc properties (absent from the matched trees). */
    CHECK(!apple_modern_adt_property(blob, "/arm-io/mcc", "amcc-plane-enable-mask",
                                     &property, &error));
    clear_error(&error);
    CHECK(!apple_modern_adt_property(blob, "/arm-io/mcc", "max-way-count", &property, &error));
    clear_error(&error);
    CHECK(!apple_modern_adt_property(blob, "/arm-io/mcc", "dcs-channel-enable-mask",
                                     &property, &error));
    clear_error(&error);
    opt_device = "MCC SLC";
    opt_property_sweep(tree, length, "amcc-plane-enable-mask", true, 0xf, slc_plan,
                       &plan, sizeof(plan), &saved);
    opt_property_sweep(tree, length, "max-way-count", false, 0x7f, slc_plan,
                       &plan, sizeof(plan), &saved);
    opt_ignored_sweep(tree, length, "dcs-channel-enable-mask", slc_plan,
                      &plan, sizeof(plan), &saved);
    /* Both validated properties together: each is still checked, the plane
     * mask first. */
    {
        OptTree copy = opt_copy(tree, length);
        opt_set(&copy, OPT_DONOR_A, "amcc-plane-enable-mask", 0xf);
        opt_set(&copy, OPT_DONOR_B, "max-way-count", 0x7f);
        opt_expect(&copy, slc_plan, &plan, sizeof(plan), &saved, NULL, NULL);
        free(copy.data);
        copy = opt_copy(tree, length);
        opt_set(&copy, OPT_DONOR_A, "amcc-plane-enable-mask", 0xf);
        opt_set(&copy, OPT_DONOR_B, "max-way-count", 0x80);
        opt_expect(&copy, slc_plan, &plan, sizeof(plan), &saved, "max-way-count", "=0x80 ");
        free(copy.data);
        copy = opt_copy(tree, length);
        opt_set(&copy, OPT_DONOR_A, "amcc-plane-enable-mask", 0x7);
        opt_set(&copy, OPT_DONOR_B, "max-way-count", 0xc);
        opt_expect(&copy, slc_plan, &plan, sizeof(plan), &saved, "amcc-plane-enable-mask",
                   "=0x7 ");
        free(copy.data);
        copy = opt_copy(tree, length);
        opt_set(&copy, OPT_DONOR_A, "amcc-plane-enable-mask", 0x7);
        opt_set(&copy, OPT_DONOR_B, "max-way-count", 0x80);
        opt_expect(&copy, slc_plan, &plan, sizeof(plan), &saved, "amcc-plane-enable-mask",
                   "=0x7 ");
        free(copy.data);
        /* A property-error rejection still validates the geometry first. */
        copy = opt_copy(tree, length);
        opt_set(&copy, OPT_DONOR_A, "amcc-plane-enable-mask", 0xf);
        AppleModernBlob mutated = {copy.data, copy.size};
        CHECK(apple_modern_adt_property(mutated, "/arm-io/mcc", "amcc-reg-idx", &property,
                                        &error));
        ((uint8_t *)property.data)[0] ^= 1;
        memset(&plan, 0x5a, sizeof(plan));
        CHECK(!apple_modern_mcc_slc_plan_build(mutated, dram, size, NULL, 0, &plan, &error));
        CHECK(strstr(error->message, "amcc-reg-idx") != NULL);
        clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        free(copy.data);
    }
    CHECK(opt_accepts && opt_rejects && opt_size_rejects);
    CHECK(!memcmp(tree, tree_before, length));
    CHECK(apple_modern_mcc_slc_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(!memcmp(&plan, &saved, sizeof(plan)) && !error);
    free(tree_before); free(tree);
    printf("{\"passed\":true,\"checks\":%u,\"optional_property_accepts\":%u,"
           "\"optional_property_rejects\":%u,\"optional_property_size_rejects\":%u,"
           "\"firmware_executed\":false}\n",
           checks, opt_accepts, opt_rejects, opt_size_rejects);
    return 0;
}
