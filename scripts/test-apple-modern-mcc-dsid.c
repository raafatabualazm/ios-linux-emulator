/* AMCC DSID profile controls/counters and matched sparse layout qualification.
 * v3: the AMCC-window bound and the optional amcc-plane-enable-mask guard.
 * v4: optional-property rejections are matched exactly with the "MCC DSID"
 * prefix (separate wrong-size and unmodelled-value messages).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-mcc-dsid.h"
static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

#define PLANES APPLE_MODERN_MCC_DSID_PLANES
#define INTERVAL APPLE_MODERN_MCC_DSID_INTERVAL_VIEW
#define COUNTER APPLE_MODERN_MCC_DSID_COUNTER_VIEW
#define VIEWS APPLE_MODERN_MCC_DSID_VIEWS
#include "test-apple-modern-mcc-optional-props.h"

/* /arm-io/pmp/iop-pmp-nub mc-dsid-ptd-config {1,0},{8,0},{15,0},{17,0}. */
static const uint64_t driver_config[PLANES] = {0x1, 0x8, 0xf, 0x11};
static const uint64_t amcc = UINT64_C(0x220000000);

static void clear_error(Error **error)
{
    CHECK(*error != NULL);
    error_free(*error);
    *error = NULL;
}

static unsigned width(unsigned view)
{
    return view >= INTERVAL && view < COUNTER ? 4 : 8;
}

static uint64_t expected_address(unsigned view)
{
    if (view < INTERVAL) {
        return amcc + view * UINT64_C(0x40000) + 0x2a000;
    }
    if (view < COUNTER) {
        return amcc + (view - INTERVAL) * UINT64_C(0x40000) + 0x2e000;
    }
    return amcc + 0x2a058;
}

static uint64_t expected_span(unsigned view)
{
    return view == 0 ? 24 : view < INTERVAL ? 16 : view < COUNTER ? 4 : 16;
}

static uint64_t control_pattern(unsigned plane, unsigned cell)
{
    return UINT64_C(0x8123456789ab0000) | (uint64_t)plane << 8 | cell << 4 | 0xe;
}

static void expect_all(AppleModernMCCDSIDCore *core,
                       const uint64_t controls[PLANES][3],
                       const uint32_t intervals[PLANES], uint64_t counter0,
                       uint64_t counter1)
{
    uint64_t value;
    for (unsigned plane = 0; plane < PLANES; plane++) {
        for (unsigned cell = 0; cell < (plane ? 2U : 3U); cell++) {
            value = ~controls[plane][cell];
            CHECK(apple_modern_mcc_dsid_core_read(core, plane, cell * 8, 8, &value));
            CHECK(value == controls[plane][cell]);
        }
        value = ~(uint64_t)intervals[plane];
        CHECK(apple_modern_mcc_dsid_core_read(core, INTERVAL + plane, 0, 4, &value));
        CHECK(value == intervals[plane]);
    }
    CHECK(apple_modern_mcc_dsid_core_read(core, COUNTER, 0, 8, &value));
    CHECK(value == counter0);
    CHECK(apple_modern_mcc_dsid_core_read(core, COUNTER, 8, 8, &value));
    CHECK(value == counter1);
}

static bool dsid_plan(AppleModernBlob tree, void *plan, Error **errp)
{
    return apple_modern_mcc_dsid_plan_build(tree, UINT64_C(0x10000000000),
                                            UINT64_C(8) << 30, NULL, 0, plan, errp);
}

int main(int argc, char **argv)
{
    AppleModernMCCDSIDCore core = {.reset_value = UINT64_C(0xd51d0123456789ab)};
    uint64_t controls[PLANES][3] = {{0}};
    uint32_t intervals[PLANES] = {0};
    uint64_t value;

    /* View geometry: 3 plane-0 controls, 2 on planes 1..3, 4 interval words,
     * plane-0 hit/miss counters; nothing beyond view 8. */
    CHECK(APPLE_MODERN_MCC_DSID_VIEWS == 9 && APPLE_MODERN_MAX_BOARD_EXCLUSIONS >= 96);
    for (unsigned view = 0; view < VIEWS + 4; view++) {
        CHECK(apple_modern_mcc_dsid_view_span(view) ==
              (view < VIEWS ? expected_span(view) : 0));
    }
    CHECK(apple_modern_mcc_dsid_view_span(UINT32_MAX) == 0);

    /* Reset: controls/intervals zero, counters at the declared virtual reset. */
    memset(&core.controls, 0xa5, sizeof(core.controls));
    memset(&core.intervals, 0xa5, sizeof(core.intervals));
    core.reads = core.writes = core.event_updates = 7;
    apple_modern_mcc_dsid_core_reset(&core);
    CHECK(!core.reads && !core.writes && !core.event_updates);
    for (unsigned plane = 0; plane < PLANES; plane++) {
        for (unsigned cell = 0; cell < 3; cell++) {
            CHECK(!core.controls[plane][cell]);
        }
        CHECK(!core.intervals[plane]);
    }
    expect_all(&core, controls, intervals, core.reset_value, core.reset_value);
    CHECK(core.reads == 15 && !core.writes);

    /* Exact enableDsidProfileCounters sequence: plane-0 +0x2a010, then per
     * plane +0x2e000=0x100, +0x2a008=config, +0x2a000=0x11 (first) or 0x1. */
    CHECK(apple_modern_mcc_dsid_core_write(&core, 0, 0x10, 8, 0x10000000));
    controls[0][2] = 0x10000000;
    for (unsigned plane = 0; plane < PLANES; plane++) {
        CHECK(apple_modern_mcc_dsid_core_write(&core, INTERVAL + plane, 0, 4, 0x100));
        CHECK(apple_modern_mcc_dsid_core_write(&core, plane, 8, 8, driver_config[plane]));
        CHECK(apple_modern_mcc_dsid_core_write(&core, plane, 0, 8, plane ? 0x1 : 0x11));
        intervals[plane] = 0x100;
        controls[plane][1] = driver_config[plane];
        controls[plane][0] = plane ? 0x1 : 0x11;
    }
    CHECK(core.writes == 13 && core.reads == 15);
    /* Perf slot 3 samples only: no event producer, counters stay at reset. */
    expect_all(&core, controls, intervals, core.reset_value, core.reset_value);
    CHECK(core.reads == 30 && core.writes == 13 && !core.event_updates);

    /* Full-width independent storage: each cell keeps all 64 (or 32) bits and
     * leaves every other cell unchanged. */
    for (unsigned plane = 0; plane < PLANES; plane++) {
        for (unsigned cell = 0; cell < (plane ? 2U : 3U); cell++) {
            CHECK(apple_modern_mcc_dsid_core_write(&core, plane, cell * 8, 8,
                                                   control_pattern(plane, cell)));
            controls[plane][cell] = control_pattern(plane, cell);
            expect_all(&core, controls, intervals, core.reset_value, core.reset_value);
        }
        uint32_t word = UINT32_C(0xa5c30000) | plane << 4 | 0xf;
        CHECK(apple_modern_mcc_dsid_core_write(&core, INTERVAL + plane, 0, 4, word));
        intervals[plane] = word;
        expect_all(&core, controls, intervals, core.reset_value, core.reset_value);
    }
    /* A 32-bit interval store keeps only its 32 bits (the transaction width). */
    CHECK(apple_modern_mcc_dsid_core_write(&core, INTERVAL + 2, 0, 4,
                                           UINT64_C(0xffffffff00000100)));
    intervals[2] = 0x100;
    expect_all(&core, controls, intervals, core.reset_value, core.reset_value);
    for (unsigned bit = 0; bit < 64; bit++) {
        CHECK(apple_modern_mcc_dsid_core_write(&core, 3, 8, 8, UINT64_C(1) << bit));
        CHECK(apple_modern_mcc_dsid_core_read(&core, 3, 8, 8, &value));
        CHECK(value == UINT64_C(1) << bit);
    }
    controls[3][1] = UINT64_C(1) << 63;
    expect_all(&core, controls, intervals, core.reset_value, core.reset_value);

    /* Event gate: plane-0 +0x2a000 bit 0 only (inferred "counter Enable"). */
    uint64_t updates = core.event_updates;
    CHECK(!updates);
    static const uint64_t closed[] = {0, 0x10, UINT64_C(0xfffffffffffffffe)};
    for (unsigned i = 0; i < 3; i++) {
        CHECK(apple_modern_mcc_dsid_core_write(&core, 0, 0, 8, closed[i]));
        for (unsigned plane = 1; plane < PLANES; plane++) {
            CHECK(apple_modern_mcc_dsid_core_write(&core, plane, 0, 8, UINT64_MAX));
        }
        CHECK(apple_modern_mcc_dsid_core_write(&core, 0, 8, 8, UINT64_MAX));
        CHECK(apple_modern_mcc_dsid_core_write(&core, 0, 16, 8, UINT64_MAX));
        for (unsigned counter = 0; counter < 2; counter++) {
            CHECK(apple_modern_mcc_dsid_core_event(&core, counter, 5));
            CHECK(apple_modern_mcc_dsid_core_event(&core, counter, UINT64_MAX));
        }
        CHECK(core.values[0] == core.reset_value && core.values[1] == core.reset_value);
        CHECK(core.event_updates == 0);
    }
    for (unsigned plane = 1; plane < PLANES; plane++) {
        controls[plane][0] = UINT64_MAX;
    }
    controls[0][1] = controls[0][2] = UINT64_MAX;
    CHECK(apple_modern_mcc_dsid_core_write(&core, 0, 0, 8, 0x11));
    controls[0][0] = 0x11;
    CHECK(apple_modern_mcc_dsid_core_event(&core, 0, 3));
    CHECK(core.values[0] == core.reset_value + 3 && core.values[1] == core.reset_value);
    CHECK(core.event_updates == 1);
    CHECK(apple_modern_mcc_dsid_core_event(&core, 1, 7));
    CHECK(core.values[0] == core.reset_value + 3 && core.values[1] == core.reset_value + 7);
    CHECK(core.event_updates == 2);
    /* Zero amount is accepted and counts nothing. */
    CHECK(apple_modern_mcc_dsid_core_event(&core, 0, 0));
    CHECK(core.event_updates == 2 && core.values[0] == core.reset_value + 3);
    /* Declared modulo-64 accumulation. */
    CHECK(apple_modern_mcc_dsid_core_event(&core, 1, UINT64_MAX));
    CHECK(core.values[1] == core.reset_value + 6 && core.event_updates == 3);
    expect_all(&core, controls, intervals, core.reset_value + 3, core.reset_value + 6);
    /* Disabling closes the gate immediately; other enables do not reopen it. */
    CHECK(apple_modern_mcc_dsid_core_write(&core, 0, 0, 8, 0x10));
    controls[0][0] = 0x10;
    CHECK(apple_modern_mcc_dsid_core_event(&core, 0, 1));
    CHECK(core.values[0] == core.reset_value + 3 && core.event_updates == 3);
    /* The driver's own enable value (0x11) also opens the gate. */
    CHECK(apple_modern_mcc_dsid_core_write(&core, 0, 0, 8, 0x1));
    controls[0][0] = 0x1;
    CHECK(apple_modern_mcc_dsid_core_event(&core, 0, 1));
    CHECK(core.values[0] == core.reset_value + 4 && core.event_updates == 4);
    expect_all(&core, controls, intervals, core.reset_value + 4, core.reset_value + 6);

    /* Every rejected operation leaves the core byte-identical and the output
     * untouched. */
    AppleModernMCCDSIDCore before = core;
    value = UINT64_C(0x123456789abcdef0);
    CHECK(!apple_modern_mcc_dsid_core_read(NULL, 0, 0, 8, &value));
    CHECK(!apple_modern_mcc_dsid_core_read(&core, 0, 0, 8, NULL));
    CHECK(!apple_modern_mcc_dsid_core_read(&core, 0, 0, 8, &core.values[0]));
    CHECK(!apple_modern_mcc_dsid_core_read(&core, 0, 0, 8, (uint64_t *)(void *)&core.reads));
    CHECK(!apple_modern_mcc_dsid_core_write(NULL, 0, 0, 8, 1));
    CHECK(!apple_modern_mcc_dsid_core_event(NULL, 0, 1));
    CHECK(!apple_modern_mcc_dsid_core_event(&core, 2, 1));
    CHECK(!apple_modern_mcc_dsid_core_event(&core, UINT32_MAX, 1));
    for (unsigned view = VIEWS; view < VIEWS + 3; view++) {
        for (unsigned size = 0; size <= 16; size++) {
            CHECK(!apple_modern_mcc_dsid_core_read(&core, view, 0, size, &value));
            CHECK(!apple_modern_mcc_dsid_core_write(&core, view, 0, size, 1));
        }
    }
    CHECK(!apple_modern_mcc_dsid_core_read(&core, UINT32_MAX, 0, 8, &value));
    CHECK(!apple_modern_mcc_dsid_core_write(&core, UINT32_MAX, 0, 8, 1));
    for (unsigned view = 0; view < VIEWS; view++) {
        unsigned w = width(view);
        uint64_t span = expected_span(view);
        for (unsigned size = 0; size <= 16; size++) {
            if (size == w) {
                continue;
            }
            for (uint64_t offset = 0; offset < span; offset += 4) {
                CHECK(!apple_modern_mcc_dsid_core_read(&core, view, offset, size, &value));
                CHECK(!apple_modern_mcc_dsid_core_write(&core, view, offset, size, 1));
            }
        }
        for (uint64_t offset = 1; offset < span; offset++) {
            if (offset % w) {
                CHECK(!apple_modern_mcc_dsid_core_read(&core, view, offset, w, &value));
                CHECK(!apple_modern_mcc_dsid_core_write(&core, view, offset, w, 1));
            }
        }
        static const uint64_t outside[] = {0, 8, 0x40, 0x1000, 0x40000,
                                           UINT64_C(1) << 32, UINT64_MAX - 7};
        for (unsigned i = 0; i < sizeof(outside) / sizeof(outside[0]); i++) {
            uint64_t offset = span + outside[i];
            if (offset < span) {
                continue;
            }
            offset &= ~(uint64_t)(w - 1);
            CHECK(!apple_modern_mcc_dsid_core_read(&core, view, offset, w, &value));
            CHECK(!apple_modern_mcc_dsid_core_write(&core, view, offset, w, 1));
        }
        CHECK(!apple_modern_mcc_dsid_core_read(&core, view, UINT64_MAX, w, &value));
        CHECK(!apple_modern_mcc_dsid_core_write(&core, view, UINT64_MAX, w, 1));
    }
    /* Plane 1..3 +0x2a010 is outside the attested cells. */
    for (unsigned plane = 1; plane < PLANES; plane++) {
        CHECK(!apple_modern_mcc_dsid_core_read(&core, plane, 0x10, 8, &value));
        CHECK(!apple_modern_mcc_dsid_core_write(&core, plane, 0x10, 8, 1));
    }
    /* Counters are read-only at every width/offset. */
    for (uint64_t offset = 0; offset < 16; offset++) {
        for (unsigned size = 0; size <= 16; size++) {
            CHECK(!apple_modern_mcc_dsid_core_write(&core, COUNTER, offset, size,
                                                    UINT64_C(0x5555aaaa5555aaaa)));
        }
    }
    CHECK(value == UINT64_C(0x123456789abcdef0));
    CHECK(!memcmp(&core, &before, sizeof(core)));

    /* Saturating diagnostics. */
    core.reads = core.writes = core.event_updates = UINT64_MAX;
    CHECK(apple_modern_mcc_dsid_core_read(&core, COUNTER, 0, 8, &value));
    CHECK(value == core.reset_value + 4);
    CHECK(apple_modern_mcc_dsid_core_write(&core, 1, 0, 8, 1));
    CHECK(apple_modern_mcc_dsid_core_event(&core, 0, 1));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX &&
          core.event_updates == UINT64_MAX && core.values[0] == core.reset_value + 5);

    /* Reset restores every cell and diagnostic, keeping the reset value. */
    apple_modern_mcc_dsid_core_reset(&core);
    memset(controls, 0, sizeof(controls));
    memset(intervals, 0, sizeof(intervals));
    CHECK(core.reset_value == UINT64_C(0xd51d0123456789ab));
    CHECK(!core.reads && !core.writes && !core.event_updates);
    expect_all(&core, controls, intervals, core.reset_value, core.reset_value);
    CHECK(core.reads == 15);
    AppleModernMCCDSIDCore extreme = {.reset_value = UINT64_MAX};
    apple_modern_mcc_dsid_core_reset(&extreme);
    CHECK(apple_modern_mcc_dsid_core_write(&extreme, 0, 0, 8, 1));
    CHECK(apple_modern_mcc_dsid_core_event(&extreme, 0, 2));
    CHECK(extreme.values[0] == 1 && extreme.values[1] == UINT64_MAX);

    /* Matched sparse layout. */
    CHECK(argc == 2);
    FILE *file = fopen(argv[1], "rb"); CHECK(file);
    CHECK(!fseek(file, 0, SEEK_END)); long length = ftell(file);
    CHECK(length > 0 && length < 1 << 20); rewind(file);
    uint8_t *tree = malloc(length); CHECK(tree);
    CHECK(fread(tree, 1, length, file) == (size_t)length); fclose(file);
    AppleModernBlob blob = {tree, length}, property;
    AppleModernMCCDSIDPlan plan, zero, saved;
    memset(&zero, 0, sizeof(zero));
    Error *error = NULL;
    const uint64_t dram = UINT64_C(0x10000000000), size = UINT64_C(8) << 30;
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(!error);
    uint64_t highest = 0;
    for (unsigned view = 0; view < VIEWS; view++) {
        CHECK(plan.addresses[view] == expected_address(view));
        CHECK(plan.spans[view] == expected_span(view));
        /* Inside the matched reg[2] AMCC window [amcc, amcc + 0x140000); the
         * plan_build bound check is unreachable with these constants. */
        CHECK(plan.addresses[view] >= amcc && plan.addresses[view] + plan.spans[view] <=
              amcc + APPLE_MODERN_MCC_AMCC_SPAN);
        if (plan.addresses[view] + plan.spans[view] - amcc > highest) {
            highest = plan.addresses[view] + plan.spans[view] - amcc;
        }
    }
    CHECK(APPLE_MODERN_MCC_AMCC_SPAN == 0x140000 && highest == 0xee004);
    for (unsigned view = 0; view < VIEWS; view++) {
        uint64_t address = expected_address(view), span = expected_span(view);
        AppleModernAddressRange first = {address, 1}, last = {address + span - 1, 1};
        AppleModernAddressRange wide = {address - 0x1000, 0x2000};
        AppleModernAddressRange *bad[] = {&first, &last, &wide};
        for (unsigned i = 0; i < 3; i++) {
            memset(&plan, 0x5a, sizeof(plan));
            CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, bad[i], 1, &plan, &error));
            clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        }
        /* DRAM covering the first byte, the last byte or exactly the view. */
        memset(&plan, 0x5a, sizeof(plan));
        CHECK(!apple_modern_mcc_dsid_plan_build(blob, address, 1, NULL, 0, &plan, &error));
        clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        CHECK(!apple_modern_mcc_dsid_plan_build(blob, address + span - 1, 1, NULL, 0, &plan, &error));
        clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        CHECK(!apple_modern_mcc_dsid_plan_build(blob, address, span, NULL, 0, &plan, &error));
        clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
        AppleModernAddressRange adjacent[] = {{address - 8, 8}, {address + span, 8}};
        CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, adjacent, 2, &plan, &error));
        CHECK(!error && plan.addresses[view] == address && plan.spans[view] == span);
        CHECK(apple_modern_mcc_dsid_plan_build(blob, address - 8, 8, NULL, 0, &plan, &error));
        CHECK(apple_modern_mcc_dsid_plan_build(blob, address + span, 8, NULL, 0, &plan, &error));
    }
    /* Each overlap is reported even when it is the last exclusion. */
    AppleModernAddressRange several[APPLE_MODERN_MAX_BOARD_EXCLUSIONS];
    for (unsigned i = 0; i < APPLE_MODERN_MAX_BOARD_EXCLUSIONS; i++) {
        several[i] = (AppleModernAddressRange){UINT64_C(0x1000) + i * 8, 8};
    }
    several[APPLE_MODERN_MAX_BOARD_EXCLUSIONS - 1] =
        (AppleModernAddressRange){expected_address(COUNTER) + 15, 1};
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, several,
                                            APPLE_MODERN_MAX_BOARD_EXCLUSIONS, &plan, &error));
    clear_error(&error);
    /* The quota banks (same AMCC block) are not DSID exclusions. */
    AppleModernAddressRange quota = {amcc + 0xa000, 128};
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, &quota, 1, &plan, &error));
    /* ...but a DRAM extent across them is rejected through the shared schema. */
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, amcc + 0xa000, 128, NULL, 0, &plan, &error));
    clear_error(&error);

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
            CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
            clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
            *byte ^= mask;
        }
    }
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(apple_modern_adt_property(blob, "/arm-io", "ranges", &property, &error));
    CHECK(property.size >= 48);
    uint8_t ranges[24]; memcpy(ranges, property.data + 24, 24);
    memcpy((uint8_t *)property.data + 24, property.data, 24);   /* ambiguous */
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
    memcpy((uint8_t *)property.data + 24, ranges, 24);
    memcpy(ranges, property.data, 24);
    ((uint8_t *)property.data)[8] ^= 1;                        /* translation */
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, ranges, 24);
    memset((uint8_t *)property.data + 16, 0xff, 8);            /* wraps */
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, ranges, 24);
    memset((uint8_t *)property.data + 16, 0, 8);               /* empty */
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    clear_error(&error); memcpy((uint8_t *)property.data, ranges, 24);
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));

    /* Exclusion budget, wrap/empty/NULL, DRAM extent, output aliasing. */
    AppleModernAddressRange exclusions[APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1];
    for (unsigned i = 0; i < APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1; i++) {
        exclusions[i] = (AppleModernAddressRange){UINT64_C(0x1000) + i * 8, 8};
    }
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, exclusions,
                                           APPLE_MODERN_MAX_BOARD_EXCLUSIONS, &plan, &error));
    saved = plan;
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, exclusions,
                                            APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &saved, sizeof(plan)));
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &saved, sizeof(plan)));
    AppleModernAddressRange wrap = {UINT64_MAX, 8}, wrap2 = {UINT64_MAX - 3, 3},
                            empty = {amcc + 0x2a000, 0};
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, &wrap, 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, &wrap2, 1, &plan, &error));
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, &empty, 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &zero, sizeof(plan)));
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, UINT64_MAX, size, NULL, 0, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, 0, NULL, 0, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, NULL, &error));
    clear_error(&error);
    uint8_t *tree_before = malloc(length); CHECK(tree_before); memcpy(tree_before, tree, length);
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0,
              (AppleModernMCCDSIDPlan *)(void *)(tree + (length / 16) * 8), &error));
    clear_error(&error); CHECK(!memcmp(tree, tree_before, length));
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    saved = plan;
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size,
              (AppleModernAddressRange *)(void *)&plan.addresses[3], 1, &plan, &error));
    clear_error(&error); CHECK(!memcmp(&plan, &saved, sizeof(plan)));
    /* NULL errp is tolerated on every failure path. */
    CHECK(!apple_modern_mcc_dsid_plan_build(blob, dram, size, &wrap, 1, &plan, NULL));
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(!memcmp(&plan, &saved, sizeof(plan)) && !error);

    /* Optional /arm-io/mcc properties (absent from the matched trees): only
     * amcc-plane-enable-mask moves DSID cells; the SLC and DCS masks do not. */
    CHECK(!apple_modern_adt_property(blob, "/arm-io/mcc", "amcc-plane-enable-mask",
                                     &property, &error));
    clear_error(&error);
    opt_device = "MCC DSID";
    opt_property_sweep(tree, length, "amcc-plane-enable-mask", true, 0xf, dsid_plan,
                       &plan, sizeof(plan), &saved);
    opt_ignored_sweep(tree, length, "max-way-count", dsid_plan, &plan, sizeof(plan), &saved);
    opt_ignored_sweep(tree, length, "dcs-channel-enable-mask", dsid_plan,
                      &plan, sizeof(plan), &saved);
    {
        OptTree copy = opt_copy(tree, length);
        opt_set(&copy, OPT_DONOR_A, "amcc-plane-enable-mask", 0xe);
        opt_set(&copy, OPT_DONOR_B, "max-way-count", 0xc);
        opt_set(&copy, OPT_DONOR_C, "dcs-channel-enable-mask", 0xf);
        opt_expect(&copy, dsid_plan, &plan, sizeof(plan), &saved, "amcc-plane-enable-mask",
                   "=0xe ");
        free(copy.data);
        copy = opt_copy(tree, length);
        opt_set(&copy, OPT_DONOR_A, "amcc-plane-enable-mask", 0xf);
        opt_set(&copy, OPT_DONOR_B, "max-way-count", 0x80);
        opt_set(&copy, OPT_DONOR_C, "dcs-channel-enable-mask", 0x3);
        opt_expect(&copy, dsid_plan, &plan, sizeof(plan), &saved, NULL, NULL);
        free(copy.data);
    }
    CHECK(opt_accepts && opt_rejects && opt_size_rejects);
    CHECK(!memcmp(tree, tree_before, length));
    CHECK(apple_modern_mcc_dsid_plan_build(blob, dram, size, NULL, 0, &plan, &error));
    CHECK(!memcmp(&plan, &saved, sizeof(plan)) && !error);
    free(tree_before); free(tree);
    printf("{\"passed\":true,\"checks\":%u,\"optional_property_accepts\":%u,"
           "\"optional_property_rejects\":%u,\"optional_property_size_rejects\":%u,"
           "\"firmware_executed\":false}\n",
           checks, opt_accepts, opt_rejects, opt_size_rejects);
    return 0;
}
