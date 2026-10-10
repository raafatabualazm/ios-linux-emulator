/* /arm-io/dcp ASC v6 aperture qualification: the plan is derived from the
 * served tree's own reg property and refuses anything that is not the attested
 * three-window ASC v6 layout, and the core decodes exactly the registers the
 * header claims, answers zero everywhere else, and never fails an access.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-dcp-asc.h"
#include "hw/arm/apple-silicon/modern-disp-trace.h"

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

#define CANDS APPLE_MODERN_DCP_ASC_CANDIDATES
#define MAPPED APPLE_MODERN_DCP_ASC_MAPPED
#define RECS APPLE_MODERN_DCP_ASC_RECORDS
#define ARMIO_PARENT UINT64_C(0x210000000)
#define DRAM_BASE (UINT64_C(1) << 40)
#define DRAM_SIZE (UINT64_C(8) << 30)

static void clear_error(Error **error)
{
    CHECK(*error != NULL);
    error_free(*error);
    *error = NULL;
}

static uint8_t *slurp(const char *path, size_t *size)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *data;
    long length;
    if (!fp) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(1);
    }
    if (fseek(fp, 0, SEEK_END) || (length = ftell(fp)) <= 0 ||
        fseek(fp, 0, SEEK_SET)) {
        exit(1);
    }
    data = malloc((size_t)length);
    if (!data || fread(data, 1, (size_t)length, fp) != (size_t)length) {
        exit(1);
    }
    fclose(fp);
    *size = (size_t)length;
    return data;
}

static uint64_t little(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static void check_plan(AppleModernBlob restored, AppleModernBlob served)
{
    static const uint64_t sizes[CANDS] = {
        APPLE_MODERN_DCP_ASC_WRAPPER_SIZE, APPLE_MODERN_DCP_ASC_CORE_SIZE,
        APPLE_MODERN_DCP_ASC_ALIAS_SIZE};
    AppleModernDcpAscPlan plan;
    AppleModernAddressRange exclusion;
    AppleModernBlob reg;
    Error *error = NULL;
    uint8_t *mutated;

    /* Positive: the restored tree yields exactly the three attested windows,
     * translated through /arm-io ranges. */
    CHECK(apple_modern_dcp_asc_plan_build(restored, DRAM_BASE, DRAM_SIZE, NULL,
                                          0, &plan, &error));
    CHECK(error == NULL);
    CHECK(plan.count == CANDS && plan.mapped == MAPPED);
    CHECK(apple_modern_adt_property(restored, "/arm-io/dcp", "reg", &reg,
                                    &error));
    CHECK(error == NULL && reg.size == CANDS * 16);
    /* reg[2] is inside reg[0], measured here on the pinned bytes themselves. */
    CHECK(!plan.contained[0] && !plan.contained[1] && plan.contained[2]);
    CHECK(plan.addresses[2] > plan.addresses[0]);
    CHECK(plan.addresses[2] - plan.addresses[0] == UINT64_C(0x2c000));
    CHECK(plan.addresses[2] - plan.addresses[0] + plan.sizes[2] <=
          plan.sizes[0]);
    for (unsigned i = 0; i < CANDS; i++) {
        uint64_t bus = little(reg.data + i * 16);
        CHECK(plan.sizes[i] == sizes[i]);
        CHECK(plan.sizes[i] == little(reg.data + i * 16 + 8));
        CHECK(plan.addresses[i] == bus + ARMIO_PARENT);
        /* Every window is inside /arm-io/disp0 reg[4], which is why the trace
         * apertures must skip that window when this model owns these. */
        CHECK(plan.addresses[i] >= UINT64_C(0x412800000));
        CHECK(plan.addresses[i] + plan.sizes[i] <= UINT64_C(0x413000000));
    }
    CHECK(strcmp(apple_modern_dcp_asc_window_name(0), "wrapper") == 0);
    CHECK(strcmp(apple_modern_dcp_asc_window_name(1), "core") == 0);
    CHECK(strcmp(apple_modern_dcp_asc_window_name(2), "wrapper-alias") == 0);
    CHECK(strcmp(apple_modern_dcp_asc_window_name(CANDS), "?") == 0);

    /* No-device oracle: the SERVED tree has no compatible on /arm-io/dcp, so
     * no AppleASCWrapV6 can exist and the model must refuse to map. */
    CHECK(!apple_modern_dcp_asc_plan_build(served, DRAM_BASE, DRAM_SIZE, NULL,
                                           0, &plan, &error));
    clear_error(&error);

    /* An exclusion over the wrapper window is refused, not silently dropped. */
    exclusion = (AppleModernAddressRange){plan.addresses[0] ?
        plan.addresses[0] : UINT64_C(0x412e00000), 0x1000};
    CHECK(!apple_modern_dcp_asc_plan_build(restored, DRAM_BASE, DRAM_SIZE,
                                           &exclusion, 1, &plan, &error));
    clear_error(&error);
    /* An empty or wrapping exclusion is refused. */
    exclusion = (AppleModernAddressRange){0x412e00000, 0};
    CHECK(!apple_modern_dcp_asc_plan_build(restored, DRAM_BASE, DRAM_SIZE,
                                           &exclusion, 1, &plan, &error));
    clear_error(&error);
    exclusion = (AppleModernAddressRange){UINT64_MAX, 2};
    CHECK(!apple_modern_dcp_asc_plan_build(restored, DRAM_BASE, DRAM_SIZE,
                                           &exclusion, 1, &plan, &error));
    clear_error(&error);
    /* DRAM over the windows is refused. */
    CHECK(!apple_modern_dcp_asc_plan_build(restored, UINT64_C(0x400000000),
                                           UINT64_C(0x40000000), NULL, 0,
                                           &plan, &error));
    clear_error(&error);
    /* An empty DRAM extent is refused. */
    CHECK(!apple_modern_dcp_asc_plan_build(restored, DRAM_BASE, 0, NULL, 0,
                                           &plan, &error));
    clear_error(&error);
    /* A NULL output and an aliasing output are refused. */
    CHECK(!apple_modern_dcp_asc_plan_build(restored, DRAM_BASE, DRAM_SIZE,
                                           NULL, 0, NULL, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_asc_plan_build(
              (AppleModernBlob){(const uint8_t *)&plan, sizeof(plan)},
              DRAM_BASE, DRAM_SIZE, NULL, 0, &plan, &error));
    clear_error(&error);
    /* A missing exclusion array with a nonzero count is refused. */
    CHECK(!apple_modern_dcp_asc_plan_build(restored, DRAM_BASE, DRAM_SIZE,
                                           NULL, 1, &plan, &error));
    clear_error(&error);

    /*
     * The attested-size oracle, which is what keeps the model off a part it
     * was not derived from: change reg[1]'s size from the attested 0x4000 and
     * the build is REFUSED rather than mapping a window of the wrong length.
     */
    mutated = malloc(restored.size);
    CHECK(mutated != NULL);
    memcpy(mutated, restored.data, restored.size);
    {
        AppleModernBlob mreg;
        size_t offset;
        Error *e = NULL;
        CHECK(apple_modern_adt_property(
                  (AppleModernBlob){mutated, restored.size}, "/arm-io/dcp",
                  "reg", &mreg, &e));
        CHECK(e == NULL);
        offset = (size_t)(mreg.data - mutated);
        for (unsigned w = 0; w < CANDS; w++) {
            uint8_t saved[8];
            memcpy(saved, mutated + offset + w * 16 + 8, 8);
            mutated[offset + w * 16 + 8] ^= 0x10;
            CHECK(!apple_modern_dcp_asc_plan_build(
                      (AppleModernBlob){mutated, restored.size}, DRAM_BASE,
                      DRAM_SIZE, NULL, 0, &plan, &error));
            clear_error(&error);
            memcpy(mutated + offset + w * 16 + 8, saved, 8);
        }
        /* With every size restored the build succeeds again, so the oracle
         * above failed for the size and not for some side effect. */
        CHECK(apple_modern_dcp_asc_plan_build(
                  (AppleModernBlob){mutated, restored.size}, DRAM_BASE,
                  DRAM_SIZE, NULL, 0, &plan, &error));
        CHECK(error == NULL);
        /* A bus address outside /arm-io ranges is refused. */
        {
            uint8_t saved[8];
            memcpy(saved, mutated + offset, 8);
            mutated[offset + 7] = 0xff;
            CHECK(!apple_modern_dcp_asc_plan_build(
                      (AppleModernBlob){mutated, restored.size}, DRAM_BASE,
                      DRAM_SIZE, NULL, 0, &plan, &error));
            clear_error(&error);
            memcpy(mutated + offset, saved, 8);
        }
    }
    free(mutated);
}

static void check_modes(void)
{
    unsigned mode = 42;
    CHECK(apple_modern_dcp_asc_mode(APPLE_MODERN_DCP_ASC_MODE_LOADED, &mode));
    CHECK(mode == APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED);
    CHECK(apple_modern_dcp_asc_mode(APPLE_MODERN_DCP_ASC_MODE_ABSENT, &mode));
    CHECK(mode == APPLE_MODERN_DCP_ASC_FIRMWARE_ABSENT);
    CHECK(!apple_modern_dcp_asc_mode("on", &mode));
    CHECK(!apple_modern_dcp_asc_mode("", &mode));
    CHECK(!apple_modern_dcp_asc_mode(NULL, &mode));
    CHECK(!apple_modern_dcp_asc_mode(APPLE_MODERN_DCP_ASC_MODE_LOADED, NULL));
}

static void check_core(void)
{
    AppleModernDcpAscCore core, copy;
    uint64_t value;

    /* The one attested predicate, both ways. */
    apple_modern_dcp_asc_core_reset(&core, APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_CORE, 0, 8,
                                   &value);
    CHECK((value & 1) == 1);
    CHECK(core.firmware_bit_reads == 1);
    CHECK(core.first_unmodelled == 0);
    apple_modern_dcp_asc_core_reset(&core, APPLE_MODERN_DCP_ASC_FIRMWARE_ABSENT);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_CORE, 0, 8,
                                   &value);
    CHECK((value & 1) == 0);
    CHECK(core.firmware_bit_reads == 1);
    CHECK(core.first_unmodelled == 0);
    /* Any other core offset is undecoded: zero, recorded, and flagged. */
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_CORE, 8, 8,
                                   &value);
    CHECK(value == 0);
    CHECK(core.first_unmodelled == 2);

    apple_modern_dcp_asc_core_reset(&core, APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED);
    /* idle-ctrl-check word and IDLE_STATUS before any RUN. */
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x40, 4,
                                   &value);
    CHECK(value == 1);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8000,
                                   4, &value);
    CHECK(value == 3);
    /* CPU_CTRL round trip, and RUN makes IDLE_STATUS report running. */
    apple_modern_dcp_asc_core_write(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x44, 4,
                                    0x10);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x44, 4,
                                   &value);
    CHECK(value == 0x10);
    CHECK(core.running);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8000,
                                   4, &value);
    CHECK(value == 0);
    /* A CPU_CTRL write without RUN does not clear running. */
    apple_modern_dcp_asc_core_write(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x44, 4,
                                    0);
    CHECK(core.running);
    /* CPU_STATUS is declared to report nothing. */
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x48, 4,
                                   &value);
    CHECK(value == 0);
    /* Both mailbox CONTROL words report EMPTY and zero occupancy. */
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8110,
                                   4, &value);
    CHECK(value == (UINT64_C(1) << 17));
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8114,
                                   4, &value);
    CHECK(value == (UINT64_C(1) << 17));
    /* The receive frame yields zeros and is counted as a poll. */
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8830,
                                   8, &value);
    CHECK(value == 0);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8838,
                                   8, &value);
    CHECK(value == 0 && core.mailbox_recv_polls == 2);
    /* Sends are counted and discarded; doorbells are counted. */
    apple_modern_dcp_asc_core_write(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8800,
                                    8, 0x1122334455667788);
    apple_modern_dcp_asc_core_write(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8808,
                                    8, 0);
    CHECK(core.mailbox_sends == 2);
    apple_modern_dcp_asc_core_write(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x1004,
                                    4, 1);
    apple_modern_dcp_asc_core_write(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x1014,
                                    4, 1);
    CHECK(core.doorbells == 2);
    /* Every dump word is decoded and answers zero; a misaligned one is not. */
    for (unsigned k = 0; k < 128; k++) {
        apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER,
                                       0x8180 + 4 * k, 4, &value);
        CHECK(value == 0);
    }
    CHECK(core.first_unmodelled == 0);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8181,
                                   1, &value);
    CHECK(value == 0 && core.first_unmodelled == core.record_count);
    CHECK(core.records[core.first_unmodelled - 1].modelled == 0);
    /* A read is truncated to its access size. */
    apple_modern_dcp_asc_core_reset(&core, APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_WRAPPER, 0x8110,
                                   1, &value);
    CHECK(value == 0);

    /* Counters, de-duplication and the record bound. */
    apple_modern_dcp_asc_core_reset(&core, APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED);
    /* Offsets from 0x100 up, so none of them is the decoded core offset 0. */
    for (unsigned i = 0; i < RECS + 64; i++) {
        apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_CORE,
                                       0x100 + i * 8, 8, &value);
        CHECK(value == 0);
    }
    CHECK(core.record_count == RECS);
    CHECK(core.dropped == 64);
    CHECK(core.reads == RECS + 64);
    CHECK(core.window_reads[APPLE_MODERN_DCP_ASC_CORE] == RECS + 64);
    CHECK(core.writes == 0);
    for (unsigned i = 0; i < 8; i++) {
        apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_CORE,
                                       0x100 + i * 8, 8, &value);
    }
    CHECK(core.record_count == RECS && core.dropped == 64);
    CHECK(apple_modern_dcp_asc_core_recorded(&core, APPLE_MODERN_DCP_ASC_CORE,
                                             0x100, false));
    CHECK(!apple_modern_dcp_asc_core_recorded(&core, APPLE_MODERN_DCP_ASC_CORE,
                                              0x100, true));

    /* An out-of-range window is ignored and leaves the core byte-identical. */
    copy = core;
    apple_modern_dcp_asc_core_read(&core, MAPPED, 0, 8, &value);
    apple_modern_dcp_asc_core_write(&core, MAPPED, 0, 8, 1);
    CHECK(value == 0);
    CHECK(!memcmp(&copy, &core, sizeof(core)));
    /* A NULL core never dereferences. */
    apple_modern_dcp_asc_core_read(NULL, 0, 0, 8, &value);
    apple_modern_dcp_asc_core_write(NULL, 0, 0, 8, 0);
    apple_modern_dcp_asc_core_reset(NULL, 0);
    CHECK(!apple_modern_dcp_asc_core_recorded(NULL, 0, 0, false));
    CHECK(value == 0);
    /* A read with no destination is accepted and still counted. */
    apple_modern_dcp_asc_core_reset(&core, APPLE_MODERN_DCP_ASC_FIRMWARE_LOADED);
    apple_modern_dcp_asc_core_read(&core, APPLE_MODERN_DCP_ASC_CORE, 0, 8, NULL);
    CHECK(core.reads == 1 && core.firmware_bit_reads == 1);
}

/*
 * The served tree and the stock tree carry BYTE-IDENTICAL /arm-io/dcp "reg"
 * and /arm-io "ranges"; the only difference the model depends on is the
 * stripped "compatible".  That is what lets the stock tree stand in for the
 * tree the loader serves under a disp0-probe arm that restores it, and it is
 * asserted here rather than assumed.
 */
static void check_trees_agree(AppleModernBlob served, AppleModernBlob stock)
{
    AppleModernBlob a, b;
    Error *error = NULL;

    CHECK(apple_modern_adt_property(served, "/arm-io/dcp", "reg", &a, &error));
    CHECK(error == NULL);
    CHECK(apple_modern_adt_property(stock, "/arm-io/dcp", "reg", &b, &error));
    CHECK(error == NULL);
    CHECK(a.size == b.size && a.size == CANDS * 16);
    CHECK(!memcmp(a.data, b.data, a.size));
    CHECK(apple_modern_adt_property(served, "/arm-io", "ranges", &a, &error));
    CHECK(error == NULL);
    CHECK(apple_modern_adt_property(stock, "/arm-io", "ranges", &b, &error));
    CHECK(error == NULL);
    CHECK(a.size == b.size && !memcmp(a.data, b.data, a.size));
    /* The served tree really is missing the compatible, and the stock tree
     * really does carry the exact bytes the disp0-probe arms restore. */
    CHECK(!apple_modern_adt_property(served, "/arm-io/dcp", "compatible", &a,
                                     &error));
    clear_error(&error);
    CHECK(apple_modern_adt_property(stock, "/arm-io/dcp", "compatible", &b,
                                    &error));
    CHECK(error == NULL);
    CHECK(b.size == sizeof("iop,ascwrap-v6"));
    CHECK(!memcmp(b.data, "iop,ascwrap-v6", b.size));
    /* The three mapper nodes dcp-mapper restores exist in both trees and carry
     * the stock compatible only in the stock one. */
    {
        static const char *const mappers[] = {
            "/arm-io/dart-dcp/mapper-dcp", "/arm-io/dart-disp0/mapper-disp0",
            "/arm-io/dart-disp0/mapper-disp0-piodma"};
        for (unsigned i = 0; i < 3; i++) {
            CHECK(apple_modern_adt_property(served, mappers[i], "name", &a,
                                            &error));
            CHECK(error == NULL && a.size >= 2);
            CHECK(!apple_modern_adt_property(served, mappers[i], "compatible",
                                             &a, &error));
            clear_error(&error);
            CHECK(apple_modern_adt_property(stock, mappers[i], "compatible",
                                            &b, &error));
            CHECK(error == NULL && b.size == sizeof("iommu-mapper"));
            CHECK(!memcmp(b.data, "iommu-mapper", b.size));
        }
    }
}

int main(int argc, char **argv)
{
    uint8_t *served_data, *stock_data;
    size_t served_size, stock_size;
    AppleModernBlob served, stock;

    if (argc != 3) {
        fprintf(stderr, "usage: %s SERVED-ADT STOCK-ADT\n", argv[0]);
        return 2;
    }
    served_data = slurp(argv[1], &served_size);
    stock_data = slurp(argv[2], &stock_size);
    served = (AppleModernBlob){served_data, served_size};
    stock = (AppleModernBlob){stock_data, stock_size};

    check_modes();
    check_trees_agree(served, stock);
    check_plan(stock, served);
    check_core();

    printf("{\"passed\": true, \"checks\": %u, \"firmware_executed\": false,"
           " \"guest_executed\": false, \"candidates\": %u,"
           " \"mapped\": %u}\n", checks, CANDS, MAPPED);
    free(served_data);
    free(stock_data);
    return 0;
}
