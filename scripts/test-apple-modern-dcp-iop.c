/* /arm-io/dcp RTKit-peer qualification (dcp-iop): the endpoint-name
 * derivation, the two declared ADT flags, and a plan that refuses anything
 * which is not the attested ASC v6 wrapper layout with a matchable
 * AppleASCWrapV6 node and a matchable RTBuddy nub.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-dcp-iop.h"

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

#define ARMIO_PARENT UINT64_C(0x210000000)
#define DRAM_BASE (UINT64_C(1) << 40)
#define DRAM_SIZE (UINT64_C(8) << 30)
/* Attested stock /arm-io/dcp interrupts, in ADT order. */
static const uint32_t stock_interrupts[APPLE_MODERN_DCP_IOP_IRQS] = {
    0x2a8, 0x2a7, 0x2aa, 0x2a9
};

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

static uint64_t little64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static void check_modes(void)
{
    unsigned mode = 0xdead;

    CHECK(apple_modern_dcp_iop_mode(APPLE_MODERN_DCP_IOP_NAME_V6, &mode) &&
          mode == APPLE_MODERN_DCP_IOP_MODE_V6);
    CHECK(apple_modern_dcp_iop_mode(APPLE_MODERN_DCP_IOP_NAME_V4, &mode) &&
          mode == APPLE_MODERN_DCP_IOP_MODE_V4);
    CHECK(apple_modern_dcp_iop_mode(APPLE_MODERN_DCP_IOP_NAME_V6_QUIESCED,
                                    &mode) &&
          mode == APPLE_MODERN_DCP_IOP_MODE_V6_QUIESCED);
    CHECK(apple_modern_dcp_iop_mode(APPLE_MODERN_DCP_IOP_NAME_FLAGS, &mode) &&
          mode == APPLE_MODERN_DCP_IOP_MODE_FLAGS_ONLY);
    CHECK(!apple_modern_dcp_iop_mode("", &mode));
    CHECK(!apple_modern_dcp_iop_mode("V6", &mode));
    CHECK(!apple_modern_dcp_iop_mode("v6 ", &mode));
    CHECK(!apple_modern_dcp_iop_mode("on", &mode));
    CHECK(!apple_modern_dcp_iop_mode(NULL, &mode));
    CHECK(!apple_modern_dcp_iop_mode(APPLE_MODERN_DCP_IOP_NAME_V6, NULL));

    /* Exactly which modes create a peer, and which serve the two ADT flags. */
    CHECK(apple_modern_dcp_iop_mode_has_peer(APPLE_MODERN_DCP_IOP_MODE_V6));
    CHECK(apple_modern_dcp_iop_mode_has_peer(APPLE_MODERN_DCP_IOP_MODE_V4));
    CHECK(apple_modern_dcp_iop_mode_has_peer(
              APPLE_MODERN_DCP_IOP_MODE_V6_QUIESCED));
    CHECK(!apple_modern_dcp_iop_mode_has_peer(
              APPLE_MODERN_DCP_IOP_MODE_FLAGS_ONLY));
    CHECK(apple_modern_dcp_iop_mode_has_flags(APPLE_MODERN_DCP_IOP_MODE_V6));
    CHECK(apple_modern_dcp_iop_mode_has_flags(APPLE_MODERN_DCP_IOP_MODE_V4));
    CHECK(!apple_modern_dcp_iop_mode_has_flags(
              APPLE_MODERN_DCP_IOP_MODE_V6_QUIESCED));
    CHECK(apple_modern_dcp_iop_mode_has_flags(
              APPLE_MODERN_DCP_IOP_MODE_FLAGS_ONLY));
    CHECK(apple_modern_dcp_iop_mode("v6-prestarted", &mode) &&
          mode == APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED);
    CHECK(apple_modern_dcp_iop_mode_has_peer(
              APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED));
    CHECK(apple_modern_dcp_iop_mode_has_flags(
              APPLE_MODERN_DCP_IOP_MODE_V6_PRESTARTED));
    /* v6-quiesced is the one arm that differs from v6 only in the flags. */
    CHECK(apple_modern_dcp_iop_mode_has_peer(APPLE_MODERN_DCP_IOP_MODE_V6) ==
          apple_modern_dcp_iop_mode_has_peer(
              APPLE_MODERN_DCP_IOP_MODE_V6_QUIESCED));
    CHECK(apple_modern_dcp_iop_mode_has_flags(APPLE_MODERN_DCP_IOP_MODE_V6) !=
          apple_modern_dcp_iop_mode_has_flags(
              APPLE_MODERN_DCP_IOP_MODE_V6_QUIESCED));
}

/* The two flags are DECLARED additions: neither tree carries either name. */
static void check_overrides(AppleModernBlob served, AppleModernBlob stock)
{
    size_t count = 0;
    const AppleModernAdtOverride *flags =
        apple_modern_dcp_iop_overrides(&count);
    const char *const names[] = {"pre-loaded", "running"};

    CHECK(flags != NULL && count == 2);
    CHECK(apple_modern_dcp_iop_overrides(NULL) == flags);
    for (size_t i = 0; i < count; i++) {
        AppleModernBlob found;
        Error *error = NULL;
        CHECK(strcmp(flags[i].path, "/arm-io/dcp/iop-dcp-nub") == 0);
        CHECK(strcmp(flags[i].name, names[i]) == 0);
        CHECK(flags[i].size == 4);
        CHECK(flags[i].value[0] == 1 && flags[i].value[1] == 0 &&
              flags[i].value[2] == 0 && flags[i].value[3] == 0);
        CHECK(!apple_modern_adt_property(stock, flags[i].path, flags[i].name,
                                         &found, &error));
        clear_error(&error);
        CHECK(!apple_modern_adt_property(served, flags[i].path, flags[i].name,
                                         &found, &error));
        clear_error(&error);
    }
    /* The node they target exists in both trees, so the override lands. */
    {
        AppleModernBlob found;
        Error *error = NULL;
        CHECK(apple_modern_adt_property(stock, "/arm-io/dcp/iop-dcp-nub",
                                        "name", &found, &error));
        CHECK(error == NULL);
        CHECK(apple_modern_adt_property(served, "/arm-io/dcp/iop-dcp-nub",
                                        "name", &found, &error));
        CHECK(error == NULL);
    }
}

/*
 * The whole module turns on one arithmetic: Apple's nub name index is
 * raw - 31, so name index 24 (what AppleDCPLinkServiceSoC matches) is raw 55
 * and user-relative 23.  These checks pin the macros and the formatter to it.
 */
static void check_endpoint_names(void)
{
    char name[APPLE_MODERN_DCP_IOP_ROLE_MAX + 16];
    char small[8];
    unsigned index = 0;
    Error *error = NULL;

    CHECK(APPLE_MODERN_DCP_IOP_EP_USER_START == 32u);
    CHECK(APPLE_MODERN_DCP_IOP_EP_NAME_BIAS == 31u);
    CHECK(APPLE_MODERN_DCP_IOP_EP_NAME_INDEX == 24u);
    CHECK(APPLE_MODERN_DCP_IOP_EP_IOMFB == 55u);
    CHECK(APPLE_MODERN_DCP_IOP_EP_IOMFB == 0x37u);
    /* The user-relative index the board passes to the RTKit layer. */
    CHECK(APPLE_MODERN_DCP_IOP_EP_IOMFB -
          APPLE_MODERN_DCP_IOP_EP_USER_START == 23u);

    CHECK(apple_modern_dcp_iop_endpoint_name(
              "DCP", APPLE_MODERN_DCP_IOP_EP_IOMFB, name, sizeof(name), &index,
              &error));
    CHECK(error == NULL);
    CHECK(strcmp(name, APPLE_MODERN_DCP_IOP_NUB_NAME) == 0);
    CHECK(strcmp(name, "DCPEndpoint24") == 0);
    CHECK(index == APPLE_MODERN_DCP_IOP_EP_NAME_INDEX);

    /* The in-tree SMC precedent: user-relative 0 is raw 32 is SMCEndpoint1. */
    CHECK(apple_modern_dcp_iop_endpoint_name(
              "SMC", APPLE_MODERN_DCP_IOP_EP_USER_START, name, sizeof(name),
              &index, &error));
    CHECK(error == NULL && strcmp(name, "SMCEndpoint1") == 0 && index == 1);
    /* Public Asahi's SYSTEM_ENDPOINT 0x20 is DCPEndpoint1 under the same rule. */
    CHECK(apple_modern_dcp_iop_endpoint_name("DCP", 0x20, name, sizeof(name),
                                             &index, &error));
    CHECK(error == NULL && strcmp(name, "DCPEndpoint1") == 0 && index == 1);
    /* AppleSPU's AOPEndpoint32 is the top of RTKit block 1 (raw 63). */
    CHECK(apple_modern_dcp_iop_endpoint_name("AOP", 63, name, sizeof(name),
                                             &index, &error));
    CHECK(error == NULL && strcmp(name, "AOPEndpoint32") == 0 && index == 32);
    CHECK(apple_modern_dcp_iop_endpoint_name("DCPEXT", 55, name, sizeof(name),
                                             &index, &error));
    CHECK(error == NULL && strcmp(name, "DCPEXTEndpoint24") == 0);

    /* An RTKit control channel gets no nub, so it is refused, not named. */
    for (unsigned raw = 0; raw < APPLE_MODERN_DCP_IOP_EP_USER_START; raw++) {
        CHECK(!apple_modern_dcp_iop_endpoint_name("DCP", raw, name,
                                                  sizeof(name), &index,
                                                  &error));
        clear_error(&error);
        CHECK(name[0] == '\0' && index == 0);
    }
    /* A raw endpoint beyond one byte is refused. */
    CHECK(!apple_modern_dcp_iop_endpoint_name("DCP", 256, name, sizeof(name),
                                              &index, &error));
    clear_error(&error);
    CHECK(apple_modern_dcp_iop_endpoint_name("DCP", 255, name, sizeof(name),
                                             &index, &error));
    CHECK(error == NULL && index == 224);
    /* Role refusals: empty, overlong, and not printable ASCII. */
    CHECK(!apple_modern_dcp_iop_endpoint_name("", 55, name, sizeof(name),
                                              &index, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_endpoint_name(
              "0123456789abcdef", 55, name, sizeof(name), &index, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_endpoint_name("DC P", 55, name, sizeof(name),
                                              &index, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_endpoint_name("DC\x7f", 55, name, sizeof(name),
                                              &index, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_endpoint_name(NULL, 55, name, sizeof(name),
                                              &index, &error));
    clear_error(&error);
    /* A buffer that cannot hold the name is refused, not truncated. */
    CHECK(!apple_modern_dcp_iop_endpoint_name("DCP", 55, small, sizeof(small),
                                              &index, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_endpoint_name("DCP", 55, NULL, sizeof(name),
                                              &index, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_endpoint_name("DCP", 55, name, 0, &index,
                                              &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_endpoint_name("DCP", 55, name, sizeof(name),
                                              NULL, &error));
    clear_error(&error);
}

static size_t property_offset(AppleModernBlob tree, const char *path,
                              const char *name, size_t *size)
{
    AppleModernBlob found;
    Error *error = NULL;
    CHECK(apple_modern_adt_property(tree, path, name, &found, &error));
    CHECK(error == NULL);
    *size = found.size;
    return (size_t)(found.data - tree.data);
}

static void check_plan(AppleModernBlob stock, AppleModernBlob served)
{
    AppleModernDcpIopPlan plan;
    AppleModernAddressRange exclusion;
    AppleModernBlob reg;
    Error *error = NULL;
    uint8_t *mutated;
    size_t offset, size;

    /* Positive: the stock tree yields the attested wrapper window and role. */
    CHECK(apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE, NULL, 0,
                                          APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan,
                                          &error));
    CHECK(error == NULL);
    CHECK(plan.wrapper_size == APPLE_MODERN_DCP_IOP_WRAPPER_SIZE);
    CHECK(plan.wrapper_size == UINT64_C(0x88000));
    CHECK(apple_modern_adt_property(stock, "/arm-io/dcp", "reg", &reg, &error));
    CHECK(error == NULL && reg.size == 48);
    CHECK(plan.wrapper_address == little64(reg.data) + ARMIO_PARENT);
    CHECK(plan.wrapper_address == UINT64_C(0x412e00000));
    CHECK(strcmp(plan.role, "DCP") == 0);
    CHECK(strcmp(plan.nub_name, "DCPEndpoint24") == 0);
    CHECK(plan.endpoint_raw == 55 && plan.endpoint_user == 23);
    for (unsigned i = 0; i < APPLE_MODERN_DCP_IOP_IRQS; i++) {
        CHECK(plan.interrupts[i] == stock_interrupts[i]);
    }

    /* No-device oracle: the SERVED tree strips /arm-io/dcp "compatible", so no
     * AppleASCWrapV6 can exist and the peer must refuse to map. */
    CHECK(!apple_modern_dcp_iop_plan_build(served, DRAM_BASE, DRAM_SIZE, NULL,
                                           0, APPLE_MODERN_DCP_IOP_EP_IOMFB,
                                           &plan, &error));
    clear_error(&error);

    /* A control-channel endpoint is refused by the plan too. */
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE, NULL, 0,
                                           0, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE, NULL, 0,
                                           31, &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE, NULL, 0,
                                           4096, &plan, &error));
    clear_error(&error);

    /* An exclusion over the wrapper window is refused, not silently dropped. */
    exclusion = (AppleModernAddressRange){UINT64_C(0x412e00000), 0x1000};
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE,
                                           &exclusion, 1,
                                           APPLE_MODERN_DCP_IOP_EP_IOMFB,
                                           &plan, &error));
    clear_error(&error);
    /* An exclusion elsewhere is accepted. */
    exclusion = (AppleModernAddressRange){UINT64_C(0x200000000), 0x1000};
    CHECK(apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE,
                                          &exclusion, 1,
                                          APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan,
                                          &error));
    CHECK(error == NULL);
    /* Empty and wrapping exclusions are refused. */
    exclusion = (AppleModernAddressRange){UINT64_C(0x412e00000), 0};
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE,
                                           &exclusion, 1,
                                           APPLE_MODERN_DCP_IOP_EP_IOMFB,
                                           &plan, &error));
    clear_error(&error);
    exclusion = (AppleModernAddressRange){UINT64_MAX, 2};
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE,
                                           &exclusion, 1,
                                           APPLE_MODERN_DCP_IOP_EP_IOMFB,
                                           &plan, &error));
    clear_error(&error);
    /* A missing exclusion array with a nonzero count is refused. */
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE, NULL, 1,
                                           APPLE_MODERN_DCP_IOP_EP_IOMFB,
                                           &plan, &error));
    clear_error(&error);
    /* Too many exclusions is refused. */
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE,
                                           &exclusion,
                                           APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1,
                                           APPLE_MODERN_DCP_IOP_EP_IOMFB,
                                           &plan, &error));
    clear_error(&error);
    /* DRAM over the window, and an empty DRAM extent, are refused. */
    CHECK(!apple_modern_dcp_iop_plan_build(stock, UINT64_C(0x400000000),
                                           UINT64_C(0x40000000), NULL, 0,
                                           APPLE_MODERN_DCP_IOP_EP_IOMFB,
                                           &plan, &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, 0, NULL, 0,
                                           APPLE_MODERN_DCP_IOP_EP_IOMFB,
                                           &plan, &error));
    clear_error(&error);
    /* A NULL output and an aliasing output are refused. */
    CHECK(!apple_modern_dcp_iop_plan_build(stock, DRAM_BASE, DRAM_SIZE, NULL, 0,
                                           APPLE_MODERN_DCP_IOP_EP_IOMFB, NULL,
                                           &error));
    clear_error(&error);
    CHECK(!apple_modern_dcp_iop_plan_build(
              (AppleModernBlob){(const uint8_t *)&plan, sizeof(plan)},
              DRAM_BASE, DRAM_SIZE, NULL, 0, APPLE_MODERN_DCP_IOP_EP_IOMFB,
              &plan, &error));
    clear_error(&error);

    mutated = malloc(stock.size);
    CHECK(mutated != NULL);

    /* Attested-size oracle: flip reg[0]'s size and the build is REFUSED. */
    memcpy(mutated, stock.data, stock.size);
    offset = property_offset((AppleModernBlob){mutated, stock.size},
                             "/arm-io/dcp", "reg", &size);
    CHECK(size == 48);
    mutated[offset + 8] ^= 0x10;
    CHECK(!apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
              stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
              APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
    clear_error(&error);
    mutated[offset + 8] ^= 0x10;
    CHECK(apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
              stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
              APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
    CHECK(error == NULL);
    /* A bus address outside /arm-io ranges is refused. */
    mutated[offset + 7] ^= 0x40;
    CHECK(!apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
              stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
              APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
    clear_error(&error);
    mutated[offset + 7] ^= 0x40;

    /* AppleASCWrapV6 oracle: break /arm-io/dcp's compatible CONTENT. */
    offset = property_offset((AppleModernBlob){mutated, stock.size},
                             "/arm-io/dcp", "compatible", &size);
    CHECK(size == sizeof("iop,ascwrap-v6"));
    mutated[offset] = 'X';
    CHECK(!apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
              stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
              APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
    clear_error(&error);
    mutated[offset] = 'i';

    /* RTBuddy oracle: break the nub's compatible CONTENT. */
    offset = property_offset((AppleModernBlob){mutated, stock.size},
                             "/arm-io/dcp/iop-dcp-nub", "compatible", &size);
    CHECK(size == sizeof("iop-nub,rtbuddy-v2"));
    mutated[offset] = 'X';
    CHECK(!apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
              stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
              APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
    clear_error(&error);
    mutated[offset] = 'i';

    /* Role oracles: an unterminated role, and a role that is not the ADT's. */
    offset = property_offset((AppleModernBlob){mutated, stock.size},
                             "/arm-io/dcp", "role", &size);
    CHECK(size == 4);
    {
        uint8_t saved[4];
        memcpy(saved, mutated + offset, 4);
        memset(mutated + offset, 'A', 4);
        CHECK(!apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
                  stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
                  APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
        clear_error(&error);
        /* A different, valid role changes the nub name, which is the whole
         * point of reporting it: a wrong role yields a nub nobody matches. */
        memcpy(mutated + offset, "ABC\0", 4);
        CHECK(apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
                  stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
                  APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
        CHECK(error == NULL && strcmp(plan.nub_name, "ABCEndpoint24") == 0);
        memcpy(mutated + offset, saved, 4);
    }

    /* Interrupt oracles: a zero line, and two identical lines. */
    offset = property_offset((AppleModernBlob){mutated, stock.size},
                             "/arm-io/dcp", "interrupts", &size);
    CHECK(size == APPLE_MODERN_DCP_IOP_IRQS * 4);
    {
        uint8_t saved[APPLE_MODERN_DCP_IOP_IRQS * 4];
        memcpy(saved, mutated + offset, sizeof(saved));
        memset(mutated + offset, 0, 4);
        CHECK(!apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
                  stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
                  APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
        clear_error(&error);
        memcpy(mutated + offset, saved, sizeof(saved));
        memcpy(mutated + offset + 4, mutated + offset, 4);
        CHECK(!apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
                  stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
                  APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
        clear_error(&error);
        memcpy(mutated + offset, saved, sizeof(saved));
        CHECK(apple_modern_dcp_iop_plan_build((AppleModernBlob){mutated,
                  stock.size}, DRAM_BASE, DRAM_SIZE, NULL, 0,
                  APPLE_MODERN_DCP_IOP_EP_IOMFB, &plan, &error));
        CHECK(error == NULL);
    }
    free(mutated);
}

/*
 * The two trees must agree on everything this model reads except the stripped
 * "compatible" values, because that is what lets the stock tree stand in for
 * the tree the loader actually serves with disp0-probe restoring them.
 */
static void check_trees_agree(AppleModernBlob served, AppleModernBlob stock)
{
    static const char *const same[][2] = {
        {"/arm-io/dcp", "reg"}, {"/arm-io/dcp", "role"},
        {"/arm-io/dcp", "interrupts"}, {"/arm-io", "ranges"},
    };
    for (unsigned i = 0; i < sizeof(same) / sizeof(same[0]); i++) {
        AppleModernBlob a, b;
        Error *error = NULL;
        CHECK(apple_modern_adt_property(served, same[i][0], same[i][1], &a,
                                        &error));
        CHECK(error == NULL);
        CHECK(apple_modern_adt_property(stock, same[i][0], same[i][1], &b,
                                        &error));
        CHECK(error == NULL);
        CHECK(a.size == b.size && memcmp(a.data, b.data, a.size) == 0);
    }
    /* And the served tree really is missing both compatibles. */
    {
        AppleModernBlob found;
        Error *error = NULL;
        CHECK(!apple_modern_adt_property(served, "/arm-io/dcp", "compatible",
                                         &found, &error));
        clear_error(&error);
        CHECK(!apple_modern_adt_property(served, "/arm-io/dcp/iop-dcp-nub",
                                         "compatible", &found, &error));
        clear_error(&error);
        CHECK(apple_modern_adt_property(stock, "/arm-io/dcp", "compatible",
                                        &found, &error));
        CHECK(error == NULL);
        CHECK(apple_modern_adt_property(stock, "/arm-io/dcp/iop-dcp-nub",
                                        "compatible", &found, &error));
        CHECK(error == NULL);
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
    check_endpoint_names();
    check_overrides(served, stock);
    check_trees_agree(served, stock);
    check_plan(stock, served);

    printf("{\"passed\": true, \"checks\": %u, \"firmware_executed\": false,"
           " \"guest_executed\": false, \"endpoint_raw\": %u,"
           " \"endpoint_user\": %u, \"nub_name\": \"%s\"}\n", checks,
           APPLE_MODERN_DCP_IOP_EP_IOMFB,
           APPLE_MODERN_DCP_IOP_EP_IOMFB - APPLE_MODERN_DCP_IOP_EP_USER_START,
           APPLE_MODERN_DCP_IOP_NUB_NAME);
    free(served_data);
    free(stock_data);
    return 0;
}
