/* ADT property overrides and the measured pmgr voltage-states profile.
 * Production-source test, no guest launch.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *   -fsanitize=address,undefined hw/arm/apple-silicon/modern-boot-layout.c \
 *   hw/arm/apple-silicon/modern-boot-metadata.c \
 *   hw/arm/apple-silicon/modern-pmgr-voltage.c \
 *   scripts/test-apple-modern-pmgr-voltage.c -o /tmp/test-pmgr-voltage \
 *   && /tmp/test-pmgr-voltage [components-dir]
 */
#define METADATA_REGRESSION_MAIN metadata_regression_main
#include "test-apple-modern-boot-metadata.c"
#include "hw/arm/apple-silicon/modern-pmgr-voltage.h"

static unsigned voltage_checks;

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}
#define VCHECK(c) do { voltage_checks++; if (!(c)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

/* Independent bounded ADT walk: counts nodes/properties and can enumerate
 * one node's properties. It shares no code with the production serializer. */
typedef struct Walk {
    const uint8_t *data;
    size_t size, cursor;
    unsigned nodes, props;
    const char *want_path;
    char names[256][32];
    const uint8_t *values[256];
    uint32_t lengths[256];
    unsigned want_count;
} Walk;

static void walk_node(Walk *w, const char *parent, unsigned depth)
{
    uint32_t count, children;
    char name[128] = "", path[512];
    size_t begin;
    VCHECK(depth < 16 && w->cursor + 8 <= w->size);
    count = rd32(w->data + w->cursor);
    children = rd32(w->data + w->cursor + 4);
    w->cursor += 8;
    begin = w->cursor;
    w->nodes++;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p = w->data + w->cursor;
        uint32_t length;
        VCHECK(w->cursor + 36 <= w->size);
        length = rd32(p + 32) & 0x7fffffff;
        w->cursor += 36;
        VCHECK(w->cursor + ((length + 3) & ~3U) <= w->size);
        if (!strcmp((const char *)p, "name")) {
            snprintf(name, sizeof(name), "%s", (const char *)w->data + w->cursor);
        }
        w->cursor += (length + 3) & ~3U;
        w->props++;
    }
    snprintf(path, sizeof(path), "%s%s%s", depth ? parent : "", depth ? "/" : "",
             depth ? name : "");
    if (!depth) {
        snprintf(path, sizeof(path), "/");
    } else if (depth == 1) {
        snprintf(path, sizeof(path), "/%s", name);
    } else {
        snprintf(path, sizeof(path), "%s/%s", parent, name);
    }
    if (w->want_path && !strcmp(path, w->want_path)) {
        size_t c = begin;
        for (uint32_t i = 0; i < count; i++) {
            const uint8_t *p = w->data + c;
            uint32_t length = rd32(p + 32) & 0x7fffffff;
            VCHECK(w->want_count < 256);
            snprintf(w->names[w->want_count], 32, "%s", (const char *)p);
            w->values[w->want_count] = p + 36;
            w->lengths[w->want_count++] = length;
            c += 36 + ((length + 3) & ~3U);
        }
    }
    for (uint32_t i = 0; i < children; i++) {
        walk_node(w, path, depth + 1);
    }
}

static Walk adt_walk(AppleModernBlob blob, const char *want_path)
{
    Walk w = {.data = blob.data, .size = blob.size, .want_path = want_path};
    walk_node(&w, "", 0);
    VCHECK(w.cursor == blob.size);
    return w;
}

static int find_prop(const Walk *w, const char *name)
{
    for (unsigned i = 0; i < w->want_count; i++) {
        if (!strcmp(w->names[i], name)) {
            return (int)i;
        }
    }
    return -1;
}

static uint32_t le32_at(const uint8_t *p)
{
    return rd32(p);
}

static void test_override_mechanism(void)
{
    AppleModernBootInput components = metadata_fixture(), changed;
    static const uint8_t new_compatible[] = "replaced graphics";
    static const uint8_t extra[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    static const uint8_t state[] = "replaced state";
    static const AppleModernAdtOverride good[] = {
        {"/arm-io/sgx", "compatible", new_compatible, sizeof(new_compatible)},
        {"/arm-io/sgx", "voltage-test", extra, sizeof(extra)},
        {"/cpus/cpu0", "state", state, sizeof(state)},
    };
    AppleModernBootMetadataInput input = {.components = &components,
        .command_line = "-v", .command_line_length = 2, .has_mte = true}, bad;
    AppleModernBootMetadata plain = {0}, patched = {0}, again = {0};
    Error *error = NULL;
    Walk before, after, node;
    AppleModernBlob view;
    uint8_t *original = malloc(components.dtree.size);
    uint8_t big[APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES + 1] = {1};
    AppleModernAdtOverride many[APPLE_MODERN_MAX_ADT_OVERRIDES + 1];
    uint8_t *alias_storage = calloc(1, sizeof(AppleModernBootMetadata));
    VCHECK(original && alias_storage);
    memcpy(original, components.dtree.data, components.dtree.size);

    VCHECK(apple_modern_boot_metadata_build(&input, &plain, &error));
    input.overrides = good;
    input.override_count = 3;
    VCHECK(apple_modern_boot_metadata_build(&input, &patched, &error));
    VCHECK(!error);
    before = adt_walk((AppleModernBlob){plain.dtree, plain.dtree_size}, "/arm-io/sgx");
    after = adt_walk((AppleModernBlob){patched.dtree, patched.dtree_size}, "/arm-io/sgx");
    /* Two replaced properties keep the count; one appended property adds one. */
    VCHECK(before.nodes == after.nodes && after.props == before.props + 1);
    VCHECK(after.want_count == before.want_count + 1);
    view = prop_view(&patched, "/arm-io/sgx", "compatible");
    VCHECK(view.size == sizeof(new_compatible) &&
           !memcmp(view.data, new_compatible, view.size));
    view = prop_view(&patched, "/arm-io/sgx", "voltage-test");
    VCHECK(view.size == 8 && !memcmp(view.data, extra, 8));
    view = prop_view(&patched, "/cpus/cpu0", "state");
    VCHECK(view.size == sizeof(state) && !memcmp(view.data, state, view.size));
    /* Untouched properties and the node name survive byte-exactly. */
    same_property(&components, &patched, "/arm-io/sgx", "name");
    same_property(&components, &patched, "/cpus/cpu0", "name");
    same_property(&components, &patched, "/arm-io", "compatible");
    same_property(&components, &patched, "/chosen", "secure-boot");
    node = adt_walk((AppleModernBlob){patched.dtree, patched.dtree_size}, "/cpus/cpu0");
    VCHECK(find_prop(&node, "state") >= 0 && find_prop(&node, "name") >= 0);
    VCHECK(!memcmp(original, components.dtree.data, components.dtree.size));
    verify_metadata(&input, &patched);
    /* Deterministic and independent of the previous output. */
    VCHECK(apple_modern_boot_metadata_build(&input, &again, &error));
    VCHECK(again.dtree != patched.dtree && again.dtree_size == patched.dtree_size &&
           !memcmp(again.dtree, patched.dtree, patched.dtree_size));
    apple_modern_boot_metadata_clear(&again);
    /* An empty list is the same as no list. */
    bad = input; bad.override_count = 0;
    VCHECK(apple_modern_boot_metadata_build(&bad, &again, &error));
    VCHECK(again.dtree_size == plain.dtree_size &&
           !memcmp(again.dtree, plain.dtree, plain.dtree_size));
    apple_modern_boot_metadata_clear(&again);

    /* Rejections: each leaves the output clean and the input unchanged. */
    {
        static const AppleModernAdtOverride list[] =
            {{"/arm-io/missing", "x", extra, 8}};
        bad = input; bad.overrides = list; bad.override_count = 1;
        rejected_metadata("override node missing", &bad);
    }
    {
        static const AppleModernAdtOverride list[] =
            {{"/arm-io/sgx", "x", extra, 8}, {"/arm-io/sgx", "x", extra, 4}};
        bad = input; bad.overrides = list; bad.override_count = 2;
        rejected_metadata("duplicate override", &bad);
    }
    static const char *const owned[] = {"/chosen", "/chosen/memory-map", "/vram",
                                        "/arm-io/aic"};
    for (unsigned i = 0; i < 4; i++) {
        AppleModernAdtOverride list[1] = {{owned[i], "x", extra, 8}};
        bad = input; bad.overrides = list; bad.override_count = 1;
        rejected_metadata("loader-owned node", &bad);
    }
    {
        static const AppleModernAdtOverride list[] = {{"/arm-io/sgx", "name", extra, 8}};
        bad = input; bad.overrides = list; bad.override_count = 1;
        rejected_metadata("override renames node", &bad);
    }
    {
        static const AppleModernAdtOverride zero[] = {{"/arm-io/sgx", "x", extra, 0}};
        bad = input; bad.overrides = zero; bad.override_count = 1;
        rejected_metadata("override size zero", &bad);
        AppleModernAdtOverride huge[] = {{"/arm-io/sgx", "x", big,
                                          APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES + 1}};
        bad.overrides = huge;
        rejected_metadata("override too large", &bad);
        AppleModernAdtOverride limit[] = {{"/arm-io/sgx", "x", big,
                                           APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES}};
        bad.overrides = limit;
        VCHECK(apple_modern_boot_metadata_build(&bad, &again, &error));
        view = prop_view(&again, "/arm-io/sgx", "x");
        VCHECK(view.size == APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES && view.data[0] == 1);
        apple_modern_boot_metadata_clear(&again);
        AppleModernAdtOverride nullvalue[] = {{"/arm-io/sgx", "x", NULL, 8}};
        bad.overrides = nullvalue;
        rejected_metadata("override value missing", &bad);
        AppleModernAdtOverride nullpath[] = {{NULL, "x", extra, 8}};
        bad.overrides = nullpath;
        rejected_metadata("override path missing", &bad);
        AppleModernAdtOverride nullname[] = {{"/arm-io/sgx", NULL, extra, 8}};
        bad.overrides = nullname;
        rejected_metadata("override name missing", &bad);
    }
    {
        static const char *const paths[] = {"/", "/arm-io/", "arm-io/sgx", ""};
        for (unsigned i = 0; i < 4; i++) {
            AppleModernAdtOverride list[1] = {{paths[i], "x", extra, 8}};
            bad = input; bad.overrides = list; bad.override_count = 1;
            rejected_metadata("override path malformed", &bad);
        }
        char long_name[40];
        memset(long_name, 'n', 32); long_name[32] = 0;
        AppleModernAdtOverride list[1] = {{"/arm-io/sgx", long_name, extra, 8}};
        bad = input; bad.overrides = list; bad.override_count = 1;
        rejected_metadata("override name too long", &bad);
        long_name[31] = 0;
        bad.override_count = 1;
        VCHECK(apple_modern_boot_metadata_build(&bad, &again, &error));
        apple_modern_boot_metadata_clear(&again);
        long_name[0] = 0;
        rejected_metadata("override name empty", &bad);
        char long_path[300];
        memset(long_path, 'p', sizeof(long_path)); long_path[0] = '/';
        long_path[299] = 0;
        AppleModernAdtOverride lp[1] = {{long_path, "x", extra, 8}};
        bad.overrides = lp;
        rejected_metadata("override path too long", &bad);
    }
    for (unsigned i = 0; i < APPLE_MODERN_MAX_ADT_OVERRIDES + 1; i++) {
        static char names[APPLE_MODERN_MAX_ADT_OVERRIDES + 1][8];
        snprintf(names[i], sizeof(names[i]), "p%u", i);
        many[i] = (AppleModernAdtOverride){"/arm-io/sgx", names[i], extra, 8};
    }
    bad = input; bad.overrides = many; bad.override_count = APPLE_MODERN_MAX_ADT_OVERRIDES;
    VCHECK(apple_modern_boot_metadata_build(&bad, &again, &error));
    apple_modern_boot_metadata_clear(&again);
    bad.override_count = APPLE_MODERN_MAX_ADT_OVERRIDES + 1;
    rejected_metadata("too many overrides", &bad);
    bad = input; bad.overrides = NULL; bad.override_count = 1;
    rejected_metadata("override list missing", &bad);
    /* The list and its value bytes must not alias the output structure. */
    memset(alias_storage, 0, sizeof(AppleModernBootMetadata));
    {
        AppleModernAdtOverride in_output[1] = {{"/arm-io/sgx", "x", alias_storage + 64, 8}};
        bad = input; bad.overrides = in_output; bad.override_count = 1;
        VCHECK(!apple_modern_boot_metadata_build(&bad,
               (AppleModernBootMetadata *)alias_storage, &error));
        VCHECK(error); error_free(error); error = NULL;
        memcpy(alias_storage, good, sizeof(good));
        bad.overrides = (const AppleModernAdtOverride *)alias_storage;
        bad.override_count = 3;
        VCHECK(!apple_modern_boot_metadata_build(&bad,
               (AppleModernBootMetadata *)alias_storage, &error));
        VCHECK(error); error_free(error); error = NULL;
        VCHECK(!memcmp(alias_storage, good, sizeof(good)));
    }
    /* Overrides cannot push the serialized tree past a tight capacity. */
    bad = input; bad.dtree_capacity_limit = plain.dtree_size + 4;
    rejected_metadata("override exceeds ADT capacity", &bad);

    apple_modern_boot_metadata_clear(&plain);
    apple_modern_boot_metadata_clear(&patched);
    free(original); free(alias_storage); free_components(&components);
    (void)changed;
}

static uint64_t period_of(uint32_t hz)
{
    return (uint64_t)65536000000000ULL / hz;
}

static void test_j700_profile(void)
{
    static const struct { const char *name; uint32_t size; } expect[] = {
        {"voltage-states0", 32}, {"voltage-states1", 48},
        {"voltage-states1-sram", 48}, {"voltage-states2", 40},
        {"voltage-states5", 136}, {"voltage-states5-sram", 136},
        {"voltage-states8", 240}, {"voltage-states9", 128},
        {"voltage-states9-sram", 128}, {"voltage-states10", 24},
        {"voltage-states11", 48},
    };
    size_t count = 99;
    const AppleModernAdtOverride *profile;
    const AppleModernAdtOverride *byname[11] = {0};
    VCHECK(!apple_modern_pmgr_voltage_profile(NULL, &count) && !count);
    count = 99;
    VCHECK(!apple_modern_pmgr_voltage_profile("", &count) && !count);
    VCHECK(!apple_modern_pmgr_voltage_profile("J700", &count) && !count);
    VCHECK(!apple_modern_pmgr_voltage_profile("j700 ", &count) && !count);
    VCHECK(!apple_modern_pmgr_voltage_profile("iphone17,3", &count) && !count);
    profile = apple_modern_pmgr_voltage_profile(APPLE_MODERN_PMGR_VOLTAGE_J700, &count);
    VCHECK(profile && count == 11 && count <= APPLE_MODERN_MAX_ADT_OVERRIDES);
    for (size_t i = 0; i < count; i++) {
        VCHECK(!strcmp(profile[i].path, "/arm-io/pmgr"));
        VCHECK(profile[i].size == expect[i].size && !strcmp(profile[i].name, expect[i].name));
        VCHECK(profile[i].size && !(profile[i].size & 7) &&
               profile[i].size <= APPLE_MODERN_MAX_ADT_OVERRIDE_BYTES);
        byname[i] = &profile[i];
    }
    /* Attested iBoot / ApplePMGR word formats, checked on the data itself. */
    const AppleModernAdtOverride *soc = byname[0], *ecpu = byname[1],
        *ecpu_sram = byname[2], *dcs = byname[3], *pcpu = byname[4],
        *pcpu_sram = byname[5], *ane = byname[6], *gpu = byname[7],
        *gpu_sram = byname[8], *ave = byname[9], *disp = byname[10];
    const AppleModernAdtOverride *cpu[2][2] = {{ecpu, ecpu_sram}, {pcpu, pcpu_sram}};
    for (unsigned c = 0; c < 2; c++) {
        const AppleModernAdtOverride *main_table = cpu[c][0], *sram = cpu[c][1];
        unsigned pairs = main_table->size / 8, leading = 0;
        VCHECK(sram->size == main_table->size && pairs >= 1 && pairs < 0x20);
        for (unsigned i = 0; i < pairs; i++) {
            uint32_t period = le32_at(main_table->value + 8 * i);
            uint32_t hz = le32_at(sram->value + 8 * i);
            uint32_t mv = le32_at(main_table->value + 8 * i + 4);
            uint32_t sram_mv = le32_at(sram->value + 8 * i + 4);
            leading += period != 0;
            /* ApplePMGR counts leading nonzero word0; word0 = 65536e9/Hz. */
            VCHECK(period && hz >= 100000000u);
            VCHECK(period_of(hz) == period);
            VCHECK(mv >= 300 && mv <= 1450 && sram_mv >= mv);
            if (i) {
                VCHECK(hz > le32_at(sram->value + 8 * (i - 1)));
                VCHECK(period < le32_at(main_table->value + 8 * (i - 1)));
            }
        }
        VCHECK(leading == pairs);
    }
    /* State counts agree with the iPhone's PMP dvfs-domain: SOC 4, DCS 5, AVE 3, DISP 6. */
    VCHECK(soc->size / 8 == 4 && dcs->size / 8 == 5 && ave->size / 8 == 3 &&
           disp->size / 8 == 6);
    const AppleModernAdtOverride *flat[4] = {soc, dcs, ave, disp};
    for (unsigned t = 0; t < 4; t++) {
        for (unsigned i = 0; i < flat[t]->size / 8; i++) {
            uint32_t mv = le32_at(flat[t]->value + 8 * i + 4);
            VCHECK(le32_at(flat[t]->value + 8 * i) == 1 && mv >= 300 && mv <= 1400);
        }
    }
    /* ANE is frequency-only: (Hz, 0xffffffff), ascending. */
    for (unsigned i = 0; i < ane->size / 8; i++) {
        VCHECK(le32_at(ane->value + 8 * i + 4) == 0xffffffffu);
        VCHECK(le32_at(ane->value + 8 * i) >= 100000000u);
        if (i) {
            VCHECK(le32_at(ane->value + 8 * i) > le32_at(ane->value + 8 * (i - 1)));
        }
    }
    /* GPU table and its -sram twin are same-size (Hz, mV) pairs. */
    VCHECK(gpu->size == gpu_sram->size && gpu->size / 8 == 16);
    VCHECK(le32_at(gpu->value) == 0);
}

static void test_actual_tree(const char *components_dir)
{
    AppleModernBootInput actual = {.dram_base = UINT64_C(1) << 40,
                                  .dram_size = UINT64_C(8) << 30};
    AppleModernBootMetadataInput input = {.components = &actual,
        .command_line = "-v", .command_line_length = 2, .has_mte = true,
        .aic_iack_offset = 0x2000};
    AppleModernBootMetadata stock = {0}, patched = {0};
    Error *error = NULL;
    size_t count;
    const AppleModernAdtOverride *profile =
        apple_modern_pmgr_voltage_profile(APPLE_MODERN_PMGR_VOLTAGE_J700, &count);
    actual.bootkc = file(components_dir, "bootkc");
    actual.sptm = file(components_dir, "sptm");
    actual.txm = file(components_dir, "txm");
    actual.dtree = file(components_dir, "dtree");
    actual.trustcache = file(components_dir, "restore-trustcache");
    VCHECK(apple_modern_boot_metadata_build(&input, &stock, &error));
    input.overrides = profile;
    input.override_count = count;
    VCHECK(apple_modern_boot_metadata_build(&input, &patched, &error));
    Walk a = adt_walk((AppleModernBlob){stock.dtree, stock.dtree_size}, "/arm-io/pmgr");
    Walk b = adt_walk((AppleModernBlob){patched.dtree, patched.dtree_size}, "/arm-io/pmgr");
    unsigned replaced = 0, added = 0;
    VCHECK(a.nodes == b.nodes);
    for (size_t i = 0; i < count; i++) {
        int in_stock = find_prop(&a, profile[i].name);
        int in_patched = find_prop(&b, profile[i].name);
        VCHECK(in_patched >= 0 && b.lengths[in_patched] == profile[i].size &&
               !memcmp(b.values[in_patched], profile[i].value, profile[i].size));
        in_stock >= 0 ? replaced++ : added++;
    }
    /* Every other pmgr property is byte-identical to the stock tree. */
    for (unsigned i = 0; i < a.want_count; i++) {
        bool overridden = false;
        for (size_t j = 0; j < count; j++) {
            overridden |= !strcmp(a.names[i], profile[j].name);
        }
        if (!overridden) {
            int k = find_prop(&b, a.names[i]);
            VCHECK(k >= 0 && b.lengths[k] == a.lengths[i] &&
                   !memcmp(b.values[k], a.values[i], a.lengths[i]));
        }
    }
    VCHECK(b.want_count == a.want_count + added);
    VCHECK(replaced + added == 11);
    /* The stock iPhone17,3 tree carries 0, 2 and 9 only; 1/5/8/10/11 are what
     * ApplePMGR::initDriver needs (BootKC panic ApplePMGR.cpp:1450). */
    VCHECK(replaced == 3 && added == 8);
    VCHECK(find_prop(&a, "voltage-states1") < 0 && find_prop(&a, "voltage-states0") >= 0);
    VCHECK(a.props + added == b.props);
    printf("ACTUAL pmgr properties stock=%u patched=%u replaced=%u added=%u\n",
           a.want_count, b.want_count, replaced, added);
    apple_modern_boot_metadata_clear(&stock);
    apple_modern_boot_metadata_clear(&patched);
    free_components(&actual);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_override_mechanism();
    test_j700_profile();
    if (argc >= 2) {
        test_actual_tree(argv[1]);
    }
    printf("PASS %u override/profile checks (+%u shared fixture checks); "
           "no guest writes or execution\n", voltage_checks, checks);
    return 0;
}
