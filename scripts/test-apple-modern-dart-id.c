/* Loader-generated dart-id for every dart,t8110 node. Production-source test,
 * no guest launch.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *   -fsanitize=address,undefined hw/arm/apple-silicon/modern-boot-layout.c \
 *   hw/arm/apple-silicon/modern-boot-metadata.c \
 *   scripts/test-apple-modern-dart-id.c -o /tmp/test-dart-id \
 *   && /tmp/test-dart-id [components-dir]
 *
 * The oracle is a second, independent ADT reader (no shared code with the
 * serializer) that flattens a whole tree into (path, property list). For every
 * node the generated tree must equal the plain-build tree except that a
 * dart,t8110 node carries one extra 4-byte dart-id equal to its depth-first
 * index among dart,t8110 nodes.
 */
#define METADATA_REGRESSION_MAIN metadata_regression_main
#include "test-apple-modern-boot-metadata.c"

static unsigned dart_checks;
#define DCHECK(c) do { dart_checks++; if (!(c)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

typedef struct FlatProp {
    char name[32];
    const uint8_t *value;
    uint32_t length;
} FlatProp;

typedef struct FlatNode {
    char path[256];
    size_t first;             /* index of the node's first property */
    uint32_t count;
} FlatNode;

#define FLAT_PROP_CAP 32768

typedef struct Flat {
    FlatNode *nodes;
    FlatProp *props;
    size_t node_count, prop_count;
    const uint8_t *data;
    size_t size, cursor;
} Flat;

static void flat_node(Flat *f, const char *parent, unsigned depth)
{
    uint32_t count, children;
    FlatNode *node;
    char name[128] = "";

    DCHECK(depth < 16 && f->cursor + 8 <= f->size);
    count = le32(f->data + f->cursor);
    children = le32(f->data + f->cursor + 4);
    f->cursor += 8;
    node = &f->nodes[f->node_count++];
    node->first = f->prop_count;
    node->count = count;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p = f->data + f->cursor;
        FlatProp *prop = &f->props[f->prop_count++];
        uint32_t length;

        DCHECK(f->prop_count <= FLAT_PROP_CAP);
        DCHECK(f->cursor + 36 <= f->size && memchr(p, 0, 32));
        length = le32(p + 32) & 0x7fffffff;
        memcpy(prop->name, p, 32);
        prop->value = p + 36;
        prop->length = length;
        f->cursor += 36;
        DCHECK(f->cursor + ((length + 3) & ~3U) <= f->size);
        if (!strcmp(prop->name, "name")) {
            snprintf(name, sizeof(name), "%.*s", (int)length, (const char *)prop->value);
        }
        f->cursor += (length + 3) & ~3U;
    }
    if (!depth) {
        snprintf(node->path, sizeof(node->path), "/");
    } else if (depth == 1) {
        snprintf(node->path, sizeof(node->path), "/%s", name);
    } else {
        snprintf(node->path, sizeof(node->path), "%s/%s", parent, name);
    }
    for (uint32_t i = 0; i < children; i++) {
        flat_node(f, node->path, depth + 1);
    }
}

static Flat flatten(AppleModernBlob blob)
{
    Flat f = {.data = blob.data, .size = blob.size};

    f.nodes = calloc(8192, sizeof(FlatNode));
    f.props = calloc(FLAT_PROP_CAP, sizeof(FlatProp));
    DCHECK(f.nodes && f.props);
    flat_node(&f, "", 0);
    DCHECK(f.cursor == blob.size);   /* the whole blob is exactly one tree */
    return f;
}

static void flat_free(Flat *f)
{
    free(f->nodes);
    free(f->props);
}

static const FlatProp *flat_find(const Flat *f, size_t node, const char *name)
{
    for (uint32_t i = 0; i < f->nodes[node].count; i++) {
        const FlatProp *p = &f->props[f->nodes[node].first + i];

        if (!strcmp(p->name, name)) {
            return p;
        }
    }
    return NULL;
}

static bool flat_is_dart(const Flat *f, size_t node)
{
    const FlatProp *c = flat_find(f, node, "compatible");
    size_t start = 0;

    while (c && start < c->length) {
        size_t end = start;

        while (end < c->length && c->value[end]) {
            end++;
        }
        if (end - start == 10 && !memcmp(c->value + start, "dart,t8110", 10)) {
            return true;
        }
        start = end + 1;
    }
    return false;
}

/* The core oracle: `on` equals `off` plus one dart-id per dart node, in order. */
static unsigned compare_trees(const Flat *off, const Flat *on)
{
    unsigned darts = 0;

    DCHECK(off->node_count == on->node_count);
    for (size_t n = 0; n < off->node_count; n++) {
        bool dart = flat_is_dart(off, n);
        uint32_t copied = 0;

        DCHECK(!strcmp(off->nodes[n].path, on->nodes[n].path));
        DCHECK(flat_is_dart(on, n) == dart);
        if (!dart) {
            /* Untouched node: same properties, same order, same bytes. */
            DCHECK(off->nodes[n].count == on->nodes[n].count);
            for (uint32_t i = 0; i < off->nodes[n].count; i++) {
                const FlatProp *a = &off->props[off->nodes[n].first + i];
                const FlatProp *b = &on->props[on->nodes[n].first + i];

                DCHECK(!strcmp(a->name, b->name) && a->length == b->length &&
                       !memcmp(a->value, b->value, a->length));
            }
            continue;
        }
        /* Dart node: every other property in order, then the new dart-id. */
        for (uint32_t i = 0; i < off->nodes[n].count; i++) {
            const FlatProp *a = &off->props[off->nodes[n].first + i];
            const FlatProp *b;

            if (!strcmp(a->name, "dart-id")) {
                continue;
            }
            b = &on->props[on->nodes[n].first + copied++];
            DCHECK(!strcmp(a->name, b->name) && a->length == b->length &&
                   !memcmp(a->value, b->value, a->length));
        }
        DCHECK(on->nodes[n].count == copied + 1);
        {
            const FlatProp *id = &on->props[on->nodes[n].first + copied];

            DCHECK(!strcmp(id->name, "dart-id") && id->length == 4);
            DCHECK(le32(id->value) == darts);
        }
        darts++;
    }
    return darts;
}

/* Tiny ADT writer for the synthetic trees. */
typedef struct Buf {
    uint8_t *data;
    size_t used, capacity;
} Buf;

static void b_node(Buf *b, uint32_t props, uint32_t children)
{
    DCHECK(b->used + 8 <= b->capacity);
    put32(b->data + b->used, props);
    put32(b->data + b->used + 4, children);
    b->used += 8;
}

static void b_prop(Buf *b, const char *name, const void *value, uint32_t length)
{
    size_t padded = (length + 3) & ~3U;

    DCHECK(b->used + 36 + padded <= b->capacity && strlen(name) < 32);
    memset(b->data + b->used, 0, 36 + padded);
    strcpy((char *)b->data + b->used, name);
    put32(b->data + b->used + 32, length);
    memcpy(b->data + b->used + 36, value, length);
    b->used += 36 + padded;
}

static void b_str(Buf *b, const char *name, const char *text)
{
    b_prop(b, name, text, strlen(text) + 1);
}

static void b_u32(Buf *b, const char *name, uint32_t value)
{
    uint8_t bytes[4];

    put32(bytes, value);
    b_prop(b, name, bytes, 4);
}

/* The layout builder requires /cpus/cpu0. */
static void b_cpus(Buf *b)
{
    b_node(b, 1, 1);
    b_str(b, "name", "cpus");
    b_node(b, 1, 0);
    b_str(b, "name", "cpu0");
}

static void b_chosen(Buf *b)
{
    b_node(b, 3, 1);
    b_str(b, "name", "chosen");
    b_str(b, "dram-base", "replaced by the loader");
    b_str(b, "secure-boot", "unchanged policy");
    b_node(b, 3, 0);
    b_str(b, "name", "memory-map");
    b_str(b, "MemoryMapReserved-0", "unchanged firmware mapping");
    b_str(b, "BootArgs", "replaced by the loader");
}

/* Depth-first dart order: dart-a(0) dart-b(1) dart-c(2) dart-d(3) unterminated(4). */
static AppleModernBlob synthetic_tree(void)
{
    static const uint8_t unterminated[10] = {'d', 'a', 'r', 't', ',', 't', '8', '1', '1', '0'};
    static const uint8_t old_id[8] = {0x99, 0, 0, 0, 0xee, 0, 0, 0};
    Buf b = {calloc(1, 16384), 0, 16384};

    DCHECK(b.data);
    b_node(&b, 2, 3);
    b_str(&b, "name", "/");
    b_str(&b, "unchanged-root", "root bytes");
    b_node(&b, 2, 9);
    b_str(&b, "name", "arm-io");
    b_str(&b, "compatible", "arm-io,t8140");
    b_node(&b, 3, 1);                                    /* dart-a */
    b_str(&b, "name", "dart-a");
    b_str(&b, "compatible", "dart,t8110");
    b_u32(&b, "page-size", 0x4000);
    b_node(&b, 2, 0);                                    /* its mapper */
    b_str(&b, "name", "mapper-a");
    b_str(&b, "compatible", "iommu-mapper");
    b_node(&b, 2, 0);                                    /* other family */
    b_str(&b, "name", "other");
    b_str(&b, "compatible", "dart,t8020");
    b_node(&b, 2, 0);                                    /* second list entry */
    b_str(&b, "name", "dart-b");
    b_prop(&b, "compatible", "foo,bar\0dart,t8110\0baz", 22);
    b_node(&b, 4, 1);                                    /* existing 8-byte id */
    b_str(&b, "name", "dart-c");
    b_str(&b, "compatible", "dart,t8110");
    b_prop(&b, "dart-id", old_id, sizeof(old_id));
    b_u32(&b, "z-last", 0x1234);
    b_node(&b, 2, 0);                                    /* nested dart */
    b_str(&b, "name", "dart-d");
    b_str(&b, "compatible", "dart,t8110");
    b_node(&b, 2, 0);                                    /* longer string */
    b_str(&b, "name", "prefix");
    b_str(&b, "compatible", "dart,t81100");
    b_node(&b, 2, 0);                                    /* shorter string */
    b_str(&b, "name", "short");
    b_str(&b, "compatible", "dart,t811");
    b_node(&b, 2, 0);                                    /* no terminating NUL */
    b_str(&b, "name", "unterminated");
    b_prop(&b, "compatible", unterminated, sizeof(unterminated));
    b_node(&b, 2, 0);                                    /* id, but no compatible */
    b_str(&b, "name", "nocompat");
    b_u32(&b, "dart-id", 7);
    b_node(&b, 2, 0);                                    /* empty list */
    b_str(&b, "name", "emptycompat");
    b_prop(&b, "compatible", "", 1);
    b_cpus(&b);
    b_chosen(&b);
    return (AppleModernBlob){b.data, b.used};
}

/* One dart node with exactly the maximum 4096 properties. */
static AppleModernBlob wide_tree(bool with_id)
{
    Buf b = {calloc(1, 400000), 0, 400000};
    char name[32];

    DCHECK(b.data);
    b_node(&b, 1, 3);
    b_str(&b, "name", "/");
    b_node(&b, 2, 1);
    b_str(&b, "name", "arm-io");
    b_str(&b, "compatible", "arm-io,t8140");
    b_node(&b, 4096, 0);
    b_str(&b, "name", "dart-big");
    b_str(&b, "compatible", "dart,t8110");
    for (unsigned i = 0; i < 4094; i++) {
        if (with_id && i == 0) {
            b_u32(&b, "dart-id", 0xabcd);
        } else {
            snprintf(name, sizeof(name), "f%u", i);
            b_u32(&b, name, i);
        }
    }
    b_cpus(&b);
    b_chosen(&b);
    return (AppleModernBlob){b.data, b.used};
}

static AppleModernBlob no_dart_tree(void)
{
    Buf b = {calloc(1, 4096), 0, 4096};

    DCHECK(b.data);
    b_node(&b, 1, 3);
    b_str(&b, "name", "/");
    b_node(&b, 2, 1);
    b_str(&b, "name", "arm-io");
    b_str(&b, "compatible", "arm-io,t8140");
    b_node(&b, 2, 0);
    b_str(&b, "name", "old-dart");
    b_str(&b, "compatible", "dart,t8020");
    b_cpus(&b);
    b_chosen(&b);
    return (AppleModernBlob){b.data, b.used};
}

static AppleModernBootMetadata build_ok(AppleModernBootMetadataInput *input)
{
    AppleModernBootMetadata out = {0};
    Error *error = NULL;

    if (!apple_modern_boot_metadata_build(input, &out, &error)) {
        fprintf(stderr, "build failed: %s\n", error ? error->message : "?");
        exit(1);
    }
    DCHECK(!error);
    return out;
}

static void use_tree(AppleModernBootInput *components, AppleModernBlob tree)
{
    free((void *)components->dtree.data);
    components->dtree = tree;
}

static void test_synthetic(void)
{
    AppleModernBootInput components = metadata_fixture();
    AppleModernBootMetadataInput input = {.components = &components,
        .command_line = "-v", .command_line_length = 2, .has_mte = true}, on_input, bad;
    AppleModernBootMetadata off, on, again, rebuilt;
    Flat flat_off, flat_on;
    AppleModernBlob tree = synthetic_tree();
    uint8_t *original = malloc(tree.size);
    static const AppleModernAdtOverride clash[] =
        {{"/arm-io/dart-a", "dart-id", (const uint8_t *)"\1\0\0\0", 4}};
    static const AppleModernAdtOverride fine[] =
        {{"/arm-io/other", "extra", (const uint8_t *)"\1\0\0\0", 4}};

    DCHECK(original);
    memcpy(original, tree.data, tree.size);
    use_tree(&components, tree);
    off = build_ok(&input);
    DCHECK(off.dart_id_count == 0);
    on_input = input;
    on_input.assign_dart_ids = true;
    on = build_ok(&on_input);
    verify_metadata(&on_input, &on);
    DCHECK(on.dart_id_count == 5);
    flat_off = flatten((AppleModernBlob){off.dtree, off.dtree_size});
    flat_on = flatten((AppleModernBlob){on.dtree, on.dtree_size});
    DCHECK(compare_trees(&flat_off, &flat_on) == 5);
    /* 5 new 40-byte properties, minus the replaced 44-byte 8-byte id. */
    DCHECK(on.dtree_size == off.dtree_size + 5 * 40 - 44);
    /* The exact ids, by name, from the tree as written above. */
    {
        static const struct { const char *path; int id; } expect[] = {
            {"/arm-io/dart-a", 0}, {"/arm-io/dart-b", 1}, {"/arm-io/dart-c", 2},
            {"/arm-io/dart-c/dart-d", 3}, {"/arm-io/unterminated", 4},
            {"/arm-io/dart-a/mapper-a", -1}, {"/arm-io/other", -1},
            {"/arm-io/prefix", -1}, {"/arm-io/short", -1},
            {"/arm-io/emptycompat", -1}, {"/arm-io/nocompat", -2},
            {"/arm-io", -1},
        };
        for (size_t i = 0; i < sizeof(expect) / sizeof(expect[0]); i++) {
            Error *error = NULL;
            AppleModernBlob view;
            bool found = apple_modern_adt_property(
                (AppleModernBlob){on.dtree, on.dtree_size}, expect[i].path,
                "dart-id", &view, &error);

            if (expect[i].id >= 0) {
                DCHECK(found && view.size == 4 && le32(view.data) == (uint32_t)expect[i].id);
            } else if (expect[i].id == -2) {
                /* No compatible: the pre-existing id is left exactly as it was. */
                DCHECK(found && view.size == 4 && le32(view.data) == 7);
            } else {
                DCHECK(!found);
                error_free(error);
            }
        }
    }
    /* Deterministic, and stable when the loader's own output is its input. */
    again = build_ok(&on_input);
    DCHECK(again.dtree != on.dtree && again.dtree_size == on.dtree_size &&
           !memcmp(again.dtree, on.dtree, on.dtree_size));
    {
        AppleModernBootInput second = components;
        AppleModernBootMetadataInput second_input = on_input;

        second.dtree = (AppleModernBlob){on.dtree, on.dtree_size};
        second_input.components = &second;
        rebuilt = build_ok(&second_input);
        DCHECK(rebuilt.dtree_size == on.dtree_size &&
               !memcmp(rebuilt.dtree, on.dtree, on.dtree_size));
        DCHECK(rebuilt.dart_id_count == 5);
    }
    /* The input tree is never modified. */
    DCHECK(!memcmp(original, components.dtree.data, components.dtree.size));
    /* Interplay with the override mechanism. */
    bad = on_input;
    bad.overrides = clash;
    bad.override_count = 1;
    rejected_metadata("override names dart-id while ids are generated", &bad);
    bad.assign_dart_ids = false;      /* the same override is legal on its own */
    {
        AppleModernBootMetadata manual = build_ok(&bad);
        AppleModernBlob view = prop_view(&manual, "/arm-io/dart-a", "dart-id");

        DCHECK(view.size == 4 && le32(view.data) == 1);
        apple_modern_boot_metadata_clear(&manual);
    }
    bad = on_input;
    bad.overrides = fine;
    bad.override_count = 1;
    {
        AppleModernBootMetadata mixed = build_ok(&bad);
        AppleModernBlob view = prop_view(&mixed, "/arm-io/other", "extra");

        DCHECK(view.size == 4 && mixed.dart_id_count == 5);
        DCHECK(le32(prop_view(&mixed, "/arm-io/dart-c", "dart-id").data) == 2);
        apple_modern_boot_metadata_clear(&mixed);
    }
    /* Capacity: exactly the generated size fits, one byte less is refused. */
    bad = on_input;
    bad.dtree_capacity_limit = on.dtree_size - 1;
    rejected_metadata("generated ids exceed ADT capacity", &bad);
    bad.dtree_capacity_limit = on.dtree_size;
    {
        AppleModernBootMetadata tight = build_ok(&bad);

        DCHECK(tight.dtree_size == on.dtree_size);
        apple_modern_boot_metadata_clear(&tight);
    }
    flat_free(&flat_off);
    flat_free(&flat_on);
    apple_modern_boot_metadata_clear(&off);
    apple_modern_boot_metadata_clear(&on);
    apple_modern_boot_metadata_clear(&again);
    apple_modern_boot_metadata_clear(&rebuilt);
    free(original);
    free_components(&components);
}

static void test_refusals(void)
{
    AppleModernBootInput components = metadata_fixture();
    AppleModernBootMetadataInput input = {.components = &components,
        .command_line = "-v", .command_line_length = 2, .has_mte = true,
        .assign_dart_ids = true}, bad;
    AppleModernBootMetadata out;

    /* The stock-shaped fixture has no dart,t8110 node: refuse, do not no-op. */
    rejected_metadata("no dart,t8110 node in the template tree", &input);
    use_tree(&components, no_dart_tree());
    rejected_metadata("only a different DART family", &input);
    input.assign_dart_ids = false;
    out = build_ok(&input);       /* the same tree builds when ids are off */
    DCHECK(out.dart_id_count == 0);
    apple_modern_boot_metadata_clear(&out);

    /* A dart node already at the 4096-property limit. */
    use_tree(&components, wide_tree(false));
    input.assign_dart_ids = true;
    rejected_metadata("dart node cannot take a 4097th property", &input);
    use_tree(&components, wide_tree(true));
    {
        AppleModernBootMetadata wide = build_ok(&input);
        Flat flat = flatten((AppleModernBlob){wide.dtree, wide.dtree_size});
        const FlatProp *id = NULL;

        for (size_t n = 0; n < flat.node_count; n++) {
            if (!strcmp(flat.nodes[n].path, "/arm-io/dart-big")) {
                DCHECK(flat.nodes[n].count == 4096);
                id = flat_find(&flat, n, "dart-id");
            }
        }
        /* A replaced id keeps the count; its old value is gone. */
        DCHECK(id && id->length == 4 && le32(id->value) == 0);
        flat_free(&flat);
        apple_modern_boot_metadata_clear(&wide);
    }
    bad = input;
    bad.assign_dart_ids = false;
    out = build_ok(&bad);
    DCHECK(le32(prop_view(&out, "/arm-io/dart-big", "dart-id").data) == 0xabcd);
    apple_modern_boot_metadata_clear(&out);
    free_components(&components);
}

static void test_actual_tree(const char *components_dir)
{
    static const char *const expected[] = {
        "aop", "pmp", "sep", "sio", "rsm", "mtp", "usb", "dcp", "disp0",
        "dispgrt", "dcpext0", "dispext0", "scaler", "jpeg-h17a", "jpeg0-h17p",
        "jpeg1-h17p", "isp", "ave", "ave1", "avd", "ane", "apr", "apcie0",
        "apcie1", "apcie2",
    };
    AppleModernBootInput actual = {.dram_base = UINT64_C(1) << 40,
                                  .dram_size = UINT64_C(8) << 30};
    AppleModernBootMetadataInput input = {.components = &actual,
        .command_line = "-v", .command_line_length = 2, .has_mte = true,
        .aic_iack_offset = 0x2000}, on_input;
    AppleModernBootMetadata off, on;
    Flat stock, flat_off, flat_on;
    unsigned darts = 0, with_id_in_stock = 0;

    actual.bootkc = file(components_dir, "bootkc");
    actual.sptm = file(components_dir, "sptm");
    actual.txm = file(components_dir, "txm");
    actual.dtree = file(components_dir, "dtree");
    actual.trustcache = file(components_dir, "restore-trustcache");
    off = build_ok(&input);
    on_input = input;
    on_input.assign_dart_ids = true;
    on = build_ok(&on_input);
    DCHECK(on.dart_id_count == 25 && off.dart_id_count == 0);
    stock = flatten(actual.dtree);
    flat_off = flatten((AppleModernBlob){off.dtree, off.dtree_size});
    flat_on = flatten((AppleModernBlob){on.dtree, on.dtree_size});
    /* Independent census of the input tree: exactly the 25 known nodes, in
     * this order, none with a dart-id (measured in the sep-review). */
    for (size_t n = 0; n < stock.node_count; n++) {
        with_id_in_stock += flat_find(&stock, n, "dart-id") != NULL;
        if (flat_is_dart(&stock, n)) {
            char want[64];

            DCHECK(darts < 25);
            snprintf(want, sizeof(want), "/arm-io/dart-%s", expected[darts]);
            DCHECK(!strcmp(stock.nodes[n].path, want));
            darts++;
        }
    }
    DCHECK(darts == 25 && !with_id_in_stock);
    DCHECK(compare_trees(&flat_off, &flat_on) == 25);
    /* Every id is present once, unique, and the sequence is 0..24 in order. */
    {
        bool seen[25] = {0};
        unsigned order = 0;

        for (size_t n = 0; n < flat_on.node_count; n++) {
            const FlatProp *id = flat_find(&flat_on, n, "dart-id");

            if (id) {
                DCHECK(le32(id->value) < 25 && !seen[le32(id->value)]);
                DCHECK(le32(id->value) == order++);
                seen[le32(id->value)] = true;
            }
        }
        DCHECK(order == 25);
    }
    DCHECK(on.dtree_size == off.dtree_size + 25 * 40);
    /* dart-sep and dart-sio, the two the SEP work restores, are 2 and 3. */
    DCHECK(le32(prop_view(&on, "/arm-io/dart-sep", "dart-id").data) == 2);
    DCHECK(le32(prop_view(&on, "/arm-io/dart-sio", "dart-id").data) == 3);
    printf("ACTUAL dart,t8110 nodes=%u ids=0..%u dart-sep=2 dart-sio=3 "
           "added_bytes=%zu\n", darts, darts - 1, on.dtree_size - off.dtree_size);
    flat_free(&stock);
    flat_free(&flat_off);
    flat_free(&flat_on);
    apple_modern_boot_metadata_clear(&off);
    apple_modern_boot_metadata_clear(&on);
    free_components(&actual);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_synthetic();
    test_refusals();
    if (argc >= 2) {
        test_actual_tree(argv[1]);
    }
    printf("PASS %u dart-id checks (+%u shared fixture checks); no guest "
           "writes or execution\n", dart_checks, checks);
    return 0;
}
