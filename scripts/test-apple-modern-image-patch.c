/* Core test for the declared anchored image-patch facility.
 * Production-source test, no guest launch.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *   -fsanitize=address,undefined \
 *   hw/arm/apple-silicon/modern-boot-layout.c \
 *   hw/arm/apple-silicon/modern-image-patch.c \
 *   scripts/test-apple-modern-image-patch.c -o /tmp/test-image-patch \
 *   && /tmp/test-image-patch
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-image-patch.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #x); exit(1); } } while (0)

static void clear_error(Error **error)
{
    CHECK(*error != NULL);
    error_free(*error);
    *error = NULL;
}

/* The demonstration anchor/replacement, duplicated here so the test is an
 * independent oracle for the shipped table entry. */
static const char DEMO_ANCHOR[] = "Warning: arc4random not implemented";
static const char DEMO_REPL[] = "Inferno demo image-patch (harmless)";

/* Build a BootKC-like buffer: filler, the anchor at `where`, more filler. */
static uint8_t *make_buf(size_t size, const char *needle, size_t where,
                         unsigned copies)
{
    uint8_t *buf = malloc(size);
    size_t nlen = strlen(needle);
    CHECK(buf != NULL);
    for (size_t i = 0; i < size; i++) {
        buf[i] = (uint8_t)(0x40 + (i % 0x30)); /* printable, != anchor[0] mostly */
    }
    for (unsigned c = 0; c < copies; c++) {
        size_t at = where + c * (nlen + 7);
        CHECK(at + nlen <= size);
        memcpy(buf + at, needle, nlen);
    }
    return buf;
}

/* ---- Test 1: the shipped "demo" set applies exactly once on BootKC. ---- */
static void test_demo_set_applies(void)
{
    const AppleModernImagePatchSet *set = apple_modern_image_patch_set("demo");
    AppleModernImagePatchResult result = {0};
    Error *error = NULL;
    size_t size = 4096, where = 1000, nlen = strlen(DEMO_ANCHOR);
    uint8_t *buf = make_buf(size, DEMO_ANCHOR, where, 1);
    uint8_t *shadow = malloc(size);

    CHECK(set != NULL && set->patch_count == 1);
    memcpy(shadow, buf, size);

    CHECK(apple_modern_image_patch_apply_image(set, APPLE_MODERN_BOOTKC, buf,
                                               size, &result, &error));
    CHECK(error == NULL);
    /* The anchor bytes became the replacement; everything else is unchanged. */
    CHECK(!memcmp(buf + where, DEMO_REPL, nlen));
    memcpy(shadow + where, DEMO_REPL, nlen);
    CHECK(!memcmp(buf, shadow, size));
    /* One applied entry, correct metadata and offset. */
    CHECK(result.count == 1);
    CHECK(!strcmp(result.entries[0].name, "demo-log-string"));
    CHECK(result.entries[0].image == APPLE_MODERN_BOOTKC);
    CHECK(result.entries[0].offset == where);
    CHECK(result.entries[0].replacement_len == nlen);
    CHECK(result.entries[0].changes && result.entries[0].removes);

    free(buf);
    free(shadow);
}

/* ---- Test 2: anchor missing -> refusal, buffer and result untouched. ---- */
static void test_anchor_missing(void)
{
    const AppleModernImagePatchSet *set = apple_modern_image_patch_set("demo");
    AppleModernImagePatchResult result = {0};
    Error *error = NULL;
    size_t size = 4096;
    uint8_t *buf = make_buf(size, "nothing-here", 100, 1);
    uint8_t *shadow = malloc(size);

    memcpy(shadow, buf, size);
    CHECK(!apple_modern_image_patch_apply_image(set, APPLE_MODERN_BOOTKC, buf,
                                                size, &result, &error));
    CHECK(strstr(error->message, "demo-log-string") &&
          strstr(error->message, "anchor not found"));
    clear_error(&error);
    CHECK(result.count == 0);
    CHECK(!memcmp(buf, shadow, size)); /* pristine */
    free(buf);
    free(shadow);
}

/* ---- Test 3: too many matches -> refusal, buffer untouched. ---- */
static void test_multiple_hits(void)
{
    /* A local set expecting one match of a short anchor, but the buffer has
     * two. The engine must refuse before writing anything. */
    static const uint8_t anchor[] = "ZZmarkerZZ";
    static const uint8_t repl[] = "zzMARKERzz";
    const AppleModernImagePatch patch = {
        .name = "dup", .image = APPLE_MODERN_BOOTKC, .anchor = anchor,
        .anchor_len = sizeof(anchor) - 1, .replacement = repl,
        .replacement_len = sizeof(repl) - 1, .replace_offset = 0,
        .expected_count = 1, .changes = "c", .removes = "r",
    };
    const AppleModernImagePatchSet set = { "local", &patch, 1 };
    AppleModernImagePatchResult result = {0};
    Error *error = NULL;
    size_t size = 4096;
    uint8_t *buf = make_buf(size, "ZZmarkerZZ", 200, 2);
    uint8_t *shadow = malloc(size);

    memcpy(shadow, buf, size);
    CHECK(!apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC, buf,
                                                size, &result, &error));
    CHECK(strstr(error->message, "dup") &&
          strstr(error->message, "more than the expected"));
    clear_error(&error);
    CHECK(result.count == 0);
    CHECK(!memcmp(buf, shadow, size));
    free(buf);
    free(shadow);
}

/* ---- Test 4: replacement longer than the anchor span -> refusal. ---- */
static void test_length_mismatch(void)
{
    static const uint8_t anchor[] = "small";
    static const uint8_t repl[] = "far-too-long-replacement";
    const AppleModernImagePatch patch = {
        .name = "toolong", .image = APPLE_MODERN_BOOTKC, .anchor = anchor,
        .anchor_len = sizeof(anchor) - 1, .replacement = repl,
        .replacement_len = sizeof(repl) - 1, .replace_offset = 0,
        .expected_count = 1, .changes = "c", .removes = "r",
    };
    const AppleModernImagePatchSet set = { "local", &patch, 1 };
    AppleModernImagePatchResult result = {0};
    Error *error = NULL;
    size_t size = 4096;
    uint8_t *buf = make_buf(size, "small", 200, 1);
    uint8_t *shadow = malloc(size);

    memcpy(shadow, buf, size);
    CHECK(!apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC, buf,
                                                size, &result, &error));
    CHECK(strstr(error->message, "toolong") &&
          strstr(error->message, "does not fit"));
    clear_error(&error);
    CHECK(result.count == 0);
    CHECK(!memcmp(buf, shadow, size));

    /* replace_offset past the anchor end also refuses. */
    const AppleModernImagePatch patch2 = {
        .name = "badoff", .image = APPLE_MODERN_BOOTKC, .anchor = anchor,
        .anchor_len = sizeof(anchor) - 1, .replacement = anchor,
        .replacement_len = 1, .replace_offset = 99, .expected_count = 1,
        .changes = "c", .removes = "r",
    };
    const AppleModernImagePatchSet set2 = { "local", &patch2, 1 };
    result = (AppleModernImagePatchResult){0};
    CHECK(!apple_modern_image_patch_apply_image(&set2, APPLE_MODERN_BOOTKC, buf,
                                                size, &result, &error));
    CHECK(strstr(error->message, "badoff") &&
          strstr(error->message, "does not fit"));
    clear_error(&error);
    CHECK(!memcmp(buf, shadow, size));
    free(buf);
    free(shadow);
}

/* ---- Test 5: masked anchor matches; a mask-inconsistent entry refuses. -- */
static void test_mask(void)
{
    /* Anchor "Ab" with a mask that ignores the case bit (0x20) of each byte:
     * mask 0xDF, anchor must already be masked. So match "ab","AB","Ab","aB". */
    static const uint8_t anchor[] = { 'A' & 0xDF, 'B' & 0xDF };
    static const uint8_t mask[] = { 0xDF, 0xDF };
    static const uint8_t repl[] = { '!', '!' };
    const AppleModernImagePatch patch = {
        .name = "masked", .image = APPLE_MODERN_BOOTKC, .anchor = anchor,
        .anchor_mask = mask, .anchor_len = 2, .replacement = repl,
        .replacement_len = 2, .replace_offset = 0, .expected_count = 1,
        .changes = "c", .removes = "r",
    };
    const AppleModernImagePatchSet set = { "local", &patch, 1 };
    AppleModernImagePatchResult result = {0};
    Error *error = NULL;
    size_t size = 256;
    uint8_t *buf = malloc(size);
    CHECK(buf);
    memset(buf, 0, size);
    memcpy(buf + 50, "aB", 2); /* lower+upper, matches under the mask */
    CHECK(apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC, buf,
                                               size, &result, &error));
    CHECK(error == NULL && result.count == 1 && buf[50] == '!' && buf[51] == '!');

    /* A mask-inconsistent entry (anchor has bits outside the mask) refuses. */
    static const uint8_t bad_anchor[] = { 0xFF };
    static const uint8_t bad_mask[] = { 0x0F };
    const AppleModernImagePatch badp = {
        .name = "badmask", .image = APPLE_MODERN_BOOTKC, .anchor = bad_anchor,
        .anchor_mask = bad_mask, .anchor_len = 1, .replacement = bad_anchor,
        .replacement_len = 1, .replace_offset = 0, .expected_count = 1,
        .changes = "c", .removes = "r",
    };
    const AppleModernImagePatchSet badset = { "local", &badp, 1 };
    result = (AppleModernImagePatchResult){0};
    CHECK(!apple_modern_image_patch_apply_image(&badset, APPLE_MODERN_BOOTKC,
                                                buf, size, &result, &error));
    CHECK(strstr(error->message, "badmask") &&
          strstr(error->message, "outside its mask"));
    clear_error(&error);
    free(buf);
}

/* ---- Test 6: set lookup / names (option parsing). ---- */
static void test_set_lookup(void)
{
    CHECK(apple_modern_image_patch_set("demo") != NULL);
    CHECK(apple_modern_image_patch_set("nonesuch") == NULL);
    CHECK(apple_modern_image_patch_set(NULL) == NULL);
    CHECK(strstr(apple_modern_image_patch_set_names(), "demo") != NULL);
}

/* ---- Test 7: the unchanged path (a set with no patch for this image). ---- */
static void test_no_targeted_patch(void)
{
    const AppleModernImagePatchSet *set = apple_modern_image_patch_set("demo");
    AppleModernImagePatchResult result = {0};
    Error *error = NULL;
    size_t size = 4096;
    uint8_t *buf = make_buf(size, DEMO_ANCHOR, 1000, 1);
    uint8_t *shadow = malloc(size);

    memcpy(shadow, buf, size);
    /* demo targets only BOOTKC; applying it to SPTM must write nothing. */
    CHECK(apple_modern_image_patch_apply_image(set, APPLE_MODERN_SPTM, buf,
                                               size, &result, &error));
    CHECK(error == NULL && result.count == 0);
    CHECK(!memcmp(buf, shadow, size));
    free(buf);
    free(shadow);
}

/* ---- Test 8b: a match count past the result-slot budget is refused BEFORE any
   write.  Regression for the stack-buffer-overflow the independent verifier of
   413e27c reproduced: pass 1 budgeted one result slot per PATCH while pass 2
   writes one per MATCH, so an entry with expected_count > the array size walked
   off result->entries[].  The refusal must leave the image byte-identical. ---- */
static void test_entry_budget(void)
{
    static const uint8_t anchor[] = "MANY!";
    static const uint8_t repl[] = "many?";
    const size_t over = APPLE_MODERN_MAX_IMAGE_PATCHES + 6;
    const AppleModernImagePatch patch = {
        .name = "over", .image = APPLE_MODERN_BOOTKC, .anchor = anchor,
        .anchor_len = sizeof(anchor) - 1, .replacement = repl,
        .replacement_len = sizeof(repl) - 1, .replace_offset = 0,
        .expected_count = over, .changes = "c", .removes = "r",
    };
    const AppleModernImagePatchSet set = { "local", &patch, 1 };
    AppleModernImagePatchResult result = {0};
    Error *error = NULL;
    size_t size = 8192;
    /* Plant exactly as many real matches as the entry claims, so the refusal can
     * only come from the slot budget and not from a count mismatch. */
    uint8_t *buf = make_buf(size, "MANY!", 64, (unsigned)over);
    uint8_t *shadow = malloc(size);

    CHECK(shadow != NULL);
    memcpy(shadow, buf, size);
    CHECK(!apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC, buf,
                                                size, &result, &error));
    CHECK(error != NULL && strstr(error->message, "over") &&
          strstr(error->message, "result slots left"));
    clear_error(&error);
    CHECK(result.count == 0);
    /* The decisive assertion: nothing was written. */
    CHECK(!memcmp(buf, shadow, size));
    /* Exactly the array size still fits. */
    result = (AppleModernImagePatchResult){0};
    const AppleModernImagePatch fits = {
        .name = "fits", .image = APPLE_MODERN_BOOTKC, .anchor = anchor,
        .anchor_len = sizeof(anchor) - 1, .replacement = repl,
        .replacement_len = sizeof(repl) - 1, .replace_offset = 0,
        .expected_count = APPLE_MODERN_MAX_IMAGE_PATCHES,
        .changes = "c", .removes = "r",
    };
    const AppleModernImagePatchSet ok_set = { "local", &fits, 1 };
    uint8_t *exact = make_buf(size, "MANY!", 64,
                              (unsigned)APPLE_MODERN_MAX_IMAGE_PATCHES);
    CHECK(apple_modern_image_patch_apply_image(&ok_set, APPLE_MODERN_BOOTKC,
                                               exact, size, &result, &error));
    CHECK(error == NULL &&
          result.count == APPLE_MODERN_MAX_IMAGE_PATCHES);
    free(buf);
    free(shadow);
    free(exact);
}

/* ---- Test 8: expected_count > 1 applies to every match. ---- */
static void test_multi_expected(void)
{
    static const uint8_t anchor[] = "TWICE!";
    static const uint8_t repl[] = "twice?";
    const AppleModernImagePatch patch = {
        .name = "two", .image = APPLE_MODERN_BOOTKC, .anchor = anchor,
        .anchor_len = sizeof(anchor) - 1, .replacement = repl,
        .replacement_len = sizeof(repl) - 1, .replace_offset = 0,
        .expected_count = 2, .changes = "c", .removes = "r",
    };
    const AppleModernImagePatchSet set = { "local", &patch, 1 };
    AppleModernImagePatchResult result = {0};
    Error *error = NULL;
    size_t size = 4096, nlen = strlen("TWICE!");
    uint8_t *buf = make_buf(size, "TWICE!", 300, 2);

    CHECK(apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC, buf,
                                               size, &result, &error));
    CHECK(error == NULL && result.count == 2);
    CHECK(!memcmp(buf + 300, repl, nlen));
    CHECK(!memcmp(buf + 300 + nlen + 7, repl, nlen));
    /* One match when two are required -> refusal. */
    result = (AppleModernImagePatchResult){0};
    uint8_t *one = make_buf(size, "TWICE!", 300, 1);
    CHECK(!apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC, one,
                                                size, &result, &error));
    CHECK(strstr(error->message, "two") &&
          strstr(error->message, "found 1 times (expected 2)"));
    clear_error(&error);
    free(buf);
    free(one);
}

static void test_result_capacity(void)
{
    static const uint8_t first[] = "AAAA!", second[] = "BBBB!";
    static const uint8_t replacement[] = "done!";
    const AppleModernImagePatch patches[] = {
        {.name = "first", .image = APPLE_MODERN_BOOTKC, .anchor = first,
         .anchor_len = 5, .replacement = replacement, .replacement_len = 5,
         .expected_count = 2, .changes = "c", .removes = "r"},
        {.name = "second", .image = APPLE_MODERN_BOOTKC, .anchor = second,
         .anchor_len = 5, .replacement = replacement, .replacement_len = 5,
         .expected_count = 2, .changes = "c", .removes = "r"},
    };
    const AppleModernImagePatchSet set = {"capacity", patches, 2};
    uint8_t bytes[] = "AAAA!....BBBB!....AAAA!....BBBB!";
    uint8_t original[sizeof(bytes)];
    Error *error = NULL;
    AppleModernImagePatchResult result = {
        .count = APPLE_MODERN_MAX_IMAGE_PATCHES - 3,
    };
    memcpy(original, bytes, sizeof(bytes));
    /* The total across two entries must fit, including prior images' slots. */
    CHECK(!apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC,
            bytes, sizeof(bytes), &result, &error));
    CHECK(error && strstr(error->message, "result slots left"));
    CHECK(result.count == APPLE_MODERN_MAX_IMAGE_PATCHES - 3);
    CHECK(!memcmp(bytes, original, sizeof(bytes)));
    clear_error(&error);
    result.count = APPLE_MODERN_MAX_IMAGE_PATCHES - 4;
    CHECK(apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC,
            bytes, sizeof(bytes), &result, &error));
    CHECK(error == NULL && result.count == APPLE_MODERN_MAX_IMAGE_PATCHES);
    CHECK(!memcmp(bytes, "done!....done!....done!....done!", sizeof(bytes)));
    memcpy(bytes, original, sizeof(bytes));
    CHECK(!apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC,
            bytes, sizeof(bytes), NULL, &error));
    CHECK(error && strstr(error->message, "null argument"));
    clear_error(&error);
    result.count = APPLE_MODERN_MAX_IMAGE_PATCHES + 1;
    CHECK(!apple_modern_image_patch_apply_image(&set, APPLE_MODERN_BOOTKC,
            bytes, sizeof(bytes), &result, &error));
    CHECK(error && strstr(error->message, "invalid result count"));
    CHECK(!memcmp(bytes, original, sizeof(bytes)));
    clear_error(&error);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_demo_set_applies();
    test_anchor_missing();
    test_multiple_hits();
    test_length_mismatch();
    test_mask();
    test_set_lookup();
    test_no_targeted_patch();
    test_multi_expected();
    test_entry_budget();
    test_result_capacity();
    printf("PASS %u image-patch checks; no guest writes or execution\n", checks);
    return 0;
}
