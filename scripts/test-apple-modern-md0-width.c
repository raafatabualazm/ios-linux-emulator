/* Core gate for the opt-in md0 width compatibility patch (no QEMU, no guest).
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Exercises the production source unchanged:
 *   hw/arm/apple-silicon/modern-kc-patch.c
 *     apple_modern_kc_md0_width_compat()
 *
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *    hw/arm/apple-silicon/modern-kc-patch.c \
 *    scripts/test-apple-modern-md0-width.c -o /tmp/test-modern-md0-width
 *
 * Fixtures are synthetic Mach-O filesets built in memory; no Apple image is
 * read, and the arithmetic oracle at the end is the one measured in
 * modern-emulator/evidence/features-20261009/w4-assets/md0-width/.
 */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hw/arm/apple-silicon/modern-kc-patch.h"

static unsigned checks;
static unsigned rejections;

void error_free(Error *error)
{
    free(error);
}

static void ok(bool condition, const char *what)
{
    if (!condition) {
        fprintf(stderr, "FAIL %s\n", what);
        exit(1);
    }
    checks++;
}

/* Asserts the call failed, named the reason, and left the image byte-exact. */
static void reject(uint8_t *image, const uint8_t *pristine, size_t len,
                   const char *what)
{
    Error *error = NULL;
    AppleModernMd0WidthPatch out;

    memset(&out, 0xA5, sizeof(out));
    ok(!apple_modern_kc_md0_width_compat(image, len, &out, &error),
       what);
    ok(error != NULL && strstr(error->message, "md0-width-compat") != NULL,
       "refusal names the option");
    ok(memcmp(image, pristine, len) == 0, "refusal left the image untouched");
    printf("REJECT %s: %s\n", what, error->message);
    error_free(error);
    rejections++;
}

/* ------------------------------------------------- instruction encoders ---
 * Independent of the production file's own constants: each is assembled here
 * from the AArch64 field layout so a typo in either copy is caught.
 */
static uint32_t enc_ldr_w(unsigned rt, unsigned rn, unsigned off)
{
    return 0xB9400000u | (((uint32_t)off / 4u) << 10) | ((uint32_t)rn << 5) |
           (uint32_t)rt;
}

static uint32_t enc_lsl_w12(unsigned rd, unsigned rn)
{
    /* UBFM Wd, Wn, #20, #19 : sf=0 opc=10 N=0 immr=20 imms=19 */
    return 0x53000000u | (20u << 16) | (19u << 10) | ((uint32_t)rn << 5) |
           (uint32_t)rd;
}

static uint32_t enc_lsl_x12(unsigned rd, unsigned rn)
{
    /* UBFM Xd, Xn, #52, #51 : sf=1 opc=10 N=1 immr=52 imms=51 */
    return 0xD3400000u | (52u << 16) | (51u << 10) | ((uint32_t)rn << 5) |
           (uint32_t)rd;
}

static uint32_t enc_cmp_x(unsigned rn, unsigned rm)
{
    return 0xEB00001Fu | ((uint32_t)rm << 16) | ((uint32_t)rn << 5);
}

static uint32_t enc_bcond(unsigned cond, unsigned imm19)
{
    return 0x54000000u | ((uint32_t)imm19 << 5) | (uint32_t)cond;
}

static uint32_t enc_add_w_lsl12(unsigned rd, unsigned rn, unsigned rm)
{
    return 0x0B000000u | ((uint32_t)rm << 16) | (12u << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t enc_sub_w_imm1(unsigned rd, unsigned rn)
{
    return 0x51000000u | (1u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t enc_udiv_w(unsigned rd, unsigned rn, unsigned rm)
{
    return 0x1AC00800u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) |
           (uint32_t)rd;
}

static uint32_t enc_nop(void)
{
    return 0xD503201Fu;
}

/* --------------------------------------------------------- image builder --
 * Minimal MH_MAGIC_64 fileset:
 *   0x0000 top header + one LC_FILESET_ENTRY naming the kernel at 0x1000
 *   0x1000 kernel header + one LC_SEGMENT_64 __TEXT_EXEC at TEXT_OFF
 *   TEXT_OFF .. text words
 */
#define KERNEL_OFF   0x1000u
#define TEXT_OFF     0x2000u
#define TEXT_WORDS   256u
#define IMAGE_LEN    (TEXT_OFF + TEXT_WORDS * 4u)

static void put32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16); p[3] = (uint8_t)(x >> 24);
}

static void put64(uint8_t *p, uint64_t x)
{
    put32(p, (uint32_t)x); put32(p + 4, (uint32_t)(x >> 32));
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void text_set(uint8_t *image, unsigned word, uint32_t insn)
{
    assert(word < TEXT_WORDS);
    put32(image + TEXT_OFF + word * 4u, insn);
}

static uint32_t text_get(const uint8_t *image, unsigned word)
{
    return get32(image + TEXT_OFF + word * 4u);
}

struct build_options {
    const char *entry_name;     /* fileset entry name (NULL -> omit the LC) */
    const char *segment_name;   /* __TEXT_EXEC, or another name */
    uint64_t    text_fileoff;
    uint64_t    text_filesize;
};

static void build(uint8_t *image, const struct build_options *o)
{
    uint8_t *lc;

    memset(image, 0, IMAGE_LEN);

    /* top-level header */
    put32(image, 0xFEEDFACFu);
    put32(image + 16, o->entry_name ? 1u : 0u);
    if (o->entry_name) {
        lc = image + 32;
        put32(lc, 0x80000035u);                  /* LC_FILESET_ENTRY */
        put32(lc + 4, 72u);                      /* cmdsize */
        put64(lc + 8, 0xFFFFFFF007000000ull);    /* vmaddr (unused) */
        put64(lc + 16, KERNEL_OFF);              /* fileoff */
        put32(lc + 24, 32u);                     /* entry_id offset */
        memcpy(lc + 32, o->entry_name, strlen(o->entry_name) + 1);
    }

    /* kernel sub-image header */
    put32(image + KERNEL_OFF, 0xFEEDFACFu);
    put32(image + KERNEL_OFF + 16, 1u);
    lc = image + KERNEL_OFF + 32;
    put32(lc, 0x19u);                            /* LC_SEGMENT_64 */
    put32(lc + 4, 72u);
    memcpy(lc + 8, o->segment_name, strlen(o->segment_name));
    put64(lc + 40, o->text_fileoff);
    put64(lc + 48, o->text_filesize);
    put32(lc + 64, 0u);                          /* nsects */

    for (unsigned i = 0; i < TEXT_WORDS; i++) {
        text_set(image, i, enc_nop());
    }
}

static struct build_options default_options(void)
{
    struct build_options o = { "com.apple.kernel", "__TEXT_EXEC", TEXT_OFF,
                               TEXT_WORDS * 4u };
    return o;
}

/* The two anchors, written at a caller-chosen word index. */
static void put_strategy(uint8_t *image, unsigned at, unsigned base_reg,
                         unsigned size_reg, unsigned blkoff_reg)
{
    text_set(image, at + 0, enc_ldr_w(size_reg, base_reg, 8));
    text_set(image, at + 1, enc_lsl_w12(size_reg, size_reg));
    text_set(image, at + 2, enc_cmp_x(blkoff_reg, size_reg));
    text_set(image, at + 3, enc_bcond(2 /* HS */, 7));
}

static void put_blockcount(uint8_t *image, unsigned at, unsigned base_reg,
                           unsigned size_reg, unsigned secs_reg,
                           unsigned acc_reg, unsigned res_reg)
{
    text_set(image, at + 0, enc_ldr_w(size_reg, base_reg, 8));
    text_set(image, at + 1, enc_ldr_w(secs_reg, base_reg, 16));
    text_set(image, at + 2, enc_add_w_lsl12(acc_reg, secs_reg, size_reg));
    text_set(image, at + 3, enc_sub_w_imm1(acc_reg, acc_reg));
    text_set(image, at + 4, enc_udiv_w(res_reg, acc_reg, secs_reg));
}

/* Shapes that must NOT match: every one breaks exactly one tie the published
 * source states, so a sloppier matcher would patch unrelated code. */
static void put_decoys(uint8_t *image, unsigned at)
{
    /* lsl w,w,#12 with no mdSize load before it */
    text_set(image, at + 0, enc_lsl_w12(3, 3));
    text_set(image, at + 1, enc_cmp_x(4, 3));
    text_set(image, at + 2, enc_bcond(2, 1));
    /* mdSize load at the wrong struct offset (+12 is mdFlags) */
    text_set(image, at + 4, enc_ldr_w(5, 6, 12));
    text_set(image, at + 5, enc_lsl_w12(5, 5));
    text_set(image, at + 6, enc_cmp_x(7, 5));
    text_set(image, at + 7, enc_bcond(2, 1));
    /* right loads and shift, wrong branch condition (NE, not HS) */
    text_set(image, at + 9, enc_ldr_w(8, 9, 8));
    text_set(image, at + 10, enc_lsl_w12(8, 8));
    text_set(image, at + 11, enc_cmp_x(10, 8));
    text_set(image, at + 12, enc_bcond(1 /* NE */, 1));
    /* shift result compared against a different register */
    text_set(image, at + 14, enc_ldr_w(11, 12, 8));
    text_set(image, at + 15, enc_lsl_w12(11, 11));
    text_set(image, at + 16, enc_cmp_x(13, 14));
    text_set(image, at + 17, enc_bcond(2, 1));
    /* add/sub/udiv chain whose udiv divides by the wrong register */
    text_set(image, at + 19, enc_ldr_w(15, 16, 8));
    text_set(image, at + 20, enc_ldr_w(17, 16, 16));
    text_set(image, at + 21, enc_add_w_lsl12(18, 17, 15));
    text_set(image, at + 22, enc_sub_w_imm1(18, 18));
    text_set(image, at + 23, enc_udiv_w(19, 18, 20));
    /* add/sub/udiv chain whose two loads use different base registers */
    text_set(image, at + 25, enc_ldr_w(21, 22, 8));
    text_set(image, at + 26, enc_ldr_w(23, 24, 16));
    text_set(image, at + 27, enc_add_w_lsl12(25, 23, 21));
    text_set(image, at + 28, enc_sub_w_imm1(25, 25));
    text_set(image, at + 29, enc_udiv_w(26, 25, 23));
    /* add/sub/udiv chain whose sub targets another register */
    text_set(image, at + 31, enc_ldr_w(1, 2, 8));
    text_set(image, at + 32, enc_ldr_w(3, 2, 16));
    text_set(image, at + 33, enc_add_w_lsl12(4, 3, 1));
    text_set(image, at + 34, enc_sub_w_imm1(5, 4));
    text_set(image, at + 35, enc_udiv_w(6, 5, 3));
    /* already-64-bit chain (what the patch produces) must not re-match */
    text_set(image, at + 37, enc_ldr_w(7, 8, 8));
    text_set(image, at + 38, enc_ldr_w(9, 8, 16));
    text_set(image, at + 39, enc_add_w_lsl12(10, 9, 7) | 0x80000000u);
    text_set(image, at + 40, enc_sub_w_imm1(10, 10) | 0x80000000u);
    text_set(image, at + 41, enc_udiv_w(11, 10, 9) | 0x80000000u);
    /* already-widened strategy shift must not re-match */
    text_set(image, at + 43, enc_ldr_w(12, 13, 8));
    text_set(image, at + 44, enc_lsl_x12(12, 12));
    text_set(image, at + 45, enc_cmp_x(14, 12));
    text_set(image, at + 46, enc_bcond(2, 1));
}

#define DECOY_WORDS 48u

/* --------------------------------------------------- arithmetic oracle ----
 * The two forms of memdev.c:437, written out in C so the acceptance number is
 * computed here and not copied from a log.
 */
static uint64_t blockcount_stock(uint64_t bytes, uint32_t secsize)
{
    uint32_t pages = (uint32_t)(bytes >> 12);
    uint32_t numerator = (uint32_t)(pages << 12) + secsize - 1u;

    return numerator / secsize;
}

static uint64_t blockcount_widened(uint64_t bytes, uint32_t secsize)
{
    uint64_t pages = bytes >> 12;
    uint64_t numerator = (pages << 12) + secsize - 1u;

    return numerator / secsize;
}

int main(void)
{
    static uint8_t image[IMAGE_LEN];
    static uint8_t pristine[IMAGE_LEN];
    struct build_options o;
    AppleModernMd0WidthPatch out;
    Error *error = NULL;

    /* ---------------------------------------------- 1. the happy path --- */
    o = default_options();
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    put_decoys(image, 120);
    memcpy(pristine, image, IMAGE_LEN);

    memset(&out, 0, sizeof(out));
    ok(apple_modern_kc_md0_width_compat(image, IMAGE_LEN, &out, &error),
       "patch applies to a well-formed fileset");
    ok(error == NULL, "no error on success");
    ok(out.strategy_anchor == TEXT_OFF + 10u * 4u, "strategy anchor offset");
    ok(out.blockcount_anchor == TEXT_OFF + 60u * 4u, "blockcount anchor offset");

    /* strategy: exactly the one shift word changed, to the 64-bit form */
    ok(out.strategy_before == enc_lsl_w12(9, 9), "strategy before word");
    ok(out.strategy_after == enc_lsl_x12(9, 9), "strategy after word");
    ok(text_get(image, 11) == enc_lsl_x12(9, 9), "strategy word rewritten");
    ok(text_get(image, 10) == enc_ldr_w(9, 20, 8), "strategy load untouched");
    ok(text_get(image, 12) == enc_cmp_x(19, 9), "strategy cmp untouched");
    ok(text_get(image, 13) == enc_bcond(2, 7), "strategy branch untouched");

    /* blockcount: the three arithmetic words gained the sf bit and nothing
     * else changed */
    ok(out.blockcount_before[0] == enc_add_w_lsl12(9, 8, 9), "bc before add");
    ok(out.blockcount_before[1] == enc_sub_w_imm1(9, 9), "bc before sub");
    ok(out.blockcount_before[2] == enc_udiv_w(8, 9, 8), "bc before udiv");
    ok(out.blockcount_after[0] == (enc_add_w_lsl12(9, 8, 9) | 0x80000000u),
       "bc after add is 64-bit");
    ok(out.blockcount_after[1] == (enc_sub_w_imm1(9, 9) | 0x80000000u),
       "bc after sub is 64-bit");
    ok(out.blockcount_after[2] == (enc_udiv_w(8, 9, 8) | 0x80000000u),
       "bc after udiv is 64-bit");
    for (unsigned i = 0; i < 3; i++) {
        ok((out.blockcount_after[i] ^ out.blockcount_before[i]) == 0x80000000u,
           "exactly the sf bit changed");
    }
    ok(text_get(image, 60) == enc_ldr_w(9, 8, 8), "bc mdSize load untouched");
    ok(text_get(image, 61) == enc_ldr_w(8, 8, 16), "bc secsize load untouched");

    /* nothing else in the image moved: 4 words differ, and only those 4 */
    {
        unsigned differing = 0;
        for (size_t i = 0; i < IMAGE_LEN; i += 4) {
            if (memcmp(image + i, pristine + i, 4) != 0) {
                differing++;
            }
        }
        ok(differing == 4, "exactly four instruction words changed");
    }

    /* ----------------------------- 2. the patch is not re-appliable ----- */
    {
        uint8_t again[IMAGE_LEN];

        memcpy(again, image, IMAGE_LEN);
        reject(again, image, IMAGE_LEN,
               "a second application finds no 32-bit anchor");
    }

    /* ------------------------------------- 3. decoys alone never match -- */
    o = default_options();
    build(image, &o);
    put_decoys(image, 0);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "decoy shapes only");

    /* ---------------------------------- 4. one anchor without the other - */
    o = default_options();
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "strategy anchor but no blockcount");

    o = default_options();
    build(image, &o);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "blockcount anchor but no strategy");

    /* ------------------------------------- 5. an ambiguous anchor ------- */
    o = default_options();
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_strategy(image, 30, 21, 5, 6);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "strategy anchor matched twice");

    o = default_options();
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    put_blockcount(image, 80, 3, 4, 3, 5, 6);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "blockcount anchor matched twice");

    /* ------------------------------- 6. malformed or foreign containers - */
    o = default_options();
    o.entry_name = NULL;
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "no fileset entry at all");

    o = default_options();
    o.entry_name = "com.apple.security.AppleImage4";
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "fileset entry is not the kernel");

    o = default_options();
    o.segment_name = "__TEXT";
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "kernel has no __TEXT_EXEC");

    o = default_options();
    o.text_filesize = IMAGE_LEN;             /* runs past the end of the image */
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "__TEXT_EXEC runs past the image");

    o = default_options();
    o.text_fileoff = TEXT_OFF + 2u;          /* not 4-byte aligned */
    o.text_filesize = TEXT_WORDS * 4u - 4u;
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "__TEXT_EXEC is unaligned");

    o = default_options();
    o.text_filesize = 16u;                   /* shorter than either anchor */
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    memcpy(pristine, image, IMAGE_LEN);
    reject(image, pristine, IMAGE_LEN, "__TEXT_EXEC too short for an anchor");

    /* a NULL image is refused without dereferencing it */
    {
        Error *null_error = NULL;

        ok(!apple_modern_kc_md0_width_compat(NULL, IMAGE_LEN, NULL,
                                             &null_error),
           "NULL kernel cache is refused");
        ok(null_error != NULL &&
           strstr(null_error->message, "md0-width-compat") != NULL,
           "NULL refusal names the option");
        printf("REJECT NULL image: %s\n", null_error->message);
        error_free(null_error);
        rejections++;
    }

    /* a NULL out pointer is allowed */
    o = default_options();
    build(image, &o);
    put_strategy(image, 10, 20, 9, 19);
    put_blockcount(image, 60, 8, 9, 8, 9, 8);
    ok(apple_modern_kc_md0_width_compat(image, IMAGE_LEN, NULL, &error),
       "NULL out pointer is accepted");
    ok(error == NULL, "no error with a NULL out pointer");
    ok(text_get(image, 11) == enc_lsl_x12(9, 9),
       "NULL out pointer still patches");

    /* register independence: a differently allocated pair still patches */
    o = default_options();
    build(image, &o);
    put_strategy(image, 40, 2, 17, 3);
    put_blockcount(image, 90, 4, 5, 6, 7, 1);
    memset(&out, 0, sizeof(out));
    ok(apple_modern_kc_md0_width_compat(image, IMAGE_LEN, &out, &error),
       "patch is register-allocation independent");
    ok(out.strategy_after == enc_lsl_x12(17, 17),
       "widened shift keeps the matched register");
    ok(text_get(image, 92) == (enc_add_w_lsl12(7, 6, 5) | 0x80000000u),
       "widened add keeps its registers");
    ok(text_get(image, 94) == (enc_udiv_w(1, 7, 6) | 0x80000000u),
       "widened udiv keeps its registers");

    /* --------------------------------- 7. the acceptance arithmetic ----- */
    /* The three rows measured in w4-assets/md0-width/ (stock kernel). */
    ok(blockcount_stock(UINT64_C(3221225472), 512) == 6291456,
       "stock 3 GiB -> 6,291,456 blocks (no wrap below 4 GiB)");
    ok(blockcount_stock(UINT64_C(5368709120), 512) == 2097152,
       "stock 5 GiB -> 2,097,152 blocks (measured)");
    ok(blockcount_stock(UINT64_C(10099884032), 512) == 2949120,
       "stock 9.41 GiB -> 2,949,120 blocks (measured)");
    /* The acceptance oracle for this track. */
    ok(blockcount_widened(UINT64_C(10099884032), 512) == 19726336,
       "widened 9.41 GiB -> 19,726,336 blocks (acceptance oracle)");
    ok(blockcount_widened(UINT64_C(3221225472), 512) == 6291456,
       "widened 3 GiB is unchanged");
    ok(blockcount_widened(UINT64_C(5368709120), 512) == 10485760,
       "widened 5 GiB -> 10,485,760 blocks");
    ok(blockcount_widened(UINT64_C(10099884032), 512) * 512 ==
       UINT64_C(10099884032),
       "widened device size equals the container size exactly");
    ok(blockcount_stock(UINT64_C(10099884032), 512) * 512 <
       UINT64_C(10099884032),
       "stock device size is smaller than the container, which APFS refuses");

    printf("PASS %u semantic checks, %u refusals\n", checks, rejections);
    return 0;
}
