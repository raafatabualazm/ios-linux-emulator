/* Modern AIC IRQ_CFG recording: production-source core test, no guest launch.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * cc -std=c11 -Wall -Wextra -Werror -DAPPLE_MODERN_AIC_STANDALONE -Iinclude \
 *   -fsanitize=address,undefined hw/intc/apple-modern-aic.c \
 *   scripts/test-apple-modern-aic-irq-config.c -o /tmp/test-aic-irq-config \
 *   && /tmp/test-aic-irq-config
 *
 * The expectations below are written from the layout in apple-modern-aic.h and
 * not from the implementation: the XNU read-modify-write (keep bits [31:8],
 * replace bits [7:0]) is the attested driver behaviour; the target [3:0] and
 * delay-index [7:5] split is analogy. The checks use an explicit check macro
 * because production sources are built with NDEBUG and an assert() would be
 * compiled out of the oracle.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/intc/apple-modern-aic.h"

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

/* Board geometry: /arm-io/aic of the stock iPhone17,3 tree. */
static AppleModernAICGeometry board_geometry(bool record)
{
    return (AppleModernAICGeometry){
        .revision = 3, .num_irqs = 4096, .max_irqs = 4096,
        .version_offset = 0x0, .config_offset = 0x14, .cap0_offset = 0x4,
        .maxnumirq_offset = 0xc, .irq_config_offset = 0x10000,
        .event_offset = APPLE_MODERN_AIC_EVENT_OFFSET,
        .timestamp_offset = 0x1000, .timestamp_size = 0x100,
        .mmio_size = 0x1cc000, .record_irq_config = record,
    };
}

static AppleModernAICCore *make(bool record)
{
    AppleModernAICCore *core = calloc(1, sizeof(*core));
    AppleModernAICGeometry geometry = board_geometry(record);
    const char *reason = NULL;

    CHECK(core);
    CHECK(apple_modern_aic_core_init(core, &geometry, &reason));
    return core;
}

static uint32_t cfg_offset(uint32_t irq)
{
    return 0x10000 + irq * 4;
}

static bool wr(AppleModernAICCore *c, uint64_t offset, uint32_t value)
{
    return apple_modern_aic_core_write(c, offset, 4, value);
}

static uint32_t rd(AppleModernAICCore *c, uint64_t offset)
{
    uint32_t value = 0xdeadbeef;

    CHECK(apple_modern_aic_core_read(c, offset, 4, &value));
    return value;
}

/* A value with every bit class exercised and nonzero for every irq. */
static uint32_t pattern(uint32_t irq)
{
    return ((irq * UINT32_C(2654435761)) ^ UINT32_C(0x5a5ac3f1)) | 1;
}

static void test_default_off(void)
{
    AppleModernAICCore *core = make(false), *before = malloc(sizeof(*core));
    static const uint32_t irqs[] = {0, 1, 42, 1092, 4094, 4095};
    static const uint32_t values[] = {1, 0x5, 0xe0, 0x10, 0x100, 0x80000000u,
                                      0xffffffffu, 0xa3};
    CHECK(before);
    /* Zero stores are the declared default route and stay accepted. */
    for (uint32_t irq = 0; irq < 4096; irq++) {
        CHECK(wr(core, cfg_offset(irq), 0));
        CHECK(rd(core, cfg_offset(irq)) == 0);
        CHECK(apple_modern_aic_core_irq_config(core, irq) == 0);
    }
    for (unsigned i = 0; i < sizeof(irqs) / sizeof(irqs[0]); i++) {
        for (unsigned j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
            memcpy(before, core, sizeof(*core));
            CHECK(!wr(core, cfg_offset(irqs[i]), values[j]));
            CHECK(!memcmp(before, core, sizeof(*core)));
            CHECK(rd(core, cfg_offset(irqs[i])) == 0);
        }
    }
    free(core);
    free(before);
}

/* Every readable 32-bit offset, with a marker for the unreadable ones. */
static void sweep(AppleModernAICCore *c, uint32_t *out)
{
    for (uint32_t offset = 0; offset < c->geometry.mmio_size; offset += 4) {
        uint32_t value;

        out[offset / 4] = apple_modern_aic_core_read(c, offset, 4, &value) ?
                          value : 0xfeedf00d;
    }
}

static void test_recording(void)
{
    AppleModernAICCore *core = make(true), *before = malloc(sizeof(*core));
    size_t words = core->geometry.mmio_size / 4;
    uint32_t *a = malloc(words * 4), *b = malloc(words * 4);

    CHECK(a && b && before);
    sweep(core, a);
    memcpy(before, core, sizeof(*core));
    for (uint32_t irq = 0; irq < 4096; irq++) {
        CHECK(wr(core, cfg_offset(irq), pattern(irq)));
    }
    sweep(core, b);
    for (size_t w = 0; w < words; w++) {
        uint32_t offset = w * 4;

        if (offset >= 0x10000 && offset < 0x10000 + 4096 * 4) {
            CHECK(b[w] == pattern((offset - 0x10000) / 4));
        } else {
            CHECK(b[w] == a[w]);   /* nothing outside the window moved */
        }
    }
    /* Controller state other than the recorded words is untouched. */
    CHECK(!memcmp(before->hardware, core->hardware, sizeof(core->hardware)));
    CHECK(!memcmp(before->software, core->software, sizeof(core->software)));
    CHECK(!memcmp(before->masked, core->masked, sizeof(core->masked)));
    CHECK(before->enabled == core->enabled && !core->enabled);
    CHECK(!apple_modern_aic_core_output(core));
    /* Decoded fields follow the analogy layout, per interrupt. */
    for (uint32_t irq = 0; irq < 4096; irq++) {
        uint32_t word = apple_modern_aic_core_irq_config(core, irq);

        CHECK(word == pattern(irq));
        CHECK((word & APPLE_MODERN_AIC_IRQ_CFG_TARGET_MASK) == (word & 0xf));
        CHECK(((word & APPLE_MODERN_AIC_IRQ_CFG_DELAY_MASK) >>
               APPLE_MODERN_AIC_IRQ_CFG_DELAY_SHIFT) == ((word >> 5) & 7));
    }
    CHECK(apple_modern_aic_core_irq_config(core, 4096) == 0);
    CHECK(apple_modern_aic_core_irq_config(core, 0xffffffffu) == 0);
    /* Zero is accepted and clears a recorded word without touching neighbours. */
    CHECK(wr(core, cfg_offset(100), 0));
    CHECK(rd(core, cfg_offset(100)) == 0);
    CHECK(rd(core, cfg_offset(99)) == pattern(99));
    CHECK(rd(core, cfg_offset(101)) == pattern(101));
    free(core);
    free(before);
    free(a);
    free(b);
}

static void test_xnu_read_modify_write(void)
{
    /* Attested: AppleInterruptControllerV3 reads the word, keeps [31:8] and
     * replaces [7:0] with the byte from aic-ext-intr-cfg. */
    AppleModernAICCore *core = make(true);
    static const struct { uint32_t irq, seed; uint8_t entry; } cases[] = {
        {7, 0xabcdef00u, 0x03}, {1092, 0, 0xa3}, {4095, 0xffffff7fu, 0x05},
        {0, 0x12345678u, 0x00}, {2048, 0x00000010u, 0xe0},
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint32_t offset = cfg_offset(cases[i].irq), old, merged;

        CHECK(wr(core, offset, cases[i].seed));
        old = rd(core, offset);
        CHECK(old == cases[i].seed);
        merged = (old & 0xffffff00u) | cases[i].entry;
        CHECK(wr(core, offset, merged));
        CHECK(rd(core, offset) == ((cases[i].seed & 0xffffff00u) | cases[i].entry));
        CHECK((rd(core, offset) >> 8) == (cases[i].seed >> 8));
    }
    free(core);
}

static void test_delivery_stays_on_cpu0(void)
{
    AppleModernAICCore *core = make(true);
    static const struct { uint32_t irq, cfg; } routes[] = {
        {42, 0x5},          /* a CPU the one-CPU model does not have */
        {1092, 0xa3},       /* delay index 5, target 3 */
        {4095, 0xffffff0f}, /* every undocumented bit set, target 15 */
        {0, 0xe0},          /* delay index 7, target 0 */
    };
    for (unsigned i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        uint32_t irq = routes[i].irq, word = irq / 32 * 4;
        uint32_t bit = UINT32_C(1) << (irq & 31);

        CHECK(wr(core, cfg_offset(irq), routes[i].cfg));
        CHECK(wr(core, 0x14, 1));                          /* enable */
        CHECK(!apple_modern_aic_core_output(core));
        /* MASK_CLEAR = SW_SET + 3 banks of 512 bytes. */
        CHECK(wr(core, 0x14000 + 0x600 + word, bit));      /* unmask */
        CHECK(!apple_modern_aic_core_output(core));
        CHECK(wr(core, 0x14000 + word, bit));              /* SW_SET */
        CHECK(apple_modern_aic_core_output(core));         /* delivered */
        CHECK(rd(core, APPLE_MODERN_AIC_EVENT_OFFSET) ==
              (APPLE_MODERN_AIC_EVENT_IRQ | irq));
        CHECK(!apple_modern_aic_core_output(core));        /* auto-masked */
        CHECK(rd(core, cfg_offset(irq)) == routes[i].cfg); /* still recorded */
        CHECK(wr(core, 0x14000 + 0x200 + word, bit));      /* SW_CLEAR */
    }
    /* A hardware input behaves the same with a nonzero route recorded. */
    CHECK(wr(core, cfg_offset(300), 0x6));
    CHECK(wr(core, 0x14000 + 0x600 + 300 / 32 * 4, UINT32_C(1) << (300 & 31)));
    CHECK(apple_modern_aic_core_set_level(core, 300, true));
    CHECK(apple_modern_aic_core_output(core));
    CHECK(rd(core, APPLE_MODERN_AIC_EVENT_OFFSET) ==
          (APPLE_MODERN_AIC_EVENT_IRQ | 300));
    free(core);
}

static void test_reset(void)
{
    AppleModernAICCore *core = make(true);

    CHECK(wr(core, cfg_offset(5), 0x1234abcd));
    CHECK(wr(core, cfg_offset(4095), 0xffffffffu));
    CHECK(apple_modern_aic_core_set_level(core, 77, true));
    apple_modern_aic_core_reset(core);       /* device reset */
    CHECK(rd(core, cfg_offset(5)) == 0 && rd(core, cfg_offset(4095)) == 0);
    CHECK(core->hardware[77 / 32] & (UINT32_C(1) << (77 & 31))); /* kept */
    CHECK(wr(core, cfg_offset(6), 0x77));
    CHECK(wr(core, 0x10, 1));                /* RESET register */
    CHECK(rd(core, cfg_offset(6)) == 0);
    CHECK(wr(core, 0x10, 0));                /* no reset requested */
    CHECK(wr(core, cfg_offset(6), 0x78));
    CHECK(wr(core, 0x10, 0));
    CHECK(rd(core, cfg_offset(6)) == 0x78);
    /* Recording survives a reset: the flag is geometry, not state. */
    CHECK(wr(core, 0x10, 1));
    CHECK(wr(core, cfg_offset(6), 0x79) && rd(core, cfg_offset(6)) == 0x79);
    free(core);
}

static void test_rejections_with_recording_on(void)
{
    AppleModernAICCore *core = make(true), *before = malloc(sizeof(*core));
    uint32_t value = 0;
    unsigned sizes[] = {1, 2, 8, 3};

    CHECK(before);
    CHECK(wr(core, cfg_offset(9), 0x42));
    memcpy(before, core, sizeof(*core));
    for (unsigned i = 0; i < 4; i++) {
        CHECK(!apple_modern_aic_core_write(core, cfg_offset(9), sizes[i], 0x77));
        CHECK(!apple_modern_aic_core_read(core, cfg_offset(9), sizes[i], &value));
    }
    CHECK(!apple_modern_aic_core_write(core, cfg_offset(9) + 2, 4, 0x77));
    CHECK(!apple_modern_aic_core_write(core, cfg_offset(9) + 1, 4, 0x77));
    CHECK(!apple_modern_aic_core_read(core, cfg_offset(9) + 2, 4, &value));
    CHECK(!apple_modern_aic_core_write(core, core->geometry.mmio_size, 4, 1));
    CHECK(!apple_modern_aic_core_write(core, core->geometry.mmio_size - 2, 4, 1));
    CHECK(!apple_modern_aic_core_read(core, core->geometry.mmio_size, 4, &value));
    CHECK(!apple_modern_aic_core_read(core, cfg_offset(9), 4, NULL));
    /* Registers that are not read-write stay refused whatever the option. */
    CHECK(!wr(core, 0x4, 0x1));                    /* cap0 */
    CHECK(!wr(core, 0xc, 0x1));                    /* maxnumirq */
    CHECK(!wr(core, APPLE_MODERN_AIC_EVENT_OFFSET, 1));
    CHECK(!wr(core, 0x14, 2));                     /* reserved config bit */
    CHECK(!wr(core, 0x10, 2));                     /* reserved reset bit */
    CHECK(!wr(core, 0x14000 + 4 * 512, 1));        /* HW_STATE is read-only */
    /* The first word after the window is the SW_SET bank, not IRQ_CFG. */
    CHECK(wr(core, 0x14000, 0x1));
    CHECK(core->software[0] == 1 && rd(core, cfg_offset(4095)) == 0);
    CHECK(rd(core, cfg_offset(9)) == 0x42);
    /* Everything above left the recorded word and all other state alone,
     * except the one deliberate SW_SET store. */
    before->software[0] = 1;
    CHECK(!memcmp(before, core, sizeof(*core)));
    free(core);
    free(before);
}

static void test_geometry_flag_is_copied(void)
{
    AppleModernAICCore *on = make(true), *off = make(false);

    CHECK(on->geometry.record_irq_config && !off->geometry.record_irq_config);
    CHECK(wr(on, cfg_offset(1), 0x21) && !wr(off, cfg_offset(1), 0x21));
    CHECK(rd(on, cfg_offset(1)) == 0x21 && rd(off, cfg_offset(1)) == 0);
    free(on);
    free(off);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_default_off();
    test_recording();
    test_xnu_read_modify_write();
    test_delivery_stays_on_cpu0();
    test_reset();
    test_rejections_with_recording_on();
    test_geometry_flag_is_copied();
    printf("PASS %u AIC IRQ_CFG checks; no guest launch\n", checks);
    return 0;
}
