/* T8140 disp0 pipe: window plan, faulting decode and reset qualification.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * argv[1] = the served or stock T8140 device tree (never modified).
 * argv[2] = optional second tree that must be REFUSED (the A13/t8030 ADT).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-disp0.h"

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)
/* Every refusal must both fail and say why; the standalone error shim aborts
 * if a second message is set over an unconsumed one, so each is consumed. */
#define REFUSE(expr) do { CHECK(!(expr)); CHECK(error); \
    error_free(error); error = NULL; } while (0)

/* The attested T8140 /arm-io/disp0 windows, after /arm-io ranges. */
static const uint64_t kAddress[APPLE_MODERN_DISP0_WINDOWS] = {
    UINT64_C(0x410000000), UINT64_C(0x412240000), UINT64_C(0x4123a8000),
    UINT64_C(0x4123ac000), UINT64_C(0x412800000), UINT64_C(0x302800000),
};
static const uint64_t kSize[APPLE_MODERN_DISP0_WINDOWS] = {
    0xafc000, 0x10000, 0x4000, 0x4000, 0x800000, 0xbc000,
};
/* Attested interrupts, in ADT order. */
static const uint32_t kIrq[APPLE_MODERN_DISP0_IRQS] = {
    0x2b1, 0x2c4, 0x2b4, 0x2b3, 0x2b2, 0x2b9, 0x2af, 0x2bd, 0x2b8,
};
/* reg[4] holds /arm-io/dcp, reg[5] is inside /arm-io/pmgr: neither is ours. */
static const uint32_t kKind[APPLE_MODERN_DISP0_WINDOWS] = {
    APPLE_MODERN_DISP0_WINDOW_PIPE, APPLE_MODERN_DISP0_WINDOW_OPAQUE,
    APPLE_MODERN_DISP0_WINDOW_OPAQUE, APPLE_MODERN_DISP0_WINDOW_OPAQUE,
    APPLE_MODERN_DISP0_WINDOW_DCP, APPLE_MODERN_DISP0_WINDOW_PMGR,
};

static uint8_t *slurp(const char *path, long *length)
{
    FILE *file = fopen(path, "rb");
    uint8_t *bytes;

    CHECK(file);
    CHECK(!fseek(file, 0, SEEK_END));
    *length = ftell(file);
    CHECK(*length > 0 && *length < 1 << 21);
    rewind(file);
    bytes = malloc(*length);
    CHECK(bytes);
    CHECK(fread(bytes, 1, *length, file) == (size_t)*length);
    fclose(file);
    return bytes;
}

static void decode_checks(AppleModernDisp0Core *core)
{
    uint32_t value = 0;
    bool kick = false;

    /* Frame size is the geometry the guest asks for, in the t8030 encoding. */
    core->width = 1024;
    core->height = 768;
    apple_modern_disp0_core_reset(core);
    CHECK(apple_modern_disp0_core_read(core, 0,
          APPLE_MODERN_DISP0_FRAME_SIZE, 4, &value));
    CHECK(value == ((1024u << 16) | 768u));

    /* Every shadow alias answers identically, and one past the last alias
     * faults. k = 5 on T8140, so 0xa00000 + offset is the last alias. */
    for (uint32_t copy = 0; copy <= core->plan.shadow_copies; copy++) {
        uint64_t offset = (uint64_t)copy * APPLE_MODERN_DISP0_SHADOW_STRIDE +
                          APPLE_MODERN_DISP0_FRAME_SIZE;
        CHECK(apple_modern_disp0_core_read(core, 0, offset, 4, &value));
        CHECK(value == ((1024u << 16) | 768u));
    }
    CHECK(!apple_modern_disp0_core_read(core, 0,
          (uint64_t)core->plan.shadow_copies *
              APPLE_MODERN_DISP0_SHADOW_STRIDE +
              APPLE_MODERN_DISP0_BLOCK_SPAN, 4, &value));

    /* Interrupt status is write-one-to-clear and gates the IRQ with enable. */
    CHECK(!apple_modern_disp0_core_irq_level(core));
    CHECK(apple_modern_disp0_core_raise(core,
          APPLE_MODERN_DISP0_INT_OUTPUT_READY) == false);
    CHECK(apple_modern_disp0_core_write(core, 0,
          APPLE_MODERN_DISP0_INT_ENABLE, 4,
          APPLE_MODERN_DISP0_INT_OUTPUT_READY, &kick));
    CHECK(!kick);
    CHECK(apple_modern_disp0_core_irq_level(core));
    CHECK(apple_modern_disp0_core_read(core, 0,
          APPLE_MODERN_DISP0_INT_STATUS, 4, &value));
    CHECK(value == APPLE_MODERN_DISP0_INT_OUTPUT_READY);
    CHECK(apple_modern_disp0_core_write(core, 0,
          APPLE_MODERN_DISP0_INT_STATUS, 4,
          APPLE_MODERN_DISP0_INT_OUTPUT_READY, &kick));
    CHECK(!apple_modern_disp0_core_irq_level(core));

    /* The kick bit, and only that bit, asks for a composition. */
    CHECK(apple_modern_disp0_core_write(core, 0, APPLE_MODERN_DISP0_KICK, 4,
          1u << APPLE_MODERN_DISP0_KICK_BIT, &kick));
    CHECK(kick && core->kicks == 1);
    CHECK(apple_modern_disp0_core_write(core, 0, APPLE_MODERN_DISP0_KICK, 4,
          ~(1u << APPLE_MODERN_DISP0_KICK_BIT), &kick));
    CHECK(!kick && core->kicks == 1);
    /* ... and the kick register is write-only. */
    CHECK(!apple_modern_disp0_core_read(core, 0, APPLE_MODERN_DISP0_KICK, 4,
          &value));

    /* Both GenPipes round-trip their modelled registers independently. */
    for (unsigned gp = 0; gp < APPLE_MODERN_DISP0_GP_COUNT; gp++) {
        uint64_t base = APPLE_MODERN_DISP0_GP_BASE +
                        (uint64_t)gp * APPLE_MODERN_DISP0_GP_BLOCK_STRIDE;
        static const uint32_t offsets[] = {
            APPLE_MODERN_DISP0_GP_CONFIG, APPLE_MODERN_DISP0_GP_PIXFMT,
            APPLE_MODERN_DISP0_GP_DATA_START, APPLE_MODERN_DISP0_GP_DATA_END,
            APPLE_MODERN_DISP0_GP_STRIDE,
        };
        for (unsigned i = 0; i < sizeof(offsets) / sizeof(*offsets); i++) {
            uint32_t word = 0x11111111u * (gp + 1) + offsets[i];
            CHECK(apple_modern_disp0_core_write(core, 0, base + offsets[i], 4,
                  word, &kick));
            CHECK(apple_modern_disp0_core_read(core, 0, base + offsets[i], 4,
                  &value));
            CHECK(value == word);
        }
        CHECK(apple_modern_disp0_core_write(core, 0,
              base + APPLE_MODERN_DISP0_GP_SRC_DIMS, 4, (640u << 16) | 480u,
              &kick));
        CHECK(apple_modern_disp0_core_read(core, 0,
              base + APPLE_MODERN_DISP0_GP_SRC_DIMS, 4, &value));
        CHECK(value == ((640u << 16) | 480u));
        CHECK(core->genpipe[gp].src_width == 640);
        CHECK(core->genpipe[gp].src_height == 480);
        CHECK(apple_modern_disp0_core_write(core, 0,
              base + APPLE_MODERN_DISP0_GP_DEST_DIMS, 4, (320u << 16) | 200u,
              &kick));
        CHECK(apple_modern_disp0_core_read(core, 0,
              base + APPLE_MODERN_DISP0_GP_DEST_DIMS, 4, &value));
        CHECK(value == ((320u << 16) | 200u));
        /* An unmodelled GenPipe register faults rather than reading zero. */
        CHECK(!apple_modern_disp0_core_read(core, 0, base + 0x160, 4, &value));
    }
    CHECK(core->genpipe[0].stride != core->genpipe[1].stride);

    /* The blend unit keeps its two layer configs and nothing else. */
    CHECK(apple_modern_disp0_core_write(core, 0,
          APPLE_MODERN_DISP0_BLEND_BASE + APPLE_MODERN_DISP0_BLEND_LAYER0, 4,
          0xdeadbeef, &kick));
    CHECK(apple_modern_disp0_core_read(core, 0,
          APPLE_MODERN_DISP0_BLEND_BASE + APPLE_MODERN_DISP0_BLEND_LAYER0, 4,
          &value));
    CHECK(value == 0xdeadbeef);
    CHECK(!apple_modern_disp0_core_read(core, 0,
          APPLE_MODERN_DISP0_BLEND_BASE + 0x1c, 4, &value));
}

int main(int argc, char **argv)
{
    AppleModernDisp0Core core;
    AppleModernDisp0Plan plan;
    Error *error = NULL;
    const uint64_t dram = UINT64_C(0x10000000000), dram_size = UINT64_C(8) << 30;
    long length = 0;
    uint8_t *tree;
    uint32_t value = 0;
    bool kick = false;

    CHECK(argc >= 2);
    tree = slurp(argv[1], &length);
    AppleModernBlob blob = { tree, length };

    /* --- the plan, derived from the served ADT -------------------------- */
    CHECK(apple_modern_disp0_plan_build(blob, dram, dram_size, NULL, 0, &plan,
                                        &error));
    CHECK(plan.shadow_copies == 5);
    CHECK(plan.dot_pitch == 460);
    CHECK(plan.mapped_count == 4);
    for (unsigned i = 0; i < APPLE_MODERN_DISP0_WINDOWS; i++) {
        CHECK(plan.windows[i].address == kAddress[i]);
        CHECK(plan.windows[i].size == kSize[i]);
        CHECK(plan.windows[i].kind == kKind[i]);
        CHECK(plan.windows[i].mapped ==
              (kKind[i] == APPLE_MODERN_DISP0_WINDOW_PIPE ||
               kKind[i] == APPLE_MODERN_DISP0_WINDOW_OPAQUE));
    }
    for (unsigned i = 0; i < APPLE_MODERN_DISP0_IRQS; i++) {
        CHECK(plan.interrupts[i] == kIrq[i]);
    }
    /* The pipe aperture really does decompose the way the port assumes. */
    CHECK(plan.windows[0].size == (uint64_t)plan.shadow_copies *
          APPLE_MODERN_DISP0_SHADOW_STRIDE + APPLE_MODERN_DISP0_BLOCK_SPAN);
    /* reg[5] is wholly inside the /arm-io/pmgr aperture whose 0x3028ac000
     * register is this project's ApplePMGR frontier: 0x302800000 + 0xac000. */
    CHECK(plan.windows[5].address + 0xac000 == UINT64_C(0x3028ac000));

    /* --- plan refusals -------------------------------------------------- */
    AppleModernDisp0Plan sink;
    for (unsigned i = 0; i < APPLE_MODERN_DISP0_WINDOWS; i++) {
        AppleModernAddressRange collision = { plan.windows[i].address, 4 };
        /* A collision with a window we map is fatal; one with a window we
         * deliberately leave to its owner is not. */
        if (plan.windows[i].mapped) {
            REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size,
                   &collision, 1, &sink, &error));
            CHECK(!sink.mapped_count);
        } else {
            CHECK(apple_modern_disp0_plan_build(blob, dram, dram_size,
                  &collision, 1, &sink, &error));
            CHECK(!memcmp(&sink, &plan, sizeof(plan)));
        }
        /*
         * A span adjacent to a mapped window is not a collision. Only windows
         * 0 and 1 have free neighbours: reg[2] and reg[3] are contiguous
         * (0x4123a8000+0x4000 == 0x4123ac000), which the overlap rule above
         * already proves it tolerates.
         */
        if (i < 2) {
            AppleModernAddressRange adjacent[] = {
                { plan.windows[i].address - 4, 4 },
                { plan.windows[i].address + plan.windows[i].size, 4 },
            };
            CHECK(apple_modern_disp0_plan_build(blob, dram, dram_size,
                  adjacent, 2, &sink, &error));
        }
    }
    REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size, NULL, 0, NULL,
                                         &error));
    REFUSE(apple_modern_disp0_plan_build(blob, dram, 0, NULL, 0, &sink,
                                         &error));
    REFUSE(apple_modern_disp0_plan_build(blob, UINT64_MAX, 2, NULL, 0, &sink,
                                         &error));
    REFUSE(apple_modern_disp0_plan_build(blob, plan.windows[0].address,
           UINT64_C(1) << 36, NULL, 0, &sink, &error));
    REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size, NULL, 1, &sink,
                                         &error));
    AppleModernAddressRange empty = { plan.windows[0].address, 0 };
    REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size, &empty, 1,
                                         &sink, &error));
    AppleModernAddressRange wrap = { UINT64_MAX - 1, 8 };
    REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size, &wrap, 1,
                                         &sink, &error));
    AppleModernAddressRange one = { plan.windows[0].address, 4 };
    REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size, &one,
           APPLE_MODERN_MAX_BOARD_EXCLUSIONS + 1, &sink, &error));
    /* Output may not alias the tree. */
    REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size, NULL, 0,
           (AppleModernDisp0Plan *)(void *)tree, &error));
    AppleModernBlob empty_tree = { tree, 0 };
    REFUSE(apple_modern_disp0_plan_build(empty_tree, dram, dram_size, NULL, 0,
                                         &sink, &error));
    AppleModernBlob null_tree = { NULL, 0 };
    REFUSE(apple_modern_disp0_plan_build(null_tree, dram, dram_size, NULL, 0,
                                         &sink, &error));
    /* Mutating any anchor the plan reads must refuse it: the dot pitch, the
     * window count, a window size, an interrupt, device_type. */
    AppleModernBlob property;
    static const char *const anchors[] = { "dot-pitch", "reg", "interrupts",
                                           "device_type" };
    for (unsigned i = 0; i < sizeof(anchors) / sizeof(*anchors); i++) {
        CHECK(apple_modern_adt_property(blob, "/arm-io/disp0", anchors[i],
                                        &property, &error));
        uint8_t *byte = (uint8_t *)property.data;
        *byte ^= 1;
        REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size, NULL, 0,
               &sink, &error));
        *byte ^= 1;
    }
    CHECK(apple_modern_adt_property(blob, "/arm-io", "ranges", &property,
                                    &error));
    uint8_t *parent = (uint8_t *)property.data + 8;
    *parent ^= 1;
    REFUSE(apple_modern_disp0_plan_build(blob, dram, dram_size, NULL, 0, &sink,
           &error));
    *parent ^= 1;
    CHECK(apple_modern_disp0_plan_build(blob, dram, dram_size, NULL, 0, &sink,
                                        &error));
    CHECK(!memcmp(&sink, &plan, sizeof(plan)));

    /* --- decode, on the real plan --------------------------------------- */
    memset(&core, 0, sizeof(core));
    core.plan = plan;
    decode_checks(&core);

    /* The three opaque windows and the two skipped ones model no register at
     * all, so every access to them faults and is recorded. */
    uint64_t faults_before = core.faults;
    for (unsigned w = 1; w < APPLE_MODERN_DISP0_WINDOWS; w++) {
        CHECK(!apple_modern_disp0_core_read(&core, w, 0, 4, &value));
        CHECK(!apple_modern_disp0_core_write(&core, w, 0x40, 4, 1, &kick));
    }
    CHECK(core.faults == faults_before + 2 * (APPLE_MODERN_DISP0_WINDOWS - 1));

    /* Out-of-range windows, sizes and alignments are refused without being
     * counted as faults of a real window. */
    uint64_t faults = core.faults;
    CHECK(!apple_modern_disp0_core_read(&core, APPLE_MODERN_DISP0_WINDOWS, 0, 4,
                                        &value));
    CHECK(!apple_modern_disp0_core_read(&core, 0, 0, 8, &value));
    CHECK(!apple_modern_disp0_core_read(&core, 0, 2, 4, &value));
    CHECK(!apple_modern_disp0_core_read(&core, 0, 0, 4, NULL));
    CHECK(!apple_modern_disp0_core_read(NULL, 0, 0, 4, &value));
    CHECK(!apple_modern_disp0_core_read(&core, 0, 0, 4, &core.int_status));
    CHECK(!apple_modern_disp0_core_write(&core, APPLE_MODERN_DISP0_WINDOWS, 0,
                                         4, 0, &kick));
    CHECK(!apple_modern_disp0_core_write(&core, 0, 0, 8, 0, &kick));
    CHECK(!apple_modern_disp0_core_write(&core, 0, 1, 4, 0, &kick));
    CHECK(!apple_modern_disp0_core_write(NULL, 0, 0, 4, 0, &kick));
    CHECK(core.faults == faults);
    /* An offset past the end of a mapped window faults. */
    CHECK(!apple_modern_disp0_core_read(&core, 0, plan.windows[0].size, 4,
                                        &value));
    CHECK(!apple_modern_disp0_core_read(&core, 1, plan.windows[1].size - 2, 4,
                                        &value));

    /* The frontier table remembers each distinct access once, never more than
     * its slots, and the fault counter keeps counting past them. */
    CHECK(core.frontier_count > 0);
    CHECK(core.frontier_count <= APPLE_MODERN_DISP0_FRONTIER_SLOTS);
    uint32_t distinct = core.frontier_count;
    for (unsigned i = 0; i < 64; i++) {
        CHECK(!apple_modern_disp0_core_read(&core, 1, 0, 4, &value));
    }
    CHECK(core.frontier_count == distinct);
    for (unsigned i = 0; i < 4096; i++) {
        CHECK(!apple_modern_disp0_core_read(&core, 1, 4 * (i + 1), 4, &value));
    }
    CHECK(core.frontier_count == APPLE_MODERN_DISP0_FRONTIER_SLOTS);
    CHECK(core.faults > APPLE_MODERN_DISP0_FRONTIER_SLOTS);
    for (uint32_t i = 0; i < core.frontier_count; i++) {
        CHECK(core.frontier[i].valid);
        CHECK(core.frontier[i].window < APPLE_MODERN_DISP0_WINDOWS);
        CHECK(core.frontier[i].address ==
              plan.windows[core.frontier[i].window].address +
                  core.frontier[i].offset);
    }

    /* Counters saturate instead of wrapping. */
    core.reads = core.writes = core.faults = core.kicks = UINT64_MAX;
    CHECK(apple_modern_disp0_core_read(&core, 0,
          APPLE_MODERN_DISP0_FRAME_SIZE, 4, &value));
    CHECK(apple_modern_disp0_core_write(&core, 0, APPLE_MODERN_DISP0_KICK, 4,
          1u << APPLE_MODERN_DISP0_KICK_BIT, &kick));
    CHECK(!apple_modern_disp0_core_read(&core, 1, 0, 4, &value));
    CHECK(core.reads == UINT64_MAX && core.writes == UINT64_MAX);
    CHECK(core.faults == UINT64_MAX && core.kicks == UINT64_MAX);

    /* Reset clears register state, counters and the frontier, and keeps the
     * plan and the geometry, which the board owns. */
    apple_modern_disp0_core_reset(&core);
    CHECK(!core.reads && !core.writes && !core.faults && !core.kicks);
    CHECK(!core.frontier_count && !core.int_status && !core.int_enable);
    CHECK(!core.blend_layer[0] && !core.blend_layer[1]);
    for (unsigned gp = 0; gp < APPLE_MODERN_DISP0_GP_COUNT; gp++) {
        CHECK(!core.genpipe[gp].config && !core.genpipe[gp].stride);
        CHECK(!core.genpipe[gp].src_width && !core.genpipe[gp].dest_height);
    }
    CHECK(core.width == 1024 && core.height == 768);
    CHECK(!memcmp(&core.plan, &plan, sizeof(plan)));

    /* --- the second tree must be refused -------------------------------- */
    if (argc >= 3) {
        long other_length = 0;
        uint8_t *other = slurp(argv[2], &other_length);
        AppleModernBlob other_blob = { other, other_length };
        REFUSE(apple_modern_disp0_plan_build(other_blob, dram, dram_size, NULL,
                                             0, &sink, &error));
        free(other);
    }

    free(tree);
    printf("{\"checks\": %u, \"shadow_copies\": %u, \"mapped_windows\": %u}\n",
           checks, plan.shadow_copies, plan.mapped_count);
    return 0;
}
