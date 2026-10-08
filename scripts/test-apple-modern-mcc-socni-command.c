/* SOCNI bank activation, independent events and command layout tests.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-mcc-socni-command.h"

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %u: %s\n", __LINE__, #c); exit(1); } } while (0)

int main(int argc, char **argv)
{
    AppleModernMCCSocniCore channels = {
        .reset_value = UINT64_MAX - 5, .commands_required = true,
    };
    AppleModernMCCSocniCommandCore command = {.channels = &channels};
    uint64_t value = 99;
    apple_modern_mcc_socni_core_reset(&channels);
    apple_modern_mcc_socni_command_core_reset(&command);
    for (unsigned bank = 0; bank < 3; bank++) {
        for (unsigned i = 0; i < apple_modern_mcc_socni_counter_count(bank); i++) {
            CHECK(apple_modern_mcc_socni_core_write(&channels, 2 * bank, 4 * i, 4, 3));
            CHECK(apple_modern_mcc_socni_core_event(&channels, bank, i, 17));
            CHECK(apple_modern_mcc_socni_core_read(&channels, 2 * bank + 1, 8 * i, 8, &value));
            CHECK(value == UINT64_MAX - 5);  /* Programming alone cannot start collection. */
        }
    }
    for (unsigned bank = 0; bank < 3; bank++) {
        CHECK(apple_modern_mcc_socni_command_core_write(&command, bank, 0, 4, 1));
        CHECK(apple_modern_mcc_socni_command_core_write(&command, bank, 0, 4, 1));
        for (unsigned b = 0; b < 3; b++) {
            for (unsigned i = 0; i < apple_modern_mcc_socni_counter_count(b); i++) {
                CHECK(apple_modern_mcc_socni_core_event(&channels, b, i, 17));
                CHECK(apple_modern_mcc_socni_core_read(&channels, 2 * b + 1, 8 * i, 8, &value));
                uint64_t expected = (UINT64_MAX - 5) + (b <= bank ? 17 * (bank - b + 1) : 0);
                CHECK(value == expected); /* Includes modulo overflow and no cross-bank activation. */
            }
        }
    }
    CHECK(command.writes == 6 && channels.active_banks == 7);
    for (unsigned bank = 0; bank < 3; bank++) {
        CHECK(command.requests[bank] == 2);
        for (unsigned i = 0; i < apple_modern_mcc_socni_counter_count(bank); i++) {
            uint64_t before = channels.values[bank][i];
            CHECK(apple_modern_mcc_socni_core_write(&channels, 2 * bank, 4 * i, 4, 0));
            CHECK(apple_modern_mcc_socni_core_event(&channels, bank, i, 23));
            CHECK(channels.values[bank][i] == before); /* Disabling is immediate. */
        }
    }
    AppleModernMCCSocniCore saved = channels;
    AppleModernMCCSocniCommandCore saved_command = command;
    for (unsigned bank = 0; bank < 4; bank++) {
        CHECK(!apple_modern_mcc_socni_command_core_read(&command, bank, 0, 4, &value));
        for (unsigned width = 0; width <= 8; width++) {
            CHECK(!apple_modern_mcc_socni_command_core_write(&command, bank, 1, width, 1));
            if (width != 4 || bank == 3) {
                CHECK(!apple_modern_mcc_socni_command_core_write(&command, bank, 0, width, 1));
            }
        }
        for (unsigned v = 0; v < 5; v++) {
            if (v != 1) {
                CHECK(!apple_modern_mcc_socni_command_core_write(&command, bank, 0, 4, v));
            }
        }
    }
    CHECK(!apple_modern_mcc_socni_command_core_write(NULL, 0, 0, 4, 1));
    CHECK(!memcmp(&channels, &saved, sizeof(saved)));
    CHECK(!memcmp(&command, &saved_command, sizeof(saved_command)));
    command.writes = command.requests[0] = UINT64_MAX;
    CHECK(apple_modern_mcc_socni_command_core_write(&command, 0, 0, 4, 1));
    CHECK(command.writes == UINT64_MAX && command.requests[0] == UINT64_MAX);
    apple_modern_mcc_socni_command_core_reset(&command);
    CHECK(command.channels == &channels && !command.writes && !channels.active_banks);
    CHECK(apple_modern_mcc_socni_core_write(&channels, 0, 0, 4, 3));
    uint64_t before = channels.values[0][0];
    CHECK(apple_modern_mcc_socni_core_event(&channels, 0, 0, 1));
    CHECK(channels.values[0][0] == before);
    apple_modern_mcc_socni_core_reset(&channels);
    CHECK(channels.commands_required && !channels.active_banks);

    CHECK(argc == 2);
    FILE *fp = fopen(argv[1], "rb");
    CHECK(fp && !fseek(fp, 0, SEEK_END));
    long size = ftell(fp);
    CHECK(size > 0 && size <= 8 * 1024 * 1024 && !fseek(fp, 0, SEEK_SET));
    uint8_t *tree = malloc(size);
    CHECK(tree && fread(tree, 1, size, fp) == (size_t)size);
    fclose(fp);
    AppleModernBlob blob = {tree, size};
    AppleModernMCCSocniCommandPlan plan;
    Error *error = NULL;
    const uint64_t dram = UINT64_C(0x10000000000), ram_size = UINT64_C(8) << 30;
    CHECK(apple_modern_mcc_socni_command_plan_build(blob, dram, ram_size, NULL, 0, &plan, &error));
    for (unsigned bank = 0; bank < 3; bank++) {
        uint64_t base = UINT64_C(0x24f008100) + bank * UINT64_C(0x1000000);
        CHECK(plan.addresses[bank] == base);
        AppleModernAddressRange overlap = {base, 4};
        CHECK(!apple_modern_mcc_socni_command_plan_build(blob, dram, ram_size, &overlap, 1, &plan, &error));
        CHECK(error != NULL); error_free(error); error = NULL;
        AppleModernAddressRange adjacent[] = {{base - 4, 4}, {base + 4, 4}};
        CHECK(apple_modern_mcc_socni_command_plan_build(blob, dram, ram_size, adjacent, 2, &plan, &error));
    }
    CHECK(!apple_modern_mcc_socni_command_plan_build(blob, dram, ram_size, NULL, 1, &plan, &error));
    CHECK(error != NULL); error_free(error); error = NULL;
    CHECK(!apple_modern_mcc_socni_command_plan_build(blob, dram, ram_size, NULL, 0,
        (AppleModernMCCSocniCommandPlan *)(void *)tree, &error));
    CHECK(error != NULL); error_free(error);
    free(tree);
    printf("PASS: %u SOCNI command checks\n", checks);
    return 0;
}
