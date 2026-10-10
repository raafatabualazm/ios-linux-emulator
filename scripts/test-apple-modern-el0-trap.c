/* Core checks for the default-off EL0 BRK classifier and its trace line.
 *
 * Every expectation here is traceable to published LLVM source (the immediate
 * -> meaning mapping) or to the line format this track's analyser parses.
 * Nothing in this test touches a device, a guest or a firmware image.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hw/arm/apple-silicon/modern-el0-trap.h"

/*
 * Negative oracle. Built with -DORACLE_WRONG_EXPECTATION the test asserts the
 * wrong answer for BRK #1 and must therefore fail: that is how we show these
 * checks are capable of failing rather than merely capable of printing "pass".
 * Both branches are compiled by the driver, so neither is unreachable code.
 */
#ifdef ORACLE_WRONG_EXPECTATION
#define WANT_BUILTIN_TRAP "ptrauth-check-fail"
#else
#define WANT_BUILTIN_TRAP "builtin-trap"
#endif

static unsigned long checks;
static unsigned long failures;

static void expect(int ok, const char *what, unsigned long detail)
{
    checks++;
    if (!ok) {
        failures++;
        fprintf(stderr, "FAIL %s (0x%lx)\n", what, detail);
    }
}

static void expect_class(uint32_t imm, const char *want)
{
    const char *got = apple_modern_el0_trap_class(imm);
    expect(got != NULL, "class-not-null", imm);
    expect(got && strcmp(got, want) == 0, want, imm);
}

int main(void)
{
    char buf[256];
    char small[8];
    int n;

    /* 1. The four named classes, at every immediate the published source
     *    actually assigns, and nowhere else. */
    expect_class(0x0001, WANT_BUILTIN_TRAP);
    expect_class(0xf000, "debugtrap");
    for (uint32_t k = 0; k <= 0xff; k++) {
        expect_class(0x5500 | k, "ubsan-trap");
    }
    for (uint32_t k = 0xc470; k <= 0xc473; k++) {
        expect_class(k, "ptrauth-check-fail");
    }

    /* 2. The boundaries. The ranges must not leak by one in either direction. */
    expect_class(0x0000, "unclassified");
    expect_class(0x0002, "unclassified");
    expect_class(0x54ff, "unclassified");
    expect_class(0x5600, "unclassified");
    expect_class(0xc46f, "unclassified");
    expect_class(0xc474, "unclassified");
    expect_class(0xefff, "unclassified");
    expect_class(0xf001, "unclassified");

    /* 3. Exhaustive: every 16-bit immediate gets a non-NULL class, and the
     *    count of immediates in each class is exactly what the published
     *    source implies (1 trap, 1 debugtrap, 256 ubsan, 4 ptrauth). */
    unsigned long named[4] = {0, 0, 0, 0};
    for (uint32_t imm = 0; imm <= 0xffff; imm++) {
        const char *c = apple_modern_el0_trap_class(imm);
        checks++;
        if (!c) {
            failures++;
            fprintf(stderr, "FAIL null class 0x%04x\n", imm);
            continue;
        }
        if (!strcmp(c, "builtin-trap")) {
            named[0]++;
        } else if (!strcmp(c, "debugtrap")) {
            named[1]++;
        } else if (!strcmp(c, "ubsan-trap")) {
            named[2]++;
        } else if (!strcmp(c, "ptrauth-check-fail")) {
            named[3]++;
        } else if (strcmp(c, "unclassified")) {
            failures++;
            fprintf(stderr, "FAIL unknown class name %s\n", c);
        }
    }
    expect(named[0] == 1, "builtin-trap-count", named[0]);
    expect(named[1] == 1, "debugtrap-count", named[1]);
    expect(named[2] == 256, "ubsan-trap-count", named[2]);
    expect(named[3] == 4, "ptrauth-count", named[3]);

    /* 4. Only the low 16 bits of the syndrome's comment field are used: a
     *    caller handing us a full 32-bit value must classify the same. */
    expect_class(0xdead0001, WANT_BUILTIN_TRAP);
    expect_class(0x0000c471, "ptrauth-check-fail");

    /* 5. The trace line: exact text, for a value this track quotes. */
    n = apple_modern_el0_trap_format(buf, sizeof(buf), 1,
                                     0x00000001a2b3c4d4ULL,
                                     0x0000000cafe00000ULL);
    expect(n > 0, "format-returns-length", (unsigned long)n);
    expect(strcmp(buf,
                  "apple-modern: el0-trap brk #0x0001 (builtin-trap) "
                  "pc=0x00000001a2b3c4d4 ttbr0=0x0000000cafe00000") == 0,
           "format-exact", 0);
    expect((size_t)n == strlen(buf), "format-length-matches", (unsigned long)n);

    /* 6. A second value, with the immediate masked and a named ptrauth key. */
    n = apple_modern_el0_trap_format(buf, sizeof(buf), 0xffff0000u | 0xc472,
                                     0, ~0ULL);
    expect(strcmp(buf,
                  "apple-modern: el0-trap brk #0xc472 (ptrauth-check-fail) "
                  "pc=0x0000000000000000 ttbr0=0xffffffffffffffff") == 0,
           "format-exact-2", 0);

    /* 7. Truncation is safe: a short buffer stays NUL-terminated and the
     *    return value is still the full length (snprintf contract). */
    n = apple_modern_el0_trap_format(small, sizeof(small), 1, 0, 0);
    expect(small[sizeof(small) - 1] == '\0', "short-buffer-terminated", 0);
    expect(strlen(small) == sizeof(small) - 1, "short-buffer-filled",
           strlen(small));
    expect(n > (int)sizeof(small), "short-buffer-length", (unsigned long)n);

    printf("{\"passed\":%s,\"checks\":%lu,\"failures\":%lu,"
           "\"firmware_executed\":false,\"guest_executed\":false}\n",
           failures ? "false" : "true", checks, failures);
    return failures ? 1 : 0;
}
