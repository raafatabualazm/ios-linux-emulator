/* Check the ADT-derived MISC_CORES site against the RE's predicted address. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "hw/arm/apple-silicon/modern-pmgr.h"

static AppleModernBlob slurp(const char *path)
{
    FILE *f = fopen(path, "rb"); long n; uint8_t *d;
    assert(f && !fseek(f, 0, SEEK_END)); n = ftell(f);
    assert(n > 0 && !fseek(f, 0, SEEK_SET)); d = malloc(n);
    assert(d && fread(d, 1, n, f) == (size_t)n); fclose(f);
    return (AppleModernBlob){d, n};
}

int main(int argc, char **argv)
{
    AppleModernBlob t = slurp(argv[1]);
    AppleModernPMGRPlan plan;
    Error *e = NULL;
    unsigned win; uint32_t off;
    assert(argc == 2);
    assert(apple_modern_pmgr_plan_build(t, UINT64_C(1) << 40, UINT64_C(8) << 30,
                                        NULL, 0, &plan, &e) && !e);
    assert(apple_modern_pmgr_core_enable_site(t, &plan, &win, &off, &e) && !e);
    printf("MISC_CORES window %u offset 0x%05x -> PA 0x%llx\n", win, off,
           (unsigned long long)(plan.windows[win].base + off));
    /* RE: enable at physical 0x300734004, i.e. base 0x300734000. */
    assert(plan.windows[win].base + off == UINT64_C(0x300734000));
    assert(win == 0 && off == 0x34000);
    /* It must fall in a hole, not on top of a power cell. */
    for (unsigned i = 0; i < plan.cell_count; i++) {
        if (plan.cells[i].window != win) continue;
        assert(plan.cells[i].offset + 8 <= off ||
               plan.cells[i].offset >= off + 0x10);
    }
    printf("OK: inside window %u, clear of all %u cells\n", win, plan.cell_count);
    free((void *)t.data);
    return 0;
}
