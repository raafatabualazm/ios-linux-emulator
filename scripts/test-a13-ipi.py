#!/usr/bin/env python3
"""Exercise the real A13 IPI dispatch function without booting firmware.

Inferno does not carry QEMU's unit-test tree. Compile the dispatch function
from a13.c with small CPU and delivery stubs so the regression covers the
production algorithm, including its source-CPU loop. Run with Python 3 and
a C compiler; optionally pass an alternate a13.c to check an older version.
"""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


PRELUDE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define A13_MAX_CPU 6
#define BIT32(n) (UINT32_C(1) << (n))
#define IPI_RR_TYPE_DEFERRED (2U << 28)
#define IPI_RR_TYPE_NOWAKE (3U << 28)
#define ctz32(n) __builtin_ctz(n)

typedef struct AppleA13State {
    bool off, asleep;
} AppleA13State;
typedef struct AppleA13Cluster {
    AppleA13State *cpus[A13_MAX_CPU];
    uint32_t deferredIPI[A13_MAX_CPU], noWakeIPI[A13_MAX_CPU];
} AppleA13Cluster;

static unsigned deliveries, last_dest, last_src, last_type;
static bool apple_a13_is_off(const AppleA13State *cpu) { return cpu->off; }
static bool apple_a13_is_asleep(const AppleA13State *cpu) { return cpu->asleep; }
static void apple_a13_cluster_deliver_ipi(AppleA13Cluster *c, uint64_t dest,
                                        uint64_t src, uint64_t type)
{
    assert(c->cpus[dest]);
    deliveries++;
    last_dest = dest;
    last_src = src;
    last_type = type;
}
"""

TESTS = r"""
int main(void)
{
    AppleA13State cpu4 = { .asleep = true }, cpu5 = { 0 };
    AppleA13Cluster c = { .cpus = { [4] = &cpu4, [5] = &cpu5 } };

    /* CPU 0 is in the other cluster: its deferred IPI must wake CPU 4. */
    c.deferredIPI[0] = BIT32(4);
    apple_a13_cluster_tick(&c);
    assert(deliveries == 1 && last_src == 0 && last_dest == 4);
    assert(last_type == IPI_RR_TYPE_DEFERRED);
    assert(c.deferredIPI[0] == BIT32(4)); /* Ack, not tick, clears it. */
    c.deferredIPI[0] = 0;

    /* Cross-cluster no-wake IPIs wait for an awake destination. */
    c.noWakeIPI[1] = BIT32(4);
    apple_a13_cluster_tick(&c);
    assert(deliveries == 1 && c.noWakeIPI[1] == BIT32(4));
    cpu4.asleep = false;
    apple_a13_cluster_tick(&c);
    assert(deliveries == 2 && last_src == 1 && last_dest == 4);
    assert(last_type == IPI_RR_TYPE_NOWAKE);
    c.noWakeIPI[1] = 0;

    /* Powered-off CPUs never receive either kind of pending IPI. */
    cpu4.off = true;
    c.deferredIPI[0] = BIT32(4);
    c.noWakeIPI[1] = BIT32(4);
    apple_a13_cluster_tick(&c);
    assert(deliveries == 2);
    c.deferredIPI[0] = c.noWakeIPI[1] = 0;

    /* Preserve delivery from a sender that is in this cluster. */
    c.deferredIPI[4] = BIT32(5);
    apple_a13_cluster_tick(&c);
    assert(deliveries == 3 && last_src == 4 && last_dest == 5);
    assert(last_type == IPI_RR_TYPE_DEFERRED);
    puts("A13 deferred/no-wake IPI regression checks passed");
    return 0;
}
"""


def main():
    source = (Path(sys.argv[1]) if len(sys.argv) > 1 else
              Path(__file__).resolve().parents[1] / "hw/arm/apple-silicon/a13.c")
    text = source.read_text()
    start = text.index("static void apple_a13_cluster_tick(")
    end = text.index("\nstatic void apple_a13_cluster_ipicr_tick(", start)
    with tempfile.TemporaryDirectory(prefix="inferno-a13-ipi-") as directory:
        cfile = Path(directory) / "test.c"
        binary = Path(directory) / "test"
        cfile.write_text(PRELUDE + text[start:end] + TESTS)
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                       ["-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
