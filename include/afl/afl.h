/*
 * AFL 2.57b integration for ChefKiss Inferno (iOS 14 / t8030), based on
 * the qemu-t8030 design from the iOS 14 edition of this module. The iOS 27
 * qemu-sptm port has a separate runtime under qemu-afl/.
 *
 * The host side of the contract (all implemented in accel/tcg/afl.c):
 *   - a constructor starts the forkserver before qemu_init() creates any
 *     thread, so every fork is single-threaded and safe;
 *   - the forked child boots the guest once and then persists: HINT #0x33
 *     stops the calling vCPU for the persistent-mode handshake, and the
 *     parent waits for every vCPU thread before publishing the map;
 *   - translated blocks call HELPER(fuzz_tb_trace) which writes edge
 *     coverage into the shared map, filtered to kernel text ranges and to
 *     the fuzzing thread;
 *   - HINT #0x32 reads the testcase AFL staged on fd 9 into guest memory;
 *   - HINT #0x30 reports whether the guest runs under afl-fuzz, and
 *     HINT #0x31 restricts coverage to the calling thread.
 */
#ifndef QEMU_AFL_AFL_H
#define QEMU_AFL_AFL_H

#include "qemu/osdep.h"

#define SHM_ENV_VAR     "__AFL_SHM_ID"
#define PERSIST_ENV_VAR "__AFL_PERSISTENT"
#define FORKSRV_FD      198
#define MAP_SIZE        (1 << 16)
#define AFL_MAX_TESTCASE_SIZE (1U << 20)

#ifdef CONFIG_AFL
extern uint8_t *__afl_area_ptr;

/* True when __AFL_SHM_ID is set, i.e. the process runs under afl-fuzz. */
bool afl_enabled(void);

/* Coverage: executable text ranges, thread filter, and per-vCPU history. */
void afl_add_range(uint64_t start, uint64_t size);
bool afl_maybe_log(uint64_t pc, uint64_t end, uint64_t tid,
                   unsigned int cpu_index, uint64_t vbar_el1);
void afl_exception_return(unsigned int cpu_index);
void afl_filter_tid(uint64_t tid);
void afl_scope_anchor(uint64_t pc);
void afl_user_pc(uint64_t pc, uint64_t tid, unsigned int cpu_index);

/* HINT #0x33: stop for the persistent-mode handshake, then reset the map. */
void afl_persistent_boundary(void);

/* Called from main(): stage AFL testcase input on fd 9, keep QEMU off fd 0. */
void afl_setup_stdio(void);

/* Guest panic: die by signal so afl-fuzz records a crash. */
void afl_crash(void);
#else
/* Normal, non-TCG, and non-Linux builds retain the upstream behavior. */
static inline bool afl_enabled(void)
{
    return false;
}

static inline void afl_add_range(uint64_t start, uint64_t size)
{
}

static inline void afl_setup_stdio(void)
{
}

static inline void afl_crash(void)
{
}
#endif

#endif /* QEMU_AFL_AFL_H */
