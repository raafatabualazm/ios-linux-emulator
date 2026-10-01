/*
 * AFL 2.57b forkserver, coverage map, and persistent-mode handshake for
 * ChefKiss Inferno. Ported from the qemu-t8030 integration
 * used by the iOS 14 edition of this module (softmmu/afl-bootstrap.c and
 * the HINT #0x3X hypercalls in target/arm/helper-a64.c).
 *
 * The iOS 27 qemu-sptm port has its own runtime in qemu-afl/. This Inferno
 * runtime adds per-vCPU edge history and a synchronous persistent stop so
 * parallel TCG execution cannot corrupt iteration boundaries or the map.
 *
 * Differences from the original iOS 14 edition:
 *
 *   - qemu-t8030 restored a savevm snapshot between cases. Both modern
 *     trees use persistent mode instead, with no guest-state reset: the guest
 *     boots once and the harness loops over testcases. Guest kernel state
 *     accumulates across cases, which is documented in the chapter. On
 *     qemu-sptm this was forced (`loadvm` fails in the ARM cpreg post-load
 *     hook); the Inferno lab uses its harness loop directly.
 *
 *   - qemu-t8030 hooked TB execution from cpu-exec.c, which was compiled
 *     per target in QEMU 6.1. Modern QEMU compiles it once, so the coverage
 *     call is emitted per translation block from the AArch64 translator
 *     instead (HELPER(fuzz_tb_trace)).
 *
 * The forkserver writes hello on FORKSRV_FD + 1, forks on demand, then
 * waits for all vCPU threads to stop before publishing the map.
 */
#include "qemu/osdep.h"
#include <dirent.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include "afl/afl.h"
#include "qemu/atomic.h"

/* afl-fuzz scans the target for this marker to enable persistent mode. */
static volatile unsigned char *afl_persist_sig
    __attribute__((used)) = (unsigned char *)"##SIG_AFL_PERSISTENT##";

static uint8_t __afl_area_initial[MAP_SIZE];
uint8_t *__afl_area_ptr = __afl_area_initial;

#define AFL_MAX_CPUS 256

struct afl_cpu_history {
    uint64_t prev_loc;
    uint64_t prev_tb_start, prev_tb_end, interrupted_tb;
};

struct afl_interrupt_frame {
    struct afl_cpu_history history;
    bool was_suspended;
};

/* TB-edge history belongs to one guest vCPU. Sharing it across TCG threads
 * interleaves unrelated PC streams and creates races in the bitmap. */
static struct afl_cpu_history cpu_history[AFL_MAX_CPUS];
static struct afl_interrupt_frame scope_interrupt_stack[AFL_MAX_CPUS][16];
static uint8_t scope_interrupt_depth[AFL_MAX_CPUS];
/* Extra nested exceptions stay suppressed until their matching ERETs. */
static unsigned int scope_interrupt_overflow[AFL_MAX_CPUS];
static bool scope_interrupt_suspended[AFL_MAX_CPUS];
static uint64_t __x_thread_id; /* 0 = no thread filter */

#define GUARD_VALUE 0xffffffffffffffULL

struct afl_range {
    uint64_t start;
    uint64_t end;
};

static struct afl_range afl_ranges[32];
static int afl_range_count;

static bool is_persistent;
static bool afl_child;   /* true in the process that boots the guest */
static bool in_afl;      /* __AFL_SHM_ID was present */
static bool tid_filter_enabled = true;
static bool afl_debug;
static bool first_boundary = true;
static bool scoped_coverage;
static bool coverage_active;
static bool scope_debug;
static unsigned int scope_debug_budget;
static unsigned int scope_coverage_debug_budget;
static uint64_t scope_entry_delta, scope_return_delta;
static uint64_t scope_anchor_pc, scope_entry, scope_return;

/* The pinned harness announces its ASLR-adjusted HINT #0x31 PC. Offsets
 * select its syscall wrapper entry and the return from libc's syscall().
 * No guest code is changed, and only actual tested syscalls enter the map. */
void afl_scope_anchor(uint64_t pc)
{
    if (scoped_coverage) {
        scope_anchor_pc = pc;
        scope_entry = pc - scope_entry_delta;
        scope_return = pc - scope_return_delta;
        if (scope_debug) {
            fprintf(stderr, "AFL_SCOPE anchor pc=%016" PRIx64
                    " entry=%016" PRIx64 " return=%016" PRIx64
                    " tid=%016" PRIx64 "\n", pc, scope_entry,
                    scope_return, qatomic_read(&__x_thread_id));
        }
    }
}

void afl_user_pc(uint64_t pc, uint64_t tid, unsigned int cpu_index)
{
    uint64_t target_tid = qatomic_read(&__x_thread_id);

    if (cpu_index >= AFL_MAX_CPUS) {
        return;
    }
    if (!scoped_coverage || !target_tid || tid != target_tid) {
        return;
    }
    if (scope_debug && scope_debug_budget &&
        pc >= scope_entry - 0x100 && pc <= scope_anchor_pc) {
        fprintf(stderr, "AFL_SCOPE pc=%016" PRIx64 " active=%d\n",
                pc, qatomic_read(&coverage_active));
        scope_debug_budget--;
    }
    if (pc == scope_entry) {
        qatomic_set(&coverage_active, true);
        scope_interrupt_depth[cpu_index] = 0;
        scope_interrupt_overflow[cpu_index] = 0;
        scope_interrupt_suspended[cpu_index] = false;
        cpu_history[cpu_index].prev_loc = 0;
        cpu_history[cpu_index].prev_tb_start = GUARD_VALUE;
        cpu_history[cpu_index].prev_tb_end = GUARD_VALUE;
        cpu_history[cpu_index].interrupted_tb = GUARD_VALUE;
        if (scope_debug) {
            fprintf(stderr, "AFL_SCOPE entered syscall wrapper tid=%016" PRIx64 "\n", tid);
        }
    } else if (pc == scope_return) {
        qatomic_set(&coverage_active, false);
        if (scope_debug) {
            fprintf(stderr, "AFL_SCOPE left syscall wrapper tid=%016" PRIx64 "\n", tid);
        }
    }
}

bool afl_enabled(void)
{
    return in_afl;
}

void afl_add_range(uint64_t start, uint64_t size)
{
    if (afl_range_count < (int)ARRAY_SIZE(afl_ranges)) {
        afl_ranges[afl_range_count].start = start;
        afl_ranges[afl_range_count].end = start + size;
        afl_range_count++;
        if (afl_debug) {
            fprintf(stderr, "AFL: range 0x%lx-0x%lx\n",
                    (unsigned long)start, (unsigned long)(start + size));
        }
    }
}

void afl_filter_tid(uint64_t tid)
{
    if (tid_filter_enabled) {
        qatomic_set(&__x_thread_id, tid);
    }
}

/*
 * Edge coverage for one guest basic block, mirroring the qemu-t8030
 * hashing: bucket = ((pc >> 4) ^ (pc << 8)) ^ prev_loc, prev_loc >>= 1.
 */
bool afl_maybe_log(uint64_t cur_loc, uint64_t cur_end, uint64_t tid,
                   unsigned int cpu_index, uint64_t vbar_el1)
{
    struct afl_cpu_history *history;
    int i;
    uint64_t bucket;
    uint64_t target_tid = qatomic_read(&__x_thread_id);

    if (cpu_index >= AFL_MAX_CPUS) {
        return false;
    }
    history = &cpu_history[cpu_index];

    if (scope_debug && scoped_coverage && qatomic_read(&coverage_active) &&
        scope_coverage_debug_budget) {
        fprintf(stderr, "AFL_SCOPE kernel-pc=%016" PRIx64
                " tid=%016" PRIx64 " filter=%016" PRIx64
                " ranges=%d\n", cur_loc, tid,
                qatomic_read(&__x_thread_id),
                afl_range_count);
        scope_coverage_debug_budget--;
    }
    if (scoped_coverage && !qatomic_read(&coverage_active)) {
        return false;
    }
    if (target_tid != 0 && tid != target_tid) {
        return false;
    }

    /* XNU's syscall uses the lower-EL synchronous vector. An asynchronous
     * IRQ/FIQ/SError can interrupt it and run unrelated clock or scheduler
     * code on the same guest thread. Save the edge predecessor at those
     * vector entries, omit the handler, and restore the predecessor when
     * HELPER(exception_return) executes its ERET. */
    if (scoped_coverage && vbar_el1 && cur_loc >= vbar_el1 &&
        cur_loc < vbar_el1 + 0x800) {
        uint64_t vector_offset = cur_loc - vbar_el1;
        bool vector_start = (vector_offset & 0x7f) == 0;
        bool asynchronous = (vector_offset & 0x1ff) != 0;

        if (vector_start && (asynchronous ||
                             scope_interrupt_suspended[cpu_index])) {
            uint8_t depth = scope_interrupt_depth[cpu_index];
            if (depth < ARRAY_SIZE(scope_interrupt_stack[cpu_index])) {
                scope_interrupt_stack[cpu_index][depth].history = *history;
                scope_interrupt_stack[cpu_index][depth].was_suspended =
                    scope_interrupt_suspended[cpu_index];
                scope_interrupt_depth[cpu_index] = depth + 1;
            } else {
                scope_interrupt_overflow[cpu_index]++;
            }
            scope_interrupt_suspended[cpu_index] = true;
            return false;
        }
    }
    if (scoped_coverage && scope_interrupt_suspended[cpu_index]) {
        return false;
    }

    for (i = 0; i < afl_range_count; i++) {
        if (afl_ranges[i].start <= cur_loc &&
            cur_loc < afl_ranges[i].end) {
            break;
        }
    }
    if (i == afl_range_count) {
        return false;
    }

    /* Skip the block we were interrupted in; it will run again. */
    if (history->interrupted_tb == cur_loc) {
        history->interrupted_tb = GUARD_VALUE;
        return false;
    }

    /* Skip the block we just logged (same TB re-entered). */
    if (history->prev_tb_start <= cur_loc && cur_loc < history->prev_tb_end) {
        return false;
    }

    history->prev_tb_start = cur_loc;
    history->prev_tb_end = cur_end;

    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;
    bucket = cur_loc ^ history->prev_loc;
    qatomic_fetch_add(&__afl_area_ptr[bucket], 1);
    if (scope_debug && scoped_coverage && scope_coverage_debug_budget) {
        fprintf(stderr, "AFL_SCOPE increment bucket=%04" PRIx64
                " value=%u\n", bucket, __afl_area_ptr[bucket]);
        scope_coverage_debug_budget--;
    }
    history->prev_loc = cur_loc >> 1;
    return true;
}

void afl_exception_return(unsigned int cpu_index)
{
    uint8_t depth;

    if (!scoped_coverage || cpu_index >= AFL_MAX_CPUS) {
        return;
    }
    if (scope_interrupt_overflow[cpu_index]) {
        scope_interrupt_overflow[cpu_index]--;
        return;
    }
    depth = scope_interrupt_depth[cpu_index];
    if (!depth) {
        return;
    }
    depth--;
    scope_interrupt_depth[cpu_index] = depth;
    cpu_history[cpu_index] = scope_interrupt_stack[cpu_index][depth].history;
    scope_interrupt_suspended[cpu_index] =
        scope_interrupt_stack[cpu_index][depth].was_suspended;
}

static void __afl_map_shm(void)
{
    const char *id_str = getenv(SHM_ENV_VAR);

    if (id_str) {
        int shm_id = atoi(id_str);

        __afl_area_ptr = shmat(shm_id, NULL, 0);
        if (__afl_area_ptr == (void *)-1) {
            _exit(1);
        }
        /* Mark the map live so afl-fuzz does not discard us. */
        __afl_area_ptr[0] = 1;
        in_afl = true;
        if (scope_debug) {
            fprintf(stderr, "AFL_SCOPE shm id=%d ptr=%p env=%s\n",
                    shm_id, __afl_area_ptr, id_str);
        }
    }
}

/*
 * The persistent-mode iteration boundary, reached through HINT #0x33.
 * The SIGSTOP hands control back to afl-fuzz: it harvests the map, stages
 * the next testcase, and SIGCONTs us. There is no snapshot to reload, so
 * the guest keeps its state and only the map is reset.
 */
void afl_persistent_boundary(void)
{
    if (!is_persistent || !afl_child) {
        return;
    }

    /* The harness's first boundary precedes its first input. AFL expects
     * that input to execute before the first response, not a boot-only map. */
    if (first_boundary) {
        first_boundary = false;
    } else {
        qatomic_set(&coverage_active, false);
        if (scope_debug) {
            size_t i, nonzero = 0;
            for (i = 1; i < MAP_SIZE; i++) {
                nonzero += __afl_area_ptr[i] != 0;
            }
            fprintf(stderr, "AFL_SCOPE boundary nonzero=%zu marker=%u\n",
                    nonzero, __afl_area_ptr[0]);
        }
        /* Target the current vCPU thread so SIGSTOP is delivered before
         * this helper returns. kill(getpid(), SIGSTOP) only queued a
         * process-directed stop and could return early, letting the code
         * below clear the map before the forkserver harvested it. */
        raise(SIGSTOP);
    }

    /* Resumed for the next testcase. */
    (void)lseek(9, 0, SEEK_SET);
    memset(__afl_area_ptr, 0, MAP_SIZE);
    __afl_area_ptr[0] = 1;
    {
        unsigned int i;
        memset(cpu_history, 0, sizeof(cpu_history));
        memset(scope_interrupt_depth, 0, sizeof(scope_interrupt_depth));
        memset(scope_interrupt_overflow, 0, sizeof(scope_interrupt_overflow));
        memset(scope_interrupt_suspended, 0,
               sizeof(scope_interrupt_suspended));
        for (i = 0; i < AFL_MAX_CPUS; i++) {
            cpu_history[i].prev_tb_start = GUARD_VALUE;
            cpu_history[i].prev_tb_end = GUARD_VALUE;
            cpu_history[i].interrupted_tb = GUARD_VALUE;
        }
    }
    /* The thread filter survives: the harness thread is still the same. */
}

void afl_setup_stdio(void)
{
    int stdin_copy, dev_null;

    if (!getenv(SHM_ENV_VAR)) {
        return;
    }

    /* AFL stages each testcase on our stdin; move it to fd 9 for HINT
     * #0x32 and keep QEMU itself (the serial chardev) off the stream. */
    stdin_copy = dup(0);
    if (stdin_copy < 0) {
        return;
    }
    dup2(stdin_copy, 9);
    /* AFL wrote the first testcase before forking, leaving the shared file
     * offset at end-of-file. Rewind so the harness's first HINT #0x32 read
     * sees the seed; later cases are rewound by afl_persistent_boundary. */
    lseek(9, 0, SEEK_SET);
    dev_null = open("/dev/null", O_RDONLY);
    if (dev_null >= 0) {
        dup2(dev_null, 0);
        close(dev_null);
    }
    close(stdin_copy);
}

void afl_crash(void)
{
    if (afl_child) {
        signal(SIGSEGV, SIG_DFL);
        kill(getpid(), SIGSEGV);
    }
}

/* waitpid(..., WUNTRACED) can report the thread-group leader as stopped
 * before every QEMU vCPU thread has reached the group stop. Do not publish
 * the coverage map to AFL until all of the persistent child is quiescent. */
static bool __afl_child_threads_stopped(pid_t pid)
{
    char task_path[64];
    DIR *tasks;
    struct dirent *entry;
    bool found = false;
    bool stopped = true;

    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
    tasks = opendir(task_path);
    if (!tasks) {
        return false;
    }
    while ((entry = readdir(tasks)) != NULL) {
        char stat_path[128];
        char line[4096];
        char *right_paren;
        FILE *stat_file;
        long tid;
        char *end;

        tid = strtol(entry->d_name, &end, 10);
        if (*entry->d_name == '\0' || *end != '\0') {
            continue;
        }
        found = true;
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/task/%ld/stat",
                 pid, tid);
        stat_file = fopen(stat_path, "r");
        if (!stat_file || !fgets(line, sizeof(line), stat_file)) {
            if (stat_file) {
                fclose(stat_file);
            }
            stopped = false;
            break;
        }
        fclose(stat_file);
        right_paren = strrchr(line, ')');
        if (!right_paren || right_paren[1] != ' ' ||
            (right_paren[2] != 'T' && right_paren[2] != 't')) {
            stopped = false;
            break;
        }
    }
    closedir(tasks);
    return found && stopped;
}

static bool __afl_wait_for_child_group_stop(pid_t pid)
{
    unsigned int waited;

    for (waited = 0; waited < 1000; waited++) {
        if (__afl_child_threads_stopped(pid)) {
            if (scope_debug) {
                fprintf(stderr, "AFL_SCOPE all vCPU threads stopped after %u ms\n",
                        waited);
            }
            return true;
        }
        usleep(1000);
    }
    fprintf(stderr, "AFL: could not verify that all child threads stopped; "
            "refusing to publish the coverage map\n");
    return false;
}

/*
 * Forkserver, verbatim from the AFL 2.57b llvm bootstrap except that the
 * persistent WUNTRACED wait is unconditional. The constructor runs before
 * qemu_init(), so the process is single-threaded at every fork.
 */
static void __afl_start_forkserver(void)
{
    uint8_t tmp[4] = { 0 };
    pid_t child_pid = -1;
    int status;
    bool child_stopped = false;

    /* Phone home; failure means we are not running under afl-fuzz. */
    if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
        return;
    }

    for (;;) {
        uint32_t was_killed = 0;

        if (read(FORKSRV_FD, &was_killed, 4) != 4) {
            _exit(1);
        }

        if (child_stopped && was_killed) {
            child_stopped = false;
            if (waitpid(child_pid, &status, 0) < 0) {
                _exit(1);
            }
        }

        if (!child_stopped) {
            child_pid = fork();
            if (child_pid < 0) {
                _exit(1);
            }
            if (child_pid == 0) {
                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);
                afl_child = true;
                return; /* boots the guest, then runs the campaign */
            }
        } else {
            kill(child_pid, SIGCONT);
            child_stopped = false;
        }

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
            _exit(1);
        }

        if (waitpid(child_pid, &status, WUNTRACED) < 0) {
            _exit(1);
        }

        if (WIFSTOPPED(status)) {
            child_stopped = true;
            if (is_persistent) {
                if (!__afl_wait_for_child_group_stop(child_pid)) {
                    /* An infrastructure failure must not appear as a
                     * completed testcase or a guest crash to AFL. */
                    kill(child_pid, SIGKILL);
                    waitpid(child_pid, &status, 0);
                    _exit(1);
                }
            }
        }

        if (write(FORKSRV_FD + 1, &status, 4) != 4) {
            _exit(1);
        }
    }
}

static void __afl_manual_init(void)
{
    static bool init_done;

    if (init_done) {
        return;
    }
    init_done = true;
    __afl_map_shm();
    __afl_start_forkserver();
    /* Only the standalone process or the forked child returns here. */
}

__attribute__((constructor))
static void __afl_auto_init(void)
{
    /* An enabled build behaves like normal QEMU outside an AFL run. */
    if (!getenv(SHM_ENV_VAR)) {
        return;
    }
    is_persistent = !!getenv(PERSIST_ENV_VAR);
    tid_filter_enabled = !getenv("AFL_NO_TID_FILTER");
    afl_debug = !!getenv("AFL_DEBUG");

    const char *scope = getenv("AFL_HARNESS_SCOPE");
    if (scope) {
        char *end;
        scope_entry_delta = strtoull(scope, &end, 0);
        if (*end != ':') { fprintf(stderr, "Invalid AFL_HARNESS_SCOPE\n"); _exit(1); }
        scope_return_delta = strtoull(end + 1, &end, 0);
        if (*end || !scope_entry_delta || !scope_return_delta) {
            fprintf(stderr, "Invalid AFL_HARNESS_SCOPE\n"); _exit(1);
        }
        scoped_coverage = true;
        scope_debug = getenv("AFL_HARNESS_SCOPE_DEBUG") != NULL;
        scope_debug_budget = 128;
        scope_coverage_debug_budget = 128;
        if (!tid_filter_enabled) {
            fprintf(stderr, "Scoped coverage requires the harness thread filter\n");
            _exit(1);
        }
    }
    __afl_manual_init();
}
