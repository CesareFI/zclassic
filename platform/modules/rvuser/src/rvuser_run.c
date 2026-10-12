/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rvuser_run, the budgeted run loop. Guest RAM is one zeroed
 * allocation through the repo allocator, sized by the caller's memory cap and
 * freed before return. The work budget counts retired instructions plus one
 * unit per system call; the retired count is reported separately. */
#include "rvuser_internal.h"
#include "base/safe_alloc.h"
#include "base/log_macros.h"
#include <stdlib.h>
#include <string.h>

static enum rvuser_stop ru_stop_for(enum rvuser_error err)
{
    if (err == RVUSER_ERR_SEGMENT_RANGE || err == RVUSER_ERR_NO_STACK)
        return RVUSER_STOP_MEMORY_CAP;
    return RVUSER_STOP_SETUP;
}

static enum rvuser_error ru_check_limits(const struct rvuser_limits *lim, size_t *stack)
{
    *stack = lim->stack_bytes ? lim->stack_bytes : RU_STACK_DEFAULT;
    if (lim->max_work == 0 || lim->max_syscalls == 0) return RVUSER_ERR_LIMITS;
    if (lim->mem_bytes < 2 * RU_PAGE || lim->mem_bytes > RU_MEM_MAX) return RVUSER_ERR_LIMITS;
    if ((lim->mem_bytes & (RU_PAGE - 1u)) || (*stack & (RU_PAGE - 1u))) return RVUSER_ERR_LIMITS;
    if (*stack >= lim->mem_bytes) return RVUSER_ERR_LIMITS;
    return RVUSER_ERR_NONE;
}

/* Checked range before any layout: lo + mem_bytes must not wrap and the image must end inside it.
 * Subtraction form throughout; runs before guest RAM is allocated. */
static enum rvuser_error ru_check_extent(const struct ru_image *img, size_t mem_bytes)
{
    if (img->lo > UINT64_MAX - (uint64_t)mem_bytes || img->hi < img->lo ||
        img->hi - img->lo > (uint64_t)mem_bytes)
        LOG_RETURN(RVUSER_ERR_SEGMENT_RANGE, "rvuser", "image [%#llx,%#llx) does not fit guest memory",
                   (unsigned long long)img->lo, (unsigned long long)img->hi);
    return RVUSER_ERR_NONE;
}

/* Heap sits between the image end and the stack floor. */
static enum rvuser_error ru_prepare(struct ru_proc *p, const uint8_t *elf,
                                    const struct ru_image *img, size_t stack)
{
    enum rvuser_error err = ru_elf_map(elf, img, &p->mem);
    if (err != RVUSER_ERR_NONE) return err;
    /* base + size cannot wrap here: rvuser_run ran ru_check_extent first, and size > stack. */
    uint64_t floor = p->mem.base + p->mem.size - stack;
    if (img->hi > floor) {
        LOG_WARN("rvuser", "image end %#llx leaves no room for the stack", (unsigned long long)img->hi);
        return RVUSER_ERR_NO_STACK;
    }
    p->heap_base = p->heap_cur = img->hi;
    p->heap_end = floor;
    rvemu_hart_init(&p->hart, img->entry);
    p->hart.x[1] = img->entry; /* exec_setregs: ra = entry */
    /* lp64d programs use FP from the first instruction: FreeBSD riscv exec_setregs leaves FS
     * Initial (01) in the user sstatus (sys/riscv/riscv/exec_machdep.c). rvemu gates every FP
     * instruction on mstatus.FS != Off (rvemu_fpu.c), so start the hart there. */
    p->hart.csr.mstatus = (p->hart.csr.mstatus & ~RU_MSTATUS_FS) | RU_MSTATUS_FS_INITIAL;
    return RVUSER_ERR_NONE;
}

/* Host abort. With a should_stop hook the run is cut into slices of stop_check_interval retired
 * instructions (default RU_STOP_INTERVAL_DEFAULT) and the hook is asked between slices. Slicing
 * only moves where rvemu_run returns; the hart resumes exactly where it stopped, so a hook that
 * never fires leaves output, instret and work unchanged. The host clock is never read here. */
static uint64_t ru_stop_interval(const struct ru_proc *p)
{
    uint64_t iv = p->io->stop_check_interval;
    return iv ? iv : RU_STOP_INTERVAL_DEFAULT;
}

static uint64_t ru_slice_limit(const struct ru_proc *p, uint64_t left)
{
    if (!p->io->should_stop) return left;
    uint64_t room = ru_stop_interval(p) - p->since_check;
    return room < left ? room : left;
}

/* True when a full interval has retired since the last ask and the hook says stop. */
static bool ru_host_abort(struct ru_proc *p)
{
    if (!p->io->should_stop || p->since_check < ru_stop_interval(p)) return false;
    p->since_check = 0;
    return p->io->should_stop(p->io->ctx);
}

/* One rvemu_run slice then the system call it stopped on. Returns 1 to keep
 * going; otherwise *stop holds the typed reason. */
static int ru_slice(struct ru_proc *p, uint64_t *work, enum rvuser_stop *stop)
{
    uint64_t left = p->lim->max_work - *work, before = p->hart.instret;
    enum rvemu_stop why = RVEMU_STOP_NONE;
    if (left == 0) { *stop = RVUSER_STOP_WORK_BUDGET; return 0; }
    if (ru_host_abort(p)) { *stop = RVUSER_STOP_HOST_ABORT; return 0; }
    rvemu_run(&p->hart, &p->mem, ru_slice_limit(p, left), &why);
    *work += p->hart.instret - before;
    p->since_check += p->hart.instret - before;
    if (why == RVEMU_STOP_STEP_LIMIT) {
        if (*work < p->lim->max_work) return 1; /* slice boundary, not the budget */
        *stop = RVUSER_STOP_WORK_BUDGET;
        return 0;
    }
    if (why != RVEMU_STOP_ECALL) { *stop = RVUSER_STOP_FAULT; return 0; }
    if (p->syscalls >= p->lim->max_syscalls) { *stop = RVUSER_STOP_SYSCALL_CAP; return 0; }
    if (*work >= p->lim->max_work) { *stop = RVUSER_STOP_WORK_BUDGET; return 0; }
    (*work)++;
    p->syscalls++;
    ru_syscall(p);
    p->hart.pc += 4u;
    if (p->exited) *stop = RVUSER_STOP_EXIT;
    return !p->exited;
}

static void ru_loop(struct ru_proc *p, struct rvuser_result *out)
{
    uint64_t work = 0;
    enum rvuser_stop stop = RVUSER_STOP_FAULT;
    while (ru_slice(p, &work, &stop)) {}
    out->stop = stop;
    out->work = work;
    out->instret = p->hart.instret;
    out->syscalls = p->syscalls;
    out->exit_status = p->exited ? p->exit_status : 0;
    ru_files_close_all(p);
}

static enum rvuser_error ru_start(struct ru_proc *p, const uint8_t *elf, const struct ru_image *img,
                                  const char *const *argv, const char *const *envp, size_t stack)
{
    enum rvuser_error err = ru_prepare(p, elf, img, stack);
    if (err != RVUSER_ERR_NONE) return err;
    return ru_stack_build(p, img, argv, envp, stack);
}

static void ru_fail(struct rvuser_result *out, enum rvuser_error err)
{
    out->error = err;
    out->stop = ru_stop_for(err);
    LOG_WARN("rvuser", "run refused: %s", rvuser_error_name(err));
}

int rvuser_run(const uint8_t *elf, size_t len, const char *const *argv, const char *const *envp,
               const struct rvuser_io *io, const struct rvuser_limits *lim,
               struct rvuser_result *out)
{
    if (!elf || !io || !lim || !out) return -1;
    memset(out, 0, sizeof(*out));
    size_t stack = 0;
    struct ru_image img;
    enum rvuser_error err = ru_check_limits(lim, &stack);
    if (err == RVUSER_ERR_NONE) err = ru_elf_parse(elf, len, &img);
    if (err == RVUSER_ERR_NONE) err = ru_check_extent(&img, lim->mem_bytes);
    if (err != RVUSER_ERR_NONE) { ru_fail(out, err); return 0; }
    struct ru_proc *p = zcl_calloc(1, sizeof(*p), "rvuser_proc");
    uint8_t *ram = zcl_calloc(1, lim->mem_bytes, "rvuser_guest_ram");
    if (!p || !ram) {
        free(p);
        free(ram);
        out->stop = RVUSER_STOP_NOMEM;
        return 0;
    }
    p->io = io;
    p->lim = lim;
    p->mem = (struct rvemu_mem){.base = img.lo, .size = lim->mem_bytes, .bytes = ram};
    err = ru_start(p, elf, &img, argv, envp, stack);
    if (err != RVUSER_ERR_NONE) ru_fail(out, err);
    else ru_loop(p, out);
    free(ram);
    free(p);
    return 0;
}

const char *rvuser_stop_name(enum rvuser_stop stop)
{
    static const char *const names[] = {"exit", "setup", "memory_cap", "work_budget",
                                        "syscall_cap", "fault", "nomem", "host_abort"};
    return (unsigned)stop < sizeof(names) / sizeof(names[0]) ? names[stop] : "unknown";
}

const char *rvuser_error_name(enum rvuser_error err)
{
    static const char *const names[] = {
        "none", "args", "limits", "truncated", "magic", "class", "endian", "version", "type",
        "machine", "flags", "phdr", "interp", "dynamic", "segment", "overlap", "no_load",
        "entry", "segment_range", "no_stack", "shared", "textrel"};
    return (unsigned)err < sizeof(names) / sizeof(names[0]) ? names[err] : "unknown";
}
