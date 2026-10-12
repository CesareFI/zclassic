/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ADR-0011 tier 2 user-mode runner. Loads a static riscv64 ELF into
 * guest RAM, builds the FreeBSD initial process stack and runs the program on
 * the rvemu hart, answering its FreeBSD system calls from a fixed table. No
 * guest kernel. The host clock is never read: time comes from a caller
 * callback. Guest RAM is the one bounded allocation, made through the repo
 * allocator and freed before rvuser_run returns. */
#ifndef ZCL_RVUSER_RVUSER_H
#define ZCL_RVUSER_RVUSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Why the run ended. EXIT means the guest called exit; every other value is
 * a host-imposed stop. */
enum rvuser_stop {
    RVUSER_STOP_EXIT = 0,
    RVUSER_STOP_SETUP,        /* bad arguments, limits or ELF: see rvuser_error */
    RVUSER_STOP_MEMORY_CAP,   /* image plus stack does not fit the guest memory */
    RVUSER_STOP_WORK_BUDGET,  /* the host work budget ran out */
    RVUSER_STOP_SYSCALL_CAP,  /* the guest asked for one more system call than allowed */
    RVUSER_STOP_FAULT,        /* illegal, misaligned, out-of-range access or ebreak */
    RVUSER_STOP_NOMEM,        /* the host could not allocate guest RAM */
    RVUSER_STOP_HOST_ABORT    /* the caller's should_stop hook asked to end the run */
};

/* Typed setup and loader errors. RVUSER_ERR_NONE when the program started. */
enum rvuser_error {
    RVUSER_ERR_NONE = 0,
    RVUSER_ERR_ARGS,          /* null pointer, argc or string area too large */
    RVUSER_ERR_LIMITS,        /* zero budget or unusable memory size */
    RVUSER_ERR_TRUNCATED,     /* file shorter than a header or table it names */
    RVUSER_ERR_MAGIC,
    RVUSER_ERR_CLASS,         /* not ELFCLASS64 */
    RVUSER_ERR_ENDIAN,        /* not little-endian */
    RVUSER_ERR_VERSION,
    RVUSER_ERR_TYPE,          /* not ET_EXEC or ET_DYN */
    RVUSER_ERR_MACHINE,       /* not EM_RISCV */
    RVUSER_ERR_FLAGS,         /* RVE or quad-float ABI */
    RVUSER_ERR_PHDR,          /* program header table malformed or out of the file */
    RVUSER_ERR_INTERP,        /* PT_INTERP present */
    RVUSER_ERR_DYNAMIC,       /* PT_DYNAMIC in ET_EXEC, or malformed in ET_DYN */
    RVUSER_ERR_SEGMENT,       /* filesz above memsz, file range or address wrap */
    RVUSER_ERR_OVERLAP,       /* two PT_LOAD segments share bytes */
    RVUSER_ERR_NO_LOAD,       /* no PT_LOAD segment */
    RVUSER_ERR_ENTRY,         /* entry point not inside an executable segment */
    RVUSER_ERR_SEGMENT_RANGE, /* a segment lies outside the guest memory */
    RVUSER_ERR_NO_STACK,      /* the initial stack does not fit */
    RVUSER_ERR_SHARED,        /* ET_DYN with DT_NEEDED: a shared-library dependency */
    RVUSER_ERR_TEXTREL        /* ET_DYN asking for text relocations */
};

/* What a guest open asks for, already decoded from the FreeBSD flags. A
 * create or truncate request always has write set, so a read-only grant can
 * never create or empty a file. */
struct rvuser_open_req {
    bool read, write, create, trunc, excl;
};

/* Caller byte sinks, sources, clock and granted files. Any member may be
 * null: a null read is end of file, a null write makes fd 1 and 2 fail with
 * EBADF, a null clock makes clock_gettime fail with EINVAL. read returns
 * bytes stored (0 = EOF); write returns bytes consumed; clock_ns returns 0
 * and stores nanoseconds.
 *
 * File access is policy in the caller, mechanism here. rvuser copies the
 * guest path (at most 1023 bytes plus NUL) and hands it over unchanged: the
 * caller decides what is granted. A null open means every open fails with
 * EACCES. open returns 0 and a handle, or a positive FreeBSD errno. pread and
 * pwrite return the byte count (0 = EOF for pread) or a negated FreeBSD
 * errno; close releases a handle (rvuser also closes every open handle when
 * the run ends). fsize returns the size or a negated errno; it backs
 * fstat, lseek SEEK_END and O_APPEND. Without fsize lseek SEEK_END and
 * O_APPEND open fail with EINVAL and fstat of a file fails with ENOSYS. */
struct rvuser_io {
    void *ctx;
    size_t (*read)(void *ctx, uint8_t *buf, size_t n);
    size_t (*write)(void *ctx, int fd, const uint8_t *buf, size_t n);
    int (*clock_ns)(void *ctx, uint32_t clock_id, uint64_t *ns);
    int (*open)(void *ctx, const char *path, const struct rvuser_open_req *req, uint64_t *handle);
    int64_t (*pread)(void *ctx, uint64_t handle, uint8_t *buf, size_t n, uint64_t off);
    int64_t (*pwrite)(void *ctx, uint64_t handle, const uint8_t *buf, size_t n, uint64_t off);
    void (*close)(void *ctx, uint64_t handle);
    int64_t (*fsize)(void *ctx, uint64_t handle);
    /* Host abort. When should_stop is set, rvuser asks it between slices of
     * stop_check_interval retired instructions (0 selects 1,000,000); true ends the run
     * with RVUSER_STOP_HOST_ABORT. It never changes a run that is not aborted. */
    bool (*should_stop)(void *ctx);
    uint64_t stop_check_interval;
};

struct rvuser_limits {
    uint64_t max_work;       /* host work budget: instructions plus system calls */
    uint64_t max_syscalls;   /* system calls dispatched, exit included */
    size_t mem_bytes;        /* guest memory size, the memory cap */
    size_t stack_bytes;      /* 0 selects 64 KiB */
};

#ifdef ZCL_TESTING
/* Test-only red twin hook: select the register holding the system call
 * number for later runs. 0 restores the verified FreeBSD riscv value (t0 =
 * x5); 17 is a7, the Linux choice. Not part of the production interface. */
void rvuser_test_set_syscall_reg(unsigned reg);
#endif

struct rvuser_result {
    int exit_status;         /* guest exit code & 0xff, valid for STOP_EXIT */
    enum rvuser_stop stop;
    enum rvuser_error error;
    uint64_t instret;        /* architectural retired instructions */
    uint64_t work;           /* work units spent against max_work */
    uint64_t syscalls;       /* system calls dispatched */
};

/* Load elf and run it with argv and envp (null-terminated string arrays, or
 * null for empty). Returns 0 when the run ended with a typed stop in *out
 * (including setup stops) and -1 only when elf, io, lim or out is null. */
int rvuser_run(const uint8_t *elf, size_t len, const char *const *argv, const char *const *envp,
               const struct rvuser_io *io, const struct rvuser_limits *lim,
               struct rvuser_result *out);

/* Short stable name of a stop or error, for logs and tests. */
const char *rvuser_stop_name(enum rvuser_stop stop);
const char *rvuser_error_name(enum rvuser_error err);

#endif
