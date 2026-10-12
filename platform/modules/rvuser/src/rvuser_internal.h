/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: internal seams between the rvuser translation units. */
#ifndef ZCL_RVUSER_INTERNAL_H
#define ZCL_RVUSER_INTERNAL_H

#include "rvuser/rvuser.h"
#include "rvemu/rvemu.h"
#include <stdbool.h>

#define RU_PAGE 4096ull
#define RU_MAX_LOADS 16u
#define RU_NSIG 128u
#define RU_SIGACT_BYTES 32u
#define RU_UNKNOWN_LOG_MAX 32u
#define RU_STACK_DEFAULT ((size_t)64 * 1024)
#define RU_MEM_MAX ((size_t)1 << 30)
#define RU_ARGS_MAX 256u
#define RU_IO_CHUNK 65536u
#define RU_MSTATUS_FS (3ull << 13)
#define RU_MSTATUS_FS_INITIAL (1ull << 13)
#define RU_FD_FIRST 3u
#define RU_FD_COUNT 16u
#define RU_PATH_MAX 1024u
/* Fixed load bias of every static-PIE (ET_DYN) program: constant, page aligned, no
 * randomisation. 0x100000 matches FreeBSD riscv ET_DYN_LOAD_ADDR (sys/riscv/include/elf.h) as
 * used for et_dyn_addr in sys/kern/imgact_elf.c __elfN(load_file)/__elfN(get_interp) callers
 * (recalled from the FreeBSD tree; no source copy was available offline to re-verify). */
#define RU_STOP_INTERVAL_DEFAULT 1000000ull
#define RU_PIE_BIAS 0x100000ull

/* One validated PT_LOAD segment. */
struct ru_segment {
    uint64_t vaddr, memsz, filesz, offset;
    uint32_t flags;
};

/* What the ELF parser extracts. phdr_addr is 0 when the program headers are
 * not inside a loaded segment. */
struct ru_image {
    uint64_t entry, phdr_addr, lo, hi, bias;
    bool pie;
    uint16_t phnum;
    unsigned nload;
    struct ru_segment seg[RU_MAX_LOADS];
};

/* Validate a riscv64 static ET_EXEC or static-PIE image, fail closed. */
enum rvuser_error ru_elf_parse(const uint8_t *elf, size_t len, struct ru_image *img);
/* Copy every segment into mem (already zeroed, so bss stays zero). */
enum rvuser_error ru_elf_map(const uint8_t *elf, const struct ru_image *img,
                             const struct rvemu_mem *mem);

/* One granted-file descriptor: caller handle, offset and open mode. */
struct ru_fd {
    uint64_t handle, off;
    bool used, can_read, can_write, append;
};

/* Process state shared by the syscall layer and the runner. */
struct ru_proc {
    struct rvemu_hart hart;
    struct rvemu_mem mem;
    const struct rvuser_io *io;
    const struct rvuser_limits *lim;
    uint64_t heap_base, heap_cur, heap_end;
    uint64_t syscalls;
    uint64_t since_check; /* instructions retired since the host abort hook was last asked */
    uint32_t closed_fds;
    struct ru_fd fds[RU_FD_COUNT]; /* guest fds RU_FD_FIRST.. */
    uint64_t sigmask[2];
    uint8_t sigact[RU_NSIG + 1u][RU_SIGACT_BYTES];
    uint32_t unknown_seen[RU_UNKNOWN_LOG_MAX];
    unsigned unknown_count;
    int exited;
    int exit_status;
};

/* Pointer to guest [addr, addr + len), or null when outside memory. */
uint8_t *ru_guest_ptr(const struct ru_proc *p, uint64_t addr, uint64_t len);

/* Build argc, argv, envp and auxv at the top of memory. Sets hart sp and a0. */
enum rvuser_error ru_stack_build(struct ru_proc *p, const struct ru_image *img,
                                 const char *const *argv, const char *const *envp,
                                 size_t stack_bytes);

/* Answer the system call the hart stopped on, FreeBSD riscv convention. */
void ru_syscall(struct ru_proc *p);

/* Granted-file system calls (rvuser_file.c). Same shape as every handler:
 * return 0 and set *ret, or a positive FreeBSD errno. */
int ru_sys_read_fd(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
int ru_sys_write_fd(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
int ru_sys_close_fd(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
int ru_sys_open(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
int ru_sys_openat(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
int ru_sys_pread(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
int ru_sys_pwrite(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
int ru_sys_lseek(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
int ru_sys_fstat(struct ru_proc *p, const uint64_t a[6], uint64_t *ret);
/* Close every handle still open; called once when the run ends. */
void ru_files_close_all(struct ru_proc *p);

#endif
