# zclassic23/rvuser

User-mode runner for ADR-0011 tier 2 (step 3c). `rvuser_run` loads a static
riscv64 ELF into guest RAM, builds the FreeBSD initial process stack and runs
the program on the rvemu hart, answering its FreeBSD system calls. There is no
guest kernel and the host clock is never read.

## Loader

ELF64, little-endian, EM_RISCV, static: ET_EXEC, or ET_DYN as a static PIE. Validation fails closed with
a typed `rvuser_error`: truncation, magic, class, byte order, machine, ABI
flags (RVE and the quad-float ABI are refused; soft, single and double float run), program header bounds, PT_INTERP,
PT_DYNAMIC in an ET_EXEC (a static executable has none, so it is a dynamically linked program needing a run-time linker), a static PIE that names a shared library (DT_NEEDED) or text relocations (DT_TEXTREL), segment size and file range, overlapping PT_LOAD segments, an
entry point outside an executable segment, a segment outside guest memory and
a stack that does not fit. Guest RAM is one zeroed allocation made through the
repo allocator, so bss needs no extra work; its base is the lowest segment page
and its size is the caller's memory cap.

## Static PIE

An ET_DYN without PT_INTERP loads at the fixed bias `RU_PIE_BIAS` = 0x100000 (page aligned, constant, no randomisation; the FreeBSD riscv `ET_DYN_LOAD_ADDR`), so guest RAM starts there. The loader applies no relocations, as the FreeBSD kernel applies none to a static PIE: the program relocates itself in its start-up code (`crt0_pie.S` applies R_RISCV_RELATIVE from the `_DYNAMIC` RELA table). auxv follows `__elfN(freebsd_copyout_auxargs)` in sys/kern/imgact_elf.c: AT_PHDR = bias + header address, AT_PHENT, AT_PHNUM, AT_ENTRY = bias + e_entry, AT_BASE = 0 (no interpreter). These FreeBSD citations were written from memory of the tree; no FreeBSD source copy was available offline to re-verify them.

## Initial stack

Per FreeBSD sys/riscv/riscv/exec_machdep.c (`exec_setregs`): `a0` holds the
address of argc, `sp` is that address rounded to 16 bytes, `ra` is the entry.
At that address: argc, argv[] and NULL, envp[] and NULL, then auxv pairs
AT_PAGESZ, AT_PHDR (when the headers are mapped), AT_PHENT, AT_PHNUM, AT_BASE (0)
AT_ENTRY and AT_NULL. The strings sit above, at the top of memory.

## System call convention (verified in FreeBSD source)

- sys/riscv/riscv/trap.c `cpu_fetch_syscall_args`: the number is read from
  `tf_t[0]`, that is **t0 (x5), not a7 as Linux does**; arguments come from
  `tf_a[0..]`, a0 to a5. `SYS_syscall` and `SYS___syscall` take the number in a0.
- sys/riscv/riscv/vm_machdep.c `cpu_set_syscall_retval`: success sets
  `t0 = 0` and returns in a0 (a1); failure sets `t0 = 1` and a0 holds the errno.
- lib/libsys/riscv/SYS.h stubs: `li t0, SYS_x; ecall; bnez t0, cerror; ret`.
  `cerror.S` stores a0 to errno and returns -1.
- Runtime contract: **a successful call may modify a0, a1 and t0.** rvuser sets t0 = 0 and a0 = the value, and clears a1 (FreeBSD zeroes td_retval[1] before the call and `cpu_set_syscall_retval` copies it to a1); on failure t0 = 1, a0 = errno and a1 is left alone, as FreeBSD does. Guest code must treat all three as outputs of the ecall.
- A zero-length read or write returns 0 without looking at the buffer (FreeBSD forms no copyin/copyout for it), even for an invalid pointer.
- Numbers from sys/kern/syscalls.master; errno, MAP_* and signal constants
  from sys/sys/errno.h, `mman.h`, `signal.h`; AT_* from sys/sys/elf_common.h;
  start-up from lib/csu/riscv/crt1_s.S.

## System calls answered

exit (1), read (3), write (4), open (5), close (6), getpid (20),
munmap (73), mprotect (74), clock_gettime (232), issetugid (253),
sigprocmask (340), sigaction (416), thr_self (432), mmap (477, anonymous
only, inside the guest heap), pread (475), pwrite (476), lseek (478), openat (499), fstat (551). fd 0 reads from the caller
source; fd 1 and 2 write to the caller sink. clock_gettime reads the caller's
deterministic clock callback. sigaction and sigprocmask record state only.
FreeBSD riscv64 libc start-up does not call sysarch (the thread pointer is
`tp`), so sysarch is not in the table. Anything else returns ENOSYS and is
logged once per number.


## Hard float (lp64d)

FreeBSD riscv64 userland is lp64d. The loader accepts e_flags float ABI soft,
single and double and refuses quad and RVE. The hart starts with
`mstatus.FS = Initial` (01), as FreeBSD `exec_setregs` leaves the user FP
state, because rvemu traps every FP instruction while FS is Off. rvemu itself
is unchanged. The `fp` fixture (`-march=rv64imafdc -mabi=lp64d`) does double
sqrt, fdiv and conversions and prints bit-exact IEEE-754 results.

## Granted files

Mechanism here, policy in the caller. `struct rvuser_io` carries optional
`open`, `pread`, `pwrite`, `close` and `fsize` callbacks; a null `open` keeps
every open at EACCES. rvuser decodes FreeBSD flags (sys/sys/fcntl.h: O_RDONLY
0, O_WRONLY 1, O_RDWR 2, O_APPEND 0x8, O_CREAT 0x200, O_TRUNC 0x400, O_EXCL
0x800; O_CLOEXEC is accepted and ignored; any other bit is EINVAL), copies the
guest path with a bounded read (1024 bytes including NUL: EFAULT when it
leaves guest memory first, ENAMETOOLONG when no NUL fits) and passes it to the
caller unchanged, so the caller must refuse relative paths, "." and ".."
components and doubled slashes itself. Create and truncate always reach the
caller as write requests. Guest fds 3..18 form a bounded table with per-fd
offset and mode (EMFILE when full); handles still open at exit are closed.
`openat` accepts AT_FDCWD (-100) only, any other dirfd is EBADF. `lseek`
SET/CUR/END: END and O_APPEND need `fsize`, otherwise EINVAL. `fstat` fills the
riscv64 `struct stat` (224 bytes, sys/sys/stat.h): st_mode, st_nlink, st_size,
st_blocks, st_blksize; without `fsize` it is ENOSYS for files. fds 0..2 report
a character device and ESPIPE on seek and positional I/O.

## Host abort

`struct rvuser_io` has `should_stop(ctx)` and `stop_check_interval` (retired instructions; 0 selects 1,000,000). When the hook is set, rvuser asks it between slices of that many instructions and ends the run with `RVUSER_STOP_HOST_ABORT` when it returns true. Slicing does not change a run that is not aborted: output, instret and work are identical with and without a hook that returns false. rvuser reads no host clock; the caller's hook owns time.

## Budgets

`max_work` bounds host work: retired instructions plus one unit per system
call. The retired count is reported separately. `max_syscalls` caps dispatched
calls, exit included. `mem_bytes` is the guest memory cap. Each ends the run
with a typed `rvuser_stop`.

Conformance: `test_rvuser` runs the freestanding fixtures in
`tests/fixtures/rvuser` (sources in `src`, MANIFEST has sha256 and the exact
build commands).

The module depends only on the lower-layer base and rvemu packages and includes no higher-layer header.
