# zclassic23/rvemu

RV64IMAFDC hart core for the in-binary RISC-V emulator. It implements the RV64I
base integer ISA, the M, A and C extensions, the F and D floating-point
extensions with fcsr, fflags and frm, M, S and U privilege with the machine
and supervisor CSRs, and the official riscv-tests rv64ui, um, ua, uc, uf, ud,
mi and si images as its oracle, the two Sv39 images included. fence is a
no-op. fence.i drops the decoded-instruction cache.

Floating point is integer-only soft float (rvemu_softfp.c, rvemu_softcvt.c):
add, sub, mul, div, sqrt, fused multiply-add and the conversions are built
from 64-bit integer arithmetic, with all five rounding modes (RMM included),
tininess detected after rounding, canonical NaN results and NaN-boxed singles.
The host FPU, fenv and libm are never touched, so results and fflags are
bit-exact on every host. FP instructions are illegal while mstatus.FS is Off
and set it to Dirty when they write state.

Byte order comes from the shared base helpers. The module depends only on base.

Caller-owned state and memory: `struct rvemu_hart` holds the registers, pc
and CSRs, and `struct rvemu_mem` names guest RAM by base and size. There is
no allocation, no I/O and no global state. Every guest access is bounds
checked. `rvemu_step` retires one instruction. `rvemu_run` steps up to a
budget and returns a typed stop reason: ECALL, EBREAK, ILLEGAL, MISALIGNED,
OUT_OF_RANGE or STEP_LIMIT.

Privilege and traps. The hart has M, S and U modes (`hart->priv`) and three
profiles chosen at init. `rvemu_hart_init` gives the STOP profile: traps are
not taken, ECALL, EBREAK and faults stop the run with pc left at the stopping
instruction, privilege stays M, mret is a plain jump to mepc and no interrupt
fires (the user-mode runner relies on this). `rvemu_hart_init_machine` gives
the MACHINE profile: synchronous exceptions and interrupts trap with the
architectural cause and tval, delegated by medeleg and mideleg to S, entered
through mtvec or stvec in direct or vectored mode; mret, sret, wfi and
sfence.vma follow the privileged spec including the TSR, TW and TVM rules;
interrupts are taken at instruction boundaries in priority order with the
per-mode global enables. A platform raises lines with `rvemu_set_irq` and
sets the `time` CSR value in `hart->time`. A wfi that finds nothing pending
makes `rvemu_step` return RVEMU_STOP_WFI until an interrupt is pending.

The SBI profile (`rvemu_hart_init_sbi`) runs a supervisor with the firmware in
the host: the hart starts in S and there is no guest M-mode. An ecall in S
returns RVEMU_STOP_ECALL to the caller with the hart untouched; the host
answers it and calls `rvemu_ecall_return`, which writes a0 and a1 and steps pc
past the ecall without retiring anything. An ecall in U, every other
exception and the supervisor interrupts are taken in S. Machine CSRs and mret
are illegal instructions delivered to S. time, cycle and instret are readable
in S; in U they are gated by scounteren alone. `hart->retired` counts retired
instructions for the host's clock and no guest write reaches it.

The physical bus. `struct rvemu_mem` names guest RAM and, optionally, device
callbacks (`io_load`, `io_store`, `io_ctx`). A data access wholly inside RAM
uses RAM; any other goes to the callbacks as one unsplit call, and a refusal
or a missing callback is an access fault. Instructions, page tables and the
atomics use RAM only.

Address translation. In the MACHINE and SBI profiles satp MODE 8 turns on Sv39
for S and U (and for M loads and stores under MPRV): 4 KiB, 2 MiB and 1 GiB
pages, SUM and MXR, A and D updated in the page table, page faults and access
faults with the faulting virtual address, also for the second page of an
access or instruction that crosses a page. The bounded walker is
`rvemu/translate.h`. lr/sc reserve the physical address.

Translation cache. Translations are cached per access kind, keyed by page,
effective privilege, SUM and MXR, for RAM pages only. A hit yields a physical
address that still goes through the bounds-checked bus, and a device page is
walked every time. sfence.vma and every satp write empty the cache, and
`rvemu_tlb_flush` does the same for a host that edits guest page tables. The
cache changes no result: a run with it and a run that walks every access end
in the same state.

Instruction cache. Completed fetches are remembered in a 32-line direct-mapped
table keyed by pc, satp and privilege. A hit checks that those bits are still
at the physical address, then skips translation and decode. A store that
overlaps the cached parcel drops that line, and fence.i or any translation
flush drops the table. A 32-bit instruction that crosses a page is not
cached. Editing guest RAM under the hart is visible on the next fetch. The
hit and miss counts are host observations; they do not change retired
instructions, time, or traps.

Choices: satp accepts MODE Bare and Sv39 (a write with any other MODE leaves
it unchanged; ASID reads zero; the STOP profile is Bare only), PMP registers
are WARL storage with the lock bit honoured but accesses are not checked,
there are no debug triggers, misa is fixed, cycle counts executed steps and
instret retired instructions. Misaligned data accesses are performed, and
only a misaligned instruction fetch traps.
