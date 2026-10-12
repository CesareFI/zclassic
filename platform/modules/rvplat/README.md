# zclassic23/rvplat

Deterministic device models for the built-in RISC-V machine, testable without
a CPU core: a PLIC (RISC-V PLIC spec 1.0), a tick-driven timer with a compare
register, a pure SBI 2.0 call handler (base, TIME, IPI, RFENCE, HSM, SRST and
the legacy console calls FreeBSD's `sbi.c` relies on), and an ns16550 UART.

Every model is a caller-owned struct. There is no allocation, no host clock, no
I/O and no global state: time comes from a caller-supplied tick count, and
console bytes cross the boundary through caller callbacks. The package has no
dependencies. Registers are 32-bit and are accessed by offset; the caller owns
bus decode and any `reg-shift`.
