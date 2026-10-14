<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Minimal C23 supervisor kernel

This optional freestanding RV64 application links no node code. It validates
the supplied FDT header's alignment, RAM bounds, big-endian magic and bounded
total size. It recovers one exact 32-bit illegal probe, handles one supervisor
timer, disarms it and requests SBI shutdown. It does not parse FDT nodes or
provide a filesystem, network stack, shell or credential store.

    devbuild --wait make z23kernel
    devbuild --wait make -j8 t-fast-exact ONLY=z23kernel_boot

The measured cross toolchain is Clang 18, mold 2.30 and LLVM objcopy 18.
Override Z23KERNEL_CC, Z23KERNEL_LD and Z23KERNEL_OBJCOPY with compatible tools.
Missing tools or invalid image layout fail the requested build. Images must
be smaller than 64 KiB; exact-cap and oversized inputs refuse. Other compiler
and linker combinations and host operating systems remain unqualified.

build/bin/z23kernel.bin uses the existing ordinary flat-image loader at
0x80200000; the ELF is inspected build evidence, not the boot artifact.
The build verifies allocated-section bounds and exact flat offsets, and emits
the image hash and probe offsets consumed by the registered acceptance.
Concurrent build prerequisites share the existing bounded build lock.
The image and identity are published as separate files; the consumer verifies
their agreement before executing or forming mutation pointers.

The guest's shutdown line states intent. Host-observed shutdown status and
reset fields establish termination. The registered acceptance uses isolated
64 MiB machines, no devices, and at most one million work units per run.
