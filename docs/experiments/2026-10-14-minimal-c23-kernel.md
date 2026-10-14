<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Minimal C23 kernel acceptance

The optional apps/z23kernel application adds a freestanding supervisor kernel
without modifying the emulator or linking node code. Source base:
9c7adf86a3cbfc11c2a152dc4d7012b2e1c22149. The measured Linux cross toolchain
is the pinned Clang 20.1.8, ld.lld 20.1.8 and LLVM objcopy 20.1.8.

On 2026-10-14, the registered z23kernel_boot group passed uncached through:

    devbuild --wait make -j8 t-fast-exact ONLY=z23kernel_boot

The acceptance observes two fresh 64 MiB machines, exact repeated transcript,
actual shutdown with reset type and reason zero, a disarmed timer, equal work
counters and the one-million-work cap. FDT validation covers header alignment,
address range, big-endian magic and bounded total size only.

Isolated refusals cover invalid magic, too-small and oversized header length,
misaligned and out-of-range tree addresses, an unexpected breakpoint and an
illegal instruction outside the exact recovery label. Malformed identity
offsets refuse before pointer formation. An insufficient work budget cannot
report shutdown acceptance.

The native runner's distinct concurrent image and identity BUILD prerequisites
passed using the existing bounded build lock. Deleting only the generated
identity and rebuilding regenerated identical bytes. The architecture tree
gate passed. The exact 4157-byte flat image SHA256 (probe 0x304, resume 0x308, end offset 0x6050) linked with ld.lld 20.1.8 is:

    84e5fb4f1e3487fdc42889339fa7684ad2b3885cb565504d7140fad50db1180b

The image is smaller than the earlier mold-linked 9240-byte image because
ld.lld emits no empty GOT padding and merges the string data into .rodata. The build rejects
misplaced sections or unsupported allocated section types, checks flat-section byte offsets and
generates the hash and probe offsets consumed by acceptance. Image and identity
publication comprises separate renames under the lock; consumer verification
refuses a mismatched pair.

No disk, entropy device, byte ports or network is configured. These observations
do not qualify a complete kernel, hostile FDT tree parsing, another cross
toolchain, another host operating system or real hardware. Repository landing
and publication require their separate exact-candidate gates.
