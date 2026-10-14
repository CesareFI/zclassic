<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Minimal C23 kernel acceptance

The optional apps/z23kernel application adds a freestanding supervisor kernel
without modifying the emulator or linking node code. Source base:
9c7adf86a3cbfc11c2a152dc4d7012b2e1c22149. The measured Linux cross toolchain
is Clang 18.1.3, mold 2.30.0 and LLVM objcopy 18.1.3.

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
gate passed. The exact 9240-byte flat image SHA256 is:

    ed3dbbfe1229694f91f37acd19223440ce33129790f086bc356a984749687fd8

This matches the separately reviewed frozen prototype. The build rejects
misplaced sections or unsupported allocated section types, checks flat-section byte offsets and
generates the hash and probe offsets consumed by acceptance. Image and identity
publication comprises separate renames under the lock; consumer verification
refuses a mismatched pair.

No disk, entropy device, byte ports or network is configured. These observations
do not qualify a complete kernel, hostile FDT tree parsing, another cross
toolchain, another host operating system or real hardware. Repository landing
and publication require their separate exact-candidate gates.
