<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Official Sv39 fixture provenance

The two additional MACHINE-profile images use riscv-tests commit
7b68f7b91f827f8d94cc1c57ff123752c5c8f704 and its riscv-test-env submodule
6de71edb142be36319e380ce782c3d1830c65d68. The existing BSD-3-Clause
fixture LICENSE matches the upstream license byte for byte.

The dirty.S and icache-alias.S copies remove only the `.global mtvec_handler`
line, preserving the existing privileged-image LLVM weak-definition recipe.
LLVM Clang and LLD 20.1.8 build each with
`--target=riscv64 -march=rv64imafdc_zicsr_zifencei -mabi=lp64d`, the upstream
p environment and link.ld, and `--build-id=none`. Two independent builds
produced identical ELF files and identical objcopy flat images. Both start
at 0x80000000 and write completion at tohost 0x80001000.

| Image | Bytes | Flat SHA-256 |
| --- | ---: | --- |
| rv64si-p-dirty | 8208 | e0266dfd15081622b0239038e5ee10c11bcdeea90b590527c4fc3864f52d99e7 |
| rv64si-p-icache-alias | 28688 | 6db1539b442832053f8ca4abec70e254f0ba6a1c32e370ed9f58872059fd7f2d |

The admitted authoring job returned EXIT=0 and REPRODUCIBILITY=PASS.
Its raw log SHA-256 is
0e13715210b81a01d7c334d658990adfc5ae5ceb3146ac86cb6f24cc20fa442f.
Exact source, tool hashes, command arguments and logs remain in the associated
handoff receipt. No guest execution was performed during fixture authoring.

## Acceptance boundary

The existing official-image harness must hash these rows before execution,
initialize M mode and report actual tohost completion. Engine integration owns
the shared image count and SATP assertions. This fixture-only slice does not
qualify translation integration or FreeBSD boot. Guest execution is NOTRUN.
The dirty image permits software D-bit fault recovery; its success alone does
not prove hardware A/D updates. The helper CAS fixtures retain that obligation.
