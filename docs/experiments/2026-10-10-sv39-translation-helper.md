<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Bounded Sv39 translation helper

Observed on 2026-10-10 with GCC 14.2.0 and ISO C23 on the Linux development host. Source base: `c0b4c57176fbfbd3d4355fff2d655c23582ebbd5`.

The existing rvemu engine gains a pure Sv39 helper. It translates through at most three physical PTE reads and one atomic full-PTE compare/exchange. It checks canonical addresses, PTE reserved bits, user and supervisor permissions, SUM, MXR, superpage alignment, and explicit fault/update policies for A/D bits. A changed PTE returns a bounded retry result rather than using stale permissions. No host pointer, allocation, second execution core, or host filesystem authority is introduced.

The machine caller remains responsible for effective privilege including MPRV, cross-page access splitting, PMP/PMA checks, retry budgets, and architectural trap delivery. Base Sv39 is supported; Svnapot and Svpbmt are not. This slice does not qualify a FreeBSD boot or machine-integrated virtual memory.

Primary reference: [RISC-V Privileged ISA supervisor specification](https://github.com/riscv/riscv-isa-manual/blob/main/src/priv/supervisor.adoc), Virtual Address Translation Process and Sv39 sections.

## Acceptance

Six fixtures are reached through the existing registered `rvemu` group. They cover base/Bare/M translation; canonical and reserved-bit refusal with original tval; U/SUM/MXR permissions; superpages and nonleaf restrictions; A/D fault, atomic update and race; and 2 MiB/high canonical mappings.

Canonical scoped gate: `devbuild --wait make -j28 agent-verify ONLY=rvemu`. The final extracted helper passed complexity, the focused group, generated inventory, and lint-fast. GATES3.log SHA256: `6023d1a77849510a2953e14c4471e830a09ef1a44d7fc153562366f1bf498be0`.

The permission-rejection production mutation failed at `test_rvemu_translate.c:97`, with one failed group and zero registered skips. MUTATION5.log SHA256: `fdfe4f1f98ba0f2a4fd20d97fb90bf4b1b04bb44148d22bea583727c9e41e41d`. Fixed source was restored exactly to SHA256 `fc345336df560f49db740527ab4d9291e003260a2c949b4140be51bd5f6eea99`.

The restored focused run passed, exit 0, one registered group, zero failed groups, zero skips, zero environment omissions, and zero flaky-load classifications. RESTORED5.log SHA256: `c1c16a847e164a5704609ed5e9a630c9623b16a1a4f139db79652190bfb92b87`.

The existing official fixtures report 110/110 user-profile and 22/22 machine-profile cases passing. Two machine-profile cases remain explicitly excluded pending integrated Sv39. Zero registered skips does not remove those exclusions.

Canonical `tools/scripts/zcode_registry_rederive.sh` completed successfully and changed only rvemu/rvuser registry projections and the rvuser dependency pin. These generated changes and capability inventory remain outside the author commit under the integration contract. The integrator regenerates them with `stack_tip_refresh.sh` and obtains fresh assembled-source proof before publication.

No parent-red claim is made for a helper absent from the base. Full publication gates, integrated machine acceptance, guest kernel boot, and cross-host reproduction remain outside this focused evidence.
