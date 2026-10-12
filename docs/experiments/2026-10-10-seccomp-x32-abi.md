<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Seccomp deny filter rejects alternate x86 syscall representations

The x86-64 deny filter must reject x32 syscall numbers before native syscall
and argument comparisons. x32 uses the same audit architecture with bit 30 set.
Kernels before Linux 5.4 also accepted native-number aliases 512–547. The
[seccomp manual](https://www.man7.org/linux/man-pages/man2/seccomp.2.html)
documents both representations and the need to reject or handle them explicitly.

The deny builder now rejects bit 30 and exactly the inclusive 512–547 range
immediately after loading the syscall number. Other native numbers continue
through the existing W^X and deny comparisons. The allow-list builder is
unchanged. Five added BPF instructions are included in the bounded filter size.
With all three W^X blocks, 243 deny entries produce at most 511 instructions;
244 entries are refused before filter construction.

## Parent experiment

- Base: `cbfcbdf6ee657d8b297410c9272bab0a1f02aa8a`.
- Host: Linux x86_64, kernel 6.8.0-142-generic; AMD Ryzen 9 7950X3D.
- Compiler: GCC 14.2.0; date: 2026-10-10; host local time zone UTC.
- Admission: normal profile, native job
  `3191688-78815650-1791626201241936166`, 28 make jobs.
- Command: `make -j28 t-fast-exact ONLY=os_sandbox T_FAST_EXACT_ARGS=--no-cache`.
- Production source SHA-256 before modification:
  `159d8532f2da68b1ec5344abba435ace5b05a874c6b15e2283cdd655732372bd`.

The registered group compiled and reached the actual
`os_sandbox_seccomp_deny` builder in fresh children. Unfiltered x32 getpid and
reserved alias 521 returned `-1/ENOSYS`, qualifying that an outer host policy did
not already kill these probes. Native getpid remained usable under the actual
production filter. Filtered x32 getpid and reserved numbers 512, 521, and 547
also returned `-1/ENOSYS` instead of terminating with SIGSYS: exactly four new
assertions failed. Existing sandbox cases passed. Canonical make returned 2;
the group ran cold with no cached or skipped groups.

All alias probes supply invalid first arguments and zero remaining arguments;
the ptrace alias uses an invalid request, so it cannot perform a tracing action.
The modern host observations qualify filter enforcement, not execution of x32
or historical alias semantics on a pre-5.4 kernel.

Parent log SHA-256:
`1b77f45da6807a5705be1f9fb78786cc3969ff1f712c940bc703674ff3bd8d08`.
The final fixture additionally checks bounded filter installation and refusal;
that case was added after the primary ABI parent witness.

## Repaired experiment

The repaired production/test patch SHA-256 is
`81b55e9833caa7290875bc3bcbf22026c7f3c1efedf5939932ba08d5b0a92132`.
Native admission job `3327711-78844049-1791626485224717254` ran the same
registered group cold with no cache hits. Canonical make returned 0; the group
reported no failures or skips. The raw host controls still returned ENOSYS,
native getpid survived, and filtered x32 plus all three reserved-range probes
terminated with SIGSYS. The maximum-size filter and overflow refusal passed.
Fixed log SHA-256:
`0c2e4b74fe6a941d576bb33b8ee441d9ea627416daec2c8cb713857bc9645172`.
The separate cyclomatic complexity gate also passed without changing its cap
or baseline pins.

## Reproduction

```sh
devbuild --wait --class normal make -j28 agent-verify ONLY=os_sandbox
```

Logs and exact patch receipts remain in the isolated lane's
`build/scratch/seccomp-abi-*` files. No production deployment, consensus change,
allow-list change, proof, or publication is part of this experiment.

## Final gates

Each command ran through `devbuild --wait --class normal` with 28 make jobs:

- `check-cyclomatic-complexity`: job
  `3369605-78853787-1791626582603499770`, return 0; log SHA-256
  `f600e1c690103e5603e574ef4a193b1ae50f25273d1f83b9dc6e50d539127e33`.
- `docs-capability-inventory`: job
  `3470187-78879532-1791626840048551572`, return 0; log SHA-256
  `d157f617eff3b688c19d8b08233c4a511895369aa4101008fdd3ac2a818a21dc`.
  The sole generated change records the added test reference to `syscall`.
- `lint-fast`: job `3477564-78881025-1791626854975456055`, return 0;
  log SHA-256
  `b2b327eb97b714613291a8ab6a7690abf337e561aa9d098cdee567b2050b08c2`.

Independent source review accepted the frozen production/test patch. The
registered runtime qualification above was performed separately; no aggregate
`agent-verify` execution is claimed. Before committing, a fresh fetch confirmed
that `origin/main` still equaled the stated base. No adoption or rebase was
performed.
