<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Release test compiler checks

Observed on 2026-10-12T23:02:57Z (2026-10-12T19:02:57-04:00).
Base: `4e3c0eaea01f013fd4b604a0413b55d5b3ea8d3d`.
Host: AMD Ryzen 9 7950X3D; GCC 14.2.0 (Ubuntu
14.2.0-4ubuntu2~24.04.1).

The release ship gate passed lint and stopped before running tests because
strict test compilation rejected five misleadingly indented cleanup returns
in `test_dev_machine_boot.c` and three unchecked `fread` results in
`test_fleet_steer_deliver.c`. No deployment occurred.

The correction preserves unconditional failure returns after conditional
cleanup. The delivery fixture closes its stream before asserting the exact
four-byte read. Its manifest and rate helpers reject empty reads, read errors,
and close failures. Production code and acceptance thresholds are unchanged.

## Executed acceptance

```sh
devbuild --wait make -j28 t-fast-exact ONLY=dev_machine_boot,fleet_steer
```

Result: 2 groups ran, 0 failed, 0 skipped, 0 unobserved; 8.5 seconds wall time.
These are focused test results, not full release or deployed-node acceptance.

Independent source review accepted the complete two-file change. Its binary
diff SHA-256 is
`aa2906986908fe372d68cf62f982ba660b336539390c31c62120866e4b457e58`.
The review made no runtime claim. Full exact-source publication and release
gates remain required.
