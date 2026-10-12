<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Command catalog parent checks record each branch once

Recorded 2026-10-12T14:58:03Z (local 2026-10-12T10:58:03-0400).
Host `t14`, clang 22.1.6, AMD Ryzen 7 PRO 8840U.
The timed call is `zcl_command_registry_validate` on the live catalog
(`zcl_command_catalog`, 911 commands), forty times inside
`test_command_registry_catalog`. This is not a `tiny.bin` boot wall.

Each command looked for its branch parent by scanning every catalog entry.
The success path now records branch paths once in an open-addressed table.
A missing parent, a parent that is a leaf, a full table, or a failed
allocation still uses the scan and the same missing-parent text. A child
listed before its branch still validates. The sealed ECDSA registry
constructor is unchanged. The SSH launcher option string and the onion
fail-closed dial are unchanged. Guest-work pins were not remeasured.

| path | forty validates | one validate |
| --- | ---: | ---: |
| scan each parent | 50558 µs | 1264 µs |
| record each branch | 3550 µs | 89 µs |

`test_command_registry_catalog` reported `groups_failed=0` on both
measurements. The repeat loop that printed those times is not part of the
committed test. The committed cases are a branch listed after its child, a
missing branch parent, and a parent that is a leaf. That group reported
`groups_failed=0` again at 2026-10-12T14:59:21Z, mode=cold, body 5910 ms.
Cyclomatic ratchet: 76438 functions, 3922 pins exact.

Published `56ff0d271f794def430e40884d2f96fc7356d3a0` measured the same
call at 2026-10-12T15:28:13Z on this host. The live catalog was 919
commands. Forty validates took 3062 µs (77 µs each).
`test_command_registry_catalog` reported `groups_failed=0`, mode=cold,
body 5700 ms. The repeat loop was removed before this note. One
`dev app machine boot` of `tiny.bin` on the `z23-dev` built before this
commit still reported handler `elapsed_us` 223 and wall 0.038 s. That
binary still contains the parent scan, so that wall is not the
published validator. Guest-work pins were not remeasured.
