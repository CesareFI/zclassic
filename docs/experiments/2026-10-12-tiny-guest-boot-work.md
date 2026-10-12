<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Tiny guest boot work

Recorded 2026-10-12T06:24:00Z (local 2026-10-12T02:24:00-04:00).

The deterministic fixture is `tests/fixtures/rvmachine/tiny.bin`. Guest work is
retired instructions plus answered firmware calls plus device work, from one
`rvmachine_run` of at most 100000 units on `RVMACHINE_RAM_MIN`. The console
marker is the full shutdown transcript.

| run | retired | fw_calls | device_work | guest_work | skip | marker bytes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| before, twice | 334 | 62 | 0 | 396 | 999 | 60, identical text |
| after, twice | 279 | 62 | 0 | 341 | 999 | 60, identical text |

The marker text is `tiny: hello from S-mode\nprobe putchar=1\ntiny: timer fired\nU\n`
on every run. The two after-runs match each other. Guest work is 341, which
is below 396.

The guest loads the legacy putchar id once per string. The firmware return
writes only `a0` and `a1`, so the id stays live across each byte. The newline
after the putchar probe reuses that id. Firmware call count stays 62. No
disk is attached, so device work stays 0.

Host: clang 22.1.6, `clang --target=riscv64-unknown-elf -march=rv64imafdc
-mno-relax`. The flat image is the assembled `.text` section. Three unchanged
`li` immediates are encoded `addi` where the previous image used `addiw`;
the 64-bit results are the same values. CPU: AMD Ryzen 7 PRO 8840U.
New image sha256
`cf69105a626e6676de0d7d2edce20a22ae489ede5015f5ada230528147dd5001`.
