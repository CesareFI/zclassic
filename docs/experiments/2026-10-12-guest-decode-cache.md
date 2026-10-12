<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Guest instruction decode cache

Recorded 2026-10-12T07:44:49Z (local 2026-10-12T03:44:49-04:00).

The deterministic guest is `tests/fixtures/rvmachine/tiny.bin`. Each completed
instruction fetch either reuses a decoded line or translates and decodes from
guest memory. At this measurement a reuse checked that the cached bits were
still at their physical address, then skipped translation. Retired
instructions, firmware calls, device work, and the console marker are
unchanged. The store-epoch section is the later behavior.

| run | fetch hits | fetch misses | retired | fw_calls | marker bytes |
| --- | ---: | ---: | ---: | ---: | --- |
| before the cache | 0 | 341 | 279 | 62 | 60 |
| after, boot command | 274 | 67 | 279 | 62 | 60 |
| after, machine run | 274 | 67 | 279 | 62 | 60 |

The before row is the same 341 fetches with no cache: every fetch was a miss.
The two after runs match each other. 274 fetches reused a decode. 67 decoded
from memory. Host: clang 22.1.6. CPU: AMD Ryzen 7 PRO 8840U.

Focused groups on this tree: `test_rvemu`, `test_rvmachine`,
`test_dev_machine_boot`, `test_guest_ssh_fixture`, `test_rom_fetch_onion`,
`test_tor`, `test_onion_stream`. Suite verdict `groups_failed=0`.

## Store epoch

Recorded 2026-10-12T10:14:29Z (local 2026-10-12T06:14:29-04:00).

A decoded line whose store epoch equals the hart's is reused without reading
the parcel. `rvemu_hart_init` sets the epoch to 1. Each noted store advances
it. The next hit of a line that survived the store re-reads the parcel once
and then adopts the new epoch. A store that overlaps the parcel, a range
wider than 8 bytes, `fence.i`, and a translation flush still drop lines.
Virtio RAM writes and the harness instruction pokes call the same note, so a
host edit cannot execute a stale decode. Epoch 0 always re-reads. A wrap
flushes the cache.

`test_rvemu` printed `icache_fast=2`. That case fetched one `addi`, fetched
it again with no store (one fast hit), re-read it after an unrelated store,
fetched it once more (second fast hit), then executed a poked nop in place of
the `addi`. `test_rvmachine` and `test_dev_machine_boot` still report
`fetch_hits=274` and `fetch_misses=67`. The three groups reported
`groups_failed=0` (3.3s wall, mode=cold). Cyclomatic ratchet: 76311 functions,
3923 pins exact. The guest is still one `rvemu_step` per instruction. This
is not native host execution.
