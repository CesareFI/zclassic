<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Exact output boundary before touch

Local time: 2026-09-27T01:26:38-04:00

UTC: 2026-09-27T05:26:38Z

## Finding

The earlier review controller rejected a second completed output in one
upload chunk, but accepted bytes after the first completed output if they
did not complete another output. That let the host advance the parser past
the first output before the next touch acknowledgement. The public comment
promised a stronger pause than the code enforced.

## Correction and evidence

The parser counts each wire byte after its output callback. The controller
now records the completed output's byte offset at that callback and checks
the feed's final offset. If the feed extends even one byte beyond the output,
it invalidates the entire review session. A focused test sends the synthetic
first output plus one byte and verifies rejection with no pending output.
The valid two-output flow still requires one acknowledgement after each
exact output boundary. The transaction-driven simulator remains valid because
it feeds pass three one byte at a time.

ARM GCC 16.2.0 compiled the corrected C23 controller with `-Os -Wall
-Wextra -Werror -pedantic -fstack-usage`. The state type remains 376 bytes
because the new offset occupies prior structure padding. The isolated object
has 572 bytes of `.text`, zero `.data`, zero `.bss`, and a largest reported
local frame of 40 bytes. This is not a linked Blue image measurement.

The security boundary remains read-only. A future device APDU handler must
map acknowledgement exclusively to a touchscreen callback; no USB command
may call it. A final digest still requires authenticated previous output,
fee, change, account, and consensus branch before signing can be considered.
