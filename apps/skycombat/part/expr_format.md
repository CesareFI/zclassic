<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->
# Data-only HUD expression format, version 0

The validator admits inert bounded data. The evaluator computes numbers only;
it has no assembler, renderer, loader, activation, or host execution authority.
Input memory
must be valid and immutable for the call. `expr_validate` retains no pointers,
allocates nothing, and changes the required `expr_info` output only on success.
Optional `expr_error` receives a fixed trusted reason and record index; refusals
log context. Status names and values are declared in `expr_format.h` (OK=0).

Integers are explicit little-endian bytes, never native structs. I32 immediates
are two's-complement bit patterns. There is no padding, checksum, compression,
extension or trailing byte. External hashes identify bytes, not correctness.
Section order: header, expressions, text descriptors, pieces, draws, literals.
Exact size is `32+16*E+8*T+12*P+24*D+L`, at most 10272 bytes. All counts may be
zero; the 32-byte empty part is valid. Counts precede length arithmetic/access.

| Header byte offset | Width | Required value |
|---|---|---|
| 0 | 4 | ASCII HUDX |
| 4,6 | 2 each | version 0, header size 32 |
| 8 | 4 | normalized snapshot schema 1 |
| 12,14,16,18 | 2 each | E<=256, D<=64, T<=64, P<=256 |
| 20 | 4 | L<=1024 |
| 24,28 | 4 each | zero |

Every reserved/unused field must have its specified value. References are u16
indices; NONE=65535. Unknown identities, kinds, fields or opcodes refuse.
An expression is 16 bytes: opcode u8 at0, reserved zero u8 at1, operands
a/b/c u16 at2/4/6, immediate u32 at8, reserved zero u32 at12. Active operands
refer strictly backward; inactive operands are NONE. Only CONST_I32 and FIELD
use the immediate; all other immediates are zero. Types are inferred as I32
or BOOL, with no implicit conversion.

| Opcode | Name | Arity | Required types -> result |
|---|---|---|---|
| 1 | CONST_I32 | 0 | immediate bits -> I32 |
| 2 | FIELD | 0 | schema field id -> field type |
| 3,4,5,6 | ADD_SAT,SUB_SAT,MIN,MAX | 2 | I32,I32 -> I32 |
| 7,8 | CLAMP,MULDIV | 3 | I32,I32,I32 -> I32 |
| 9,10 | LT,LE | 2 | I32,I32 -> BOOL |
| 11 | EQ | 2 | matching types -> BOOL |
| 12,13,14 | AND,OR,NOT | 2,2,1 | BOOL operands -> BOOL |
| 15 | SELECT | 3 | BOOL, matching branch types -> branch type |

Schema fields 0..12 are I32: screen_w, screen_h, elapsed_seconds, team_count,
score_0..score_3, score_limit, health_milli, max_health_milli, boost_ms,
weapon_index. Fields 13..15 are BOOL: shield, connected, flash. The format does
not admit other host data, pointers, imports, callbacks, commands or jumps.
Validation checks structure/types, not numeric domains or evaluation results.
Successful validation does not establish numeric domains or rendered behavior.
Numeric draw ranges and raw host snapshot normalization remain outside this API.

Text descriptors are 8 bytes: first/count u16 at0/2, reserved zero u32 at4.
Counts are nonzero and descriptors exactly partition P in order, with no gaps
or overlap. Pieces are 12 bytes: kind u8 at0, reserved zero u8 at1, ref u16 at2,
offset/length u32 at4/8. LITERAL=1 requires ref NONE, offset equal to the running
pool cursor in piece order, length<=L-offset, then advances the cursor. The
final cursor must equal L. Zero-length literals use the current cursor,
including at L. Sharing, reordering, overlap and unused pool bytes refuse.
All pool bytes must be printable ASCII 32..126. DECIMAL=2 requires an existing
I32 ref and zero offset/length. Its conservative output length is 11 bytes.
All templates' literal lengths plus 11 per DECIMAL must total <=1024.

Draws are 24 bytes: kind u8 at0, zero u8 at1, BOOL visibility ref u16 at2,
seven I32 refs x/y/w/h/rgba/font_px/align u16 at4/6/8/10/12/14/16, text ref u16
at18, reserved zero u32 at20. RECT=1/RECT_LINES=2 require text NONE and actual
CONST_I32 zero font/align. TEXT=3 requires valid text and CONST_I32 zero w/h.
TEXT_BOX=4 requires valid text and CONST_I32 zero align. Computed zeros refuse
in structural fields. Sum of worst template lengths over all text draws must
be <=1024, including repetitions and invisible/mutually exclusive draws.

The bounded scan consumes wire sections once forward; only bounded inferred
types, structural-zero flags and text budgets are revisited. Canonical literal
ownership is representation canonicality, not uniqueness of equivalent DAGs.

`expr_evaluate(bytes,n,fields,budget,out,error)` validates the complete immutable
part before evaluating expressions. `fields` contains exactly 16 readable
normalized numbers in the field order above. All fields, even unused ones,
must be finite, integral, in [-2147483648,2147483647]; Boolean fields must be
exactly 0 or 1. NaN, either infinity, fractions, out-of-range values and other
Boolean values refuse with EX_SNAPSHOT. Finite/range checks precede conversion;
exact-integral checks follow the safe cast.
Negative zero is accepted as integer zero. This is no raw host snapshot ABI or
conversion of seconds, flags, health units or weapon indices.

Evaluation computes all expressions eagerly in wire order, including unused
ones and unselected SELECT branches. One expression costs one step. Budget
0..256 is explicit: insufficient budget refuses EX_EVAL_BUDGET, values above
256 refuse EX_LIMIT, and the empty part accepts budget zero. Validation is a
separate bounded scan over at most 10272 bytes; it is not charged as expression
steps. Every record extent and active operand index is checked against the
validated expression section before reading a record or cached value.

CONST_I32 preserves the signed immediate. FIELD returns the admitted field.
ADD_SAT and SUB_SAT use signed 64-bit intermediates and saturate to I32 limits.
MIN/MAX compare signed values. CLAMP limits a to [b,c], refusing EX_RANGE if
b>c. MULDIV computes signed 64-bit a*b/c, truncates toward zero, then saturates;
c=0 refuses EX_DIV_ZERO. Every I32 product fits I64 and cannot be INT64_MIN,
so even division by -1 is defined. Comparisons and Boolean operators return
exactly 0 or 1. SELECT returns b if a is true, otherwise c; it is not lazy.
No non-finite result is possible: expression operations are integer-only.

The evaluator has no recursion, heap allocation, callbacks or input retention.
Its fixed workspace is 256 I32 result slots plus 16 I32 snapshot slots, metadata
and scalar temporaries; the validator also uses fixed bounded arrays. Call depth
is fixed independently of the part. Success reports E results and E steps with
zeroed unused slots. Required output changes only on complete success; failures
leave it byte-for-byte unchanged and optionally set/log a trusted error.
Input storage and the two output objects must not overlap, and input storage
must remain valid and immutable for the entire call.

`expr_build_draws(bytes,n,values,op_capacity,text_capacity,out,error)` revalidates
this complete part and assembles its visible draws in order into the supplied
SKY_HUD_PART v1.2 data ABI: 64 forty-byte operations and a 1024-byte text arena,
3592 bytes total. No loader, renderer, file/network input, or host string API is
introduced. Capacities may reduce these limits; values above them refuse EX_LIMIT.
Exceeding either capacity refuses EX_OUTPUT for the whole part, never truncates
or publishes a partial recipe. Zero capacities accept an empty/fully hidden list.

The caller supplies the complete `expr_evaluate` result for these exact immutable
part bytes; count and steps must equal E or EX_VALUES refuses. These metadata
checks do not establish byte identity or authenticate computed numbers. All
input/output objects must be valid, disjoint, and immutable during the call.
Every section record, expression reference, text partition and literal extent is
checked before use. Visibility must be canonical 0/1 (otherwise EX_VALUES).
Only visible draws require nonnegative w/h; text additionally requires font
1..4096 and alignment 0..2, otherwise EX_RANGE. x/y stay signed I32; rgba preserves
the I32 bit pattern modulo 2^32. Structural zero fields still obey validation.

RECT/RECT_LINES emit their respective kind and geometry with zero text fields.
TEXT emits an anchor and font/alignment, with w=h=0. TEXT_BOX emits centre/top,
padding/height and font, with align=0; measurement remains the host's operation.
LITERAL bytes come only from the canonical literal pool with explicit lengths;
DECIMAL pieces emit canonical signed decimal I32 (including INT32_MIN), without
locale, formatting strings or external text. Each visible text use copies its
pieces into the arena, with checked text_off/text_len. Empty literals are valid.
The arena is counted bytes, not NUL-terminated strings; repeated uses cost bytes.

Assembly allocates nothing, recurses nowhere and retains no input. One fixed
local recipe plus bounded scalar metadata/11-byte decimal workspace provides
atomic publication. Success zeroes unused operations/arena bytes; every refusal
leaves output unchanged and optionally reports a trusted error. Validation's
conservative 1024-byte text budget includes invisible and repeated uses.

`expr_admit_file(path,pin,fields,budget,op_capacity,text_capacity,current,error)`
reads one regular file into a fixed 10272-byte candidate, checks its raw 32-byte
SHA-256 pin, then validates, evaluates and assembles in that order. `expr_part`
retains the exact admitted bytes, length, computed digest and initial recipe.
Only complete success replaces the whole current part; every refusal preserves
it byte-for-byte. Unused candidate byte/recipe storage is zeroed on success.
No game-loop integration, renderer, executable loader or activation is added.

Top-level typed outcomes distinguish ARGUMENT, READ, PIN, VALIDATE, EVALUATE,
and DRAW. Optional error carries that stage and the underlying expression
status/index/trusted reason. READ uses EX_LIMIT for oversize or EX_IO for open,
metadata, short/error read or changed metadata; PIN uses EX_FORMAT. Empty or
truncated files with matching pins reach VALIDATE and refuse EX_BOUNDS.
All outputs/inputs must be valid and disjoint; pin, path and normalized fields
stay immutable during the call; one externally serialized owner publishes.

The requested base has no ELF file reader: its ELF implementation on staged
main also accepts memory, with only an allocating private test reader. Admission
therefore uses existing `platform_positioned_file` regular-file primitives, a
fixed-buffer read loop, and standalone `zsha256`. It refuses final-component
symlinks and nonregular objects. Parent-directory confinement is caller policy.
One opened handle supplies metadata and bytes; before/after snapshots must match.
Each successful partial read advances, so there are at most 10272 read calls.
This is a byte/work bound, not an I/O deadline or protection against a hostile
filesystem blocking a syscall. No heap allocation is performed by admission.
Concurrent file changes can cause READ/PIN refusals; a matching digest binds
only the captured candidate, not a guarantee that the path stays unchanged
later. Publication uses the immutable captured bytes, never rereads the path.
