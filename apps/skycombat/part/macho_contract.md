<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->
<!-- purpose: Define the receiver-controlled Mach-O HUD-part admission and mapping-wide W^X lifecycle contract. -->

# Mach-O HUD parts

The receiver authorizes native execution separately. Admission checks a bounded
object format and relocation plan; W^X, hashes and signatures do not prove
machine-code safety or provide a sandbox.

The public gate in `part_open.h` copies stable readable bytes and the expected
raw SHA256 digest into private storage. It verifies the snapshot, runs inert
admission, then passes the same snapshot and digest to the loader. Digest and
admission refusals never dispatch. Opening never calls a candidate function.
The native loader also takes its own frozen copy and uses the same admission
and relocation implementation; there is no second, weaker parser.

The strict profile is thin little-endian arm64-all `MH_OBJECT`, at most 16 MiB,
64 sections and 4096 symbols/fixups, with a 1 MiB retained generation. Header
flags may contain only `MH_SUBSECTIONS_VIA_SYMBOLS` (0x2000); zero is allowed.
Reserved header and segment fields are zero, and the one segment's entire
16-byte name is empty. Its VM extent cannot overflow. Every section's declared
VM extent fits that segment, and every nonempty file-backed section fits the
segment's bounded file extent. File regions and virtual sections cannot overlap.

Both maxprot and initprot support only R/W/X bits. Initprot is a subset of
maxprot. Conventional compiler 7/7 declarations are accepted for MH_OBJECT:
its single declarative segment combines separate code and data sections and
does not describe an executable mapping. Actual staging and publication
permissions are fixed by the receiver, never derived from these declarations.
Writable data sections and instruction attributes on non-code sections still
refuse; accepting segment metadata does not admit a section combining writable
data and executable code. Tests admit exact unmodified Apple-produced objects
and observe NONE -> RW -> RX requests without executable-memory allocation.

There are no undefined imports, indirect/resolver symbols, weak imports,
startup/termination hooks, TLS or writable globals. The descriptor is a regular
non-text section with ABI 1, size 16 and an eight-byte-aligned mapped address.
Retained section starts are aligned to at least 16 bytes; the descriptor's
offset within its section must therefore be a multiple of eight.
Regular, cstring, literal8 and literal16
sections are supported, as are bounded linker optimization hints. ADDEND,
literal4, DATA_IN_CODE and unlisted forms refuse.

UNSIGNED, BRANCH26, PAGE21 and PAGEOFF12 retained fixups are checked for site
bounds, shape, alignment, effective target containment and overlap. Retained
references into discarded unwind sections refuse. Dropped unwind records
support only UNSIGNED and external BRANCH26; they undergo the same declared
effective-destination validation, including signed addends and instruction
opcode/alignment checks. Resolution uses declared old addresses and permits
dropped targets without inventing mapped addresses. Dropped bytes produce no
mapping writes or fixups. Both full-width `__compact_unwind` and `__eh_frame`
names are recognized.

The serialized arm64 macOS backend reserves an arena with PROT_NONE and
replans at the checked, 16 KiB aligned actual inactive-slot address. It removes
execute permission while changing that entire slot to RW, writes only after
that call succeeds, then changes the slot to RX and flushes its instruction
cache before publishing a new generation. It never requests RWX or MAP_JIT
and creates no writable alias. A refused protection transition never publishes
or changes the current generation. An inactive slot may remain RW after a
failed RX transition; the current slot stays RX. Cleanup failure retains the
arena and marks the host failed until successful disposal. Generation borrows
block replacement and disposal.

If the OS refuses reservation or protection, loading fails closed without a
per-thread-JIT fallback. Other production platforms refuse without mappings.
Native macOS execution and OS protection qualification remain separate from
portable acceptance; a Linux mock cannot establish native support.

The canonical `skycombat_macho_parts` group reuses the existing C23 SHA256
package, preserves all 37 original typed strict mutations on an RX-declared
copy, and covers all three assurance gaps. VM observers compile the actual
loader body but substitute ordinary inert allocated memory for all VM calls;
they require RW during full-slot clearing and before RX publication, and observe
injected refusals, cleanup and generation lifetime without POSIX mapping headers,
and never execute candidate code. These optional sources are not integrated
into the playable game's existing build targets.
