# zclassic23/fdt

Flattened Device Tree (DTB) writer and reader, devicetree specification v0.4
(blob version 17, last compatible version 16). It lets the RISC-V emulator hand
a device tree to the guest kernel.

The writer builds a blob into a caller-owned buffer: header, memory
reservation block, structure block and a de-duplicated strings block. The
reader validates a blob in full before any lookup (`fdt_check`), then finds
nodes by path and reads their properties. Errors are typed; a corrupt or
truncated blob fails closed.

There is no allocation, no I/O and no global state. The code is original
Apache-2.0 work written from the specification; it does not copy libfdt. It
depends only on the C standard library.
