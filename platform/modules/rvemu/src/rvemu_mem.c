/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the physical bus beyond RAM: the optional device callbacks for a
 * data access that is not wholly inside RAM. The bounds-checked little-endian
 * RAM accessors are inline in rvemu_internal.h; the byte order comes from the
 * one shared base helper, zcl_read/write_u64_le. */
#include "rvemu_internal.h"

/* The low n bytes of v (n is 1 to 8), through the shared little-endian codec. */
static uint64_t low_bytes(uint64_t v, unsigned n)
{
    uint8_t wide[8];
    zcl_write_u64_le(wide, v);
    memset(wide + n, 0, 8u - n);
    return zcl_read_u64_le(wide);
}

int rvemu_mem_load(const struct rvemu_mem *mem, uint64_t addr, unsigned n, uint64_t *out)
{
    if (rvemu_ram_load(mem, addr, n, out) == 0) return 0;
    if (!mem->io_load || n == 0 || n > 8) return -1;
    uint64_t v = 0;
    if (mem->io_load(mem->io_ctx, addr, n, &v) != 0) return -1;
    *out = low_bytes(v, n);
    return 0;
}

int rvemu_mem_store(struct rvemu_mem *mem, uint64_t addr, unsigned n, uint64_t val)
{
    if (rvemu_ram_store(mem, addr, n, val) == 0) return 0;
    if (!mem->io_store || n == 0 || n > 8) return -1;
    return mem->io_store(mem->io_ctx, addr, n, low_bytes(val, n)) == 0 ? 0 : -1;
}
