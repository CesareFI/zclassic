/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "fdt/fdt.h"

#include <string.h>

/* Standalone smoke test for the package gate: write a small tree, check it,
 * find a node and read a property back. The full proof lives in
 * tests/harness/src/test_fdt.c. */
int main(void)
{
    uint8_t blob[256];
    struct fdt_writer w;
    size_t len = 0;
    fdt_node_t node = 0;
    const uint8_t *data = NULL;
    size_t data_len = 0;
    if (fdt_writer_init(&w, blob, sizeof blob) != FDT_OK) return 1;
    if (fdt_begin_node(&w, "") != FDT_OK) return 2;
    if (fdt_prop_string(&w, "compatible", "riscv-virtio") != FDT_OK) return 3;
    if (fdt_begin_node(&w, "cpus") != FDT_OK) return 4;
    if (fdt_prop_u32(&w, "timebase-frequency", 10000000) != FDT_OK) return 5;
    if (fdt_end_node(&w) != FDT_OK || fdt_end_node(&w) != FDT_OK) return 6;
    if (fdt_finish(&w, &len) != FDT_OK) return 7;
    if (fdt_check(blob, len) != FDT_OK) return 8;
    if (fdt_find_node(blob, len, "/cpus", &node) != FDT_OK) return 9;
    if (fdt_get_prop(blob, len, node, "timebase-frequency", &data, &data_len) != FDT_OK) return 10;
    if (data_len != 4 || memcmp(data, "\x00\x98\x96\x80", 4) != 0) return 11;
    return 0;
}
