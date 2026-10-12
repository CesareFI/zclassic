/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Flattened Device Tree (DTB) writer and reader, devicetree specification
 * v0.4 (blob version 17, last compatible version 16).
 *
 * Every buffer is caller-owned. Nothing allocates, performs I/O or keeps
 * global state. Every error is a typed enum value, and a failed call leaves
 * the writer unchanged. */
#ifndef ZCL_FDT_FDT_H
#define ZCL_FDT_FDT_H

#include <stddef.h>
#include <stdint.h>

#define FDT_MAGIC UINT32_C(0xd00dfeed)
#define FDT_VERSION 17u
#define FDT_LAST_COMP_VERSION 16u
#define FDT_HEADER_SIZE 40u
#define FDT_RSV_ENTRY_SIZE 16u
#define FDT_TOKEN_BEGIN_NODE UINT32_C(0x1)
#define FDT_TOKEN_END_NODE UINT32_C(0x2)
#define FDT_TOKEN_PROP UINT32_C(0x3)
#define FDT_TOKEN_NOP UINT32_C(0x4)
#define FDT_TOKEN_END UINT32_C(0x9)
/* Deepest node nesting either side accepts. */
#define FDT_MAX_DEPTH 32u
/* Longest node or property name, excluding the terminating NUL. */
#define FDT_MAX_NAME 31u
/* Capacity of the writer's de-duplicated property-name table, in bytes. */
#define FDT_STRINGS_MAX 2048u

enum fdt_status {
    FDT_OK = 0,
    FDT_ERR_ARG,
    FDT_ERR_NO_SPACE,
    FDT_ERR_NESTING,
    FDT_ERR_BAD_NAME,
    FDT_ERR_NOT_FINISHED,
    FDT_ERR_STATE,
    FDT_ERR_BAD_MAGIC,
    FDT_ERR_BAD_VERSION,
    FDT_ERR_TOTALSIZE,
    FDT_ERR_OFFSET,
    FDT_ERR_ALIGN,
    FDT_ERR_TRUNCATED,
    FDT_ERR_NO_END,
    FDT_ERR_BAD_TOKEN,
    FDT_ERR_STRING_OFFSET,
    FDT_ERR_NOT_FOUND,
    FDT_ERR_BAD_NODE
};

/* Writer. Layout in the caller buffer: header, memory reservation block,
 * structure block, strings block. Property names are de-duplicated into the
 * writer's own table and copied to the strings block by fdt_finish. */
struct fdt_writer {
    uint8_t *buf;
    size_t cap;
    size_t rsv_bytes;
    size_t struct_len;
    size_t depth;
    size_t str_len;
    int root_closed;
    int finished;
    uint8_t strings[FDT_STRINGS_MAX];
};

enum fdt_status fdt_writer_init(struct fdt_writer *w, uint8_t *buf, size_t cap);
enum fdt_status fdt_add_reservation(struct fdt_writer *w, uint64_t addr, uint64_t size);
enum fdt_status fdt_begin_node(struct fdt_writer *w, const char *name);
enum fdt_status fdt_end_node(struct fdt_writer *w);
enum fdt_status fdt_prop(struct fdt_writer *w, const char *name, const void *data, size_t len);
enum fdt_status fdt_prop_u32(struct fdt_writer *w, const char *name, uint32_t value);
enum fdt_status fdt_prop_u64(struct fdt_writer *w, const char *name, uint64_t value);
enum fdt_status fdt_prop_string(struct fdt_writer *w, const char *name, const char *value);
enum fdt_status fdt_prop_strings(struct fdt_writer *w, const char *name,
                                 const char *const *values, size_t count);
enum fdt_status fdt_finish(struct fdt_writer *w, size_t *len);

/* Reader. Every entry point revalidates the whole blob first (fdt_check), so a
 * corrupt or truncated blob fails closed. A node handle is the byte offset of
 * its FDT_TOKEN_BEGIN_NODE token, as returned by fdt_find_node. */
typedef size_t fdt_node_t;

enum fdt_status fdt_check(const void *buf, size_t len);
enum fdt_status fdt_find_node(const void *buf, size_t len, const char *path,
                              fdt_node_t *node);
enum fdt_status fdt_get_prop(const void *buf, size_t len, fdt_node_t node,
                             const char *name, const uint8_t **data, size_t *data_len);

#endif
