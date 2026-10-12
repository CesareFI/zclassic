/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Internal layout of the facts index shared by its loader (devloop_facts_index.c) and its graph (devloop_facts_graph.c). */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_FACTS_INDEX_PRIV_H
#define ZCL_TOOLS_DEV_DEVLOOP_FACTS_INDEX_PRIV_H

#include "devloop_facts_index.h"

#include "vcs/semantic_manifest.h"

struct fxi_ent {
    char *id;         /* owned, NUL-terminated */
    const char *bare; /* the name after the last ':' */
    uint8_t digest[32];
    uint8_t whole[32]; /* every record of it, the main file's included */
    bool main_owned;  /* a record of it lies in the main file */
    bool other_row;   /* a record of it lies outside the main file */
    bool root;
    bool main_fn;     /* the main file defines it as a function */
    bool defined_fn;  /* a FUNCTIONS record in any file defines it */
    bool has_span;
    const char *span_path; /* into the manifest; not NUL-terminated */
    size_t span_path_len;
    uint32_t span_lo, span_hi;
    uint32_t first_row, nrows;
    uint8_t unknown_kinds; /* 1 << UNKNOWNS kind, for each record at it */
};

struct fxi_row {
    uint32_t ent;
    uint32_t seq;      /* manifest order */
    uint8_t section;
    int8_t main;       /* 1 main file, 0 other, -1 decided by its entity */
    const uint8_t *raw;
    uint32_t len;
};

struct fxi_edge {
    uint32_t from, to;
    uint8_t kind; /* the REFS kind, 0 for a closure edge */
};

/* A macro definition: its entity, its name group and its body. */
struct fxi_macro {
    uint32_t ent, group;
    const char *body;
    size_t len;
};

struct fxi_file {
    char *path; /* NUL-terminated copy */
    size_t path_len;
    const uint8_t *digest;
    uint8_t origin;
};

struct fxi {
    const uint8_t *m;
    size_t n;
    char *main;
    const uint8_t *main_digest;
    bool complete;
    uint8_t revision;
    const uint8_t *identity; /* the IDENTITY record body, into m */
    size_t identity_len;
    const char *compiler;    /* its compiler text, into m; not NUL-terminated */
    size_t compiler_len;
    const char *target;      /* its target text, into m; not NUL-terminated */
    size_t target_len;
    uint8_t producer[32];
    uint8_t section_digest[VCS_SEMANTIC_SECTION_V1_COUNT][32];
    struct fxi_file *files;
    size_t nfiles, capfiles;
    struct fxi_ent *ents;
    size_t nents, capents;
    uint32_t *slots; /* id hash table: entity index + 1 */
    size_t nslots;
    struct fxi_row *rows;
    size_t nrows, caprows;
    struct fxi_macro *macros;
    size_t nmacros, capmacros;
    struct fxi_edge *edges;
    size_t nedges, capedges;
    /* CSR adjacency over edge indices, built once the edges are complete:
     * out_edge[out_off[e] .. out_off[e + 1]) leave e, in_edge[...] enter it */
    uint32_t *out_off, *out_edge, *in_off, *in_edge;
    bool failed;
};

/* devloop_facts_index.c */
bool fxi_ent_get(struct fxi *x, const char *id, size_t len, uint32_t *e);
bool fxi_edge_add(struct fxi *x, uint32_t from, uint32_t to, uint8_t kind);
bool fxi_lookup(const struct fxi *x, const char *id, size_t len, uint32_t *e);

/* devloop_facts_graph.c: closure edges, adjacency, roots */
bool fxi_graph_build(struct fxi *x);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_FACTS_INDEX_PRIV_H */
