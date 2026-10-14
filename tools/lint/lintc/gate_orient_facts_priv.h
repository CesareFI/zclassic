/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by gate_orient_facts.c and its
 * selftest.
 */
#ifndef GATE_ORIENT_FACTS_PRIV_H
#define GATE_ORIENT_FACTS_PRIV_H

#include <stddef.h>
#include <stdio.h>

struct of_index {
    char **files;
    size_t nfiles;
    int any_include;
    char *topics;
    size_t topics_len;
    size_t ntopic_rows;
};

struct of_run {
    FILE *out;
    FILE *err;
    const char *dir;
    char *index;
    struct of_index *ix;
    long rows;
    int rc;
};

void of_index_load(struct of_index *ix, const char *path);
void of_index_free(struct of_index *ix);
void of_split_fields(char *line, char *f[5]);
int of_anchor_found(const char *path, const char *anchor);
/* Scans one facts directory; 0 when every row is true. */
int of_scan(const char *dir, FILE *out, FILE *err);

#endif
