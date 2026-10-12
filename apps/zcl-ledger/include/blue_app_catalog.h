/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_APP_CATALOG_H
#define ZCL_BLUE_APP_CATALOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue app catalog requires ISO C23"
#endif

enum { ZCL_BLUE_APP_NAME_SIZE = 32 };

typedef struct {
    char name[ZCL_BLUE_APP_NAME_SIZE];
    uint32_t flags;
    uint8_t hash_code_data[32];
    uint8_t hash[32];
} blue_app_entry;

/* Parses a Ledger Blue format-1 app-list page; an empty page ends the list. */
int blue_app_catalog_parse(const uint8_t *page, size_t length,
                           blue_app_entry *entries, size_t capacity,
                           size_t *count);

/* Requires exactly one catalog entry for name and its complete app hash. */
bool blue_app_catalog_unique_hash(const blue_app_entry *entries,
    size_t count, const char *name, const uint8_t expected[32]);

#endif
