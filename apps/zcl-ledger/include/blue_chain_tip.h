/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef BLUE_CHAIN_TIP_H
#define BLUE_CHAIN_TIP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t next_height;
    char block_hash[65];
} blue_chain_tip;

bool blue_chain_tip_parse(const char *reply, size_t length,
                          blue_chain_tip *tip);
bool blue_chain_tip_same(const blue_chain_tip *first,
                         const blue_chain_tip *second);
bool blue_rpc_capture(const char *rpc_binary, const char *method,
                      const char *argument, char *reply, size_t capacity,
                      size_t *length);
bool blue_chain_tip_query(const char *rpc_binary, blue_chain_tip *tip);
bool blue_chain_tip_still_current(const char *rpc_binary,
                                  const blue_chain_tip *initial);

#endif
