/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef BLUE_UTXO_H
#define BLUE_UTXO_H

#include "zcl_tx_prevout.h"
#include "blue_chain_tip.h"

bool blue_utxo_parse(const char *reply, size_t length, const char *txid_hex,
                     uint32_t output_index, uint64_t value_zat,
                     const uint8_t *script, size_t script_length,
                     uint32_t next_height);
bool blue_utxo_check_inputs(const char *rpc_binary, const uint8_t *wire,
                            size_t length,
                            const zcl_tx_previous_transaction *previous,
                            size_t previous_count, uint32_t next_height);
bool blue_utxo_recheck_at_tip(const char *rpc_binary,
                              const blue_chain_tip *initial,
                              const uint8_t *wire, size_t length,
                              const zcl_tx_previous_transaction *previous,
                              size_t previous_count);

#endif
