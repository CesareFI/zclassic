/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_TX_SCRIPT_FACTS_H
#define ZCL_TX_SCRIPT_FACTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "ZCL script review requires ISO C23"
#endif

typedef struct {
    uint32_t p2pkh_outputs;
    uint32_t p2sh_outputs;
    uint32_t op_return_outputs;
    uint32_t other_outputs;
    bool zslp_marker;
} zcl_tx_script_facts;

typedef enum {
    ZCL_TX_OUTPUT_P2PKH,
    ZCL_TX_OUTPUT_P2SH,
    ZCL_TX_OUTPUT_OP_RETURN,
    ZCL_TX_OUTPUT_OTHER
} zcl_tx_output_type;

typedef struct {
    uint32_t index;
    uint64_t value_zat;
    const uint8_t *script;
    size_t script_length;
    zcl_tx_output_type type;
} zcl_tx_output;

typedef bool (*zcl_tx_output_visitor)(void *context,
                                      const zcl_tx_output *output);

typedef struct {
    uint32_t index;
    const uint8_t *previous_txid;
    uint32_t previous_output_index;
    const uint8_t *script;
    size_t script_length;
    uint32_t sequence;
} zcl_tx_input;

typedef bool (*zcl_tx_input_visitor)(void *context,
                                     const zcl_tx_input *input);

/* Visits every transparent input after validating the complete v4 wire. */
int zcl_tx_inputs_visit(const uint8_t *wire, size_t length,
                        zcl_tx_input_visitor visitor, void *context);

/* Visits every transparent output after validating the complete wire. */
int zcl_tx_outputs_visit(const uint8_t *wire, size_t length,
                          zcl_tx_output_visitor visitor, void *context);

/* Host-only wire observations. The marker does not validate a ZSLP transfer;
 * P2SH does not establish a multisig threshold. */
int zcl_tx_script_facts_parse(const uint8_t *wire, size_t length,
                              zcl_tx_script_facts *facts);

#endif
