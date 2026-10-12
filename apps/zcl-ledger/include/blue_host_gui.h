/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_HOST_GUI_H
#define ZCL_BLUE_HOST_GUI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue host GUI requires ISO C23"
#endif

/* Laptop-side facts for one transparent payment. They are display text
 * plus the 32-byte ZIP-243 digest the Blue would sign. They grant no
 * key, review, signing, or installation authority by themselves. */
enum {
    BLUE_HOST_GUI_CONNECTION_SIZE = 48,
    BLUE_HOST_GUI_APP_SIZE = 32,
    BLUE_HOST_GUI_VERSION_SIZE = 16,
    BLUE_HOST_GUI_ADDRESS_SIZE = 40,
    BLUE_HOST_GUI_AMOUNT_SIZE = 32,
    BLUE_HOST_GUI_NETWORK_SIZE = 24,
    BLUE_HOST_GUI_MEMO_SIZE = 80,
    BLUE_HOST_GUI_APPROVAL_SIZE = 24,
    BLUE_HOST_GUI_DIGEST_SIZE = 32
};

typedef struct {
    char connection[BLUE_HOST_GUI_CONNECTION_SIZE];
    char app_name[BLUE_HOST_GUI_APP_SIZE];
    char app_version[BLUE_HOST_GUI_VERSION_SIZE];
    char receive[BLUE_HOST_GUI_ADDRESS_SIZE];
    char recipient[BLUE_HOST_GUI_ADDRESS_SIZE];
    char amount[BLUE_HOST_GUI_AMOUNT_SIZE];
    char fee[BLUE_HOST_GUI_AMOUNT_SIZE];
    char network[BLUE_HOST_GUI_NETWORK_SIZE];
    char memo[BLUE_HOST_GUI_MEMO_SIZE];
    char approval[BLUE_HOST_GUI_APPROVAL_SIZE];
    uint8_t digest[BLUE_HOST_GUI_DIGEST_SIZE];
} blue_host_gui_facts;

typedef enum {
    BLUE_HOST_GUI_BIND_MATCH = 0,
    BLUE_HOST_GUI_BIND_CONNECTION,
    BLUE_HOST_GUI_BIND_APP_NAME,
    BLUE_HOST_GUI_BIND_APP_VERSION,
    BLUE_HOST_GUI_BIND_RECEIVE,
    BLUE_HOST_GUI_BIND_RECIPIENT,
    BLUE_HOST_GUI_BIND_AMOUNT,
    BLUE_HOST_GUI_BIND_FEE,
    BLUE_HOST_GUI_BIND_NETWORK,
    BLUE_HOST_GUI_BIND_MEMO,
    BLUE_HOST_GUI_BIND_APPROVAL,
    BLUE_HOST_GUI_BIND_DIGEST
} blue_host_gui_bind_status;

/* Distinct authorities. A value names one role; combinations are refused. */
enum {
    BLUE_HOST_GUI_AUTHORITY_REVIEW = 1,
    BLUE_HOST_GUI_AUTHORITY_KEYS = 2,
    BLUE_HOST_GUI_AUTHORITY_SIGN = 3,
    BLUE_HOST_GUI_AUTHORITY_INSTALL = 4
};

bool blue_host_gui_facts_set(blue_host_gui_facts *facts,
    const char *connection, const char *app_name, const char *app_version,
    const char *receive, const char *recipient, const char *amount,
    const char *fee, const char *network, const char *memo,
    const char *approval, const uint8_t digest[BLUE_HOST_GUI_DIGEST_SIZE]);

/* Representative transparent payment from the public fixture and the
 * simulator's published test vector. The digest is the ZIP-243 value. */
bool blue_host_gui_load_representative(blue_host_gui_facts *facts);

/* Screen facts must match the laptop facts, and both digests must match
 * signed_bytes. A mismatch names the first differing field. */
blue_host_gui_bind_status blue_host_gui_bind(
    const blue_host_gui_facts *gui, const blue_host_gui_facts *screen,
    const uint8_t *signed_bytes, size_t signed_length);

/* Copies device_signature only when authority is exactly SIGN and bind
 * matches. Every refusal wipes out. Review, keys, and install cannot sign. */
bool blue_host_gui_release_signature(
    const blue_host_gui_facts *gui, const blue_host_gui_facts *screen,
    const uint8_t *signed_bytes, size_t signed_length, int authority,
    const uint8_t *device_signature, size_t device_signature_length,
    uint8_t *out, size_t out_capacity, size_t *out_length);

/* True only for exact INSTALL authority and an image the installer allows.
 * Wallet 0.3.46 stays blocked. Review cannot install. */
bool blue_host_gui_permit_install(int authority, const char *name,
                                  const char *version);

/* Draws every fact. Large text and dark mode keep the same strings.
 * Returns false if any fact would be omitted. */
bool blue_host_gui_render_png(const char *path,
    const blue_host_gui_facts *facts, bool dark, bool large_text);

bool blue_host_gui_write_log(FILE *out, const blue_host_gui_facts *facts,
                             blue_host_gui_bind_status status);

#endif
