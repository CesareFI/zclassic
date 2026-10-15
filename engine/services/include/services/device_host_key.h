/* purpose: Define canonical public SSH composite-key representation and approval roots. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_HOST_KEY_H
#define ZCL_SERVICES_DEVICE_HOST_KEY_H
#include "base/result.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DEVICE_HOST_KEY_BLOB_SIZE 1371u
/* Parse only the plain ssh-mldsa44-ed25519 SSH public-key wire blob for the
 * recognized pairing backend profile. No text, certificates or trailing bytes.
 * Hash the canonical bytes using the device_pairing.h Z23HOSTSSHKEY1 contract.
 * This establishes representation and root identity only, not cryptographic
 * validity, ownership, possession or backend qualification. No allocations.
 * Caller supplies independent input/output storage; output is unchanged on
 * refusal, with a contextual failed result. Success has canonical code zero.
 * No private keys, filesystem, process or transport authority. */
struct zcl_result device_host_key_root(uint32_t backend_profile, const uint8_t *blob,
    size_t length, uint8_t root[32]);
#endif
