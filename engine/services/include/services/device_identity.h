/* purpose: Define supplied device key custody and exclusive private identity publication. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_IDENTITY_H
#define ZCL_SERVICES_DEVICE_IDENTITY_H
#include "base/result.h"
#include "models/device_pairing.h"
#include <stdbool.h>
#include <stdint.h>

struct device_identity {
    char directory[1024];
    uint8_t private_key[32], public_key[32];
};
enum device_identity_publication {
    DEVICE_IDENTITY_NOT_PUBLISHED,
    DEVICE_IDENTITY_DURABLE,
    DEVICE_IDENTITY_DURABILITY_UNKNOWN
};
struct device_identity_publication_report {
    enum device_identity_publication state;
    bool public_key_known;
    uint8_t public_key[32];
};
/* Initialization requires an absent destination beneath trusted ancestors.
 * Read-only open never writes or repairs. Outputs and directory must be
 * independent of each other; caller releases any prior identity before reuse.
 * Every failure cleanses identity; the separate report retains public facts.
 * Unknown initialization preserves artifacts and must not be retried blindly.
 * A fresh read proves exact bytes, never historical publication durability.
 * Windows creation refuses before mutation until directory durability is
 * qualified; existing-profile observation retains its read-only contract. */
struct zcl_result device_identity_open(struct device_identity *identity,
    const char *directory, bool create, struct device_identity_publication_report *report);
void device_identity_close(struct device_identity *identity);
#ifdef ZCL_TESTING
/* One-shot faults after durable intent, durable key/profile, and intent retire. */
void device_identity_test_interrupt(unsigned stage);
#endif
/* Caller-owned explicitly accepted identity in a trusted owner-private profile.
 * The caller establishes the directory-to-public-key binding and explicit
 * owner approval; a fingerprint or checksum alone establishes neither.
 * Hostile preexisting files or ancestor/path replacement are unqualified here.
 * The caller supplies a matching private/public key pair, retains it through
 * the exchange and cleanses its private bytes afterward.
 * All input/output storage is independent. */
struct zcl_result device_identity_pair_store(const struct device_identity *identity,
                                             const uint8_t peer[32],
                                             struct device_pairing_store *store);
#endif
