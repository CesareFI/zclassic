/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: A no-root dress rehearsal of the fixed-result verifier pipeline
 *          for the verify_signer group: the real worker's `qualify` output,
 *          a fixture "launcher" that writes launch receipt v2 and failure
 *          receipt v2 records, the signer, the publisher, and the receiver
 *          (cold -E and -c, key v2, zcl_verify_store_lookup_site_fixture,
 *          which runs production's policy, pins and store walk under the
 *          fixture's own anchor).
 *
 * Every trust root is a test directory the fixture creates and every UID
 * is the test's own; the signer and publisher accept that only through
 * their explicit allow_same_uid fixture flag. Linux only. */
#ifndef ZCL_TEST_VERIFY_SIGNER_FIXTURE_H
#define ZCL_TEST_VERIFY_SIGNER_FIXTURE_H

#include "dev/verify_store.h"
#include "verify/fixed_result_contract.h"
#include "verify/fixed_result_publisher.h"
#include "verify/fixed_result_signer.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VSG_RECEIPT_CAP 8192u
#define VSG_FAIL_STDERR "platform/modules/base/src/result.c:1:1: error: x\n"

struct vsg_bytes {
    uint8_t *p;
    size_t n;
};

/* One launch's root-written evidence. */
struct vsg_launch {
    char id[ZCL_FR_ID_LEN + 1u];
    uint8_t bytes[VSG_RECEIPT_CAP];
    size_t len;
    bool failure;
};

/* A fresh site: anchor/etc/z23verify holds the trust files (store.policy,
 * pins, profile, verifier.pub, box_signer.pub) and dir is
 * anchor/var/lib/z23verify with store/, locks/fixed_result.lock,
 * launches/<id>/, publish-tmp/, conflicts/, staging/ and key/signer.seed. */
struct vsg_state {
    char anchor[PATH_MAX];
    char etc[PATH_MAX];
    char dir[PATH_MAX];
    char staging[PATH_MAX];
    char key_dir[PATH_MAX];
    char lock[PATH_MAX];
    char pass_launch[PATH_MAX];
    char fail_launch[PATH_MAX];
};

/* Built in place; never copy it. */
struct vsg_world {
    char root[PATH_MAX];
    char build[PATH_MAX];
    char key_root[PATH_MAX];
    char cwd[PATH_MAX];
    char target[ZCL_FR_TARGET_LEN + 1u];
    struct zcl_fixed_result_v2_roots pins;
    uint8_t seed[32];
    uint8_t pub[32];
    uint8_t box_seed[32];
    uint8_t box_pub[32];
    struct zcl_verify_attest_box_key box;
    struct vsg_bytes profile;
    /* The worker's qualify outputs. */
    struct vsg_bytes object, deps, err, pp;
    struct vsg_launch pass, fail;
    unsigned states;
};

/* Run the worker, write the trust files and both receipts. */
bool vsg_world_make(struct vsg_world *w);
void vsg_world_free(struct vsg_world *w);

bool vsg_state_make(struct vsg_world *w, struct vsg_state *s);

/* Rewrite one trust file in the site's etc (0444, or 0644 for a key). */
bool vsg_etc_write(const struct vsg_state *s, const char *name,
                   const void *bytes, size_t len);
bool vsg_etc_pins(const struct vsg_state *s,
                  const struct zcl_fixed_result_v2_roots *pins);
bool vsg_etc_pubkey(const struct vsg_state *s, const char *name,
                    const uint8_t pub[32]);

/* Replace a file's bytes and mode by unlink and exclusive create. */
bool vsg_file_replace(const char *dir, const char *name, const void *bytes,
                      size_t len, unsigned mode);

bool vsg_path(char out[PATH_MAX], const char *a, const char *b);

struct zcl_frs_fixture vsg_signer(const struct vsg_state *s);
struct zcl_frp_fixture vsg_publisher(const struct vsg_state *s);

/* Seal the launch in `launch_dir` with `fx`. */
void vsg_seal(const struct zcl_frs_fixture *fx, const char *launch_dir,
              struct zcl_frs_result *out);

/* The receiver: its own cold -E and -c of result.c into build/<tag>/,
 * key v2 from its own inputs, then the site store lookup (allow_same_uid
 * false is the production receiver's refusal). `cold_object` gets
 * the cold object's bytes. */
bool vsg_receive(struct vsg_world *w, const struct vsg_state *s,
                 const char *tag, bool allow_same_uid,
                 struct zcl_verify_store_result *out,
                 struct vsg_bytes *cold_object);

void vsg_bytes_free(struct vsg_bytes *b);
void vsg_hex(const uint8_t *bytes, size_t len, char out[65]);

#endif
