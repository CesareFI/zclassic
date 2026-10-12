/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The receiver inside a landing proof for the one fixed
 *          translation unit, test-fast platform/modules/base/src/result.c.
 *
 * The proof driver (the lander's pinned z23-dev, never the candidate's
 * build) decides whether a signed separate-account observation may stand in
 * for compiling that unit. Before the bundle `make` it builds every
 * expectation itself from the generation's own files and root-owned
 * policy: a fresh `-E` in the generation with the pinned profile, the
 * portable source content root over the files that `-E` read, the
 * expected key v2, and a store lookup that verifies the signed record, its
 * root launch receipt and every artifact byte. Only an admitted
 * observation is written into a driver-private directory; the in-tree zcc
 * epoch publisher copies those bytes into the exact epoch target instead
 * of launching the compiler, and only when make's actual compiler argv
 * equals the pinned profile token for token. After make the driver rehashes
 * the published object and depfile and the source it measured, so the
 * build can never claim a HIT for bytes the driver did not admit.
 *
 * Every outcome is a stable token written to phases.txt:
 *   object_reuse_admit=cold(<token>)   compile ran, nothing reused
 *   object_reuse_admit=block(<token>)  contradiction; the step fails
 *   object_reuse_admit=hit(<store_key>,<record_sha3>)
 * See docs/work/separate-verifier.md, "Receiver". */
#ifndef ZCL_TOOLS_DEV_VERIFY_RECEIVER_H
#define ZCL_TOOLS_DEV_VERIFY_RECEIVER_H

#include "verify_attest.h"
#include "verify/fixed_result_key_v2.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The environment variable the driver sets for the bundle make, naming the
 * admitted directory; zcc honours it only in proof mode (ZCC_VERIFIED). */
#define ZCL_VERIFY_RECEIVER_ENV "ZCC_ADMITTED"
/* Admitted directory members, read by zcc. */
#define ZCL_VERIFY_RECEIVER_ARGV "argv"
#define ZCL_VERIFY_RECEIVER_OBJECT "object.o"
#define ZCL_VERIFY_RECEIVER_DEP_TAIL "depfile.tail"
#define ZCL_VERIFY_RECEIVER_STDERR "stderr.bin"
#define ZCL_VERIFY_RECEIVER_LOG "zcc.log"
/* The physical generation root; zcc serves only when its cwd is exactly
 * this directory, so a sub-make run in another tree is never served. */
#define ZCL_VERIFY_RECEIVER_ROOT "root"
/* The -MT target of the receiver's own -E: the fixed 121-byte shape with an
 * all-zero epoch, so its depfile wraps exactly like the real target's. */
#define ZCL_VERIFY_RECEIVER_PLACEHOLDER_TARGET \
    "build/test-obj/epochs/" \
    "0000000000000000000000000000000000000000000000000000000000000000" \
    "/platform/modules/base/src/result.o"
#define ZCL_VERIFY_RECEIVER_PROFILE_PATH "/etc/z23verify/fixed_result_fast.args"
#define ZCL_VERIFY_RECEIVER_COMPILER "/usr/bin/cc"

enum zcl_verify_receiver_verdict {
    ZCL_VERIFY_RECEIVER_COLD = 0,
    /* Prepared: an observation is admitted and waits to be consumed. */
    ZCL_VERIFY_RECEIVER_ADMITTED = 1,
    ZCL_VERIFY_RECEIVER_HIT = 2,
    ZCL_VERIFY_RECEIVER_BLOCK = 3,
};

struct zcl_verify_receiver {
    enum zcl_verify_receiver_verdict verdict;
    const char *reason; /* a stable token; NULL only on ADMITTED and HIT */
    char reason_buf[64]; /* storage for a token read back from the zcc log */
    char generation[PATH_MAX]; /* physical generation root */
    char work[PATH_MAX];       /* driver-private admitted directory */
    char store_key[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    char record_sha3[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    uint8_t obj_sha3[32];
    size_t obj_len;
    uint8_t *dep_tail; /* own depfile bytes after the placeholder target */
    size_t dep_tail_len;
    char **inputs;     /* project files the fresh -E read, sorted */
    size_t input_count;
    uint8_t source_content[32];
    int lock_fd; /* shared publication lock, held until release */
    /* Measurement. CPU covers the driver and its -E child only. */
    int64_t wall_us;
    int64_t cpu_us;
    uint64_t bytes;
    unsigned launches_avoided;
    unsigned compile_launches; /* compiler launches zcc logged in the step */
};

/* The receiver's portable source identity over the files its own -E read:
 * the source content root v2 (zcl_fr_source_content_v2), measured by the
 * same reader the launcher uses for its pin (zcl_fr_source_content_at).
 * Owner and mode are not part of it, so a 0600 proof generation and a
 * root-owned 0444 image of the same bytes agree. Returns NULL or a token. */
const char *zcl_verify_receiver_source_content(int root_fd,
                                               char *const *paths,
                                               size_t count,
                                               uint8_t out[32]);

/* Parse the prerequisites of a depfile's first rule (after `target:`),
 * sorted and de-duplicated. `*out` is allocated; release with
 * zcl_verify_receiver_paths_free. Returns NULL or a token. */
const char *zcl_verify_receiver_depfile_inputs(const uint8_t *dep,
                                               size_t dep_len,
                                               const char *target,
                                               char ***out, size_t *count);
void zcl_verify_receiver_paths_free(char **paths, size_t count);

/* Production: the root-pinned key, the root-owned profile, pins and store.
 * `generation` is the directory make runs in; `work_dir` is created fresh
 * (0700) and must not lie inside the generation. With no installed
 * verifier the result is COLD with reason no_verifier_key. */
void zcl_verify_receiver_prepare(const char *generation, const char *work_dir,
                                 const struct zcl_verify_attest_box_key *box,
                                 struct zcl_verify_receiver *out);

#ifdef ZCL_TESTING
/* Isolated fixture only: production's exact policy, pins and store walk
 * under a test-owned anchor (zcl_verify_store_lookup_site_fixture), with
 * the pins read from anchor/etc/z23verify/fixed_result.pins by the same
 * custody checks. The profile and compiler come from the test. Production
 * does not compile an override. */
struct zcl_verify_receiver_fixture {
    const char *site_anchor;
    bool allow_same_uid;
    const char *profile_path;
    const char *compiler; /* NULL: /usr/bin/cc */
};

void zcl_verify_receiver_prepare_fixture(
    const char *generation, const char *work_dir,
    const struct zcl_verify_attest_box_key *box,
    const struct zcl_verify_receiver_fixture *fixture,
    struct zcl_verify_receiver *out);
#endif

/* Set (ADMITTED) or clear the zcc environment for the step that may consume
 * the observation: ZCC_ADMITTED and ZCC_LOG, both under `work`. */
bool zcl_verify_receiver_env_apply(const struct zcl_verify_receiver *r);
bool zcl_verify_receiver_env_clear(void);

/* After the step: decide HIT, COLD or BLOCK from what was actually
 * published, rehashing the object, the exact-target depfile and the
 * source it measured. A no-op for a COLD or BLOCK preparation apart from
 * counting compiler launches. */
void zcl_verify_receiver_finish(struct zcl_verify_receiver *r);

/* Write the object_reuse_* rows to phases.txt. */
bool zcl_verify_receiver_phases_write(const struct zcl_verify_receiver *r,
                                      const char *phases_path);

/* "hit(...)", "cold(...)" or "block(...)". */
bool zcl_verify_receiver_admit_text(const struct zcl_verify_receiver *r,
                                    char *out, size_t cap);

/* This box's proof signer key, so the trust root can refuse it by name. */
void zcl_verify_receiver_box_key(struct zcl_verify_attest_box_key *out);

/* Close the lock, free buffers, remove the work directory. */
void zcl_verify_receiver_release(struct zcl_verify_receiver *r);

#endif
