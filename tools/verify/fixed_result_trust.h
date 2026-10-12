/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The trust material the fixed-result signer and publisher act on,
 *          read only through descriptor walks over root-owned files: the
 *          store policy, pins v2, the test-fast profile, the pinned verifier
 *          public key and the per-box proof signer key it must never equal.
 *
 * Production reads fixed paths under /etc/z23verify; pins v2 come through
 * the store reader's own root-custody loader, zcl_verify_store_pins_load(),
 * so the signer, publisher and receiver read them one way. Every directory from
 * "/" down is opened with O_NOFOLLOW and must be root-owned and not group-
 * or world-writable; every file must be a root-owned regular file with one
 * link, stable across the read. Nothing here accepts a path, UID or key
 * from the environment. A ZCL_TESTING build adds one fixture loader whose
 * files live under a caller-trusted anchor directory and whose owner and
 * UIDs the test names explicitly; a production build does not compile it.
 * Every refusal is a stable token. Linux only: the verifier scope is one
 * Linux x86-64 translation unit. */
#ifndef Z23_FIXED_RESULT_TRUST_H
#define Z23_FIXED_RESULT_TRUST_H

#include "dev/verify_attest.h"
#include "verify/fixed_result_key_v2.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_FRT_SIGNER_UID 60092u /* z23verify, fixed by the contract */
#define ZCL_FRT_PUBLISHER_UID 0u
#define ZCL_FRT_LAUNCHER_UID 0u
#define ZCL_FRT_ETC_DIR "etc/z23verify" /* below "/" */
#define ZCL_FRT_STATE_DIR "var/lib/z23verify"
#define ZCL_FRT_POLICY "store.policy"
#define ZCL_FRT_PINS "fixed_result.pins"
#define ZCL_FRT_PROFILE "fixed_result_fast.args"
#define ZCL_FRT_VERIFIER_PUB "verifier.pub"
#define ZCL_FRT_BOX_PUB "box_signer.pub"

#define ZCL_FRT_WHY_ARGUMENTS "trust_arguments_invalid"
#define ZCL_FRT_WHY_NO_MEMORY "trust_out_of_memory"
#define ZCL_FRT_WHY_PATH_UNSAFE "trust_path_unsafe"
#define ZCL_FRT_WHY_FILE_MISSING "trust_file_missing"
#define ZCL_FRT_WHY_FILE_UNSAFE "trust_file_unsafe"
#define ZCL_FRT_WHY_FILE_CHANGED "trust_file_changed"
#define ZCL_FRT_WHY_FILE_LIMIT "trust_file_limit"
#define ZCL_FRT_WHY_POLICY_MALFORMED "trust_policy_malformed"
#define ZCL_FRT_WHY_POLICY_UIDS "trust_policy_uids_invalid"
#define ZCL_FRT_WHY_PROFILE_MISMATCH "trust_profile_mismatch"
#define ZCL_FRT_WHY_PUBKEY_MALFORMED "trust_pubkey_malformed"
#define ZCL_FRT_WHY_VERIFIER_IS_BOX "trust_verifier_is_box_signer"

/* A file's required custody. `mode` 0 accepts any permission bits with no
 * group or world write; otherwise the permission bits must equal it. */
struct zcl_frt_custody {
    uint32_t owner;
    uint32_t mode;
    size_t max;
};

struct zcl_frt_trust {
    uint32_t signer_uid;
    uint32_t publisher_uid;
    uint32_t launcher_uid;
    struct zcl_fixed_result_v2_roots pins;
    uint8_t *profile; /* the exact pinned profile bytes, owned */
    size_t profile_len;
    uint8_t verifier_pubkey[ZCL_VERIFY_ATTEST_PUBKEY_BYTES];
    struct zcl_verify_attest_box_key box;
};

/* Open "/" and require it root-owned and not group- or world-writable. */
int zcl_frt_open_root(const char **why);

/* openat(parent, name) as a directory without following a symlink; the
 * directory must be owned by `owner`, not group- or world-writable, and
 * with `private_dir` have no group or world bits at all. -1 on refusal. */
int zcl_frt_open_dir(int parent, const char *name, uint32_t owner,
                     bool private_dir, const char **why);

/* Walk `path` ("a/b/c", no leading slash) below `start`, each directory
 * root-owned or owned by `owner`, none group- or world-writable. */
int zcl_frt_open_path(int start, const char *path, uint32_t owner,
                      const char **why);

/* Read one regular file below `dir` under `custody`, stable across the
 * read, into a zcl_malloc'd buffer. */
bool zcl_frt_read_file(int dir, const char *name,
                       const struct zcl_frt_custody *custody,
                       uint8_t **out, size_t *len, const char **why);

/* Read an already open descriptor under the same rules. */
bool zcl_frt_read_fd(int fd, const struct zcl_frt_custody *custody,
                     uint8_t **out, size_t *len, const char **why);

/* The per-box proof signer key file: 64 lowercase hex and a newline, or
 * "none\n" when the box has no signer key. */
bool zcl_frt_box_parse(const uint8_t *bytes, size_t len,
                       struct zcl_verify_attest_box_key *out);

/* Production: /etc/z23verify/{store.policy, fixed_result.pins,
 * fixed_result_fast.args, verifier.pub, box_signer.pub}, all root-owned.
 * store.policy must name signer UID 60092 and publisher UID 0. */
bool zcl_frt_load_production(struct zcl_frt_trust *out, const char **why);

void zcl_frt_release(struct zcl_frt_trust *trust);

#ifdef ZCL_TESTING
/* Test trust root. `etc_dir` is an absolute directory the test created and
 * vouches for; the five files inside it (store.policy is not read) must be
 * owned by `owner`. The UIDs are the ones the test names; equal UIDs are
 * only accepted by the signer and publisher fixtures' explicit flag. */
struct zcl_frt_fixture {
    const char *etc_dir;
    uint32_t owner;
    uint32_t signer_uid;
    uint32_t publisher_uid;
    uint32_t launcher_uid;
};

bool zcl_frt_load_fixture(const struct zcl_frt_fixture *fixture,
                          struct zcl_frt_trust *out, const char **why);
#endif

#endif
