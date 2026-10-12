/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Signed compile attestations from a separate verifier account,
 *          the root-pinned public key that admits them, and the admission
 *          decision a proof makes before it reuses an object.
 *
 * A proof may reuse a compiled object only when a verifier running under a
 * different account compiled that translation unit itself and signed a
 * record saying so. This module owns three pieces of that path:
 *
 *   - the record `z23verify.attest.v2`, one canonical encoding in the
 *     z23verify.fixed_result.v2 framing, signed with Ed25519 over a
 *     domain-separated message, and bound to one root launch receipt;
 *     a well-formed `zcl.verify_attest.v1` record still parses, and is
 *     refused by name because it names no receipt;
 *   - the trust root: the verifier's public key, read from a file that
 *     root owns and nobody else can write, down a directory chain with the
 *     same property, and refused by name otherwise;
 *   - admission: an object is reused only when the record verifies under
 *     that key, names this compiler, these flags and this preprocessed
 *     input, repeats the receiver's independently built receipt binding,
 *     reports exit 0, and hashes to the bytes actually in hand.
 *
 * The per-box proof signer key (dev_proof_signer.h) is readable by the
 * account that runs candidate code, so a record signed by it is refused by
 * name, and so is a trust root that names it. Every refusal is a stable
 * token; nothing here returns an anonymous false.
 *
 * Nothing in this module creates keys, writes files or opens a network.
 * See docs/work/separate-verifier.md for the design. */

#ifndef ZCL_TOOLS_DEV_VERIFY_ATTEST_H
#define ZCL_TOOLS_DEV_VERIFY_ATTEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_VERIFY_ATTEST_SCHEMA "z23verify.attest.v2"
#define ZCL_VERIFY_ATTEST_SCHEMA_V1 "zcl.verify_attest.v1"
#define ZCL_VERIFY_ATTEST_HASH_BYTES 32u
#define ZCL_VERIFY_ATTEST_PUBKEY_BYTES 32u
#define ZCL_VERIFY_ATTEST_SIGNATURE_BYTES 64u
#define ZCL_VERIFY_ATTEST_SEED_BYTES 32u
#define ZCL_VERIFY_ATTEST_STORE_KEY_HEX 65u /* 64 hex digits + NUL */
/* Field bounds. A record outside them is malformed, never truncated. */
#define ZCL_VERIFY_ATTEST_TOOLCHAIN_MAX 256u
#define ZCL_VERIFY_ATTEST_ARGV_MAX 65536u
#define ZCL_VERIFY_ATTEST_CWD_MAX 4096u
#define ZCL_VERIFY_ATTEST_PATH_MAX 4096u
#define ZCL_VERIFY_ATTEST_CONTRACT_MAX 64u
#define ZCL_VERIFY_ATTEST_TARGET_MAX 4096u
#define ZCL_VERIFY_ATTEST_DEFAULT_PUBKEY_PATH "/etc/z23verify/verifier.pub"

/* Trust-root refusals. */
#define ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY "no_verifier_key"
#define ZCL_VERIFY_ATTEST_WHY_KEY_PATH_NOT_ABSOLUTE "verifier_key_path_not_absolute"
#define ZCL_VERIFY_ATTEST_WHY_KEY_PATH_NOT_CANONICAL "verifier_key_path_not_canonical"
#define ZCL_VERIFY_ATTEST_WHY_KEY_UNREADABLE "verifier_key_unreadable"
#define ZCL_VERIFY_ATTEST_WHY_KEY_NOT_REGULAR "verifier_key_not_regular_file"
#define ZCL_VERIFY_ATTEST_WHY_KEY_NOT_ROOT_OWNED "verifier_key_not_root_owned"
#define ZCL_VERIFY_ATTEST_WHY_KEY_WRITABLE "verifier_key_group_or_world_writable"
#define ZCL_VERIFY_ATTEST_WHY_DIR_NOT_DIRECTORY "verifier_key_parent_not_directory"
#define ZCL_VERIFY_ATTEST_WHY_DIR_NOT_ROOT_OWNED "verifier_key_parent_not_root_owned"
#define ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE "verifier_key_parent_group_or_world_writable"
#define ZCL_VERIFY_ATTEST_WHY_KEY_MALFORMED "verifier_key_malformed"
#define ZCL_VERIFY_ATTEST_WHY_KEY_IS_BOX_SIGNER "verifier_key_is_box_signer"
#define ZCL_VERIFY_ATTEST_WHY_BOX_KEY_UNKNOWN "box_signer_key_unknown"
#define ZCL_VERIFY_ATTEST_WHY_PLATFORM "verifier_key_platform_unsupported"
#define ZCL_VERIFY_ATTEST_WHY_ARGUMENTS "verify_attest_arguments_invalid"
#define ZCL_VERIFY_ATTEST_WHY_NO_MEMORY "verify_attest_out_of_memory"

/* Record refusals. */
#define ZCL_VERIFY_ATTEST_WHY_SCHEMA_UNKNOWN "attest_schema_unknown"
#define ZCL_VERIFY_ATTEST_WHY_MALFORMED "attest_record_malformed"
#define ZCL_VERIFY_ATTEST_WHY_SIGNED_BY_BOX "attest_signed_by_box_signer"
#define ZCL_VERIFY_ATTEST_WHY_SIGNER_NOT_VERIFIER "attest_signer_not_verifier"
#define ZCL_VERIFY_ATTEST_WHY_SIGNATURE_INVALID "attest_signature_invalid"
#define ZCL_VERIFY_ATTEST_WHY_EXIT_NONZERO "attest_exit_nonzero"
#define ZCL_VERIFY_ATTEST_WHY_TOOLCHAIN_MISMATCH "attest_toolchain_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_ARGV_MISMATCH "attest_argv_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_CWD_MISSING "attest_cwd_missing"
#define ZCL_VERIFY_ATTEST_WHY_CWD_MISMATCH "attest_cwd_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_PP_MISMATCH "attest_pp_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_CLOSURE_MISMATCH "attest_closure_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_CLOSURE_MISSING "attest_closure_missing"
#define ZCL_VERIFY_ATTEST_WHY_OBJ_EMPTY "attest_obj_empty"
#define ZCL_VERIFY_ATTEST_WHY_OBJ_MISMATCH "attest_obj_hash_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_DEP_EMPTY "attest_dep_empty"
#define ZCL_VERIFY_ATTEST_WHY_DEP_MISMATCH "attest_dep_hash_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_STDERR_MISMATCH "attest_stderr_hash_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_NO_OBSERVATION "attest_no_observation"
#define ZCL_VERIFY_ATTEST_WHY_ELIGIBLE_CONFLICT "attest_eligible_conflict"
/* Receipt-binding refusals (record v2). */
#define ZCL_VERIFY_ATTEST_WHY_RECORD_V1_UNBOUND "attest_record_v1_unbound"
#define ZCL_VERIFY_ATTEST_WHY_BINDING_MISSING "attest_binding_missing"
#define ZCL_VERIFY_ATTEST_WHY_CONTRACT_MISMATCH "attest_contract_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_PROFILE_MISMATCH "attest_profile_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_TARGET_MISMATCH "attest_target_mismatch"
#define ZCL_VERIFY_ATTEST_WHY_RECEIPT_MISMATCH "attest_receipt_mismatch"

/* A borrowed byte string. Never NUL-terminated by contract; `len` is the
 * whole value. Embedded NUL bytes are malformed in every text field. */
struct zcl_verify_attest_text {
    const char *bytes;
    size_t len;
};

/* The launch a record was sealed for. The signer repeats it from the root
 * launch receipt it authenticated; the receiver rebuilds it from the
 * root-published receipt and its own pins (zcl_fr_receipt_bind) and
 * admission requires the two to be equal, field by field. */
struct zcl_verify_attest_binding {
    struct zcl_verify_attest_text contract; /* "z23verify.fixed_result.v2" */
    uint8_t profile_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
    struct zcl_verify_attest_text target;   /* the receipt's -MT target */
    uint8_t receipt_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
};

struct zcl_verify_attest_record {
    /* Set by parse: 2 for the current schema, 1 for a retired record.
     * Encode ignores it and always writes the current schema. */
    uint32_t schema_version;
    struct zcl_verify_attest_binding binding;
    struct zcl_verify_attest_text toolchain_id;
    struct zcl_verify_attest_text argv_norm;
    struct zcl_verify_attest_text recorded_cwd;
    uint8_t pp_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
    uint8_t closure_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
    uint8_t obj_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
    uint8_t dep_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
    uint8_t stderr_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
    int32_t exit_code;
};

/* A parsed signed record. Text fields point into the parsed buffer, which
 * must outlive this struct. `body_len` is the signed prefix length. */
struct zcl_verify_attest_signed {
    struct zcl_verify_attest_record record;
    uint8_t signer_pubkey[ZCL_VERIFY_ATTEST_PUBKEY_BYTES];
    uint8_t signature[ZCL_VERIFY_ATTEST_SIGNATURE_BYTES];
    size_t body_len;
};

/* Canonical unsigned body, in the z23verify.fixed_result.v2 framing where
 * F(x) is u64le(len(x)) followed by x:
 *
 *   F("z23verify.attest.v2")
 *   F("contract")     F(1..CONTRACT_MAX bytes, no NUL)
 *   F("toolchain_id") F(1..TOOLCHAIN_MAX, no NUL)
 *   F("argv_norm")    F(1..ARGV_MAX, no NUL)
 *   F("recorded_cwd") F(0..CWD_MAX, no NUL)
 *   F("target")       F(0..TARGET_MAX, no NUL)
 *   F("pp_sha3") F(32)  F("closure_sha3") F(32)  F("profile_sha3") F(32)
 *   F("receipt_sha3") F(32)  F("obj_sha3") F(32)  F("dep_sha3") F(32)
 *   F("stderr_sha3") F(32)
 *   F("exit_code")    F(u64le of the sign-extended 32-bit exit code)
 *
 * A signed record appends F("signer_pubkey") F(32) F("signature") F(64);
 * the signature covers F("z23verify.attest.signature.v2") then the body.
 * `*out` is allocated with zcl_malloc and owned by the caller. */
bool zcl_verify_attest_body_encode(const struct zcl_verify_attest_record *record,
                                   uint8_t **out, size_t *out_len,
                                   const char **why);

/* Encode and sign with a 32-byte Ed25519 seed. Used by the verifier
 * daemon, which alone holds its seed, and by fixtures. */
bool zcl_verify_attest_seal(const struct zcl_verify_attest_record *record,
                            const uint8_t seed[ZCL_VERIFY_ATTEST_SEED_BYTES],
                            uint8_t **out, size_t *out_len, const char **why);

/* Strict parse: schema first (attest_schema_unknown), then every length
 * and bound (attest_record_malformed), with no trailing bytes. A
 * well-formed retired v1 record parses with schema_version 1 and an empty
 * binding so admission can refuse it by name. It does not verify the
 * signature; admission does. */
bool zcl_verify_attest_parse(const uint8_t *bytes, size_t len,
                             struct zcl_verify_attest_signed *out,
                             const char **why);

/* Store key: SHA3-256 of F("z23verify.attest.store_key.v2") then the
 * labeled fields toolchain_id, argv_norm, recorded_cwd, pp_sha3 and
 * closure_sha3 in that order. The binding is per observation and is not
 * part of the key. A matching preprocessed stream alone does not identify
 * a direct-source object under debug/LTO profiles. */
void zcl_verify_attest_store_key(
    const struct zcl_verify_attest_text *toolchain_id,
    const struct zcl_verify_attest_text *argv_norm,
    const struct zcl_verify_attest_text *recorded_cwd,
    const uint8_t pp_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES],
    const uint8_t closure_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES],
    uint8_t out[ZCL_VERIFY_ATTEST_HASH_BYTES]);

void zcl_verify_attest_store_key_hex(
    const struct zcl_verify_attest_text *toolchain_id,
    const struct zcl_verify_attest_text *argv_norm,
    const struct zcl_verify_attest_text *recorded_cwd,
    const uint8_t pp_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES],
    const uint8_t closure_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES],
    char out[ZCL_VERIFY_ATTEST_STORE_KEY_HEX]);

/* ── Trust root ─────────────────────────────────────────────────────────── */

/* The per-box proof signer key, as the caller read it from
 * zcl_dev_proof_signer_public(). `known` must be true: a caller that never
 * looked cannot exclude that key, so the loader refuses instead. */
struct zcl_verify_attest_box_key {
    bool known;
    bool present;
    uint8_t pubkey[ZCL_VERIFY_ATTEST_PUBKEY_BYTES];
};

struct zcl_verify_attest_trust_root {
    bool loaded;
    uint8_t verifier_pubkey[ZCL_VERIFY_ATTEST_PUBKEY_BYTES];
    struct zcl_verify_attest_box_key box;
};

/* One path component as the policy sees it: entry 0 is the key file,
 * entries 1.. are its parent directories from nearest to "/". */
struct zcl_verify_attest_path_entry {
    uint32_t uid;
    uint32_t mode; /* permission and type bits, as st_mode */
    bool is_regular;
    bool is_dir;
};

struct zcl_verify_attest_path_policy {
    uint32_t trusted_uid;   /* 0 in production; root is always trusted */
    bool allow_sticky_root; /* root-owned sticky dirs (tmpfs); tests only */
};

/* Pure ownership and mode decision over a stat chain. Returns NULL when
 * the chain is acceptable, otherwise the refusal token. */
const char *zcl_verify_attest_path_check(
    const struct zcl_verify_attest_path_entry *entries, size_t count,
    const struct zcl_verify_attest_path_policy *policy);

/* Parse a public key file's bytes: exactly 64 lowercase hex digits and an
 * optional single trailing newline, and not any encoding of a small-order
 * point (order 1, 2, 4 or 8, either sign bit, canonical or not). */
bool zcl_verify_attest_pubkey_parse(
    const uint8_t *bytes, size_t len,
    uint8_t out[ZCL_VERIFY_ATTEST_PUBKEY_BYTES]);

/* Load the pinned verifier key. `configured_path` NULL means the default
 * path. A missing file refuses with no_verifier_key, the normal state of a
 * box that has no verifier installed.
 *
 * Only in a ZCL_TESTING build, the environment variable
 * ZCL_TEST_VERIFY_ATTEST_PUBKEY replaces the path, and the key file and
 * its parents may then also be owned by the effective uid. A production
 * build does not compile that branch, so the variable has no effect. */
bool zcl_verify_attest_trust_root_load(
    const char *configured_path, const struct zcl_verify_attest_box_key *box,
    struct zcl_verify_attest_trust_root *out, const char **why);

/* True only in a build that honours the test override. Tests assert it,
 * and a production build returns false by construction. */
bool zcl_verify_attest_test_override_compiled(void);

/* ── Admission ──────────────────────────────────────────────────────────── */

struct zcl_verify_attest_expected {
    struct zcl_verify_attest_text toolchain_id;
    struct zcl_verify_attest_text argv_norm;
    struct zcl_verify_attest_text recorded_cwd;
    uint8_t pp_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
    uint8_t closure_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES];
};

enum zcl_verify_attest_verdict {
    ZCL_VERIFY_ATTEST_REFUSE = 0,
    ZCL_VERIFY_ATTEST_ADMIT = 1,
    /* Exact signed compile failure or eligible observation conflict: the
     * caller must fail, never compile past it as a cold miss. */
    ZCL_VERIFY_ATTEST_FAIL = 2,
};

struct zcl_verify_attest_decision {
    enum zcl_verify_attest_verdict verdict;
    const char *reason; /* NULL on admit, a refusal token otherwise */
};

/* Decide whether the fetched object and its compiler artifacts may be reused on the strength of
 * `record_bytes`. A valid verifier signature over the exact expected inputs
 * with a nonzero compiler exit returns FAIL, which blocks cold fallback;
 * an unrelated or malformed record returns REFUSE. A successful record
 * admits only after its binding equals `binding` (the receiver's own
 * receipt expectation; NULL refuses attest_binding_missing) and the exact
 * fetched object, depfile, and stderr bytes match. A retired v1 record
 * refuses attest_record_v1_unbound.
 * An empty stderr is valid; an empty object or depfile is not. `trust_root` NULL
 * or not loaded refuses no_verifier_key. */
struct zcl_verify_attest_decision zcl_verify_attest_admit(
    const uint8_t *record_bytes, size_t record_len,
    const uint8_t *obj_bytes, size_t obj_len,
    const uint8_t *dep_bytes, size_t dep_len,
    const uint8_t *stderr_bytes, size_t stderr_len,
    const struct zcl_verify_attest_binding *binding,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_verify_attest_trust_root *trust_root);

/* An immutable store key may have several observations. The caller must
 * enumerate the whole key under its publication lock and fetch every named
 * artifact before calling this function. A signed, exact-input failure
 * blocks fallback, including when a later PASS exists. Two exact-input PASS
 * records with different output hashes also block. Any unadmitted member
 * makes the set cold; an untrusted member never suppresses a signed failure.
 * On ADMIT, selected_index names an observation whose artifact bytes were
 * checked by zcl_verify_attest_admit. No record is selected on other verdicts.
 * Reload the current root-pinned key before each call. */
struct zcl_verify_attest_observation {
    const uint8_t *record_bytes;
    size_t record_len;
    const uint8_t *obj_bytes;
    size_t obj_len;
    const uint8_t *dep_bytes;
    size_t dep_len;
    const uint8_t *stderr_bytes;
    size_t stderr_len;
    /* This observation's receipt binding as the receiver rebuilt it, or
     * NULL when its receipt was absent or refused. */
    const struct zcl_verify_attest_binding *binding;
};

struct zcl_verify_attest_decision zcl_verify_attest_admit_set(
    const struct zcl_verify_attest_observation *observations, size_t count,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_verify_attest_trust_root *trust_root,
    size_t *selected_index);

#endif
