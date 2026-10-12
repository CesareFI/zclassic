/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_verify_attest — proof that an object is reused only on the word of a
 * separate verifier account, and that every other word is refused by name.
 *
 * The attacker here runs as the same account as the proof. It can write any
 * cache, read the per-box proof signer key, and hand the proof any bytes it
 * likes. Each negative below is a record or a key file that attacker can
 * produce; each must be refused with its own token. The one admit is a
 * record sealed with a key the fixture holds and the trust root pins.
 *
 * Signer fixtures live under test-tmp/ with XDG_STATE_HOME redirected into
 * it. The loader key fixture uses a private system-temp directory because
 * the loader checks every parent for writable-path attacks. No assertion
 * reads or writes the operator's real signing key. */

#include "test/test_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "dev_proof_signer.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "sha3/sha3.h"
#include "verify_attest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

/* Repeated verbatim from verify_attest.c on purpose: a test that asks the
 * subject for its own domain string cannot notice the string changing. */
#define VA_SIGN_DOMAIN "z23verify.attest.signature.v2"
#define VA_SIGN_PREFIX (8u + sizeof(VA_SIGN_DOMAIN) - 1u) /* F(domain) */
#define VA_V1_SIGN_DOMAIN "zcl.verify_attest.sig.v1"
#define VA_V1_SIGN_BYTES (sizeof(VA_V1_SIGN_DOMAIN)) /* includes the NUL */
/* F("signer_pubkey") F(pub32) F("signature") F(sig64), and where the two
 * values start inside it. */
#define VA_TRAILER 150u
#define VA_TRAILER_PUB 29u
#define VA_TRAILER_SIG 86u
/* F(schema)=27, F("contract")=16, F(contract)=33, F("toolchain_id")=20,
 * then the toolchain value's own 8-byte prefix. */
#define VA_TOOLCHAIN_AT 104u
#define VA_SCHEMA_LAST 26u
#define VA_ENV "ZCL_TEST_VERIFY_ATTEST_PUBKEY"
#define VA_CONTRACT "z23verify.fixed_result.v2"
#define VA_TARGET "build/a.o"

#define VA_TOOLCHAIN "gcc-13.2.0-x86_64-linux-gnu"
#define VA_ARGV "-std=c2x -O2 -Iinclude -c src/a.c -o build/a.o"
#define VA_CWD "/src"
#define VA_OBJ "\x7f" "ELF-object-bytes"
#define VA_DEP "build/a.o: src/a.c include/a.h\n"
#define VA_STDERR ""

static char g_va_state[PATH_MAX];
static char g_va_saved_xdg[PATH_MAX];
static bool g_va_had_xdg;

static const uint8_t k_va_verifier_seed[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
};
static const uint8_t k_va_stranger_seed[32] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
};

static void va_isolate(const char *tag)
{
    char base[PATH_MAX - 64];
    test_make_tmpdir(base, sizeof(base), "verify_attest", tag);
    (void)snprintf(g_va_state, sizeof(g_va_state), "%s/state", base);
    if (!g_va_had_xdg && getenv("XDG_STATE_HOME")) {
        g_va_had_xdg = true;
        (void)snprintf(g_va_saved_xdg, sizeof(g_va_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    }
    setenv("XDG_STATE_HOME", g_va_state, 1);
    unsetenv(VA_ENV);
}

static void va_restore(void)
{
    if (g_va_had_xdg)
        setenv("XDG_STATE_HOME", g_va_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
    unsetenv(VA_ENV);
}

static struct zcl_verify_attest_text va_text(const char *s)
{
    struct zcl_verify_attest_text t = {s, strlen(s)};
    return t;
}

static void va_obj_hash(uint8_t out[32])
{
    zcl_sha3_256((const unsigned char *)VA_OBJ, sizeof(VA_OBJ) - 1u, out);
}

/* The receipt binding every fixture record carries and every admission
 * expects, unless a case changes one side on purpose. */
static struct zcl_verify_attest_binding va_binding_value(void)
{
    struct zcl_verify_attest_binding b;
    memset(&b, 0, sizeof(b));
    b.contract = va_text(VA_CONTRACT);
    memset(b.profile_sha3, 0x03, sizeof(b.profile_sha3));
    b.target = va_text(VA_TARGET);
    memset(b.receipt_sha3, 0x04, sizeof(b.receipt_sha3));
    return b;
}

static const struct zcl_verify_attest_binding *va_bind(void)
{
    static struct zcl_verify_attest_binding b;
    b = va_binding_value();
    return &b;
}

static struct zcl_verify_attest_record va_record(void)
{
    struct zcl_verify_attest_record r;
    memset(&r, 0, sizeof(r));
    r.binding = va_binding_value();
    r.toolchain_id = va_text(VA_TOOLCHAIN);
    r.argv_norm = va_text(VA_ARGV);
    r.recorded_cwd = va_text(VA_CWD);
    memset(r.pp_sha3, 0x01, sizeof(r.pp_sha3));
    memset(r.closure_sha3, 0x02, sizeof(r.closure_sha3));
    va_obj_hash(r.obj_sha3);
    zcl_sha3_256((const unsigned char *)VA_DEP, sizeof(VA_DEP) - 1u,
                 r.dep_sha3);
    zcl_sha3_256((const unsigned char *)VA_STDERR, sizeof(VA_STDERR) - 1u,
                 r.stderr_sha3);
    r.exit_code = 0;
    return r;
}

static struct zcl_verify_attest_expected va_expected(void)
{
    struct zcl_verify_attest_expected e;
    memset(&e, 0, sizeof(e));
    e.toolchain_id = va_text(VA_TOOLCHAIN);
    e.argv_norm = va_text(VA_ARGV);
    e.recorded_cwd = va_text(VA_CWD);
    memset(e.pp_sha3, 0x01, sizeof(e.pp_sha3));
    memset(e.closure_sha3, 0x02, sizeof(e.closure_sha3));
    return e;
}

static void va_pub(const uint8_t seed[32], uint8_t pub[32])
{
    uint8_t secret[32];
    ed25519_keypair(pub, secret, seed);
}

/* A trust root pinned to the fixture verifier, excluding `box`. */
static struct zcl_verify_attest_trust_root va_root(const uint8_t box[32])
{
    struct zcl_verify_attest_trust_root root;
    memset(&root, 0, sizeof(root));
    root.loaded = true;
    va_pub(k_va_verifier_seed, root.verifier_pubkey);
    root.box.known = true;
    root.box.present = box != NULL;
    if (box)
        memcpy(root.box.pubkey, box, 32);
    return root;
}

static struct zcl_verify_attest_decision va_admit(
    const uint8_t *rec, size_t len,
    const struct zcl_verify_attest_expected *e,
    const struct zcl_verify_attest_trust_root *root)
{
    return zcl_verify_attest_admit(rec, len, (const uint8_t *)VA_OBJ,
                                   sizeof(VA_OBJ) - 1u,
                                   (const uint8_t *)VA_DEP,
                                   sizeof(VA_DEP) - 1u,
                                   (const uint8_t *)VA_STDERR,
                                   sizeof(VA_STDERR) - 1u, va_bind(), e,
                                   root);
}

static bool va_refused(struct zcl_verify_attest_decision d, const char *why)
{
    return d.verdict == ZCL_VERIFY_ATTEST_REFUSE && d.reason &&
           strcmp(d.reason, why) == 0;
}

static bool va_blocked(struct zcl_verify_attest_decision d, const char *why)
{
    return d.verdict == ZCL_VERIFY_ATTEST_FAIL && d.reason &&
           strcmp(d.reason, why) == 0;
}

/* Replace the trailer of a sealed record with `pub` and a signature over
 * the body made by `sign`, exactly as a hostile producer would. */
/* The v2 signed message, spelled by hand: u64le(len(domain)), the domain,
 * then the body. `*msg_len` receives its length. */
static uint8_t *va_sign_message(const uint8_t *rec, size_t body,
                                size_t *msg_len)
{
    uint8_t *msg = zcl_malloc(VA_SIGN_PREFIX + body, "va-sign-message");
    if (!msg)
        return NULL;
    memset(msg, 0, 8u);
    msg[0] = (uint8_t)(sizeof(VA_SIGN_DOMAIN) - 1u);
    memcpy(msg + 8u, VA_SIGN_DOMAIN, sizeof(VA_SIGN_DOMAIN) - 1u);
    memcpy(msg + VA_SIGN_PREFIX, rec, body);
    *msg_len = VA_SIGN_PREFIX + body;
    return msg;
}

static void va_resign(uint8_t *rec, size_t len, const uint8_t seed[32],
                      const uint8_t claimed_pub[32])
{
    size_t body = len - VA_TRAILER, msg_len = 0;
    uint8_t *msg = va_sign_message(rec, body, &msg_len);
    uint8_t pub[32], secret[32];
    if (!msg)
        return;
    ed25519_keypair(pub, secret, seed);
    ed25519_sign(rec + body + VA_TRAILER_SIG, msg, msg_len, seed, pub);
    memcpy(rec + body + VA_TRAILER_PUB, claimed_pub ? claimed_pub : pub, 32);
    free(msg);
}

static bool va_write(const char *path, const char *data, unsigned mode)
{
    FILE *f = fopen(path, "wb");
    size_t len = strlen(data);
    bool ok = f && (len == 0 || fwrite(data, 1, len, f) == len);
    if (f) ok = fclose(f) == 0 && ok;
#if !defined(_WIN32)
    if (ok) ok = chmod(path, (mode_t)mode) == 0;
#else
    (void)mode;
#endif
    return ok;
}

static struct zcl_verify_attest_box_key va_no_box(void)
{
    struct zcl_verify_attest_box_key box = {.known = true, .present = false};
    return box;
}

/* ── 1. canonical encoding ─────────────────────────────────────────────── */

/* The retired v1 body of va_record(), spelled out by hand: a record a v1
 * signer could still hold. It parses, and admission refuses it by name. */
static bool va_v1_body(uint8_t *out, size_t cap, size_t *len)
{
    static const char schema[] = "zcl.verify_attest.v1";
    const char *texts[3] = {VA_TOOLCHAIN, VA_ARGV, VA_CWD};
    size_t n = 0;
    uint8_t obj[32];
    if (cap < 2u + 20u + 3u * 4u + 128u + 5u * 32u + 4u)
        return false;
    out[n++] = 20u;
    out[n++] = 0u;
    memcpy(out + n, schema, 20u);
    n += 20u;
    for (size_t i = 0; i < 3; i++) {
        size_t tl = strlen(texts[i]);
        out[n++] = (uint8_t)tl;
        out[n++] = 0u;
        out[n++] = 0u;
        out[n++] = 0u;
        memcpy(out + n, texts[i], tl);
        n += tl;
    }
    for (uint8_t fill = 1; fill <= 5; fill++) {
        if (fill == 3) {
            va_obj_hash(obj);
            memcpy(out + n, obj, 32);
        } else if (fill == 4) {
            zcl_sha3_256((const unsigned char *)VA_DEP,
                         sizeof(VA_DEP) - 1u, out + n);
        } else if (fill == 5) {
            zcl_sha3_256((const unsigned char *)VA_STDERR,
                         sizeof(VA_STDERR) - 1u, out + n);
        } else {
            memset(out + n, fill, 32);
        }
        n += 32u;
    }
    memset(out + n, 0, 4);
    n += 4u;
    *len = n;
    return true;
}

/* One frame by hand: eight little-endian length bytes, then the bytes. */
static void va_frame(uint8_t *out, size_t *n, const void *bytes, size_t len)
{
    for (size_t i = 0; i < 8u; i++)
        out[(*n)++] = (uint8_t)((uint64_t)len >> (8u * i));
    memcpy(out + *n, bytes, len);
    *n += len;
}

static void va_frame_text(uint8_t *out, size_t *n, const char *s)
{
    va_frame(out, n, s, strlen(s));
}

/* The body of va_record(), spelled out by hand. Any change to field order,
 * width, endianness, labels or the schema string changes these bytes. */
static bool va_expected_body(uint8_t *out, size_t cap, size_t *len)
{
    static const char *const texts[5][2] = {
        {"contract", VA_CONTRACT}, {"toolchain_id", VA_TOOLCHAIN},
        {"argv_norm", VA_ARGV}, {"recorded_cwd", VA_CWD},
        {"target", VA_TARGET}};
    static const char *const hashes[7] = {
        "pp_sha3", "closure_sha3", "profile_sha3", "receipt_sha3",
        "obj_sha3", "dep_sha3", "stderr_sha3"};
    uint8_t h[7][32], zero[8] = {0};
    size_t n = 0;
    if (cap < 1024u)
        return false;
    memset(h[0], 0x01, 32); memset(h[1], 0x02, 32);
    memset(h[2], 0x03, 32); memset(h[3], 0x04, 32);
    va_obj_hash(h[4]);
    zcl_sha3_256((const unsigned char *)VA_DEP, sizeof(VA_DEP) - 1u, h[5]);
    zcl_sha3_256((const unsigned char *)VA_STDERR, sizeof(VA_STDERR) - 1u,
                 h[6]);
    va_frame_text(out, &n, "z23verify.attest.v2");
    for (size_t i = 0; i < 5; i++) {
        va_frame_text(out, &n, texts[i][0]);
        va_frame_text(out, &n, texts[i][1]);
    }
    for (size_t i = 0; i < 7; i++) {
        va_frame_text(out, &n, hashes[i]);
        va_frame(out, &n, h[i], 32u);
    }
    va_frame_text(out, &n, "exit_code");
    va_frame(out, &n, zero, sizeof(zero));
    *len = n;
    return true;
}

/* The store key preimage spelled by hand, hashed here. */
static void va_expected_store_key(char hex[65])
{
    static const char *const texts[3][2] = {
        {"toolchain_id", VA_TOOLCHAIN}, {"argv_norm", VA_ARGV},
        {"recorded_cwd", VA_CWD}};
    uint8_t pre[512], pp[32], closure[32], digest[32];
    size_t n = 0;
    memset(pp, 0x01, 32);
    memset(closure, 0x02, 32);
    va_frame_text(pre, &n, "z23verify.attest.store_key.v2");
    for (size_t i = 0; i < 3; i++) {
        va_frame_text(pre, &n, texts[i][0]);
        va_frame_text(pre, &n, texts[i][1]);
    }
    va_frame_text(pre, &n, "pp_sha3");
    va_frame(pre, &n, pp, 32u);
    va_frame_text(pre, &n, "closure_sha3");
    va_frame(pre, &n, closure, 32u);
    zcl_sha3_256(pre, n, digest);
    zcl_hex_encode(digest, 32, hex);
}

/* Pinned SHA3-256 of the hand-built body above and of the store key for
 * (VA_TOOLCHAIN, VA_ARGV, VA_CWD, pp=0x01.., closure=0x02..). The store
 * key is SHA3-256 over F("z23verify.attest.store_key.v2") then F(label)
 * F(value) for toolchain_id, argv_norm, recorded_cwd, pp_sha3 and
 * closure_sha3. Recomputing either is a format change and needs an
 * explicit domain review. */
#define VA_BODY_SHA3 \
    "7ec65557955d18286d40e2910c31f38fc6e42415a51964deb7eb3af5b355e11c"
#define VA_STORE_KEY \
    "a8704b91825ebdd07a93feccf66f0ab2c3d13e5abcf508da75bed619c6f4cbbb"

static int test_va_encoding_vector(void)
{
    int failures = 0;
    uint8_t want[1024];
    size_t want_len = 0;
    uint8_t *body = NULL;
    size_t body_len = 0;
    uint8_t digest[32];
    char hex[65];
    const char *why = NULL;
    TEST("verify attest: the canonical body is fixed bytes with a fixed "
         "hash, and the store key is fixed too") {
        struct zcl_verify_attest_record r = va_record();
        struct zcl_verify_attest_expected e = va_expected();
        ASSERT(va_expected_body(want, sizeof(want), &want_len));
        ASSERT(zcl_verify_attest_body_encode(&r, &body, &body_len, &why));
        ASSERT(body_len == want_len);
        ASSERT(memcmp(body, want, want_len) == 0);
        zcl_sha3_256(body, body_len, digest);
        zcl_hex_encode(digest, 32, hex);
        if (strcmp(hex, VA_BODY_SHA3) != 0)
            printf("body sha3 = %s ", hex);
        ASSERT_STR_EQ(hex, VA_BODY_SHA3);
        zcl_verify_attest_store_key_hex(&e.toolchain_id, &e.argv_norm,
                                        &e.recorded_cwd, e.pp_sha3,
                                        e.closure_sha3, hex);
        if (strcmp(hex, VA_STORE_KEY) != 0)
            printf("store key = %s ", hex);
        ASSERT_STR_EQ(hex, VA_STORE_KEY);
        char spelled[65];
        va_expected_store_key(spelled);
        ASSERT_STR_EQ(hex, spelled);
        /* The store key binds every input: one changed byte, new key. */
        char other[65];
        e.pp_sha3[31] ^= 1u;
        zcl_verify_attest_store_key_hex(&e.toolchain_id, &e.argv_norm,
                                        &e.recorded_cwd, e.pp_sha3,
                                        e.closure_sha3, other);
        ASSERT(strcmp(other, hex) != 0);
        e = va_expected();
        e.recorded_cwd = va_text("/another-tree");
        zcl_verify_attest_store_key_hex(&e.toolchain_id, &e.argv_norm,
                                        &e.recorded_cwd, e.pp_sha3,
                                        e.closure_sha3, other);
        ASSERT(strcmp(other, hex) != 0);
        e = va_expected();
        e.closure_sha3[0] ^= 1u;
        zcl_verify_attest_store_key_hex(&e.toolchain_id, &e.argv_norm,
                                        &e.recorded_cwd, e.pp_sha3,
                                        e.closure_sha3, other);
        ASSERT(strcmp(other, hex) != 0);
        PASS();
    } _test_next:;
    free(body);
    return failures;
}

static int test_va_parse_strict(void)
{
    int failures = 0;
    uint8_t *rec = NULL, *body = NULL;
    size_t len = 0, body_len = 0;
    const char *why = NULL;
    struct zcl_verify_attest_signed parsed;
    TEST("verify attest: parse is strict and re-encodes to the same bytes") {
        struct zcl_verify_attest_record r = va_record();
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed, &rec, &len,
                                      &why));
        ASSERT(zcl_verify_attest_parse(rec, len, &parsed, &why));
        ASSERT(parsed.body_len == len - VA_TRAILER);
        ASSERT(zcl_verify_attest_body_encode(&parsed.record, &body,
                                             &body_len, &why));
        ASSERT(body_len == parsed.body_len);
        ASSERT(memcmp(body, rec, body_len) == 0);
        ASSERT(!zcl_verify_attest_parse(rec, len - 1u, &parsed, &why));
        ASSERT_STR_EQ(why, ZCL_VERIFY_ATTEST_WHY_MALFORMED);
        uint8_t *longer = zcl_malloc(len + 1u, "va-longer");
        ASSERT(longer);
        memcpy(longer, rec, len);
        longer[len] = 0;
        bool parsed_long = zcl_verify_attest_parse(longer, len + 1u, &parsed,
                                                   &why);
        free(longer);
        ASSERT(!parsed_long);
        ASSERT_STR_EQ(why, ZCL_VERIFY_ATTEST_WHY_MALFORMED);
        /* A zero-length toolchain is malformed, not a wildcard. */
        r.toolchain_id = va_text("");
        free(body);
        body = NULL;
        ASSERT(!zcl_verify_attest_body_encode(&r, &body, &body_len, &why));
        ASSERT_STR_EQ(why, ZCL_VERIFY_ATTEST_WHY_MALFORMED);
        PASS();
    } _test_next:;
    free(rec);
    free(body);
    return failures;
}

/* ── 2. admission ──────────────────────────────────────────────────────── */

static int test_va_admit(void)
{
    int failures = 0;
    uint8_t *rec = NULL;
    size_t len = 0;
    const char *why = NULL;
    TEST("verify attest: a record sealed by the pinned verifier admits") {
        struct zcl_verify_attest_record r = va_record();
        struct zcl_verify_attest_expected e = va_expected();
        struct zcl_verify_attest_trust_root root = va_root(NULL);
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed, &rec, &len,
                                      &why));
        struct zcl_verify_attest_decision d = va_admit(rec, len, &e, &root);
        ASSERT(d.verdict == ZCL_VERIFY_ATTEST_ADMIT);
        ASSERT(d.reason == NULL);
        PASS();
    } _test_next:;
    free(rec);
    return failures;
}

/* One sealed record, one mutation, one expected refusal token. */
static int va_refuse_case(const char *name,
                          struct zcl_verify_attest_record r,
                          struct zcl_verify_attest_expected e,
                          size_t flip_at, const char *want)
{
    int failures = 0;
    uint8_t *rec = NULL;
    size_t len = 0;
    const char *why = NULL;
    TEST(name) {
        struct zcl_verify_attest_trust_root root = va_root(NULL);
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed, &rec, &len,
                                      &why));
        if (flip_at != SIZE_MAX)
            rec[flip_at < len ? flip_at : len - 1u] ^= 0x01u;
        ASSERT(va_refused(va_admit(rec, len, &e, &root), want));
        PASS();
    } _test_next:;
    free(rec);
    return failures;
}

static int test_va_refuse_fields(void)
{
    int failures = 0;
    struct zcl_verify_attest_record r = va_record();
    struct zcl_verify_attest_expected e = va_expected();
    failures += va_refuse_case("verify attest: a flipped signature byte "
                               "refuses attest_signature_invalid",
                               r, e, SIZE_MAX - 1u,
                               ZCL_VERIFY_ATTEST_WHY_SIGNATURE_INVALID);
    failures += va_refuse_case("verify attest: an edited body under the "
                               "old signature refuses attest_signature_invalid",
                               r, e, VA_TOOLCHAIN_AT + 2u,
                               ZCL_VERIFY_ATTEST_WHY_SIGNATURE_INVALID);
    e.toolchain_id = va_text("gcc-14.1.0-x86_64-linux-gnu");
    failures += va_refuse_case("verify attest: another compiler refuses "
                               "attest_toolchain_mismatch",
                               r, e, SIZE_MAX,
                               ZCL_VERIFY_ATTEST_WHY_TOOLCHAIN_MISMATCH);
    e = va_expected();
    e.argv_norm = va_text("-std=c2x -O0 -Iinclude -c src/a.c -o build/a.o");
    failures += va_refuse_case("verify attest: other flags refuse "
                               "attest_argv_mismatch",
                               r, e, SIZE_MAX,
                               ZCL_VERIFY_ATTEST_WHY_ARGV_MISMATCH);
    e = va_expected();
    e.recorded_cwd = va_text("");
    r.recorded_cwd = e.recorded_cwd;
    failures += va_refuse_case("verify attest: missing cwd refuses",
                               r, e, SIZE_MAX,
                               ZCL_VERIFY_ATTEST_WHY_CWD_MISSING);
    r = va_record();
    e = va_expected();
    e.recorded_cwd = va_text("/other-source-tree");
    failures += va_refuse_case("verify attest: another working directory "
                               "refuses attest_cwd_mismatch",
                               r, e, SIZE_MAX,
                               ZCL_VERIFY_ATTEST_WHY_CWD_MISMATCH);
    e = va_expected();
    e.pp_sha3[0] ^= 0x80u;
    failures += va_refuse_case("verify attest: other preprocessed input "
                               "refuses attest_pp_mismatch",
                               r, e, SIZE_MAX,
                               ZCL_VERIFY_ATTEST_WHY_PP_MISMATCH);
    e = va_expected();
    memset(e.closure_sha3, 0, sizeof(e.closure_sha3));
    memset(r.closure_sha3, 0, sizeof(r.closure_sha3));
    failures += va_refuse_case("verify attest: missing closure refuses",
                               r, e, SIZE_MAX,
                               ZCL_VERIFY_ATTEST_WHY_CLOSURE_MISSING);
    r = va_record();
    e = va_expected();
    e.closure_sha3[0] ^= 0x80u;
    failures += va_refuse_case("verify attest: another input closure "
                               "refuses attest_closure_mismatch",
                               r, e, SIZE_MAX,
                               ZCL_VERIFY_ATTEST_WHY_CLOSURE_MISMATCH);
    e = va_expected();
    r.obj_sha3[5] ^= 0x10u;
    failures += va_refuse_case("verify attest: an object that is not the "
                               "attested bytes refuses attest_obj_hash_mismatch",
                               r, e, SIZE_MAX,
                               ZCL_VERIFY_ATTEST_WHY_OBJ_MISMATCH);
    r = va_record();
    r.dep_sha3[5] ^= 0x10u;
    failures += va_refuse_case("verify attest: substituted depfile refuses",
                               r, e, SIZE_MAX, "attest_dep_hash_mismatch");
    r = va_record();
    r.stderr_sha3[5] ^= 0x10u;
    failures += va_refuse_case("verify attest: substituted stderr refuses",
                               r, e, SIZE_MAX, "attest_stderr_hash_mismatch");
    /* The schema's last character: "v2" becomes "v3". */
    failures += va_refuse_case("verify attest: another schema refuses "
                               "attest_schema_unknown",
                               va_record(), e, VA_SCHEMA_LAST,
                               ZCL_VERIFY_ATTEST_WHY_SCHEMA_UNKNOWN);
    return failures;
}

/* One sealed record, admitted against a receiver binding that differs in
 * exactly one field. */
static bool va_binding_refuses(const struct zcl_verify_attest_binding *want,
                               const char *token)
{
    struct zcl_verify_attest_record r = va_record();
    struct zcl_verify_attest_expected e = va_expected();
    struct zcl_verify_attest_trust_root root = va_root(NULL);
    uint8_t *rec = NULL;
    size_t len = 0;
    const char *why = NULL;
    if (!zcl_verify_attest_seal(&r, k_va_verifier_seed, &rec, &len, &why))
        return false;
    struct zcl_verify_attest_decision d = zcl_verify_attest_admit(
        rec, len, (const uint8_t *)VA_OBJ, sizeof(VA_OBJ) - 1u,
        (const uint8_t *)VA_DEP, sizeof(VA_DEP) - 1u,
        (const uint8_t *)VA_STDERR, sizeof(VA_STDERR) - 1u, want, &e, &root);
    free(rec);
    if (!va_refused(d, token)) {
        printf("[binding -> %s, want %s] ", d.reason ? d.reason : "(admit)",
               token);
        return false;
    }
    return true;
}

static int test_va_refuse_binding(void)
{
    int failures = 0;
    TEST("verify attest: a record bound to another receipt, target, profile "
         "or contract is refused by name; no binding admits nothing") {
        struct zcl_verify_attest_binding b = va_binding_value();
        b.receipt_sha3[31] ^= 1u;
        ASSERT(va_binding_refuses(&b, ZCL_VERIFY_ATTEST_WHY_RECEIPT_MISMATCH));
        b = va_binding_value();
        memset(b.receipt_sha3, 0, sizeof(b.receipt_sha3));
        ASSERT(va_binding_refuses(&b, ZCL_VERIFY_ATTEST_WHY_RECEIPT_MISMATCH));
        b = va_binding_value();
        b.target = va_text("build/b.o");
        ASSERT(va_binding_refuses(&b, ZCL_VERIFY_ATTEST_WHY_TARGET_MISMATCH));
        b = va_binding_value();
        b.target = va_text("");
        ASSERT(va_binding_refuses(&b, ZCL_VERIFY_ATTEST_WHY_TARGET_MISMATCH));
        b = va_binding_value();
        b.profile_sha3[0] ^= 1u;
        ASSERT(va_binding_refuses(&b, ZCL_VERIFY_ATTEST_WHY_PROFILE_MISMATCH));
        b = va_binding_value();
        b.contract = va_text("z23verify.fixed_result.v3");
        ASSERT(va_binding_refuses(&b, ZCL_VERIFY_ATTEST_WHY_CONTRACT_MISMATCH));
        ASSERT(va_binding_refuses(NULL, ZCL_VERIFY_ATTEST_WHY_BINDING_MISSING));
        PASS();
    } _test_next:;
    return failures;
}

static struct zcl_verify_attest_observation va_observation(const uint8_t *rec,
                                                            size_t len);

/* A retired v1 record, correctly signed by the pinned verifier under the
 * v1 signature domain, still parses so it can be named, and never admits:
 * it carries no receipt binding. */
static int test_va_refuse_v1_record(void)
{
    int failures = 0;
    uint8_t rec[1024], pub[32], secret[32];
    uint8_t msg[sizeof(rec) + VA_V1_SIGN_BYTES];
    size_t body = 0;
    struct zcl_verify_attest_signed parsed;
    const char *why = NULL;
    TEST("verify attest: a signed v1 record parses as version 1 and is "
         "refused attest_record_v1_unbound") {
        ASSERT(va_v1_body(rec, sizeof(rec) - 96u, &body));
        ed25519_keypair(pub, secret, k_va_verifier_seed);
        memcpy(msg, VA_V1_SIGN_DOMAIN, VA_V1_SIGN_BYTES);
        memcpy(msg + VA_V1_SIGN_BYTES, rec, body);
        memcpy(rec + body, pub, 32);
        ed25519_sign(rec + body + 32u, msg, VA_V1_SIGN_BYTES + body,
                     k_va_verifier_seed, pub);
        ASSERT(zcl_verify_attest_parse(rec, body + 96u, &parsed, &why));
        ASSERT(parsed.record.schema_version == 1u);
        ASSERT(parsed.body_len == body);
        struct zcl_verify_attest_expected e = va_expected();
        struct zcl_verify_attest_trust_root root = va_root(NULL);
        ASSERT(va_refused(va_admit(rec, body + 96u, &e, &root),
                          ZCL_VERIFY_ATTEST_WHY_RECORD_V1_UNBOUND));
        struct zcl_verify_attest_observation o[1] = {
            va_observation(rec, body + 96u)};
        size_t selected = SIZE_MAX;
        ASSERT(va_refused(zcl_verify_attest_admit_set(o, 1u, &e, &root,
                                                      &selected),
                          ZCL_VERIFY_ATTEST_WHY_RECORD_V1_UNBOUND));
        ASSERT(selected == SIZE_MAX);
        PASS();
    } _test_next:;
    return failures;
}


static int test_va_signed_failure_blocks(void)
{
    int failures = 0;
    uint8_t *rec = NULL;
    size_t len = 0;
    const char *why = NULL;
    TEST("verify attest: exact signed compile failure blocks fallback") {
        struct zcl_verify_attest_record r = va_record();
        struct zcl_verify_attest_expected e = va_expected();
        struct zcl_verify_attest_trust_root root = va_root(NULL);
        r.exit_code = 1;
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed, &rec, &len,
                                      &why));
        struct zcl_verify_attest_decision d = zcl_verify_attest_admit(
            rec, len, NULL, 0, NULL, 1, NULL, 1, va_bind(), &e, &root);
        ASSERT(d.verdict == ZCL_VERIFY_ATTEST_FAIL);
        ASSERT_STR_EQ(d.reason, ZCL_VERIFY_ATTEST_WHY_EXIT_NONZERO);
        d = zcl_verify_attest_admit(rec, len, NULL, 1, NULL, 1,
                                    NULL, 1, va_bind(), &e, &root);
        ASSERT(d.verdict == ZCL_VERIFY_ATTEST_FAIL);
        ASSERT_STR_EQ(d.reason, ZCL_VERIFY_ATTEST_WHY_EXIT_NONZERO);
        e.toolchain_id = va_text("different-toolchain");
        d = zcl_verify_attest_admit(rec, len, NULL, 0, NULL, 0,
                                    NULL, 0, va_bind(), &e, &root);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_TOOLCHAIN_MISMATCH));
        e = va_expected();
        e.closure_sha3[0] ^= 1u;
        d = zcl_verify_attest_admit(rec, len, NULL, 0, NULL, 0,
                                    NULL, 0, va_bind(), &e, &root);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_CLOSURE_MISMATCH));
        e = va_expected();
        e.pp_sha3[0] ^= 1u;
        d = zcl_verify_attest_admit(rec, len, NULL, 0, NULL, 0,
                                    NULL, 0, va_bind(), &e, &root);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_PP_MISMATCH));
        e.pp_sha3[0] ^= 1u;
        rec[len - 1u] ^= 1u;
        d = zcl_verify_attest_admit(rec, len, NULL, 0, NULL, 0,
                                    NULL, 0, va_bind(), &e, &root);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_SIGNATURE_INVALID));
        PASS();
    } _test_next:;
    free(rec);
    return failures;
}

static int test_va_empty_object(void)
{
    int failures = 0;
    uint8_t *rec = NULL;
    size_t len = 0;
    const char *why = NULL;
    TEST("verify attest: signed empty output is not a compiled object") {
        struct zcl_verify_attest_record r = va_record();
        struct zcl_verify_attest_expected e = va_expected();
        struct zcl_verify_attest_trust_root root = va_root(NULL);
        zcl_sha3_256((const unsigned char *)"", 0u, r.obj_sha3);
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed, &rec, &len,
                                      &why));
        struct zcl_verify_attest_decision d = zcl_verify_attest_admit(
            rec, len, NULL, 0u, (const uint8_t *)VA_DEP,
            sizeof(VA_DEP) - 1u, NULL, 0u, va_bind(), &e, &root);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_OBJ_EMPTY));
        PASS();
    } _test_next:;
    free(rec);
    return failures;
}

static int test_va_artifact_substitution(void)
{
    int failures = 0;
    uint8_t *rec = NULL;
    size_t len = 0;
    const char *why = NULL;
    TEST("verify attest: fetched depfile and stderr bytes are exact") {
        struct zcl_verify_attest_record r = va_record();
        struct zcl_verify_attest_expected e = va_expected();
        struct zcl_verify_attest_trust_root root = va_root(NULL);
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed, &rec, &len,
                                      &why));
        struct zcl_verify_attest_decision d = zcl_verify_attest_admit(
            rec, len, (const uint8_t *)VA_OBJ, sizeof(VA_OBJ) - 1u,
            (const uint8_t *)"other", 5u, NULL, 0u, va_bind(), &e, &root);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_DEP_MISMATCH));
        d = zcl_verify_attest_admit(
            rec, len, (const uint8_t *)VA_OBJ, sizeof(VA_OBJ) - 1u,
            (const uint8_t *)VA_DEP, sizeof(VA_DEP) - 1u,
            (const uint8_t *)"warning", 7u, va_bind(), &e, &root);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_STDERR_MISMATCH));
        d = zcl_verify_attest_admit(
            rec, len, (const uint8_t *)VA_OBJ, sizeof(VA_OBJ) - 1u,
            NULL, 0u, NULL, 0u, va_bind(), &e, &root);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_DEP_EMPTY));
        d = va_admit(rec, len, &e, &root);
        ASSERT(d.verdict == ZCL_VERIFY_ATTEST_ADMIT);
        PASS();
    } _test_next:;
    free(rec);
    return failures;
}

static struct zcl_verify_attest_observation va_observation(const uint8_t *rec,
                                                            size_t len)
{
    return (struct zcl_verify_attest_observation) {
        .record_bytes = rec, .record_len = len,
        .obj_bytes = (const uint8_t *)VA_OBJ, .obj_len = sizeof(VA_OBJ) - 1u,
        .dep_bytes = (const uint8_t *)VA_DEP, .dep_len = sizeof(VA_DEP) - 1u,
        .stderr_bytes = (const uint8_t *)VA_STDERR,
        .stderr_len = sizeof(VA_STDERR) - 1u, .binding = va_bind()};
}

static int test_va_observation_set(void)
{
    int failures = 0;
    uint8_t *pass = NULL, *fail = NULL;
    size_t pass_len = 0, fail_len = 0;
    const char *why = NULL;
    TEST("verify attest: whole-key scan blocks a signed failure and "
         "contradiction regardless of observation order") {
        struct zcl_verify_attest_record r = va_record();
        struct zcl_verify_attest_expected e = va_expected();
        struct zcl_verify_attest_trust_root root = va_root(NULL);
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed,
                                      &pass, &pass_len, &why));
        r.exit_code = 1;
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed,
                                      &fail, &fail_len, &why));
        struct zcl_verify_attest_observation entries[2] = {
            va_observation(pass, pass_len), va_observation(fail, fail_len)};
        size_t selected = SIZE_MAX;
        struct zcl_verify_attest_decision d = zcl_verify_attest_admit_set(
            entries, 2u, &e, &root, &selected);
        ASSERT(va_blocked(d, ZCL_VERIFY_ATTEST_WHY_ELIGIBLE_CONFLICT));
        ASSERT(selected == SIZE_MAX);
        entries[0] = va_observation(fail, fail_len);
        entries[1] = va_observation(pass, pass_len);
        d = zcl_verify_attest_admit_set(entries, 2u, &e, &root, &selected);
        ASSERT(va_blocked(d, ZCL_VERIFY_ATTEST_WHY_ELIGIBLE_CONFLICT));
        entries[1].obj_bytes = NULL;
        entries[1].obj_len = 0u;
        d = zcl_verify_attest_admit_set(entries, 2u, &e, &root, &selected);
        ASSERT(va_blocked(d, ZCL_VERIFY_ATTEST_WHY_ELIGIBLE_CONFLICT));
        d = zcl_verify_attest_admit_set(entries, 1u, &e, &root, &selected);
        ASSERT(d.verdict == ZCL_VERIFY_ATTEST_FAIL);
        ASSERT_STR_EQ(d.reason, ZCL_VERIFY_ATTEST_WHY_EXIT_NONZERO);
        PASS();
    } _test_next:;
    free(pass); free(fail);
    return failures;
}

static int test_va_observation_set_refusals(void)
{
    int failures = 0;
    uint8_t *pass = NULL, *other = NULL;
    size_t pass_len = 0, other_len = 0;
    const char *why = NULL;
    TEST("verify attest: forged, changed, missing and conflicting PASS "
         "observations never become a HIT") {
        struct zcl_verify_attest_record r = va_record();
        struct zcl_verify_attest_expected e = va_expected();
        struct zcl_verify_attest_trust_root root = va_root(NULL);
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed,
                                      &pass, &pass_len, &why));
        struct zcl_verify_attest_observation entries[2] = {
            va_observation(pass, pass_len), va_observation(pass, pass_len)};
        size_t selected = SIZE_MAX;
        struct zcl_verify_attest_decision d = zcl_verify_attest_admit_set(
            entries, 2u, &e, &root, &selected);
        ASSERT(d.verdict == ZCL_VERIFY_ATTEST_ADMIT && selected == 0u);
        entries[1].obj_bytes = NULL;
        entries[1].obj_len = 0u;
        d = zcl_verify_attest_admit_set(entries, 2u, &e, &root, &selected);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_OBJ_EMPTY));
        ASSERT(selected == SIZE_MAX);
        entries[1] = va_observation(pass, pass_len);
        entries[1].record_bytes = other = zcl_malloc(pass_len, "va-forged");
        ASSERT(other);
        memcpy(other, pass, pass_len);
        other_len = pass_len;
        other[other_len - 1u] ^= 1u;
        d = zcl_verify_attest_admit_set(entries, 2u, &e, &root, &selected);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_SIGNATURE_INVALID));
        free(other);
        other = NULL;
        r.obj_sha3[0] ^= 1u;
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed,
                                      &other, &other_len, &why));
        entries[1] = va_observation(other, other_len);
        d = zcl_verify_attest_admit_set(entries, 2u, &e, &root, &selected);
        ASSERT(va_blocked(d, ZCL_VERIFY_ATTEST_WHY_ELIGIBLE_CONFLICT));
        entries[1].obj_bytes = NULL;
        entries[1].obj_len = 0u;
        d = zcl_verify_attest_admit_set(entries, 2u, &e, &root, &selected);
        ASSERT(va_blocked(d, ZCL_VERIFY_ATTEST_WHY_ELIGIBLE_CONFLICT));
        e.closure_sha3[0] ^= 1u;
        d = zcl_verify_attest_admit_set(entries, 1u, &e, &root, &selected);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_CLOSURE_MISMATCH));
        e = va_expected();
        root.loaded = false;
        d = zcl_verify_attest_admit_set(entries, 1u, &e, &root, &selected);
        ASSERT(va_refused(d, ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY));
        root = va_root(NULL);
        ASSERT(va_refused(zcl_verify_attest_admit_set(entries, 0u, &e,
                         &root, &selected),
                         ZCL_VERIFY_ATTEST_WHY_NO_OBSERVATION));
        PASS();
    } _test_next:;
    free(pass); free(other);
    return failures;
}

static int test_va_refuse_signers(void)
{
    int failures = 0;
    uint8_t *rec = NULL;
    size_t len = 0;
    const char *why = NULL;
    uint8_t box_pub[32], box_sig[64], verifier_pub[32];
    TEST("verify attest: a record signed by the per-box proof signer is "
         "refused by name, whatever key it claims") {
        va_isolate("box_signer");
        struct zcl_verify_attest_record r = va_record();
        struct zcl_verify_attest_expected e = va_expected();
        ASSERT(zcl_verify_attest_seal(&r, k_va_verifier_seed, &rec, &len,
                                      &why));
        /* The real per-box signer, the key the proof account can read. */
        size_t body = len - VA_TRAILER, msg_len = 0;
        uint8_t *msg = va_sign_message(rec, body, &msg_len);
        ASSERT(msg);
        bool signed_ok = zcl_dev_proof_signer_sign(msg, msg_len, box_pub,
                                                   box_sig, &why);
        free(msg);
        ASSERT(signed_ok);
        struct zcl_verify_attest_trust_root root = va_root(box_pub);
        memcpy(rec + body + VA_TRAILER_PUB, box_pub, 32);
        memcpy(rec + body + VA_TRAILER_SIG, box_sig, 64);
        ASSERT(va_refused(va_admit(rec, len, &e, &root),
                          ZCL_VERIFY_ATTEST_WHY_SIGNED_BY_BOX));
        /* Same box signature, trailer claiming the verifier's key. */
        va_pub(k_va_verifier_seed, verifier_pub);
        memcpy(rec + body + VA_TRAILER_PUB, verifier_pub, 32);
        ASSERT(va_refused(va_admit(rec, len, &e, &root),
                          ZCL_VERIFY_ATTEST_WHY_SIGNED_BY_BOX));
        /* A stranger's key is not the verifier. */
        va_resign(rec, len, k_va_stranger_seed, NULL);
        ASSERT(va_refused(va_admit(rec, len, &e, &root),
                          ZCL_VERIFY_ATTEST_WHY_SIGNER_NOT_VERIFIER));
        /* A trust root that pins the box key itself admits nothing. */
        memcpy(root.verifier_pubkey, box_pub, 32);
        ASSERT(va_refused(va_admit(rec, len, &e, &root),
                          ZCL_VERIFY_ATTEST_WHY_KEY_IS_BOX_SIGNER));
        /* No trust root at all is the normal state today. */
        root.loaded = false;
        ASSERT(va_refused(va_admit(rec, len, &e, &root),
                          ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY));
        ASSERT(va_refused(va_admit(rec, len, &e, NULL),
                          ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY));
        va_restore();
        PASS();
    } _test_next:;
    free(rec);
    return failures;
}

/* ── 3. trust root: pure policy ─────────────────────────────────────────── */

static const char *va_chain(uint32_t fuid, uint32_t fmode, uint32_t duid,
                            uint32_t dmode, bool sticky_ok, uint32_t trusted)
{
    struct zcl_verify_attest_path_entry chain[3] = {
        {.uid = fuid, .mode = fmode, .is_regular = true},
        {.uid = duid, .mode = dmode, .is_dir = true},
        {.uid = 0, .mode = 0755, .is_dir = true},
    };
    struct zcl_verify_attest_path_policy policy = {
        .trusted_uid = trusted, .allow_sticky_root = sticky_ok};
    return zcl_verify_attest_path_check(chain, 3, &policy);
}

static int test_va_path_policy(void)
{
    int failures = 0;
    TEST("verify attest: the key path policy names every ownership and "
         "mode refusal") {
        ASSERT(va_chain(0, 0644, 0, 0755, false, 0) == NULL);
        ASSERT_STR_EQ(va_chain(1000, 0644, 0, 0755, false, 0),
                      ZCL_VERIFY_ATTEST_WHY_KEY_NOT_ROOT_OWNED);
        ASSERT_STR_EQ(va_chain(0, 0664, 0, 0755, false, 0),
                      ZCL_VERIFY_ATTEST_WHY_KEY_WRITABLE);
        ASSERT_STR_EQ(va_chain(0, 0646, 0, 0755, false, 0),
                      ZCL_VERIFY_ATTEST_WHY_KEY_WRITABLE);
        ASSERT_STR_EQ(va_chain(0, 0644, 1000, 0755, false, 0),
                      ZCL_VERIFY_ATTEST_WHY_DIR_NOT_ROOT_OWNED);
        ASSERT_STR_EQ(va_chain(0, 0644, 0, 0775, false, 0),
                      ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE);
        ASSERT_STR_EQ(va_chain(0, 0644, 0, 0757, false, 0),
                      ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE);
        /* Sticky root-owned tmpfs parents only under the test policy. */
        ASSERT_STR_EQ(va_chain(0, 0644, 0, 01777, false, 0),
                      ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE);
        ASSERT(va_chain(0, 0644, 0, 01777, true, 0) == NULL);
        ASSERT_STR_EQ(va_chain(0, 0644, 1000, 01777, true, 1000),
                      ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE);
        /* A trusted non-root owner is the test policy, never production. */
        ASSERT(va_chain(1000, 0644, 1000, 0700, false, 1000) == NULL);
        ASSERT_STR_EQ(va_chain(1001, 0644, 0, 0755, false, 1000),
                      ZCL_VERIFY_ATTEST_WHY_KEY_NOT_ROOT_OWNED);
        struct zcl_verify_attest_path_entry odd[2] = {
            {.uid = 0, .mode = 0644, .is_regular = false},
            {.uid = 0, .mode = 0755, .is_dir = true},
        };
        struct zcl_verify_attest_path_policy prod = {0};
        ASSERT_STR_EQ(zcl_verify_attest_path_check(odd, 2, &prod),
                      ZCL_VERIFY_ATTEST_WHY_KEY_NOT_REGULAR);
        odd[0].is_regular = true;
        odd[1].is_dir = false;
        ASSERT_STR_EQ(zcl_verify_attest_path_check(odd, 2, &prod),
                      ZCL_VERIFY_ATTEST_WHY_DIR_NOT_DIRECTORY);
        ASSERT_STR_EQ(zcl_verify_attest_path_check(odd, 0, &prod),
                      ZCL_VERIFY_ATTEST_WHY_ARGUMENTS);
        PASS();
    } _test_next:;
    return failures;
}

static int test_va_pubkey_parse(void)
{
    int failures = 0;
    uint8_t want[32], got[32];
    char hex[66];
    TEST("verify attest: a public key file is 64 lowercase hex digits and "
         "at most one newline") {
        va_pub(k_va_verifier_seed, want);
        zcl_hex_encode(want, 32, hex);
        ASSERT(zcl_verify_attest_pubkey_parse((const uint8_t *)hex, 64, got));
        ASSERT(memcmp(got, want, 32) == 0);
        hex[64] = '\n';
        hex[65] = 0;
        ASSERT(zcl_verify_attest_pubkey_parse((const uint8_t *)hex, 65, got));
        ASSERT(!zcl_verify_attest_pubkey_parse((const uint8_t *)hex, 63, got));
        ASSERT(!zcl_verify_attest_pubkey_parse((const uint8_t *)"\n\n", 2,
                                               got));
        char upper[65];
        memcpy(upper, hex, 64);
        upper[64] = 0;
        for (size_t i = 0; i < 64; i++)
            if (upper[i] >= 'a' && upper[i] <= 'f')
                upper[i] = (char)(upper[i] - 'a' + 'A');
        ASSERT(!zcl_verify_attest_pubkey_parse((const uint8_t *)upper, 64,
                                               got));
        char zero[65];
        memset(zero, '0', 64);
        zero[64] = 0;
        ASSERT(!zcl_verify_attest_pubkey_parse((const uint8_t *)zero, 64,
                                               got));
        PASS();
    } _test_next:;
    return failures;
}

/* Every encoding of a point in the order-1/2/4/8 torsion subgroup, spelled
 * independently of the subject (the same set test_ed25519_differential
 * feeds the verifier). Each is tried with both sign bits; the last two are
 * the non-canonical y = p and y = p + 1 spellings of the order-4 and
 * identity points. A pinned key of small order would let one forged
 * signature verify for many messages, so none may load. */
static int test_va_pubkey_small_order(void)
{
    int failures = 0;
    static const char *const small_order[] = {
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    };
    uint8_t point[32], got[32], real[32];
    char hex[65];
    TEST("verify attest: a small-order public key (order 8, 4, 2 or 1, "
         "canonical or not, either sign) is malformed") {
        for (size_t i = 0; i < sizeof(small_order) / sizeof(small_order[0]);
             i++) {
            for (int sign = 0; sign < 2; sign++) {
                test_hex_to_bytes(small_order[i], point, 32);
                if (sign)
                    point[31] ^= 0x80u;
                zcl_hex_encode(point, 32, hex);
                if (zcl_verify_attest_pubkey_parse((const uint8_t *)hex, 64,
                                                   got))
                    printf("[admitted %s] ", hex);
                ASSERT(!zcl_verify_attest_pubkey_parse((const uint8_t *)hex,
                                                       64, got));
            }
        }
        /* An ordinary key still loads. */
        va_pub(k_va_stranger_seed, real);
        zcl_hex_encode(real, 32, hex);
        ASSERT(zcl_verify_attest_pubkey_parse((const uint8_t *)hex, 64, got));
        ASSERT(memcmp(got, real, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* seal() with no output pointer is a caller error, named, never a write
 * through NULL. Runs last: before the guard existed it crashed. */
static int test_va_seal_null_out(void)
{
    int failures = 0;
    size_t len = 99;
    const char *why = NULL;
    TEST("verify attest: seal refuses a NULL output by name") {
        struct zcl_verify_attest_record r = va_record();
        ASSERT(!zcl_verify_attest_seal(&r, k_va_verifier_seed, NULL, &len,
                                       &why));
        ASSERT(len == 0);
        ASSERT_STR_EQ(why, ZCL_VERIFY_ATTEST_WHY_ARGUMENTS);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. trust root: loader on real files ────────────────────────────────── */

#if !defined(_WIN32)
static bool va_system_temp_create(char *out, size_t cap, bool *created)
{
    const char *prior = getenv("TMPDIR");
    char saved[PATH_MAX];
    *created = false;
    if (prior) {
        int n = snprintf(saved, sizeof(saved), "%s", prior);
        if (n < 0 || (size_t)n >= sizeof(saved)) return false;
    }
    /* This trust-root fixture needs the system temp root even if the test
     * runner confines its own scratch files beneath a writable checkout. */
    if (unsetenv("TMPDIR") != 0) return false;
    *created = platform_temp_directory_create(
        "z23-verify-attest-", out, cap);
    bool restored = prior ? setenv("TMPDIR", saved, 1) == 0
                          : unsetenv("TMPDIR") == 0;
    return restored && *created;
}

static bool va_load_refuses(const char *path, bool via_env,
                            const struct zcl_verify_attest_box_key *box,
                            const char *want)
{
    struct zcl_verify_attest_trust_root root;
    const char *why = NULL;
    if (via_env)
        setenv(VA_ENV, path, 1);
    else
        unsetenv(VA_ENV);
    bool ok = zcl_verify_attest_trust_root_load(via_env ? NULL : path, box,
                                                &root, &why);
    unsetenv(VA_ENV);
    if (ok || root.loaded || !why || strcmp(why, want) != 0) {
        printf("[load %s -> %s, want %s] ", path, why ? why : "(admit)",
               want);
        return false;
    }
    return true;
}

static int test_va_loader(void)
{
    int failures = 0;
    char dir[PATH_MAX - 128] = {0}, key[PATH_MAX], sub[PATH_MAX],
         subkey[PATH_MAX], grp[PATH_MAX], grpkey[PATH_MAX];
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    bool fixture_dir_created = false;
    char hex[66];
    uint8_t pub[32], box_sig[64], box_pub[32];
    const char *why = NULL;
    TEST("verify attest: the loader admits only a pinned key file and "
         "refuses every other file by name") {
        va_isolate("loader");
        ASSERT(zcl_verify_attest_test_override_compiled());
        struct zcl_verify_attest_box_key none = va_no_box();
        /* The loader checks every parent of the pinned key. The checkout
         * may be group writable, so place this key beneath the canonical
         * sticky system temp directory and keep XDG signer state isolated. */
        ASSERT(va_system_temp_create(temporary, sizeof(temporary),
                                     &fixture_dir_created));
        ASSERT(platform_directory_canonical_real(temporary, dir, sizeof(dir)));
        (void)snprintf(key, sizeof(key), "%s/verifier.pub", dir);
        /* Missing is the normal state and is named. */
        ASSERT(va_load_refuses(key, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY));
        va_pub(k_va_verifier_seed, pub);
        zcl_hex_encode(pub, 32, hex);
        hex[64] = '\n';
        hex[65] = 0;
        ASSERT(va_write(key, hex, 0644));
        /* Production policy: a file this account owns is not root's. */
        if (geteuid() != 0)
            ASSERT(va_load_refuses(key, false, &none,
                                   ZCL_VERIFY_ATTEST_WHY_KEY_NOT_ROOT_OWNED));
        ASSERT(va_load_refuses("relative/verifier.pub", false, &none,
                               ZCL_VERIFY_ATTEST_WHY_KEY_PATH_NOT_ABSOLUTE));
        /* Test override: the same file, owned by this account, loads. */
        struct zcl_verify_attest_trust_root root;
        setenv(VA_ENV, key, 1);
        bool loaded = zcl_verify_attest_trust_root_load(NULL, &none, &root,
                                                        &why);
        unsetenv(VA_ENV);
        ASSERT(loaded && root.loaded);
        ASSERT(memcmp(root.verifier_pubkey, pub, 32) == 0);
        struct zcl_verify_attest_box_key unknown = {0};
        ASSERT(va_load_refuses(key, true, &unknown,
                               ZCL_VERIFY_ATTEST_WHY_BOX_KEY_UNKNOWN));
        ASSERT(chmod(key, 0664) == 0);
        ASSERT(va_load_refuses(key, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_KEY_WRITABLE));
        ASSERT(chmod(key, 0646) == 0);
        ASSERT(va_load_refuses(key, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_KEY_WRITABLE));
        ASSERT(chmod(key, 0644) == 0);
        (void)snprintf(sub, sizeof(sub), "%s/open", dir);
        ASSERT(mkdir(sub, 0700) == 0);
        (void)snprintf(subkey, sizeof(subkey), "%s/verifier.pub", sub);
        ASSERT(va_write(subkey, hex, 0644));
        ASSERT(chmod(sub, 0770) == 0);
        ASSERT(va_load_refuses(subkey, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE));
        ASSERT(chmod(sub, 0702) == 0);
        ASSERT(va_load_refuses(subkey, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE));
        ASSERT(chmod(sub, 0700) == 0);
        /* A 0775 directory this account owns, as a umask-002 login leaves
         * ~/.local: refused as the key's parent and as any higher
         * ancestor, even when the directory in between is 0700. */
        (void)snprintf(grp, sizeof(grp), "%s/shared", dir);
        ASSERT(mkdir(grp, 0700) == 0 && chmod(grp, 0775) == 0);
        (void)snprintf(grpkey, sizeof(grpkey), "%s/verifier.pub", grp);
        ASSERT(va_write(grpkey, hex, 0644));
        ASSERT(va_load_refuses(grpkey, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE));
        (void)snprintf(grpkey, sizeof(grpkey), "%s/inner", grp);
        ASSERT(mkdir(grpkey, 0700) == 0);
        (void)snprintf(grpkey, sizeof(grpkey), "%s/inner/verifier.pub", grp);
        ASSERT(va_write(grpkey, hex, 0644));
        ASSERT(va_load_refuses(grpkey, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE));
        ASSERT(va_write(subkey, "not a key\n", 0644));
        ASSERT(va_load_refuses(subkey, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_KEY_MALFORMED));
        (void)snprintf(subkey, sizeof(subkey), "%s/link.pub", sub);
        ASSERT(symlink(key, subkey) == 0);
        ASSERT(va_load_refuses(subkey, true, &none,
                               ZCL_VERIFY_ATTEST_WHY_KEY_NOT_REGULAR));
        /* A key file that names the per-box proof signer is refused. */
        ASSERT(zcl_dev_proof_signer_sign((const uint8_t *)"x", 1, box_pub,
                                         box_sig, &why));
        struct zcl_verify_attest_box_key box = {.known = true,
                                                .present = true};
        memcpy(box.pubkey, box_pub, 32);
        zcl_hex_encode(box_pub, 32, hex);
        ASSERT(va_write(key, hex, 0644));
        ASSERT(va_load_refuses(key, true, &box,
                               ZCL_VERIFY_ATTEST_WHY_KEY_IS_BOX_SIGNER));
        PASS();
    } _test_next:;
    if (fixture_dir_created)
        test_rm_rf_recursive(temporary);
    va_restore();
    return failures;
}

/* The default path is refused as missing on any host without a verifier;
 * on a host with one installed it must load. Either way it never admits a
 * file this account could have written. */
static int test_va_default_path(void)
{
    int failures = 0;
    struct stat st;
    const char *why = NULL;
    TEST("verify attest: the default key path is missing or root-pinned") {
        va_isolate("default_path");
        struct zcl_verify_attest_box_key none = va_no_box();
        struct zcl_verify_attest_trust_root root;
        bool ok = zcl_verify_attest_trust_root_load(NULL, &none, &root, &why);
        if (lstat(ZCL_VERIFY_ATTEST_DEFAULT_PUBKEY_PATH, &st) != 0) {
            ASSERT(!ok);
            ASSERT_STR_EQ(why, ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY);
        } else if (ok) {
            ASSERT(st.st_uid == 0);
        }
        va_restore();
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_verify_attest(void)
{
    int failures = 0;
    failures += test_va_encoding_vector();
    failures += test_va_parse_strict();
    failures += test_va_admit();
    failures += test_va_refuse_fields();
    failures += test_va_refuse_binding();
    failures += test_va_refuse_v1_record();
    failures += test_va_signed_failure_blocks();
    failures += test_va_empty_object();
    failures += test_va_artifact_substitution();
    failures += test_va_observation_set();
    failures += test_va_observation_set_refusals();
    failures += test_va_refuse_signers();
    failures += test_va_path_policy();
    failures += test_va_pubkey_parse();
#if !defined(_WIN32)
    failures += test_va_loader();
    failures += test_va_default_path();
#endif
    failures += test_va_pubkey_small_order();
    failures += test_va_seal_null_out();
    va_restore();
    return failures;
}
