/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zssh_auth — ssh-ed25519 blobs/signatures (RFC 8709), service negotiation
 * (RFC 4253 10) and the ssh-userauth "publickey" method (RFC 4252 7), layer c.
 *
 * References resolved against the pinned OpenSSH 10.0p2 tree (file:line):
 *   - key blob  string "ssh-ed25519" || string pk(32): rfc8709.txt:110-118
 *     (section 4). ssh-ed25519.c:55-62 ssh_ed25519_serialize_public writes
 *     only the pk string (line 62); the name string comes from the generic
 *     key-to-blob code, which is not in the pinned set.
 *   - signature string "ssh-ed25519" || string sig(64): rfc8709.txt:135-145
 *     (section 6); ssh-ed25519.c:181-182 ssh_ed25519_sign
 *     (sshbuf_put_cstring + sshbuf_put_string).
 *   - strict verify shape (name, one string, nothing after): ssh-ed25519.c:
 *     227-228 (get_cstring, get_string_direct) and 234 (sshbuf_len(b) != 0
 *     rejects trailing bytes).
 *   - probe request (boolean FALSE) and PK_OK echo: rfc4252.txt:462-468 and
 *     482-484; PK_OK = 60: rfc4252.txt:536.
 *   - signed data (session id, byte 50, user, service, "publickey", TRUE,
 *     alg, key blob): rfc4252.txt:514-522; the USERAUTH_REQUEST signature
 *     field is the signature blob wrapped in one more string.
 *   - SERVICE_REQUEST / SERVICE_ACCEPT: rfc4253.txt:1331-1332, 1354-1355.
 * No allocation, no globals, no I/O. Secret seeds and expanded keys are
 * cleansed on every exit.
 *
 * Builder rule (all zssh_auth_build_*): on writer overflow, or a NULL argument
 * that cannot be encoded, w->off is restored to its value at entry and the
 * writer's sticky `bad` flag stays set, so the caller detects the failure with
 * zssh_wr_ok() and never commits a half-written payload. */

#include "zssh_internal.h"

#include <string.h>

static bool nl_is(struct zssh_namelist s, const char *lit)
{
    size_t n = strlen(lit);
    return s.len == n && (n == 0 || memcmp(s.p, lit, n) == 0);
}

/* Builder rule: a failed build restores the entry offset and leaves `bad` set. */
static void wr_rollback_if_bad(struct zssh_wr *w, size_t start)
{
    if (!zssh_wr_ok(w))
        w->off = start;
}

/* ---- blobs -------------------------------------------------------------- */

void zssh_auth_blob_encode(const uint8_t pk[ZSSH_ED25519_PK_LEN],
                           uint8_t out[ZSSH_ED25519_BLOB_LEN])
{
    struct zssh_wr w;
    zssh_wr_init(&w, out, ZSSH_ED25519_BLOB_LEN);
    zssh_wr_cstr(&w, ZSSH_HOSTKEY_ALG);
    zssh_wr_string(&w, pk, ZSSH_ED25519_PK_LEN);
}

enum zssh_error zssh_auth_blob_parse(const uint8_t *blob, size_t len,
                                     uint8_t pk[ZSSH_ED25519_PK_LEN])
{
    struct zssh_rd r;
    struct zssh_namelist alg = { NULL, 0 };
    const uint8_t *k = NULL;
    size_t kn = 0;

    if (!pk)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL output key");
    memory_cleanse(pk, ZSSH_ED25519_PK_LEN);
    if (!blob && len != 0)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "NULL blob with length %zu", len);
    zssh_rd_init(&r, blob, len);
    zssh_rd_string(&r, &alg.p, &alg.len);
    zssh_rd_string(&r, &k, &kn);
    if (!zssh_rd_done(&r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "host key blob truncated or has trailing bytes");
    if (!nl_is(alg, ZSSH_HOSTKEY_ALG))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "host key algorithm is not ssh-ed25519");
    if (kn != ZSSH_ED25519_PK_LEN)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "ed25519 key length %zu != 32", kn);
    memcpy(pk, k, ZSSH_ED25519_PK_LEN);
    return ZSSH_E_NONE;
}

void zssh_auth_fingerprint(const uint8_t blob[ZSSH_ED25519_BLOB_LEN],
                           uint8_t out[ZSSH_FINGERPRINT_LEN])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, blob, ZSSH_ED25519_BLOB_LEN);
    sha256_finalize(&c, out);
}

/* ---- sign / verify ------------------------------------------------------ */

enum zssh_error zssh_auth_sign(const uint8_t seed[ZSSH_ED25519_SEED_LEN],
                               const uint8_t pk[ZSSH_ED25519_PK_LEN],
                               const uint8_t *msg, size_t msg_len,
                               uint8_t out[ZSSH_ED25519_SIGBLOB_LEN])
{
    uint8_t sk[32], dpk[32], sig[ZSSH_ED25519_SIG_LEN];
    struct zssh_wr w;
    enum zssh_error e = ZSSH_E_NONE;

    if (!seed || !pk || !out || (!msg && msg_len != 0))
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    zcl_ed25519_keypair(dpk, sk, seed);
    if (!zssh_ct_eq(dpk, pk, ZSSH_ED25519_PK_LEN)) {
        /* The header names no code for a seed/pk mismatch (INTERNAL "only on
         * NULL args"). zssh.h defines ZSSH_E_INTERNAL as "invariant violated",
         * which a mismatched keypair is; no new enum value is invented. The
         * header sentence needs amending (reported to the lead). */
        ZSSH_LOG("public key does not belong to the seed");
        e = ZSSH_E_INTERNAL;
    } else {
        zcl_ed25519_sign(sig, msg, msg_len, sk, dpk);
        zssh_wr_init(&w, out, ZSSH_ED25519_SIGBLOB_LEN);
        zssh_wr_cstr(&w, ZSSH_HOSTKEY_ALG);
        zssh_wr_string(&w, sig, sizeof sig);
    }
    memory_cleanse(sk, sizeof sk);
    memory_cleanse(dpk, sizeof dpk);
    memory_cleanse(sig, sizeof sig);
    return e;
}

enum zssh_error zssh_auth_verify(const uint8_t pk[ZSSH_ED25519_PK_LEN],
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sigblob, size_t sigblob_len,
                                 bool host)
{
    struct zssh_rd r;
    struct zssh_namelist alg = { NULL, 0 };
    const uint8_t *sig = NULL;
    size_t sn = 0;
    enum zssh_error bad = host ? ZSSH_E_HOST_SIG : ZSSH_E_AUTH_REFUSED;

    if (!pk || (!msg && msg_len != 0) || (!sigblob && sigblob_len != 0))
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    zssh_rd_init(&r, sigblob, sigblob_len);
    zssh_rd_string(&r, &alg.p, &alg.len);
    zssh_rd_string(&r, &sig, &sn);
    if (!zssh_rd_done(&r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "signature blob truncated or has trailing bytes");
    if (!nl_is(alg, ZSSH_HOSTKEY_ALG))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "signature algorithm is not ssh-ed25519");
    if (sn != ZSSH_ED25519_SIG_LEN)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "ed25519 signature length %zu != 64", sn);
    if (!ed25519_verify(sig, msg, msg_len, pk))
        ZSSH_FAIL(bad, "ed25519 signature did not verify (%s)",
                  host ? "host" : "user");
    return ZSSH_E_NONE;
}

/* ---- service messages --------------------------------------------------- */

static void build_service(struct zssh_wr *w, uint8_t msg, const char *service)
{
    size_t start;

    if (!w)
        return;
    start = w->off;
    if (!service) {
        w->bad = true;
        return;
    }
    zssh_wr_u8(w, msg);
    zssh_wr_cstr(w, service);
    wr_rollback_if_bad(w, start);
}

void zssh_auth_build_service_request(struct zssh_wr *w, const char *service)
{
    build_service(w, ZSSH_MSG_SERVICE_REQUEST, service);
}

void zssh_auth_build_service_accept(struct zssh_wr *w, const char *service)
{
    build_service(w, ZSSH_MSG_SERVICE_ACCEPT, service);
}

enum zssh_error zssh_auth_parse_service(const uint8_t *payload, size_t len,
                                        uint8_t expect_msg,
                                        struct zssh_namelist *service)
{
    struct zssh_rd r;
    struct zssh_namelist s = { NULL, 0 };
    uint8_t t;

    if (!service)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL output");
    service->p = NULL;
    service->len = 0;
    if (!payload && len != 0)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "NULL payload");
    zssh_rd_init(&r, payload, len);
    t = zssh_rd_u8(&r);
    zssh_rd_string(&r, &s.p, &s.len);
    if (!zssh_rd_done(&r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "service message malformed");
    if (t != expect_msg)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "service message type %u, expected %u",
                  (unsigned)t, (unsigned)expect_msg);
    *service = s;
    return ZSSH_E_NONE;
}

/* ---- userauth signed data ----------------------------------------------- */

/* RFC 4252 7, user given as slice so the server can use the wire bytes. */
static enum zssh_error signed_data_n(const uint8_t sid[ZSSH_SESSION_ID_LEN],
                                     const uint8_t *user, size_t user_len,
                                     const uint8_t pk[ZSSH_ED25519_PK_LEN],
                                     uint8_t *out, size_t cap, size_t *n)
{
    struct zssh_wr w;
    uint8_t blob[ZSSH_ED25519_BLOB_LEN];

    *n = 0;
    if (user_len > ZSSH_MAX_USER)
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "user name %zu > %u", user_len,
                  (unsigned)ZSSH_MAX_USER);
    zssh_auth_blob_encode(pk, blob);
    zssh_wr_init(&w, out, cap);
    zssh_wr_string(&w, sid, ZSSH_SESSION_ID_LEN);
    zssh_wr_u8(&w, ZSSH_MSG_USERAUTH_REQUEST);
    zssh_wr_string(&w, user, user_len);
    zssh_wr_cstr(&w, ZSSH_SERVICE_CONNECTION);
    zssh_wr_cstr(&w, "publickey");
    zssh_wr_bool(&w, true);
    zssh_wr_cstr(&w, ZSSH_HOSTKEY_ALG);
    zssh_wr_string(&w, blob, sizeof blob);
    if (!zssh_wr_ok(&w))
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "signed-data buffer too small");
    *n = w.off;
    return ZSSH_E_NONE;
}

enum zssh_error zssh_auth_signed_data(const uint8_t session_id[ZSSH_SESSION_ID_LEN],
                                      const char *user,
                                      const uint8_t pk[ZSSH_ED25519_PK_LEN],
                                      uint8_t *out, size_t cap, size_t *n)
{
    if (!session_id || !user || !pk || !out || !n)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    return signed_data_n(session_id, (const uint8_t *)user, strlen(user), pk,
                         out, cap, n);
}

/* ---- client request ----------------------------------------------------- */

enum zssh_error zssh_auth_build_request(struct zssh_wr *w, const char *user,
        const uint8_t session_id[ZSSH_SESSION_ID_LEN],
        const uint8_t user_seed[ZSSH_ED25519_SEED_LEN],
        const uint8_t user_pk[ZSSH_ED25519_PK_LEN])
{
    uint8_t sd[ZSSH_AUTH_SIGDATA_MAX];
    uint8_t sig[ZSSH_ED25519_SIGBLOB_LEN];
    uint8_t blob[ZSSH_ED25519_BLOB_LEN];
    size_t sdn = 0, start;
    enum zssh_error e;

    if (!w || !user || !session_id || !user_seed || !user_pk)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    e = zssh_auth_signed_data(session_id, user, user_pk, sd, sizeof sd, &sdn);
    if (e != ZSSH_E_NONE)
        return e;
    e = zssh_auth_sign(user_seed, user_pk, sd, sdn, sig);
    if (e != ZSSH_E_NONE)
        return e;
    zssh_auth_blob_encode(user_pk, blob);
    start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_USERAUTH_REQUEST);
    zssh_wr_cstr(w, user);
    zssh_wr_cstr(w, ZSSH_SERVICE_CONNECTION);
    zssh_wr_cstr(w, "publickey");
    zssh_wr_bool(w, true);
    zssh_wr_cstr(w, ZSSH_HOSTKEY_ALG);
    zssh_wr_string(w, blob, sizeof blob);
    zssh_wr_string(w, sig, sizeof sig);
    if (!zssh_wr_ok(w)) {
        wr_rollback_if_bad(w, start);
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "request does not fit the writer");
    }
    return ZSSH_E_NONE;
}

/* ---- server request ----------------------------------------------------- */

static void parse_publickey_tail(struct zssh_rd *r, struct zssh_auth_request *o)
{
    o->has_signature = zssh_rd_bool(r);
    zssh_rd_string(r, &o->alg.p, &o->alg.len);
    zssh_rd_string(r, &o->key_blob.p, &o->key_blob.len);
    if (o->has_signature)
        zssh_rd_string(r, &o->sig.p, &o->sig.len);
}

enum zssh_error zssh_auth_parse_request(const uint8_t *payload, size_t len,
                                        struct zssh_auth_request *out)
{
    struct zssh_rd r;
    struct zssh_auth_request o;
    uint8_t t;

    if (!out)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL output");
    memset(out, 0, sizeof *out);
    memset(&o, 0, sizeof o);
    if (!payload && len != 0)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "NULL payload");
    zssh_rd_init(&r, payload, len);
    t = zssh_rd_u8(&r);
    zssh_rd_string(&r, &o.user.p, &o.user.len);
    zssh_rd_string(&r, &o.service.p, &o.service.len);
    zssh_rd_string(&r, &o.method.p, &o.method.len);
    if (!zssh_rd_ok(&r) || t != ZSSH_MSG_USERAUTH_REQUEST)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "userauth request header malformed");
    if (nl_is(o.method, "publickey")) {
        o.kind = ZSSH_AUTH_PUBLICKEY;
        parse_publickey_tail(&r, &o);
    } else if (nl_is(o.method, "none")) {
        o.kind = ZSSH_AUTH_NONE_METHOD;
    } else {
        o.kind = ZSSH_AUTH_OTHER;
        /* the method-specific tail is ignored, not parsed */
        *out = o;
        return ZSSH_E_NONE;
    }
    if (!zssh_rd_done(&r))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "userauth request truncated or trailing bytes");
    *out = o;
    return ZSSH_E_NONE;
}

/* Exact user match. FAIL CLOSED: a NULL or empty expected_user matches nothing
 * (the configured account must always be named), so a missing configuration
 * can never authenticate an arbitrary user. Whole-string compare: a strict
 * prefix in either direction does not match. */
static bool user_matches(struct zssh_namelist user, const char *expected_user)
{
    size_t n;

    if (!expected_user || expected_user[0] == '\0')
        return false;
    n = strlen(expected_user);
    return n == user.len && user.p && memcmp(expected_user, user.p, n) == 0;
}

/* Checks shared by the probe and the signed request: service, user, method
 * kind and algorithm name. */
static bool request_head_matches(const struct zssh_auth_request *req,
                                 const char *expected_user)
{
    bool ok = nl_is(req->service, ZSSH_SERVICE_CONNECTION);

    ok = user_matches(req->user, expected_user) && ok;
    ok = (req->kind == ZSSH_AUTH_PUBLICKEY) && ok;
    ok = nl_is(req->alg, ZSSH_HOSTKEY_ALG) && ok;
    return ok;
}

/* Parse the offered blob into pk (zeroed on failure) and compare it with the
 * authorized key in constant time. */
static bool offered_key_matches(const struct zssh_auth_request *req,
                                const uint8_t authorized_pk[ZSSH_ED25519_PK_LEN],
                                uint8_t pk[ZSSH_ED25519_PK_LEN])
{
    bool ok = zssh_auth_blob_parse(req->key_blob.p, req->key_blob.len, pk)
              == ZSSH_E_NONE;

    return zssh_ct_eq(pk, authorized_pk, ZSSH_ED25519_PK_LEN) && ok;
}

/* All checks run; the verdict is the AND. The peer only learns "failure". */
enum zssh_error zssh_auth_check_request(const struct zssh_auth_request *req,
        const uint8_t session_id[ZSSH_SESSION_ID_LEN], const char *expected_user,
        const uint8_t authorized_pk[ZSSH_ED25519_PK_LEN])
{
    uint8_t pk[ZSSH_ED25519_PK_LEN];
    uint8_t sd[ZSSH_AUTH_SIGDATA_MAX];
    size_t sdn = 0;
    bool ok;

    if (!req || !session_id || !authorized_pk)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    ok = request_head_matches(req, expected_user);
    ok = req->has_signature && ok;
    ok = offered_key_matches(req, authorized_pk, pk) && ok;
    ok = (signed_data_n(session_id, req->user.p, req->user.len, pk, sd,
                        sizeof sd, &sdn) == ZSSH_E_NONE) && ok;
    ok = (zssh_auth_verify(pk, sd, sdn, req->sig.p, req->sig.len, false)
          == ZSSH_E_NONE) && ok;
    memory_cleanse(pk, sizeof pk);
    if (!ok)
        ZSSH_FAIL(ZSSH_E_AUTH_REFUSED, "userauth request refused");
    return ZSSH_E_NONE;
}

void zssh_auth_build_failure(struct zssh_wr *w)
{
    size_t start;

    if (!w)
        return;
    start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_USERAUTH_FAILURE);
    zssh_wr_cstr(w, "publickey");
    zssh_wr_bool(w, false);
    wr_rollback_if_bad(w, start);
}

void zssh_auth_build_success(struct zssh_wr *w)
{
    size_t start;

    if (!w)
        return;
    start = w->off;
    zssh_wr_u8(w, ZSSH_MSG_USERAUTH_SUCCESS);
    wr_rollback_if_bad(w, start);
}

/* ---- client result ------------------------------------------------------ */

enum zssh_error zssh_auth_client_result(const uint8_t *payload, size_t len,
                                        bool *success)
{
    struct zssh_rd r;
    const uint8_t *s;
    size_t n;
    uint8_t t;

    if (!success)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL output");
    *success = false;
    if (!payload || len == 0)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "empty userauth reply");
    zssh_rd_init(&r, payload, len);
    t = zssh_rd_u8(&r);
    switch (t) {
    case ZSSH_MSG_USERAUTH_SUCCESS:
        if (!zssh_rd_done(&r))
            ZSSH_FAIL(ZSSH_E_PROTOCOL, "trailing bytes after USERAUTH_SUCCESS");
        *success = true;
        return ZSSH_E_NONE;
    case ZSSH_MSG_USERAUTH_FAILURE:
        zssh_rd_string(&r, &s, &n);
        (void)zssh_rd_bool(&r);
        if (!zssh_rd_done(&r))
            ZSSH_FAIL(ZSSH_E_PROTOCOL, "USERAUTH_FAILURE malformed");
        ZSSH_FAIL(ZSSH_E_AUTH_REFUSED, "server refused the key");
    case ZSSH_MSG_USERAUTH_BANNER:
        zssh_rd_string(&r, &s, &n);
        zssh_rd_string(&r, &s, &n);
        if (!zssh_rd_done(&r))
            ZSSH_FAIL(ZSSH_E_PROTOCOL, "USERAUTH_BANNER malformed");
        return ZSSH_E_NONE;
    case ZSSH_MSG_USERAUTH_PK_OK:
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unsolicited USERAUTH_PK_OK (not success)");
    default:
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "unexpected message %u during userauth",
                  (unsigned)t);
    }
}

/* ---- probe-aware decision (declared in zssh_internal.h) ------------------ *
 * OpenSSH clients first send the request with has-signature FALSE
 * (rfc4252.txt:462-468). For the single authorized key and algorithm the
 * server answers PK_OK (rfc4252.txt:482-484) and stays unauthenticated;
 * anything else is FAILURE. Only a signed request that passes
 * zssh_auth_check_request is SUCCESS. */

static bool probe_matches(const struct zssh_auth_request *req,
                          const char *expected_user,
                          const uint8_t authorized_pk[ZSSH_ED25519_PK_LEN])
{
    uint8_t pk[ZSSH_ED25519_PK_LEN];
    bool ok = request_head_matches(req, expected_user);

    ok = !req->has_signature && ok;
    ok = offered_key_matches(req, authorized_pk, pk) && ok;
    memory_cleanse(pk, sizeof pk);
    return ok;
}

enum zssh_auth_verdict zssh_auth_server_decide(const struct zssh_auth_request *req,
        const uint8_t session_id[ZSSH_SESSION_ID_LEN], const char *expected_user,
        const uint8_t authorized_pk[ZSSH_ED25519_PK_LEN])
{
    if (!req || !session_id || !authorized_pk)
        return ZSSH_AUTH_V_FAILURE;
    if (req->kind == ZSSH_AUTH_PUBLICKEY && !req->has_signature)
        return probe_matches(req, expected_user, authorized_pk)
               ? ZSSH_AUTH_V_PK_OK : ZSSH_AUTH_V_FAILURE;
    return zssh_auth_check_request(req, session_id, expected_user, authorized_pk)
           == ZSSH_E_NONE ? ZSSH_AUTH_V_SUCCESS : ZSSH_AUTH_V_FAILURE;
}

/* RFC 4252 7 (rfc4252.txt:482-484): byte 60, string algorithm, string key blob
 * (echoed). A NULL req is a caller bug: nothing is written and the writer's
 * sticky `bad` flag is set. */
void zssh_auth_build_pk_ok(struct zssh_wr *w, const struct zssh_auth_request *req)
{
    size_t start;

    if (!w)
        return;
    start = w->off;
    if (!req) {
        w->bad = true;
        return;
    }
    zssh_wr_u8(w, ZSSH_MSG_USERAUTH_PK_OK);
    zssh_wr_string(w, req->alg.p, req->alg.len);
    zssh_wr_string(w, req->key_blob.p, req->key_blob.len);
    wr_rollback_if_bad(w, start);
}

/* Like zssh_auth_client_result but a well-formed PK_OK is E_NONE with
 * *pk_ok true (and *success false): the client then sends the signed request. */
enum zssh_error zssh_auth_client_result_ex(const uint8_t *payload, size_t len,
                                           bool *success, bool *pk_ok)
{
    struct zssh_rd r;
    const uint8_t *s;
    size_t n;

    if (!success || !pk_ok)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL output");
    *pk_ok = false;
    if (payload && len > 0 && payload[0] == ZSSH_MSG_USERAUTH_PK_OK) {
        *success = false;
        zssh_rd_init(&r, payload, len);
        (void)zssh_rd_u8(&r);
        zssh_rd_string(&r, &s, &n);
        zssh_rd_string(&r, &s, &n);
        if (!zssh_rd_done(&r))
            ZSSH_FAIL(ZSSH_E_PROTOCOL, "USERAUTH_PK_OK malformed");
        *pk_ok = true;
        return ZSSH_E_NONE;
    }
    return zssh_auth_client_result(payload, len, success);
}
