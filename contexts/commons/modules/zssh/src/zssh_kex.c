/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zssh_kex — KEXINIT, negotiation, curve25519 / mlkem768x25519, H, keys (layer b).
 *
 * References resolved against the pinned OpenSSH 10.0p2 sources (cited by
 * file name and line):
 *   - exchange hash field order: kexgen.c:67-78 (V_C, V_S, string(I_C),
 *     string(I_S) where I_x is the payload with its type byte, K_S, Q_C, Q_S,
 *     then the shared secret ALREADY ENCODED, appended raw by sshbuf_putb).
 *   - curve25519 K: kexc25519.c:70-79 sshbuf_put_bignum2_bytes of the 32
 *     X25519 output bytes as given (RFC 8731 3.1: the octets are read as a
 *     big-endian integer; there is NO byte reversal), all-zero output refused
 *     (kexc25519.c:60-66).
 *   - hybrid: kexmlkem768x25519.c:80-100 client blob = ek(1184) || x25519 pk;
 *     :146-190 server blob = ct(1088) || x25519 pk, shared = SHA-256(mlkem_ss
 *     || x25519_raw) (:151-156 combiner order), encoded sshbuf_put_string
 *     (:166-169, :244-245) so it enters H and the key derivation as a string.
 *   - message numbers: kexgen.c:132,360 use SSH_MSG_KEX_ECDH_INIT / _REPLY for
 *     every method including the hybrid; the values 30 / 31 are from RFC 5656
 *     4 (not in the pinned set; matches OpenSSH ssh2.h).
 *   - KEXINIT layout: kex.c:158-171 (cookie, 10 lists, first_kex u8, u32 0);
 *     strict KEX markers: kex.c:940-960 and PROTOCOL:140-165. */

#include "zssh_internal.h"

#include "crypto/curve25519.h"

#include <string.h>

#define KEX_NAMES_CAP 128u
#define KEX_K_ENC_CAP 40u   /* string(32) = 36, mpint(32) <= 37 */

/* ---- KEXINIT -------------------------------------------------------------- */

static enum zssh_error kex_policy_check(const struct zssh_kex_policy *pol)
{
    const uint32_t known = ZSSH_KEX_MLKEM768X25519_SHA256 | ZSSH_KEX_CURVE25519_SHA256;
    if (!pol || (pol->role != ZSSH_ROLE_CLIENT && pol->role != ZSSH_ROLE_SERVER))
        ZSSH_FAIL(ZSSH_E_INTERNAL, "bad kex policy");
    if (pol->allowed == 0 || (pol->allowed & ~known) != 0)
        ZSSH_FAIL(ZSSH_E_CONFIG, "kex policy allowed set 0x%x invalid", pol->allowed);
    if (pol->require_pq && !(pol->allowed & ZSSH_KEX_MLKEM768X25519_SHA256))
        ZSSH_FAIL(ZSSH_E_CONFIG, "require_pq without the hybrid");
    return ZSSH_E_NONE;
}

static size_t kex_append_name(char *out, size_t n, const char *name)
{
    size_t l = strlen(name);
    if (n > 0) out[n++] = ',';
    memcpy(out + n, name, l);
    out[n + l] = '\0';
    return n + l;
}

/* The algorithm names WE offer (no strict marker), hybrid first. */
static size_t kex_our_names(const struct zssh_kex_policy *pol, char out[KEX_NAMES_CAP])
{
    size_t n = 0;
    out[0] = '\0';
    if (pol->allowed & ZSSH_KEX_MLKEM768X25519_SHA256)
        n = kex_append_name(out, n, ZSSH_KEX_NAME_MLKEM);
    if (!pol->require_pq && (pol->allowed & ZSSH_KEX_CURVE25519_SHA256))
        n = kex_append_name(out, n, ZSSH_KEX_NAME_CURVE25519);
    return n;
}

enum zssh_error zssh_kex_build_kexinit(const struct zssh_kex_policy *pol,
                                       const uint8_t cookie16[16],
                                       struct zssh_wr *w)
{
    char names[KEX_NAMES_CAP];
    size_t n;
    enum zssh_error e = kex_policy_check(pol);
    if (e != ZSSH_E_NONE) return e;
    if (!cookie16 || !w) ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    n = kex_our_names(pol, names);
    kex_append_name(names, n,
        pol->role == ZSSH_ROLE_CLIENT ? ZSSH_KEX_NAME_STRICT_C : ZSSH_KEX_NAME_STRICT_S);

    zssh_wr_u8(w, ZSSH_MSG_KEXINIT);
    zssh_wr_bytes(w, cookie16, 16);
    zssh_wr_cstr(w, names);
    zssh_wr_cstr(w, ZSSH_HOSTKEY_ALG);
    zssh_wr_cstr(w, ZSSH_CIPHER_NAME);
    zssh_wr_cstr(w, ZSSH_CIPHER_NAME);
    zssh_wr_cstr(w, ZSSH_MAC_PLACEHOLDER);
    zssh_wr_cstr(w, ZSSH_MAC_PLACEHOLDER);
    zssh_wr_cstr(w, ZSSH_COMPRESSION_NAME);
    zssh_wr_cstr(w, ZSSH_COMPRESSION_NAME);
    zssh_wr_cstr(w, "");
    zssh_wr_cstr(w, "");
    zssh_wr_bool(w, false);
    zssh_wr_u32(w, 0);
    if (!zssh_wr_ok(w)) ZSSH_FAIL(ZSSH_E_TOO_LARGE, "KEXINIT does not fit");
    return ZSSH_E_NONE;
}

enum zssh_error zssh_kex_parse_kexinit(const uint8_t *payload, size_t len,
                                       struct zssh_kexinit_view *view)
{
    struct zssh_rd r;
    const uint8_t *cookie = nullptr;
    if (!view) ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL view");
    memset(view, 0, sizeof *view);
    if (len > ZSSH_KEXINIT_MAX) ZSSH_FAIL(ZSSH_E_TOO_LARGE, "KEXINIT %zu bytes", len);
    if (!payload || len == 0) ZSSH_FAIL(ZSSH_E_PROTOCOL, "empty KEXINIT");
    zssh_rd_init(&r, payload, len);
    if (zssh_rd_u8(&r) != ZSSH_MSG_KEXINIT) {
        memset(view, 0, sizeof *view);
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "not a KEXINIT");
    }
    zssh_rd_bytes(&r, &cookie, 16);
    if (zssh_rd_ok(&r)) memcpy(view->cookie, cookie, 16);
    for (int i = 0; i < ZSSH_KI_COUNT; i++)
        zssh_rd_string(&r, &view->list[i].p, &view->list[i].len);
    view->first_kex_packet_follows = zssh_rd_bool(&r);
    (void)zssh_rd_u32(&r);   /* reserved, ignored (RFC 4253 7.1) */
    if (!zssh_rd_done(&r)) {
        memset(view, 0, sizeof *view);
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "KEXINIT truncated or has trailing bytes");
    }
    return ZSSH_E_NONE;
}

/* ---- negotiation ---------------------------------------------------------- */

static bool name_is(const uint8_t *p, size_t n, const char *name)
{
    return n == strlen(name) && memcmp(p, name, n) == 0;
}

static enum zssh_kex_alg kex_pick(const struct zssh_kex_policy *pol,
                                  const struct zssh_kexinit_view *peer)
{
    char names[KEX_NAMES_CAP];
    struct zssh_namelist ours, client, server;
    const uint8_t *nm = nullptr;
    size_t nl = 0;
    ours.len = kex_our_names(pol, names);
    ours.p = (const uint8_t *)names;
    client = pol->role == ZSSH_ROLE_CLIENT ? ours : peer->list[ZSSH_KI_KEX];
    server = pol->role == ZSSH_ROLE_CLIENT ? peer->list[ZSSH_KI_KEX] : ours;
    if (zssh_namelist_pick(client, server, &nm, &nl) < 0) return ZSSH_KEXALG_NONE;
    if (name_is(nm, nl, ZSSH_KEX_NAME_MLKEM)) return ZSSH_KEXALG_MLKEM768X25519;
    if (name_is(nm, nl, ZSSH_KEX_NAME_CURVE25519)) return ZSSH_KEXALG_CURVE25519;
    return ZSSH_KEXALG_NONE;
}

static bool suites_ok(const struct zssh_kexinit_view *v)
{
    return zssh_namelist_has(v->list[ZSSH_KI_HOSTKEY], ZSSH_HOSTKEY_ALG)
        && zssh_namelist_has(v->list[ZSSH_KI_ENC_C2S], ZSSH_CIPHER_NAME)
        && zssh_namelist_has(v->list[ZSSH_KI_ENC_S2C], ZSSH_CIPHER_NAME)
        && zssh_namelist_has(v->list[ZSSH_KI_COMP_C2S], ZSSH_COMPRESSION_NAME)
        && zssh_namelist_has(v->list[ZSSH_KI_COMP_S2C], ZSSH_COMPRESSION_NAME);
}

enum zssh_error zssh_kex_negotiate(const struct zssh_kex_policy *pol,
                                   const struct zssh_kexinit_view *peer,
                                   struct zssh_neg *out)
{
    enum zssh_kex_alg alg;
    enum zssh_error e;
    if (!out) ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL out");
    out->alg = ZSSH_KEXALG_NONE;
    out->strict = false;
    if (!peer) ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL peer view");
    e = kex_policy_check(pol);
    if (e != ZSSH_E_NONE) return e;
    if (!zssh_namelist_has(peer->list[ZSSH_KI_KEX],
            pol->role == ZSSH_ROLE_CLIENT ? ZSSH_KEX_NAME_STRICT_S : ZSSH_KEX_NAME_STRICT_C))
        ZSSH_FAIL(ZSSH_E_STRICT_KEX_REQUIRED, "peer did not offer strict KEX");
    alg = kex_pick(pol, peer);
    if (alg == ZSSH_KEXALG_NONE)
        ZSSH_FAIL(ZSSH_E_KEX_NO_MATCH, "no common key exchange (require_pq=%d)",
                  (int)pol->require_pq);
    if (!suites_ok(peer))
        ZSSH_FAIL(ZSSH_E_KEX_NO_MATCH, "no common host key / cipher / compression");
    if (peer->first_kex_packet_follows)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "first_kex_packet_follows is not supported");
    out->alg = alg;
    out->strict = true;
    return ZSSH_E_NONE;
}

const char *zssh_kex_alg_name(enum zssh_kex_alg a)
{
    switch (a) {
    case ZSSH_KEXALG_MLKEM768X25519: return ZSSH_KEX_NAME_MLKEM;
    case ZSSH_KEXALG_CURVE25519:     return ZSSH_KEX_NAME_CURVE25519;
    case ZSSH_KEXALG_NONE:           break;
    }
    return "";
}

/* ---- key agreement helpers ------------------------------------------------ */

static bool alg_valid(enum zssh_kex_alg a)
{
    return a == ZSSH_KEXALG_MLKEM768X25519 || a == ZSSH_KEXALG_CURVE25519;
}

static enum zssh_error mlkem_err(enum zcl_mlkem_status s)
{
    return s == ZCL_MLKEM_ERR_RANDOM ? ZSSH_E_RANDOM : ZSSH_E_KEX_FAILED;
}

static size_t qc_expect(enum zssh_kex_alg a)
{
    return a == ZSSH_KEXALG_MLKEM768X25519 ? ZSSH_QC_MLKEM_LEN : ZSSH_X25519_LEN;
}

static size_t qs_expect(enum zssh_kex_alg a)
{
    return a == ZSSH_KEXALG_MLKEM768X25519 ? ZSSH_QS_MLKEM_LEN : ZSSH_X25519_LEN;
}

static enum zssh_error x25519_keygen(zssh_rand_fn rand, void *ctx,
                                     uint8_t sk[ZSSH_X25519_LEN],
                                     uint8_t pk[ZSSH_X25519_LEN])
{
    if (!rand(ctx, sk, ZSSH_X25519_LEN)) {
        memory_cleanse(sk, ZSSH_X25519_LEN);
        ZSSH_FAIL(ZSSH_E_RANDOM, "rng failed (x25519 key)");
    }
    if (!curve25519_scalarmult_base(pk, sk)) {
        memory_cleanse(sk, ZSSH_X25519_LEN);
        memory_cleanse(pk, ZSSH_X25519_LEN);
        ZSSH_FAIL(ZSSH_E_KEX_FAILED, "x25519 base multiplication failed");
    }
    return ZSSH_E_NONE;
}

/* K material: curve25519 keeps the raw X25519 output; the hybrid is
 * SHA-256(mlkem_ss || x25519_raw) (kexmlkem768x25519.c:151-156). */
static void set_shared(struct zssh_kex *k, const uint8_t x[ZSSH_X25519_LEN],
                       const uint8_t *mlkem_ss)
{
    if (!mlkem_ss) {
        memcpy(k->k, x, ZSSH_X25519_LEN);
    } else {
        struct sha256_ctx c;
        sha256_init(&c);
        sha256_write(&c, mlkem_ss, ZCL_MLKEM768_SHARED_SECRET_SIZE);
        sha256_write(&c, x, ZSSH_X25519_LEN);
        sha256_finalize(&c, k->k);
        memory_cleanse(&c, sizeof c);
    }
    k->k_len = ZSSH_HASH_LEN;
}

/* Zero everything a failed exchange may have produced. A session id that
 * existed before this call (a rekey) is kept. */
static void clear_result(struct zssh_kex *k, bool had_sid)
{
    memory_cleanse(k->k, sizeof k->k);
    k->k_len = 0;
    memory_cleanse(k->h, sizeof k->h);
    k->have_h = false;
    memory_cleanse(k->host_blob, sizeof k->host_blob);
    if (!had_sid) {
        memory_cleanse(k->session_id, sizeof k->session_id);
        k->have_session_id = false;
    }
}

/* ---- client step 1 -------------------------------------------------------- */

enum zssh_error zssh_kex_client_init(struct zssh_kex *k, zssh_rand_fn rand,
                                     void *rand_ctx, struct zssh_wr *w)
{
    uint8_t pk[ZSSH_X25519_LEN];
    enum zssh_error e;
    size_t off = 0, saved;
    if (!k || !rand || !w || k->role != ZSSH_ROLE_CLIENT || !alg_valid(k->neg.alg))
        ZSSH_FAIL(ZSSH_E_INTERNAL, "bad client_init arguments");
    k->q_c_len = 0;
    e = x25519_keygen(rand, rand_ctx, k->x25519_sk, pk);
    if (e != ZSSH_E_NONE) goto fail;
    if (k->neg.alg == ZSSH_KEXALG_MLKEM768X25519) {
        enum zcl_mlkem_status st = zcl_mlkem768_keygen(rand, rand_ctx, k->q_c, k->mlkem_dk);
        if (st != ZCL_MLKEM_OK) {
            ZSSH_LOG("mlkem keygen status %d", (int)st);
            e = mlkem_err(st);
            goto fail;
        }
        off = ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE;
    }
    memcpy(k->q_c + off, pk, ZSSH_X25519_LEN);
    k->q_c_len = off + ZSSH_X25519_LEN;
    /* Builder rule (all zssh layers): on failure the offset is rolled back,
     * the writer stays bad, and the returned error is the result; callers
     * check the enum, not zssh_wr_ok. */
    saved = w->off;
    zssh_wr_u8(w, ZSSH_MSG_KEX_INIT_30);
    zssh_wr_string(w, k->q_c, k->q_c_len);
    if (!zssh_wr_ok(w)) {
        w->off = saved;
        ZSSH_LOG("INIT does not fit");
        e = ZSSH_E_TOO_LARGE;
        goto fail;
    }
    return ZSSH_E_NONE;
fail:
    memory_cleanse(k->x25519_sk, sizeof k->x25519_sk);
    memory_cleanse(k->mlkem_dk, sizeof k->mlkem_dk);
    k->q_c_len = 0;
    memory_cleanse(pk, sizeof pk);
    return e;
}

/* ---- exchange hash -------------------------------------------------------- */

static void h_string(struct sha256_ctx *c, const uint8_t *p, size_t n)
{
    uint8_t l[4];
    zssh_put_u32(l, (uint32_t)n);
    sha256_write(c, l, 4);
    if (n > 0) sha256_write(c, p, n);
}

/* K exactly as it enters H and the key derivation: string for the hybrid,
 * mpint of the raw X25519 bytes (read big-endian, RFC 8731 3.1) otherwise. */
static size_t k_encode(const struct zssh_kex *k, uint8_t out[KEX_K_ENC_CAP])
{
    struct zssh_wr w;
    zssh_wr_init(&w, out, KEX_K_ENC_CAP);
    if (k->neg.alg == ZSSH_KEXALG_MLKEM768X25519) zssh_wr_string(&w, k->k, k->k_len);
    else zssh_wr_mpint(&w, k->k, k->k_len);
    return zssh_wr_ok(&w) ? w.off : 0;
}

static bool h_inputs_ok(const struct zssh_kex *k)
{
    return alg_valid(k->neg.alg)
        && k->v_c_len > 0 && k->v_c_len <= ZSSH_MAX_VERSION_LINE
        && k->v_s_len > 0 && k->v_s_len <= ZSSH_MAX_VERSION_LINE
        && k->i_c_len > 0 && k->i_c_len <= ZSSH_KEXINIT_MAX
        && k->i_s_len > 0 && k->i_s_len <= ZSSH_KEXINIT_MAX
        && k->q_c_len == qc_expect(k->neg.alg)
        && k->q_s_len == qs_expect(k->neg.alg)
        && k->k_len == ZSSH_HASH_LEN;
}

enum zssh_error zssh_kex_compute_h(struct zssh_kex *k)
{
    struct sha256_ctx c;
    uint8_t kenc[KEX_K_ENC_CAP];
    size_t kl;
    if (!k || !h_inputs_ok(k)) ZSSH_FAIL(ZSSH_E_INTERNAL, "H transcript incomplete");
    kl = k_encode(k, kenc);
    if (kl == 0) {
        memory_cleanse(kenc, sizeof kenc);
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "K encoding overflow");
    }
    sha256_init(&c);
    h_string(&c, k->v_c, k->v_c_len);
    h_string(&c, k->v_s, k->v_s_len);
    h_string(&c, k->i_c, k->i_c_len);
    h_string(&c, k->i_s, k->i_s_len);
    h_string(&c, k->host_blob, sizeof k->host_blob);
    h_string(&c, k->q_c, k->q_c_len);
    h_string(&c, k->q_s, k->q_s_len);
    sha256_write(&c, kenc, kl);
    sha256_finalize(&c, k->h);
    k->have_h = true;
    if (!k->have_session_id) {
        memcpy(k->session_id, k->h, ZSSH_SESSION_ID_LEN);
        k->have_session_id = true;
    }
    memory_cleanse(&c, sizeof c);
    memory_cleanse(kenc, sizeof kenc);
    return ZSSH_E_NONE;
}

/* ---- server reply --------------------------------------------------------- */

static enum zssh_error srv_parse_init(const struct zssh_kex *k, const uint8_t *p,
                                      size_t n, const uint8_t **qc)
{
    struct zssh_rd r;
    const uint8_t *s = nullptr;
    size_t sl = 0;
    if (!p || n == 0) ZSSH_FAIL(ZSSH_E_PROTOCOL, "empty INIT");
    zssh_rd_init(&r, p, n);
    if (zssh_rd_u8(&r) != ZSSH_MSG_KEX_INIT_30) ZSSH_FAIL(ZSSH_E_PROTOCOL, "not an INIT (30)");
    zssh_rd_string(&r, &s, &sl);
    if (!zssh_rd_done(&r)) ZSSH_FAIL(ZSSH_E_PROTOCOL, "INIT truncated or trailing bytes");
    if (sl != qc_expect(k->neg.alg))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "Q_C is %zu bytes, expected %zu", sl, qc_expect(k->neg.alg));
    *qc = s;
    return ZSSH_E_NONE;
}

/* Run the server half of the agreement: fills q_c, q_s, k, k_len. */
static enum zssh_error srv_agree(struct zssh_kex *k, const uint8_t *qc,
                                 zssh_rand_fn rand, void *ctx)
{
    uint8_t sk[ZSSH_X25519_LEN], pk[ZSSH_X25519_LEN], x[ZSSH_X25519_LEN];
    uint8_t ss[ZCL_MLKEM768_SHARED_SECRET_SIZE];
    bool hybrid = k->neg.alg == ZSSH_KEXALG_MLKEM768X25519;
    size_t off = hybrid ? ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE : 0;
    enum zssh_error e = x25519_keygen(rand, ctx, sk, pk);
    if (e != ZSSH_E_NONE) goto out;
    if (hybrid) {
        enum zcl_mlkem_status st = zcl_mlkem768_encaps(rand, ctx, qc, off, k->q_s, ss);
        if (st != ZCL_MLKEM_OK) {
            ZSSH_LOG("mlkem encaps status %d", (int)st);
            e = mlkem_err(st);
            goto out;
        }
    }
    if (!x25519_safe(x, sk, qc + off)) {
        ZSSH_LOG("x25519 shared secret rejected (all-zero)");
        e = ZSSH_E_KEX_FAILED;
        goto out;
    }
    off = hybrid ? ZCL_MLKEM768_CIPHERTEXT_SIZE : 0;
    memcpy(k->q_s + off, pk, ZSSH_X25519_LEN);
    k->q_s_len = off + ZSSH_X25519_LEN;
    memcpy(k->q_c, qc, qc_expect(k->neg.alg));
    k->q_c_len = qc_expect(k->neg.alg);
    set_shared(k, x, hybrid ? ss : nullptr);
out:
    memory_cleanse(sk, sizeof sk);
    memory_cleanse(x, sizeof x);
    memory_cleanse(ss, sizeof ss);
    if (e != ZSSH_E_NONE) { k->q_s_len = 0; k->q_c_len = 0; }
    return e;
}

static enum zssh_error srv_emit(struct zssh_kex *k, const uint8_t *host_pk,
                                const uint8_t *host_sk, struct zssh_wr *w)
{
    uint8_t sig[ZSSH_ED25519_SIGBLOB_LEN];
    size_t saved = w->off;
    enum zssh_error e;
    zssh_auth_blob_encode(host_pk, k->host_blob);
    e = zssh_kex_compute_h(k);
    if (e != ZSSH_E_NONE) return e;
    e = zssh_auth_sign(host_sk, host_pk, k->h, ZSSH_HASH_LEN, sig);
    if (e != ZSSH_E_NONE) return e;
    zssh_wr_u8(w, ZSSH_MSG_KEX_REPLY_31);
    zssh_wr_string(w, k->host_blob, sizeof k->host_blob);
    zssh_wr_string(w, k->q_s, k->q_s_len);
    zssh_wr_string(w, sig, sizeof sig);
    if (!zssh_wr_ok(w)) {
        w->off = saved;
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "REPLY does not fit");
    }
    return ZSSH_E_NONE;
}

enum zssh_error zssh_kex_server_reply(struct zssh_kex *k,
        const uint8_t *init_payload, size_t init_len,
        const uint8_t host_pk[ZSSH_ED25519_PK_LEN],
        const uint8_t host_sk[ZSSH_ED25519_SEED_LEN],
        zssh_rand_fn rand, void *rand_ctx, struct zssh_wr *w)
{
    const uint8_t *qc = nullptr;
    enum zssh_error e;
    bool had_sid;
    if (!k || !host_pk || !host_sk || !rand || !w || k->role != ZSSH_ROLE_SERVER
        || !alg_valid(k->neg.alg))
        ZSSH_FAIL(ZSSH_E_INTERNAL, "bad server_reply arguments");
    had_sid = k->have_session_id;
    e = srv_parse_init(k, init_payload, init_len, &qc);
    if (e == ZSSH_E_NONE) e = srv_agree(k, qc, rand, rand_ctx);
    if (e == ZSSH_E_NONE) e = srv_emit(k, host_pk, host_sk, w);
    if (e != ZSSH_E_NONE) clear_result(k, had_sid);
    return e;
}

/* ---- client step 2 -------------------------------------------------------- */

struct reply_view {
    const uint8_t *ks, *qs, *sig;
    size_t ks_len, qs_len, sig_len;
};

static enum zssh_error cli_parse_reply(const uint8_t *p, size_t n, struct reply_view *v)
{
    struct zssh_rd r;
    memset(v, 0, sizeof *v);
    if (!p || n == 0) ZSSH_FAIL(ZSSH_E_PROTOCOL, "empty REPLY");
    zssh_rd_init(&r, p, n);
    if (zssh_rd_u8(&r) != ZSSH_MSG_KEX_REPLY_31) ZSSH_FAIL(ZSSH_E_PROTOCOL, "not a REPLY (31)");
    zssh_rd_string(&r, &v->ks, &v->ks_len);
    zssh_rd_string(&r, &v->qs, &v->qs_len);
    zssh_rd_string(&r, &v->sig, &v->sig_len);
    if (!zssh_rd_done(&r)) ZSSH_FAIL(ZSSH_E_PROTOCOL, "REPLY truncated or trailing bytes");
    return ZSSH_E_NONE;
}

/* Steps (1) and (2): K_S parses and is byte-equal to the pinned blob. */
static enum zssh_error cli_check_hostkey(struct zssh_kex *k, const struct reply_view *v,
                                         const uint8_t pinned_pk[ZSSH_ED25519_PK_LEN])
{
    uint8_t pk[ZSSH_ED25519_PK_LEN], pinned[ZSSH_ED25519_BLOB_LEN];
    enum zssh_error e = zssh_auth_blob_parse(v->ks, v->ks_len, pk);
    if (e != ZSSH_E_NONE) return e;
    zssh_auth_blob_encode(pinned_pk, pinned);
    if (v->ks_len != sizeof pinned || !zssh_ct_eq(v->ks, pinned, sizeof pinned))
        ZSSH_FAIL(ZSSH_E_HOST_KEY_MISMATCH, "server host key is not the pinned key");
    memcpy(k->host_blob, v->ks, sizeof k->host_blob);
    return ZSSH_E_NONE;
}

/* Step (3): the client half of the agreement. */
static enum zssh_error cli_agree(struct zssh_kex *k, const uint8_t *qs, size_t qs_len)
{
    uint8_t x[ZSSH_X25519_LEN], ss[ZCL_MLKEM768_SHARED_SECRET_SIZE];
    bool hybrid = k->neg.alg == ZSSH_KEXALG_MLKEM768X25519;
    size_t off = hybrid ? ZCL_MLKEM768_CIPHERTEXT_SIZE : 0;
    enum zssh_error e = ZSSH_E_NONE;
    if (qs_len != qs_expect(k->neg.alg))
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "Q_S is %zu bytes, expected %zu", qs_len,
                  qs_expect(k->neg.alg));
    if (hybrid) {
        enum zcl_mlkem_status st = zcl_mlkem768_decaps(k->mlkem_dk, sizeof k->mlkem_dk,
                                                       qs, off, ss);
        if (st != ZCL_MLKEM_OK) {
            ZSSH_LOG("mlkem decaps status %d", (int)st);
            e = ZSSH_E_KEX_FAILED;
            goto out;
        }
    }
    if (!x25519_safe(x, k->x25519_sk, qs + off)) {
        ZSSH_LOG("x25519 shared secret rejected (all-zero)");
        e = ZSSH_E_KEX_FAILED;
        goto out;
    }
    memcpy(k->q_s, qs, qs_len);
    k->q_s_len = qs_len;
    set_shared(k, x, hybrid ? ss : nullptr);
out:
    memory_cleanse(x, sizeof x);
    memory_cleanse(ss, sizeof ss);
    return e;
}

static enum zssh_error cli_run(struct zssh_kex *k, const uint8_t *reply, size_t len,
                               const uint8_t pinned_pk[ZSSH_ED25519_PK_LEN])
{
    struct reply_view v;
    enum zssh_error e = cli_parse_reply(reply, len, &v);
    if (e != ZSSH_E_NONE) return e;
    e = cli_check_hostkey(k, &v, pinned_pk);
    if (e != ZSSH_E_NONE) return e;
    e = cli_agree(k, v.qs, v.qs_len);
    if (e != ZSSH_E_NONE) return e;
    e = zssh_kex_compute_h(k);
    if (e != ZSSH_E_NONE) return e;
    return zssh_auth_verify(pinned_pk, k->h, ZSSH_HASH_LEN, v.sig, v.sig_len, true);
}

enum zssh_error zssh_kex_client_finish(struct zssh_kex *k,
        const uint8_t *reply_payload, size_t reply_len,
        const uint8_t pinned_host_pk[ZSSH_ED25519_PK_LEN])
{
    bool had_sid;
    enum zssh_error e;
    if (!k || !pinned_host_pk || k->role != ZSSH_ROLE_CLIENT || !alg_valid(k->neg.alg))
        ZSSH_FAIL(ZSSH_E_INTERNAL, "bad client_finish arguments");
    had_sid = k->have_session_id;
    e = cli_run(k, reply_payload, reply_len, pinned_host_pk);
    /* The ephemeral secrets are single-use: once the agreement ran (or failed)
     * they are never needed again, so wipe them on EVERY path, success
     * included. K and H are NOT wiped here on success: CONN still derives the
     * keys from them and remains responsible for calling zssh_kex_wipe
     * (K, and any ephemerals) afterwards. The server side keeps its
     * ephemerals only in locals of srv_agree, wiped there on every exit. */
    memory_cleanse(k->x25519_sk, sizeof k->x25519_sk);
    memory_cleanse(k->mlkem_dk, sizeof k->mlkem_dk);
    if (e != ZSSH_E_NONE) {
        clear_result(k, had_sid);
        k->q_s_len = 0;
    }
    return e;
}

/* ---- key derivation (RFC 4253 7.2) ----------------------------------------- */

static void derive_one(const struct zssh_kex *k, const uint8_t *kenc, size_t kl,
                       uint8_t letter, uint8_t out[ZSSH_CIPHER_KEY_LEN])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, kenc, kl);
    sha256_write(&c, k->h, ZSSH_HASH_LEN);
    sha256_write(&c, &letter, 1);
    sha256_write(&c, k->session_id, ZSSH_SESSION_ID_LEN);
    sha256_finalize(&c, out);
    sha256_init(&c);
    sha256_write(&c, kenc, kl);
    sha256_write(&c, k->h, ZSSH_HASH_LEN);
    sha256_write(&c, out, ZSSH_HASH_LEN);
    sha256_finalize(&c, out + ZSSH_HASH_LEN);
    memory_cleanse(&c, sizeof c);
}

enum zssh_error zssh_kex_derive_keys(const struct zssh_kex *k, struct zssh_keys *out)
{
    uint8_t kenc[KEX_K_ENC_CAP];
    size_t kl;
    if (!out) ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL out");
    memory_cleanse(out, sizeof *out);
    if (!k || !alg_valid(k->neg.alg) || !k->have_h || !k->have_session_id
        || k->k_len != ZSSH_HASH_LEN)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "no exchange result to derive from");
    kl = k_encode(k, kenc);
    if (kl == 0) {
        memory_cleanse(kenc, sizeof kenc);
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "K encoding overflow");
    }
    derive_one(k, kenc, kl, 'C', out->c2s);
    derive_one(k, kenc, kl, 'D', out->s2c);
    memory_cleanse(kenc, sizeof kenc);
    return ZSSH_E_NONE;
}

/* ---- message order and wipe ------------------------------------------------ */

/* Defined message numbers only: transport 2-7, the rekey-refusal KEXINIT (20),
 * userauth 50-53 and 60, global requests 80-82 and channel messages 90-100.
 * Undefined numbers (8-19, 22-29, 83-89, 101+, ...) are refused here; the
 * header does not widen this set. */
static bool kex_done_msg_ok(uint8_t msg)
{
    return (msg >= ZSSH_MSG_IGNORE && msg <= ZSSH_MSG_EXT_INFO)
        || msg == ZSSH_MSG_KEXINIT
        || (msg >= ZSSH_MSG_USERAUTH_REQUEST && msg <= ZSSH_MSG_USERAUTH_BANNER)
        || msg == ZSSH_MSG_USERAUTH_PK_OK
        || (msg >= ZSSH_MSG_GLOBAL_REQUEST && msg <= ZSSH_MSG_REQUEST_FAILURE)
        || (msg >= ZSSH_MSG_CHANNEL_OPEN && msg <= ZSSH_MSG_CHANNEL_FAILURE);
}

bool zssh_kex_msg_allowed(uint8_t msg, enum zssh_kex_phase phase)
{
    if (msg == ZSSH_MSG_DISCONNECT) return true;
    switch (phase) {
    case ZSSH_KP_WAIT_KEXINIT: return msg == ZSSH_MSG_KEXINIT;
    case ZSSH_KP_WAIT_INIT:    return msg == ZSSH_MSG_KEX_INIT_30;
    case ZSSH_KP_WAIT_REPLY:   return msg == ZSSH_MSG_KEX_REPLY_31;
    case ZSSH_KP_WAIT_NEWKEYS: return msg == ZSSH_MSG_NEWKEYS;
    case ZSSH_KP_DONE:        return kex_done_msg_ok(msg);
    }
    return false;
}

void zssh_kex_wipe(struct zssh_kex *k)
{
    if (!k) return;
    memory_cleanse(k->x25519_sk, sizeof k->x25519_sk);
    memory_cleanse(k->mlkem_dk, sizeof k->mlkem_dk);
    memory_cleanse(k->k, sizeof k->k);
    k->k_len = 0;
}
