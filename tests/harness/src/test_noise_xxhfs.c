/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256 (noise/noise_handshake.h):
 * the XX pattern with the hybrid-forward-secrecy modifier,
 *
 *     -> e, e1
 *     <- e, ee, ekem1, s, es
 *     -> s, se
 *
 * Covered: a full handshake with default randomness (message sizes 1216, 1200
 * and 64; matching transport keys; records in both directions), a known-answer
 * transcript, single-bit tampering of every message with the read at which it
 * is detected, truncation and trailing bytes, implicit rejection of a wrong
 * KEM ciphertext, transcript binding to the KEM randomness, rejection of an
 * invalid encapsulation key, wiping of the KEM state, an independent
 * recomputation of the chaining key and transport keys, role and order errors,
 * and terminal failure state.
 *
 * The known-answer values are self-generated: the Noise hybrid-forward-secrecy
 * draft publishes no vectors for ML-KEM-768. They pin this implementation
 * against regression; ML-KEM-768 itself is covered by the FIPS 203 vectors in
 * the mlkem group.
 *
 * Known-answer inputs (all messages carry empty payloads):
 *   - prologue: the 5 bytes 78 78 68 66 73 ("xxhfs"), mixed into h before the
 *     first message.
 *   - 32-byte scalars are scalar(seed)[i] = (seed + 7*i + 1) mod 256 for
 *     i = 0..31. Static keys: initiator seed 0x51, responder seed 0x99.
 *     Ephemeral keys: initiator seed 0x21, responder seed 0x42. X25519 clamps
 *     the scalars; public keys are X25519(scalar, 9).
 *   - ML-KEM-768 randomness: a party with seed s answers its k-th request
 *     (k = 0, 1, ...) for n bytes with byte[i] = (s*29 + k*7 + 3*i + 1) mod 256
 *     for i = 0..n-1. The initiator (seed 0x11) is asked once, for the 64-byte
 *     key-generation seed d || z; the responder (seed 0x22) once, for the
 *     32-byte encapsulation message m.
 *   - pinned values: SHA-256 of msg1, msg2 and msg3 as transmitted, and the
 *     final handshake hash h.
 *
 * Each case lives in its own function because TEST_END defines one fixed label
 * per function. Failure positions are read from the transcript hash: a failed
 * read leaves h at the value reached before the field that failed. */

#include "test/test_core.h"
#include "base/hex.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/hmac_sha256.h"
#include "crypto/sha256.h"
#include "mlkem/mlkem.h"
#include "noise/noise_handshake.h"
#include "noise/session_transport.h"

#include <string.h>

enum {
    MSG1_LEN = 32 + NOISE_MLKEM_EK_LEN,
    MSG2_LEN = 32 + NOISE_MLKEM_CT_LEN + 16 + 32 + 16 + 16,
    MSG3_LEN = 32 + 16 + 16,
    MSG2_CT_OFF = 32,
    MSG2_S_OFF = MSG2_CT_OFF + NOISE_MLKEM_CT_LEN + 16,
};

static const uint8_t k_prologue[] = { 'x', 'x', 'h', 'f', 's' };

static void mk_scalar(uint8_t out[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(seed + i * 7 + 1);
}

/* Deterministic ML-KEM randomness: every request is filled from (seed, call). */
struct kem_replay {
    uint8_t seed;
    uint32_t calls;
};

static bool replay_random(void *context, uint8_t *out, size_t len)
{
    struct kem_replay *r = context;
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)(r->seed * 29u + r->calls * 7u + (uint32_t)i * 3u + 1u);
    r->calls++;
    return true;
}

static bool all_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= b[i];
    return acc == 0;
}

/* h' = SHA-256(h || data): the MixHash step. */
static void mixh(uint8_t h[32], const uint8_t *data, size_t len)
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, h, 32);
    sha256_write(&c, data, len);
    sha256_finalize(&c, h);
}

struct run {
    struct noise_handshake init, resp;
    uint8_t m[3][NOISE_MAX_MESSAGE];
    size_t len[3];
    uint8_t h_before[3][32]; /* reader's h before processing message i */
    uint8_t h_fail[32];      /* reader's h at the failure */
    size_t plen1;            /* payload length the responder read from msg1 */
    struct kem_replay ki, kr;
};

static bool run_setup(struct run *r, bool deterministic, uint8_t seed_i, uint8_t seed_r)
{
    uint8_t i_priv[32], r_priv[32];
    mk_scalar(i_priv, 0x51);
    mk_scalar(r_priv, 0x99);
    memset(r->m, 0, sizeof(r->m));
    if (!noise_hs_init(&r->init, noise_pattern_xxhfs(), true, k_prologue,
                       sizeof(k_prologue), i_priv, NULL)) return false;
    if (!noise_hs_init(&r->resp, noise_pattern_xxhfs(), false, k_prologue,
                       sizeof(k_prologue), r_priv, NULL)) return false;
    if (!deterministic) return true;
    uint8_t ei[32], er[32];
    mk_scalar(ei, 0x21);
    mk_scalar(er, 0x42);
    noise_hs_set_ephemeral(&r->init, ei);
    noise_hs_set_ephemeral(&r->resp, er);
    r->ki = (struct kem_replay){ .seed = seed_i };
    r->kr = (struct kem_replay){ .seed = seed_r };
    noise_hs_set_kem_random(&r->init, replay_random, &r->ki);
    noise_hs_set_kem_random(&r->resp, replay_random, &r->kr);
    return true;
}

enum mut_kind { MUT_NONE, MUT_FLIP, MUT_SET, MUT_TRUNC, MUT_EXTRA };

struct mut {
    int msg;           /* 0..2 */
    enum mut_kind kind;
    size_t off;
    size_t val;     /* byte value, or the number of bytes MUT_TRUNC removes */
};

static void apply_mut(uint8_t *buf, size_t *len, const struct mut *mu)
{
    switch (mu->kind) {
    case MUT_FLIP:  buf[mu->off] ^= (uint8_t)mu->val; break;
    case MUT_SET:   buf[mu->off] = (uint8_t)mu->val; break;
    case MUT_TRUNC: *len -= mu->val; break;
    case MUT_EXTRA: buf[(*len)++] = 0xA5; break;
    case MUT_NONE:  break;
    }
}

/* Writes and reads the three messages in order, applying `mu` to the bytes the
 * reader sees. Returns 0 when every read succeeds, else the 1-based index of
 * the first failing read; -1 if a write fails. */
static int play(struct run *r, const struct mut *mu)
{
    struct noise_handshake *wr[3] = { &r->init, &r->resp, &r->init };
    struct noise_handshake *rd[3] = { &r->resp, &r->init, &r->resp };
    for (int i = 0; i < 3; i++) {
        uint8_t buf[NOISE_MAX_MESSAGE], pout[NOISE_MAX_MESSAGE];
        if (!noise_hs_write_message(wr[i], NULL, 0, r->m[i], &r->len[i])) return -1;
        size_t blen = r->len[i];
        memcpy(buf, r->m[i], blen);
        if (mu && mu->msg == i) apply_mut(buf, &blen, mu);
        (void)noise_hs_transcript_hash(rd[i], r->h_before[i]);
        size_t plen = 0;
        if (!noise_hs_read_message(rd[i], buf, blen, pout, &plen)) {
            (void)noise_hs_transcript_hash(rd[i], r->h_fail);
            return i + 1;
        }
        if (i == 0) r->plen1 = plen;
    }
    return 0;
}

static void sha256_of(const uint8_t *d, size_t n, uint8_t out[32])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, d, n);
    sha256_finalize(&c, out);
}

/* Fresh deterministic run, played with `mu`; returns play()'s verdict. */
static int play_det(struct run *r, const struct mut *mu)
{
    if (!run_setup(r, true, 0x11, 0x22)) return -1;
    return play(r, mu);
}

/* ── (a) full handshake, default randomness ─────────────────────────────── */

static int case_full_handshake(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: default-randomness handshake, sizes, keys, records") {
        static struct run r;
        ASSERT(run_setup(&r, false, 0, 0));
        ASSERT_EQ(play(&r, NULL), 0);
        ASSERT_EQ(r.len[0], (size_t)1216);
        ASSERT_EQ(r.len[1], (size_t)1200);
        ASSERT_EQ(r.len[2], (size_t)64);
        ASSERT_EQ((size_t)MSG1_LEN, (size_t)1216);
        ASSERT_EQ((size_t)MSG2_LEN, (size_t)1200);
        ASSERT_EQ((size_t)MSG3_LEN, (size_t)64);
        ASSERT(noise_hs_done(&r.init) && noise_hs_done(&r.resp));

        uint8_t hi[32], hr[32];
        ASSERT(noise_hs_transcript_hash(&r.init, hi));
        ASSERT(noise_hs_transcript_hash(&r.resp, hr));
        ASSERT(memcmp(hi, hr, 32) == 0);

        uint8_t i_send[32], i_recv[32], r_send[32], r_recv[32];
        ASSERT(noise_hs_split(&r.init, i_send, i_recv));
        ASSERT(noise_hs_split(&r.resp, r_send, r_recv));
        ASSERT(memcmp(i_send, r_recv, 32) == 0);
        ASSERT(memcmp(i_recv, r_send, 32) == 0);
        ASSERT(memcmp(i_send, i_recv, 32) != 0);

        uint8_t i_pub[32], r_pub[32], got[32], priv[32];
        mk_scalar(priv, 0x51);
        ASSERT(curve25519_scalarmult_base(i_pub, priv));
        mk_scalar(priv, 0x99);
        ASSERT(curve25519_scalarmult_base(r_pub, priv));
        ASSERT(noise_hs_remote_static(&r.init, got));
        ASSERT(memcmp(got, r_pub, 32) == 0);
        ASSERT(noise_hs_remote_static(&r.resp, got));
        ASSERT(memcmp(got, i_pub, 32) == 0);

        struct session_transport ts_i, ts_r;
        session_transport_init(&ts_i, i_send, i_recv);
        session_transport_init(&ts_r, r_send, r_recv);
        const uint8_t ping[] = "initiator-to-responder";
        const uint8_t pong[] = "responder-to-initiator";
        uint8_t frame[SESSION_FRAME_MAX_WIRE], out[SESSION_MAX_PAYLOAD];
        size_t flen = 0, olen = 0;
        enum session_channel ch;
        ASSERT(session_transport_encrypt(&ts_i, SESSION_CH_DATA, ping, sizeof(ping),
                                         frame, &flen));
        ASSERT(session_transport_decrypt(&ts_r, &ch, frame, flen, out, &olen));
        ASSERT(olen == sizeof(ping) && memcmp(out, ping, olen) == 0);
        ASSERT(session_transport_encrypt(&ts_r, SESSION_CH_DATA, pong, sizeof(pong),
                                         frame, &flen));
        ASSERT(session_transport_decrypt(&ts_i, &ch, frame, flen, out, &olen));
        ASSERT(olen == sizeof(pong) && memcmp(out, pong, olen) == 0);

        /* An independent default-randomness run derives different keys. */
        static struct run r2;
        uint8_t j_send[32], j_recv[32];
        ASSERT(run_setup(&r2, false, 0, 0));
        ASSERT_EQ(play(&r2, NULL), 0);
        ASSERT(noise_hs_split(&r2.init, j_send, j_recv));
        ASSERT(memcmp(j_send, i_send, 32) != 0);
    } TEST_END
    return failures;
}

/* ── (b) known answer ───────────────────────────────────────────────────── */

#define KAT_MSG1_SHA256 "bedca0c3d64c0845df117691d809b8813d19e7e6d7e4cf4f74e3c3dc5552a2cf"
#define KAT_MSG2_SHA256 "be9ee64c2636c3a2d96ad0a60c75eee4a19515d4747bd74ba1afdb942b3464d7"
#define KAT_MSG3_SHA256 "9e5d3a48a4a6477b84f09870381b26c4c178502db353997c3ba98e6d6ef04f4e"
#define KAT_HASH        "baf3619ae8b98b0c6a3362e921ebfc65964dd4e52cd3296b063cb57fcebe99b1"

static int case_known_answer(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: known-answer transcript") {
        static struct run r;
        ASSERT_EQ(play_det(&r, NULL), 0);
        uint8_t d[32], h[32];
        char hex[65];
        sha256_of(r.m[0], r.len[0], d);
        zcl_hex_encode(d, 32, hex); hex[64] = 0;
        ASSERT_STR_EQ(hex, KAT_MSG1_SHA256);
        sha256_of(r.m[1], r.len[1], d);
        zcl_hex_encode(d, 32, hex); hex[64] = 0;
        ASSERT_STR_EQ(hex, KAT_MSG2_SHA256);
        sha256_of(r.m[2], r.len[2], d);
        zcl_hex_encode(d, 32, hex); hex[64] = 0;
        ASSERT_STR_EQ(hex, KAT_MSG3_SHA256);
        ASSERT(noise_hs_transcript_hash(&r.init, h));
        zcl_hex_encode(h, 32, hex); hex[64] = 0;
        ASSERT_STR_EQ(hex, KAT_HASH);
    } TEST_END
    return failures;
}

/* ── (c) single-bit tampering ───────────────────────────────────────────── */

static int case_bit_flips(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: one-bit flips are detected at the expected read") {
        static struct run r;
        uint8_t h[32];

        /* msg1, inside the rho seed at the end of the encapsulation key: the key
         * stays valid, the responder accepts it and encapsulates to the wrong key
         * context; the initiator rejects msg2 at the ekem1 field (the first
         * authenticated field), before any decapsulation. */
        struct mut m1 = { .msg = 0, .kind = MUT_FLIP, .off = 32 + 1152 + 3, .val = 0x01 };
        ASSERT_EQ(play_det(&r, &m1), 2);
        memcpy(h, r.h_before[1], 32);
        mixh(h, r.m[1], 32);
        ASSERT(memcmp(h, r.h_fail, 32) == 0);

        /* msg1, inside the ephemeral public key: DH keys disagree, so the
         * ekem1 field fails to authenticate as well. */
        struct mut m1e = { .msg = 0, .kind = MUT_FLIP, .off = 5, .val = 0x01 };
        ASSERT_EQ(play_det(&r, &m1e), 2);

        /* msg2, inside the KEM ciphertext field: fails at ekem1, which is never
         * mixed into h. */
        struct mut m2c = { .msg = 1, .kind = MUT_FLIP, .off = MSG2_CT_OFF + 100, .val = 0x01 };
        ASSERT_EQ(play_det(&r, &m2c), 2);
        memcpy(h, r.h_before[1], 32);
        mixh(h, r.m[1], 32);
        ASSERT(memcmp(h, r.h_fail, 32) == 0);

        /* msg2, inside the encrypted static key: ekem1 is accepted and mixed,
         * the s field fails. */
        struct mut m2s = { .msg = 1, .kind = MUT_FLIP, .off = MSG2_S_OFF + 5, .val = 0x01 };
        ASSERT_EQ(play_det(&r, &m2s), 2);
        memcpy(h, r.h_before[1], 32);
        mixh(h, r.m[1], 32);
        mixh(h, r.m[1] + MSG2_CT_OFF, NOISE_MLKEM_CT_LEN + 16);
        ASSERT(memcmp(h, r.h_fail, 32) == 0);

        /* msg2, payload tag. */
        struct mut m2t = { .msg = 1, .kind = MUT_FLIP, .off = MSG2_LEN - 1, .val = 0x01 };
        ASSERT_EQ(play_det(&r, &m2t), 2);

        /* msg3, static field and payload tag: the first authenticated field
         * fails with h unchanged since the start of the read. */
        struct mut m3s = { .msg = 2, .kind = MUT_FLIP, .off = 5, .val = 0x01 };
        ASSERT_EQ(play_det(&r, &m3s), 3);
        ASSERT(memcmp(r.h_before[2], r.h_fail, 32) == 0);
        struct mut m3t = { .msg = 2, .kind = MUT_FLIP, .off = MSG3_LEN - 1, .val = 0x01 };
        ASSERT_EQ(play_det(&r, &m3t), 3);
    } TEST_END
    return failures;
}

/* ── (d) truncation and trailing bytes ──────────────────────────────────── */

static int case_length_changes(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: truncation fails; trailing byte is payload or fails") {
        static struct run r;
        for (int i = 0; i < 3; i++) {
            struct mut t = { .msg = i, .kind = MUT_TRUNC, .val = 1 };
            ASSERT_EQ(play_det(&r, &t), i + 1);
        }
        /* Cut inside the e1 and ekem1 fields: the read stops there, with only
         * the ephemeral key mixed into h. */
        uint8_t h[32];
        struct mut c0 = { .msg = 0, .kind = MUT_TRUNC, .val = MSG1_LEN - 132 };
        ASSERT_EQ(play_det(&r, &c0), 1);
        memcpy(h, r.h_before[0], 32);
        mixh(h, r.m[0], 32);
        ASSERT(memcmp(h, r.h_fail, 32) == 0);
        struct mut c1 = { .msg = 1, .kind = MUT_TRUNC, .val = MSG2_LEN - 132 };
        ASSERT_EQ(play_det(&r, &c1), 2);
        memcpy(h, r.h_before[1], 32);
        mixh(h, r.m[1], 32);
        ASSERT(memcmp(h, r.h_fail, 32) == 0);
        /* msg1 has no key yet, so a trailing byte is an unauthenticated payload
         * that the responder reads and hashes; the initiator's transcript then
         * differs and msg2 fails. */
        struct mut e0 = { .msg = 0, .kind = MUT_EXTRA };
        ASSERT_EQ(play_det(&r, &e0), 2);
        ASSERT_EQ(r.plen1, (size_t)1);
        /* Keyed messages authenticate their tail: a trailing byte breaks the tag. */
        for (int i = 1; i < 3; i++) {
            struct mut e = { .msg = i, .kind = MUT_EXTRA };
            ASSERT_EQ(play_det(&r, &e), i + 1);
        }
    } TEST_END
    return failures;
}

/* ── (e) wrong ciphertext: implicit rejection ───────────────────────────── */

static int case_implicit_rejection(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: wrong ciphertext decapsulates, fails at the next field") {
        static struct run r;
        uint8_t h[32];
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        noise_hs_test_corrupt_kem_ciphertext(&r.resp);
        ASSERT_EQ(play(&r, NULL), 2);
        ASSERT_EQ(r.len[1], (size_t)MSG2_LEN);
        /* ekem1 authenticated and was mixed into h; decapsulation did not fail;
         * the s field is the first one sealed under the diverged key. */
        memcpy(h, r.h_before[1], 32);
        mixh(h, r.m[1], 32);
        mixh(h, r.m[1] + MSG2_CT_OFF, NOISE_MLKEM_CT_LEN + 16);
        ASSERT(memcmp(h, r.h_fail, 32) == 0);
        ASSERT_EQ(r.init.msg_index, 1);

        /* The same randomness without the hook completes. */
        ASSERT_EQ(play_det(&r, NULL), 0);
    } TEST_END
    return failures;
}

/* ── (f) transcript binding ─────────────────────────────────────────────── */

static int case_transcript_binding(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: KEM randomness changes the transcript and keys") {
        static struct run a, b, c;
        uint8_t ha[32], hb[32], hc[32], ka[32], kb[32], kc[32], tmp[32];
        ASSERT(run_setup(&a, true, 0x11, 0x22));
        ASSERT_EQ(play(&a, NULL), 0);
        ASSERT(run_setup(&b, true, 0x11, 0x23)); /* encapsulation differs */
        ASSERT_EQ(play(&b, NULL), 0);
        ASSERT(run_setup(&c, true, 0x12, 0x22)); /* key generation differs */
        ASSERT_EQ(play(&c, NULL), 0);
        ASSERT(noise_hs_transcript_hash(&a.init, ha));
        ASSERT(noise_hs_transcript_hash(&b.init, hb));
        ASSERT(noise_hs_transcript_hash(&c.init, hc));
        ASSERT(memcmp(ha, hb, 32) != 0);
        ASSERT(memcmp(ha, hc, 32) != 0);
        ASSERT(memcmp(hb, hc, 32) != 0);
        ASSERT(noise_hs_split(&a.init, ka, tmp));
        ASSERT(noise_hs_split(&b.init, kb, tmp));
        ASSERT(noise_hs_split(&c.init, kc, tmp));
        ASSERT(memcmp(ka, kb, 32) != 0);
        ASSERT(memcmp(ka, kc, 32) != 0);
        ASSERT(memcmp(kb, kc, 32) != 0);
    } TEST_END
    return failures;
}

/* ── (g) invalid encapsulation key ──────────────────────────────────────── */

static int case_invalid_encapsulation_key(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: responder rejects an out-of-range encapsulation key") {
        static struct run r;
        /* Byte 1 of the key = 0xFF makes the first 12-bit coefficient >= 3840 > q. */
        struct mut bad = { .msg = 0, .kind = MUT_SET, .off = 32 + 1, .val = 0xFF };
        ASSERT_EQ(play_det(&r, &bad), 1);
        uint8_t key[NOISE_MLKEM_EK_LEN];
        memcpy(key, r.m[0] + 32, sizeof(key));
        ASSERT(zcl_mlkem768_check_encapsulation_key(key, sizeof(key)) == ZCL_MLKEM_OK);
        key[1] = 0xFF;
        ASSERT(zcl_mlkem768_check_encapsulation_key(key, sizeof(key)) != ZCL_MLKEM_OK);
        /* The responder consumed the key into h before the check, then wiped. */
        ASSERT_EQ(r.resp.msg_index, 0);
        ASSERT(!r.resp.have_kem);
        ASSERT(all_zero(&r.resp.kem, sizeof(r.resp.kem)));
    } TEST_END
    return failures;
}

/* ── (h) wiping ─────────────────────────────────────────────────────────── */

static int case_wipe(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: KEM state is wiped at decapsulation, split, cleanse, failure") {
        static struct run r;
        uint8_t k1[32], k2[32];
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        uint8_t pout[NOISE_MAX_MESSAGE];
        size_t plen = 0;

        ASSERT(noise_hs_write_message(&r.init, NULL, 0, r.m[0], &r.len[0]));
        ASSERT(!all_zero(&r.init.kem, sizeof(r.init.kem)));
        ASSERT(noise_hs_read_message(&r.resp, r.m[0], r.len[0], pout, &plen));
        ASSERT(!all_zero(r.resp.kem.remote_ek, NOISE_MLKEM_EK_LEN));
        ASSERT(noise_hs_write_message(&r.resp, NULL, 0, r.m[1], &r.len[1]));
        ASSERT(noise_hs_read_message(&r.init, r.m[1], r.len[1], pout, &plen));
        /* The decapsulation key is gone right after decapsulation. */
        ASSERT(all_zero(r.init.kem.dk, sizeof(r.init.kem.dk)));
        ASSERT(!r.init.have_kem);
        ASSERT(noise_hs_write_message(&r.init, NULL, 0, r.m[2], &r.len[2]));
        ASSERT(noise_hs_read_message(&r.resp, r.m[2], r.len[2], pout, &plen));

        ASSERT(!all_zero(&r.resp.kem, sizeof(r.resp.kem)));
        ASSERT(all_zero(&r.init.kem, sizeof(r.init.kem))); /* dk already consumed */
        ASSERT(noise_hs_split(&r.init, k1, k2));
        ASSERT(noise_hs_split(&r.resp, k1, k2));
        ASSERT(all_zero(&r.init.kem, sizeof(r.init.kem)));
        ASSERT(all_zero(&r.resp.kem, sizeof(r.resp.kem)));

        /* Cleanse of an aborted handshake. */
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        ASSERT(noise_hs_write_message(&r.init, NULL, 0, r.m[0], &r.len[0]));
        ASSERT(!all_zero(&r.init.kem, sizeof(r.init.kem)));
        noise_hs_cleanse(&r.init);
        ASSERT(all_zero(&r.init.kem, sizeof(r.init.kem)));
        ASSERT(noise_hs_read_message(&r.resp, r.m[0], r.len[0], pout, &plen));
        ASSERT(!all_zero(&r.resp.kem, sizeof(r.resp.kem)));
        noise_hs_cleanse(&r.resp);
        ASSERT(all_zero(&r.resp.kem, sizeof(r.resp.kem)));

        /* A failed read wipes the initiator's key pair. */
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        struct mut t = { .msg = 1, .kind = MUT_FLIP, .off = MSG2_CT_OFF + 100, .val = 0x01 };
        ASSERT_EQ(play(&r, &t), 2);
        ASSERT(all_zero(&r.init.kem, sizeof(r.init.kem)));
        ASSERT(!r.init.have_kem);
    } TEST_END
    return failures;
}

/* ── cuts inside the encrypted static field ─────────────────────────────── */

static int case_static_field_truncation(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: truncation inside the s field of msg2 and msg3") {
        static struct run r;
        uint8_t h[32];
        /* msg2 cut 20 bytes into s: ekem1 was accepted and mixed, s was not. */
        struct mut c1 = { .msg = 1, .kind = MUT_TRUNC, .val = MSG2_LEN - (MSG2_S_OFF + 20) };
        ASSERT_EQ(play_det(&r, &c1), 2);
        memcpy(h, r.h_before[1], 32);
        mixh(h, r.m[1], 32);
        mixh(h, r.m[1] + MSG2_CT_OFF, NOISE_MLKEM_CT_LEN + 16);
        ASSERT(memcmp(h, r.h_fail, 32) == 0);
        /* msg3 cut 20 bytes in: nothing was mixed. */
        struct mut c2 = { .msg = 2, .kind = MUT_TRUNC, .val = MSG3_LEN - 20 };
        ASSERT_EQ(play_det(&r, &c2), 3);
        ASSERT(memcmp(r.h_before[2], r.h_fail, 32) == 0);
    } TEST_END
    return failures;
}

/* ── payloads in every message ──────────────────────────────────────────── */

static int case_payloads(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: payloads round-trip and add to the message sizes") {
        static struct run r;
        static const size_t plen_in[3] = { 5, 100, 300 };
        static const size_t base[3] = { MSG1_LEN, MSG2_LEN, MSG3_LEN };
        uint8_t payload[3][300];
        for (int i = 0; i < 3; i++)
            for (size_t j = 0; j < sizeof(payload[i]); j++)
                payload[i][j] = (uint8_t)(i * 50 + (int)j);
        struct noise_handshake *wr[3] = { &r.init, &r.resp, &r.init };
        struct noise_handshake *rd[3] = { &r.resp, &r.init, &r.resp };
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        for (int i = 0; i < 3; i++) {
            uint8_t pout[NOISE_MAX_MESSAGE];
            size_t plen = 0;
            ASSERT(noise_hs_write_message(wr[i], payload[i], plen_in[i], r.m[i], &r.len[i]));
            ASSERT_EQ(r.len[i], base[i] + plen_in[i]);
            ASSERT(noise_hs_read_message(rd[i], r.m[i], r.len[i], pout, &plen));
            ASSERT_EQ(plen, plen_in[i]);
            ASSERT(memcmp(pout, payload[i], plen) == 0);
        }
        uint8_t a[32], b[32], c[32], d[32];
        ASSERT(noise_hs_split(&r.init, a, b));
        ASSERT(noise_hs_split(&r.resp, c, d));
        ASSERT(memcmp(a, d, 32) == 0 && memcmp(b, c, 32) == 0);
    } TEST_END
    return failures;
}

/* ── size bounds ────────────────────────────────────────────────────────── */

static int case_size_bounds(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: oversize write is terminal; oversize read is refused") {
        static struct run r;
        static uint8_t big[NOISE_MAX_MESSAGE + 1];
        size_t len = 0;
        const size_t max_payload = NOISE_MAX_MESSAGE - MSG1_LEN;

        ASSERT(run_setup(&r, true, 0x11, 0x22));
        ASSERT(noise_hs_write_message(&r.init, big, max_payload, r.m[0], &len));
        ASSERT_EQ(len, (size_t)NOISE_MAX_MESSAGE);

        ASSERT(run_setup(&r, true, 0x11, 0x22));
        ASSERT(!noise_hs_write_message(&r.init, big, max_payload + 1, r.m[0], &len));
        ASSERT(all_zero(&r.init.kem, sizeof(r.init.kem)));
        /* Terminal: a retry with a valid payload is refused too. */
        ASSERT(!noise_hs_write_message(&r.init, NULL, 0, r.m[0], &len));
        ASSERT_EQ(r.init.msg_index, 0);

        /* One byte over the limit with no payload buffer: refused before any
         * token or payload is processed. */
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        uint8_t before[32], after[32];
        ASSERT(noise_hs_transcript_hash(&r.resp, before));
        ASSERT(!noise_hs_read_message(&r.resp, big, NOISE_MAX_MESSAGE + 1, NULL, NULL));
        ASSERT(noise_hs_transcript_hash(&r.resp, after));
        ASSERT(memcmp(before, after, 32) == 0);
        ASSERT_EQ(r.resp.msg_index, 0);
    } TEST_END
    return failures;
}

/* ── mixed-version peers ────────────────────────────────────────────────── */

static int case_mixed_version(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: classical and hybrid peers fail cleanly") {
        static struct run r;
        struct noise_handshake classical;
        uint8_t i_priv[32], pout[NOISE_MAX_MESSAGE], h[32];
        size_t plen = 0, len = 0;
        mk_scalar(i_priv, 0x51);

        /* Classical XX responder, hybrid initiator. Noise reads everything after
         * the e token of an unkeyed first message as payload, so the 1216-byte
         * message is accepted; the hybrid initiator then rejects the 96-byte
         * reply as truncated at ekem1. */
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        ASSERT(noise_hs_init(&classical, noise_pattern_xx(), false, k_prologue,
                             sizeof(k_prologue), i_priv, NULL));
        ASSERT(noise_hs_write_message(&r.init, NULL, 0, r.m[0], &len));
        ASSERT(noise_hs_read_message(&classical, r.m[0], len, pout, &plen));
        ASSERT_EQ(plen, (size_t)NOISE_MLKEM_EK_LEN);
        ASSERT(noise_hs_write_message(&classical, NULL, 0, r.m[1], &len));
        ASSERT_EQ(len, (size_t)96);
        (void)noise_hs_transcript_hash(&r.init, h);
        ASSERT(!noise_hs_read_message(&r.init, r.m[1], len, pout, &plen));
        mixh(h, r.m[1], 32);
        uint8_t hf[32];
        ASSERT(noise_hs_transcript_hash(&r.init, hf));
        ASSERT(memcmp(h, hf, 32) == 0);
        ASSERT(all_zero(&r.init.kem, sizeof(r.init.kem)));

        /* Hybrid responder, classical initiator: the 32-byte first message ends
         * before the e1 field. */
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        ASSERT(noise_hs_init(&classical, noise_pattern_xx(), true, k_prologue,
                             sizeof(k_prologue), i_priv, NULL));
        ASSERT(noise_hs_write_message(&classical, NULL, 0, r.m[0], &len));
        ASSERT_EQ(len, (size_t)32);
        (void)noise_hs_transcript_hash(&r.resp, h);
        ASSERT(!noise_hs_read_message(&r.resp, r.m[0], len, pout, &plen));
        mixh(h, r.m[0], 32);
        ASSERT(noise_hs_transcript_hash(&r.resp, hf));
        ASSERT(memcmp(h, hf, 32) == 0);
        ASSERT_EQ(r.resp.msg_index, 0);
        ASSERT(all_zero(&r.resp.kem, sizeof(r.resp.kem)));
    } TEST_END
    return failures;
}

/* ── independent key schedule ───────────────────────────────────────────── */

/* A reference SymmetricState that shares no code with the library: HKDF is
 * built here from HMAC-SHA256, and the DH, KEM and AEAD inputs are recomputed
 * from the fixed secrets. Only the ciphertext bytes are taken from the wire. */
struct ref {
    uint8_t ck[32], h[32], k[32];
    uint8_t ei[32], er[32], si[32], sr[32];
    uint8_t ei_pub[32], er_pub[32], si_pub[32], sr_pub[32];
    uint8_t ek[NOISE_MLKEM_EK_LEN], dk[ZCL_MLKEM768_DECAPSULATION_KEY_SIZE];
    uint8_t ct[NOISE_MLKEM_CT_LEN], ss[NOISE_KEM_SS_LEN];
};

static void ref_hmac(const uint8_t key[32], const uint8_t *a, size_t na,
                     const uint8_t *b, size_t nb, uint8_t out[32])
{
    struct hmac_sha256_ctx c;
    hmac_sha256_init(&c, key, 32);
    if (na) hmac_sha256_write(&c, a, na);
    if (nb) hmac_sha256_write(&c, b, nb);
    hmac_sha256_finalize(&c, out);
}

/* Noise HKDF with two outputs: temp = HMAC(ck, ikm); o1 = HMAC(temp, 0x01);
 * o2 = HMAC(temp, o1 || 0x02). */
static void ref_hkdf2(const uint8_t ck[32], const uint8_t *ikm, size_t n,
                      uint8_t o1[32], uint8_t o2[32])
{
    uint8_t temp[32];
    const uint8_t one = 1, two = 2;
    ref_hmac(ck, ikm, n, NULL, 0, temp);
    ref_hmac(temp, &one, 1, NULL, 0, o1);
    ref_hmac(temp, o1, 32, &two, 1, o2);
}

static void ref_mixkey(struct ref *r, const uint8_t ikm[32])
{
    uint8_t nk[32], k[32];
    ref_hkdf2(r->ck, ikm, 32, nk, k);
    memcpy(r->ck, nk, 32);
    memcpy(r->k, k, 32);
}

static void ref_dh(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    (void)curve25519_scalarmult(out, scalar, point);
}

/* Opens `len` wire bytes under the reference key at nonce counter `n` with the
 * reference h as AAD; true when the plaintext equals `expect`. Then MixHash. */
static bool ref_field(struct ref *r, uint64_t n, const uint8_t *wire, size_t len,
                      const uint8_t *expect, size_t plen)
{
    uint8_t nonce[12] = { 0 }, pt[NOISE_MLKEM_CT_LEN];
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(n >> (8 * i));
    bool ok = len == plen + 16 &&
              chacha20poly1305_decrypt(wire, len, r->h, 32, nonce, r->k, pt) &&
              (plen == 0 || memcmp(pt, expect, plen) == 0);
    mixh(r->h, wire, len);
    return ok;
}

static void ref_start(struct ref *r)
{
    static const char name[] = "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256";
    struct kem_replay ki = { .seed = 0x11 }, kr = { .seed = 0x22 };
    sha256_of((const uint8_t *)name, sizeof(name) - 1, r->h);
    memcpy(r->ck, r->h, 32);
    mixh(r->h, k_prologue, sizeof(k_prologue));
    mk_scalar(r->ei, 0x21);
    mk_scalar(r->er, 0x42);
    mk_scalar(r->si, 0x51);
    mk_scalar(r->sr, 0x99);
    (void)curve25519_scalarmult_base(r->ei_pub, r->ei);
    (void)curve25519_scalarmult_base(r->er_pub, r->er);
    (void)curve25519_scalarmult_base(r->si_pub, r->si);
    (void)curve25519_scalarmult_base(r->sr_pub, r->sr);
    (void)zcl_mlkem768_keygen(replay_random, &ki, r->ek, r->dk);
    (void)zcl_mlkem768_encaps(replay_random, &kr, r->ek, sizeof(r->ek), r->ct, r->ss);
}

/* msg1: e, e1 and an empty payload, all unkeyed. */
static bool ref_msg1(struct ref *r, const uint8_t *m)
{
    mixh(r->h, m, 32);
    bool ok = memcmp(m, r->ei_pub, 32) == 0 &&
              memcmp(m + 32, r->ek, NOISE_MLKEM_EK_LEN) == 0;
    mixh(r->h, m + 32, NOISE_MLKEM_EK_LEN);
    mixh(r->h, m + 32 + NOISE_MLKEM_EK_LEN, 0);
    return ok;
}

/* msg2: e, ee, ekem1, s, es and an empty payload. */
static bool ref_msg2(struct ref *r, const uint8_t *m)
{
    uint8_t dh[32];
    mixh(r->h, m, 32);
    ref_dh(dh, r->er, r->ei_pub);
    ref_mixkey(r, dh);
    bool ok = ref_field(r, 0, m + MSG2_CT_OFF, NOISE_MLKEM_CT_LEN + 16, r->ct,
                        NOISE_MLKEM_CT_LEN);
    ref_mixkey(r, r->ss);
    ok = ref_field(r, 0, m + MSG2_S_OFF, 48, r->sr_pub, 32) && ok;
    ref_dh(dh, r->sr, r->ei_pub);
    ref_mixkey(r, dh);
    return ref_field(r, 0, m + MSG2_LEN - 16, 16, NULL, 0) && ok;
}

/* msg3: s, se and an empty payload. */
static bool ref_msg3(struct ref *r, const uint8_t *m)
{
    uint8_t dh[32];
    bool ok = ref_field(r, 1, m, 48, r->si_pub, 32);
    ref_dh(dh, r->si, r->er_pub);
    ref_mixkey(r, dh);
    return ref_field(r, 0, m + 48, 16, NULL, 0) && ok;
}

static int case_independent_key_schedule(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: transport keys match an independent key schedule") {
        static struct run r;
        static struct ref f;
        uint8_t h[32], k1[32], k2[32], is[32], ir[32], rs[32], rr[32];
        ASSERT_EQ(play_det(&r, NULL), 0);
        ref_start(&f);
        ASSERT(ref_msg1(&f, r.m[0]));
        ASSERT(ref_msg2(&f, r.m[1]));
        ASSERT(ref_msg3(&f, r.m[2]));
        ASSERT(noise_hs_transcript_hash(&r.init, h));
        ASSERT(memcmp(h, f.h, 32) == 0);
        ref_hkdf2(f.ck, NULL, 0, k1, k2);
        ASSERT(noise_hs_split(&r.init, is, ir));
        ASSERT(noise_hs_split(&r.resp, rs, rr));
        ASSERT(memcmp(is, k1, 32) == 0 && memcmp(ir, k2, 32) == 0);
        ASSERT(memcmp(rs, k2, 32) == 0 && memcmp(rr, k1, 32) == 0);
    } TEST_END
    return failures;
}

/* ── tampering with the KEM fields, role and order errors ───────────────── */

static int case_kem_field_tampering(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: a bit flipped in the encapsulation key fails") {
        static struct run r;
        /* Inside the t vector: the responder encapsulates to a key the
         * initiator never sent, and h diverges before the first tag. */
        for (size_t off = 32; off < 32 + NOISE_MLKEM_EK_LEN; off += 197) {
            struct mut m1 = { .msg = 0, .kind = MUT_FLIP, .off = off, .val = 0x10 };
            int at = play_det(&r, &m1);
            ASSERT(at == 1 || at == 2);
        }
    } TEST_END
    return failures;
}

static int case_role_and_order(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: messages out of order or to the wrong role fail") {
        static struct run r, f;
        uint8_t pout[NOISE_MAX_MESSAGE];
        size_t plen = 0;
        ASSERT_EQ(play_det(&r, NULL), 0);

        /* The initiator reads the message it wrote. */
        ASSERT(run_setup(&f, true, 0x11, 0x22));
        ASSERT(!noise_hs_read_message(&f.init, r.m[0], r.len[0], pout, &plen));
        /* The responder is handed msg2 or msg3 first. */
        ASSERT(run_setup(&f, true, 0x11, 0x22));
        ASSERT(!noise_hs_read_message(&f.resp, r.m[1], r.len[1], pout, &plen));
        ASSERT(run_setup(&f, true, 0x11, 0x22));
        ASSERT(!noise_hs_read_message(&f.resp, r.m[2], r.len[2], pout, &plen));
        /* msg1 is replayed to the responder. */
        ASSERT(run_setup(&f, true, 0x11, 0x22));
        ASSERT(noise_hs_read_message(&f.resp, r.m[0], r.len[0], pout, &plen));
        ASSERT(!noise_hs_read_message(&f.resp, r.m[0], r.len[0], pout, &plen));
        /* The responder writes first. */
        ASSERT(run_setup(&f, true, 0x11, 0x22));
        ASSERT(!noise_hs_write_message(&f.resp, NULL, 0, f.m[1], &f.len[1]));
        /* A finished handshake takes no further message. */
        ASSERT(!noise_hs_read_message(&r.resp, r.m[0], r.len[0], pout, &plen));
        ASSERT(!noise_hs_write_message(&r.init, NULL, 0, r.m[0], &r.len[0]));
    } TEST_END
    return failures;
}

/* ── failure is terminal ────────────────────────────────────────────────── */

static int case_terminal_state(void)
{
    int failures = 0;
    TEST_CASE("noise_xxhfs: after a failed read or write every call fails") {
        static struct run r;
        static uint8_t big[NOISE_MAX_MESSAGE + 1];
        uint8_t pout[NOISE_MAX_MESSAGE], k1[32], k2[32];
        size_t plen = 0, len = 0;

        /* Read failure: the genuine message is refused afterwards, and so are
         * writes and split. */
        struct mut t = { .msg = 1, .kind = MUT_FLIP, .off = MSG2_S_OFF + 5, .val = 0x01 };
        ASSERT_EQ(play_det(&r, &t), 2);
        ASSERT(!noise_hs_read_message(&r.init, r.m[1], r.len[1], pout, &plen));
        ASSERT(!noise_hs_write_message(&r.init, NULL, 0, r.m[2], &len));
        ASSERT(!noise_hs_done(&r.init));
        ASSERT(!noise_hs_split(&r.init, k1, k2));
        ASSERT_EQ(r.init.msg_index, 1);

        /* A turn error is terminal: the genuine msg1 is refused afterwards. */
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        ASSERT(!noise_hs_write_message(&r.resp, NULL, 0, r.m[1], &len));
        ASSERT(noise_hs_write_message(&r.init, NULL, 0, r.m[0], &len));
        ASSERT(!noise_hs_read_message(&r.resp, r.m[0], len, pout, &plen));

        /* Write failure after tokens began: no retry, no split. */
        ASSERT(run_setup(&r, true, 0x11, 0x22));
        ASSERT(noise_hs_write_message(&r.init, NULL, 0, r.m[0], &len));
        ASSERT(noise_hs_read_message(&r.resp, r.m[0], len, pout, &plen));
        ASSERT(!noise_hs_write_message(&r.resp, big, sizeof(big), r.m[1], &len));
        ASSERT(!noise_hs_write_message(&r.resp, NULL, 0, r.m[1], &len));
        ASSERT(!noise_hs_split(&r.resp, k1, k2));
    } TEST_END
    return failures;
}

int test_noise_xxhfs_handshake(void)
{
    int failures = 0;
    failures += case_full_handshake();
    failures += case_known_answer();
    failures += case_bit_flips();
    failures += case_length_changes();
    failures += case_implicit_rejection();
    failures += case_transcript_binding();
    failures += case_invalid_encapsulation_key();
    failures += case_wipe();
    failures += case_static_field_truncation();
    failures += case_payloads();
    failures += case_size_bounds();
    failures += case_mixed_version();
    failures += case_independent_key_schedule();
    failures += case_kem_field_tampering();
    failures += case_role_and_order();
    failures += case_terminal_state();
    return failures;
}
