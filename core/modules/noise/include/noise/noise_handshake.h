/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Noise Protocol Framework handshake — SymmetricState + HandshakeState,
 * pattern-parameterised so Noise_NK (client<->server sessions) and Noise_XX
 * (future P2P) share ONE token-table-driven implementation. Suite is
 * Noise_{NK,XX}_25519_ChaChaPoly_SHA256 and Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256: SHA-256 transcript, HKDF-SHA256 KDF,
 * X25519 (via x25519_safe) DH, ChaCha20-Poly1305 AEAD. See
 * docs/work/secure-transport-design.md §3. cognition/modules/session depends only on
 * core/modules/crypto + platform/modules/support. No external dependencies.
 *
 * Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256 adds the hybrid-forward-secrecy
 * modifier: the `e1` and `ekem1` tokens carry an ML-KEM-768 (FIPS 203)
 * encapsulation key and ciphertext, and the KEM shared secret is mixed into
 * the chaining key. This adds the dependency on platform/modules/mlkem. */

#ifndef ZCL_SESSION_NOISE_HANDSHAKE_H
#define ZCL_SESSION_NOISE_HANDSHAKE_H

#include "mlkem/mlkem.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NOISE_HASHLEN 32
#define NOISE_DHLEN   32
#define NOISE_KEYLEN  32
#define NOISE_TAGLEN  16
/* ML-KEM-768 field sizes carried by the e1 and ekem1 tokens. */
#define NOISE_MLKEM_EK_LEN 1184 /* encapsulation key */
#define NOISE_MLKEM_CT_LEN 1088 /* ciphertext */
#define NOISE_KEM_SS_LEN   32   /* shared secret */
static_assert(NOISE_MLKEM_EK_LEN == ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE,
              "e1 field must match the ML-KEM-768 encapsulation key size");
static_assert(NOISE_MLKEM_CT_LEN == ZCL_MLKEM768_CIPHERTEXT_SIZE,
              "ekem1 field must match the ML-KEM-768 ciphertext size");
static_assert(NOISE_KEM_SS_LEN == ZCL_MLKEM768_SHARED_SECRET_SIZE,
              "KEM shared secret must match the ML-KEM-768 shared secret size");

/* Largest handshake message: the 1216-byte first message of the hybrid pattern
 * (e + ML-KEM-768 encapsulation key) is the biggest fixed part; a caller-supplied
 * handshake payload adds to it. Callers cap their own payloads; the transport
 * (session_transport.h) handles bulk data. */
#define NOISE_MAX_MESSAGE 4096

/* Noise message tokens. */
enum noise_token {
    NOISE_TOK_E = 1, /* ephemeral pubkey */
    NOISE_TOK_S,     /* static pubkey (encrypted once a key is established) */
    NOISE_TOK_EE,    /* DH(e_local, e_remote) */
    NOISE_TOK_ES,    /* DH over e-of-initiator, s-of-responder */
    NOISE_TOK_SE,    /* DH over s-of-initiator, e-of-responder */
    NOISE_TOK_SS,    /* DH(s_local, s_remote) */
    NOISE_TOK_E1,    /* initiator ML-KEM-768 encapsulation key */
    NOISE_TOK_EKEM1, /* responder KEM ciphertext; shared secret mixed into ck */
};

/* Which party owns a premessage key (`-> s` / `<- s`). */
enum noise_premsg {
    NOISE_PRE_NONE = 0,
    NOISE_PRE_INITIATOR_S, /* initiator's static known ahead of time */
    NOISE_PRE_RESPONDER_S, /* responder's static known ahead of time (NK) */
};

/* A handshake pattern: protocol name (used verbatim as the initial h when
 * <=32 bytes, else SHA-256'd), the premessage, and up to 4 message patterns. */
struct noise_pattern {
    const char *name;
    enum noise_premsg premsg;
    struct { enum noise_token tok[8]; int n; } msg[4];
    int n_msgs;
};

/* Canonical patterns: NK, XX and XXhfs (XX with the ML-KEM-768 hybrid modifier). */
const struct noise_pattern *noise_pattern_nk(void); /* premsg <- s ; -> e,es ; <- e,ee */
const struct noise_pattern *noise_pattern_xx(void); /* -> e ; <- e,ee,s,es ; -> s,se */
const struct noise_pattern *noise_pattern_xxhfs(void); /* -> e,e1 ; <- e,ee,ekem1,s,es ; -> s,se */

/* Noise SymmetricState. */
struct noise_symmetric {
    uint8_t ck[NOISE_HASHLEN];
    uint8_t h[NOISE_HASHLEN];
    uint8_t k[NOISE_KEYLEN];
    uint64_t n;
    bool has_key;
};

/* Noise HandshakeState. */
struct noise_handshake {
    struct noise_symmetric sym;
    const struct noise_pattern *pattern;
    bool initiator;
    int msg_index;   /* next message pattern to process */
    bool split_done;

    /* local static (optional) + ephemeral */
    uint8_t s_priv[32], s_pub[32]; bool have_s;
    uint8_t e_priv[32], e_pub[32]; bool have_e;
    /* remote keys learned during the handshake / premessage */
    uint8_t rs[32]; bool have_rs;
    uint8_t re[32]; bool have_re;

    /* ML-KEM-768 state, role-exclusive: the initiator holds the decapsulation key
     * of the key pair it generated for e1; the responder holds the encapsulation
     * key it read. */
    union {
        uint8_t dk[ZCL_MLKEM768_DECAPSULATION_KEY_SIZE];
        uint8_t remote_ek[NOISE_MLKEM_EK_LEN];
    } kem;
    bool have_kem;
    zcl_mlkem_random_fn kem_random; /* NULL selects the secret CSPRNG */
    void *kem_random_ctx;
    bool kem_corrupt_ciphertext; /* read only by the ZCL_TESTING hook */
    bool failed; /* a read or write failed; terminal */
};

/* Initialise a handshake.
 *   pattern    — noise_pattern_nk() / noise_pattern_xx() / noise_pattern_xxhfs().
 *   initiator  — true for the dialing side.
 *   prologue   — bytes bound into h before any message (may be NULL).
 *   s_priv     — 32-byte local static scalar, or NULL if the pattern needs none
 *                on this side (NK initiator needs none; NK responder needs one).
 *   rs         — 32-byte remote static pubkey when the pattern's premessage
 *                gives it to this side (NK initiator MUST supply the responder
 *                static here), else NULL.
 * Returns false on a contract violation (missing required key material). */
bool noise_hs_init(struct noise_handshake *hs, const struct noise_pattern *pattern,
                   bool initiator, const uint8_t *prologue, size_t prologue_len,
                   const uint8_t *s_priv, const uint8_t *rs);

/* Testing hook: force the ephemeral scalar instead of drawing from the CSPRNG,
 * enabling deterministic transcripts / known-answer vectors. Call before the
 * first noise_hs_write_message on the side that emits `e`. */
void noise_hs_set_ephemeral(struct noise_handshake *hs, const uint8_t e_priv[32]);

#ifdef ZCL_TESTING
/* Test-only: replace the randomness source of the ML-KEM-768 key generation
 * (e1) and encapsulation (ekem1) with `random`; NULL restores the CSPRNG. Call
 * after noise_hs_init and before the first message that uses the KEM. Release
 * builds always draw from the CSPRNG. */
void noise_hs_set_kem_random(struct noise_handshake *hs, zcl_mlkem_random_fn random,
                             void *context);

/* Test-only: make a responder flip one bit of the ekem1 ciphertext after
 * encapsulation. The ciphertext stays well-formed, so the initiator's
 * decapsulation succeeds with the implicit-rejection secret. */
void noise_hs_test_corrupt_kem_ciphertext(struct noise_handshake *hs);
#endif

/* Write the next handshake message (only valid when it is this side's turn):
 * processes the pattern's tokens, appends the AEAD-sealed payload, emits the
 * full message into out[0..*out_len). `out` must have room for
 * NOISE_MAX_MESSAGE bytes (the XXhfs messages are 1216, 1200 and 64 bytes
 * without payload); a message that would exceed that bound is refused before
 * any byte past it is written. Any failure, including a turn or size error,
 * is terminal: every later write, read or split on that handshake fails, and
 * the caller must noise_hs_cleanse and discard it. */
bool noise_hs_write_message(struct noise_handshake *hs,
                            const uint8_t *payload, size_t payload_len,
                            uint8_t *out, size_t *out_len);

/* Read the next handshake message (only valid when it is the peer's turn):
 * consumes tokens, verifies + decrypts the payload into payload_out, which
 * needs NOISE_MAX_MESSAGE bytes when non-NULL. Messages longer than
 * NOISE_MAX_MESSAGE are refused. Returns false on turn error, malformed
 * length, DH or KEM failure, or AEAD auth failure (tampered handshake); the
 * failure is terminal as for noise_hs_write_message. */
bool noise_hs_read_message(struct noise_handshake *hs,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *payload_out, size_t *payload_len);

/* True once every message pattern has been processed and Split() is due. */
bool noise_hs_done(const struct noise_handshake *hs);

/* Split() — derive the two directional transport keys. `send_key` is the key
 * this side encrypts with; `recv_key` the key it decrypts with (role-adjusted).
 * Zeroizes all ephemeral/DH/chaining material. Returns false unless the
 * handshake is complete. */
bool noise_hs_split(struct noise_handshake *hs,
                    uint8_t send_key[32], uint8_t recv_key[32]);

/* Copy out the final transcript hash h (channel binding). Valid once done. */
bool noise_hs_transcript_hash(const struct noise_handshake *hs, uint8_t out[32]);

/* Expose the peer static learned during the handshake (XX responder auth /
 * TOFU pinning). Returns false if no remote static was received. */
bool noise_hs_remote_static(const struct noise_handshake *hs, uint8_t out[32]);

/* Zeroize all secret material in a handshake (call on abort). */
void noise_hs_cleanse(struct noise_handshake *hs);

#endif /* ZCL_SESSION_NOISE_HANDSHAKE_H */
