/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verified-signature memo for proof tickets and checkpoints.
 *          See vcs/proof_signature.h. */

#include "vcs/proof_signature.h"

#include "base/bytes.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "platform/rng.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <string.h>

#define PSIG_LOG "vcs.proof_signature"
#define PSIG_SLOTS (1u << 17)
#define PSIG_CLEAR_AT (PSIG_SLOTS / 4u * 3u)

static const char psig_domain[] = "zcl.proof_signature_memo.v1";

/* Open addressing over salted keys; an all-zero key marks an empty slot. */
struct psig_memo {
    zcl_mutex_t lock;
    uint8_t salt[32];
    bool salted;
    uint8_t (*keys)[32];
    size_t count;
};

static struct psig_memo g_psig;
static zcl_once_t g_psig_once = ZCL_ONCE_INIT;
static _Atomic uint64_t g_psig_verified;
static _Atomic uint64_t g_psig_refused;
static _Atomic uint64_t g_psig_reused;

static void psig_init(void)
{
    zcl_mutex_init(&g_psig.lock);
    g_psig.salted = rng_fill(g_psig.salt, sizeof(g_psig.salt));
    if (!g_psig.salted)
        LOG_WARN(PSIG_LOG, "no salt: every proof signature is verified");
}

static bool psig_ready(void)
{
    return zcl_once_call(&g_psig_once, psig_init) && g_psig.salted;
}

/* False only for the all-zero key, which cannot be stored. */
static bool psig_key(const uint8_t sig[64], const uint8_t *msg,
                     size_t msg_len, const uint8_t pubkey[32],
                     uint8_t key[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)psig_domain, sizeof(psig_domain));
    sha3_256_write(&sha, g_psig.salt, sizeof(g_psig.salt));
    sha3_256_write(&sha, pubkey, 32);
    sha3_256_write(&sha, sig, 64);
    if (msg_len) sha3_256_write(&sha, msg, msg_len);
    sha3_256_finalize(&sha, key);
    return zcl_bytes_any_set(key, 32);
}

/* The slot holding `key`, or the empty slot where it belongs. The table is
 * never more than three-quarters full, so the probe ends. */
static size_t psig_slot_locked(const uint8_t key[32])
{
    size_t slot = (size_t)(zcl_read_u64_le(key) & (PSIG_SLOTS - 1u));
    while (zcl_bytes_any_set(g_psig.keys[slot], 32) &&
           memcmp(g_psig.keys[slot], key, 32) != 0)
        slot = (slot + 1u) & (PSIG_SLOTS - 1u);
    return slot;
}

static bool psig_seen(const uint8_t key[32])
{
    zcl_mutex_lock(&g_psig.lock);
    bool seen = g_psig.keys &&
                zcl_bytes_any_set(g_psig.keys[psig_slot_locked(key)], 32);
    zcl_mutex_unlock(&g_psig.lock);
    return seen;
}

static void psig_remember(const uint8_t key[32])
{
    zcl_mutex_lock(&g_psig.lock);
    if (!g_psig.keys) {
        g_psig.keys = zcl_calloc(PSIG_SLOTS, sizeof(*g_psig.keys),
                                 "proof_signature_memo");
        if (!g_psig.keys)
            LOG_WARN(PSIG_LOG, "memo allocation failed; verifying again");
    }
    if (g_psig.keys && g_psig.count >= PSIG_CLEAR_AT) {
        memset(g_psig.keys, 0, PSIG_SLOTS * sizeof(*g_psig.keys));
        g_psig.count = 0;
    }
    if (g_psig.keys) {
        size_t slot = psig_slot_locked(key);
        if (!zcl_bytes_any_set(g_psig.keys[slot], 32)) {
            memcpy(g_psig.keys[slot], key, 32);
            g_psig.count++;
        }
    }
    zcl_mutex_unlock(&g_psig.lock);
}

bool vcs_proof_signature_verify(const uint8_t sig[64], const uint8_t *msg,
                                size_t msg_len, const uint8_t pubkey[32])
{
    if (!sig || !pubkey || (!msg && msg_len))
        LOG_RETURN(false, PSIG_LOG, "signature check: null argument");
    uint8_t key[32];
    bool memo = psig_ready() && psig_key(sig, msg, msg_len, pubkey, key);
    if (memo && psig_seen(key)) {
        atomic_fetch_add(&g_psig_reused, 1u);
        return true;
    }
    bool ok = ed25519_verify(sig, msg, msg_len, pubkey);
    atomic_fetch_add(ok ? &g_psig_verified : &g_psig_refused, 1u);
    if (ok && memo) psig_remember(key);
    return ok;
}

void vcs_proof_signature_stats(struct vcs_proof_signature_stats *out)
{
    if (!out) return;
    out->verified = atomic_load(&g_psig_verified);
    out->refused = atomic_load(&g_psig_refused);
    out->reused = atomic_load(&g_psig_reused);
}

void vcs_proof_signature_forget(void)
{
    if (!zcl_once_call(&g_psig_once, psig_init)) return;
    zcl_mutex_lock(&g_psig.lock);
    if (g_psig.keys)
        memset(g_psig.keys, 0, PSIG_SLOTS * sizeof(*g_psig.keys));
    g_psig.count = 0;
    zcl_mutex_unlock(&g_psig.lock);
}
