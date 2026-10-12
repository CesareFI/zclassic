/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The receiver's retained ticket set and delta-only verification
 *          of per-issuer signed MMR checkpoints, with equivocation kept. */

#include "proof_reuse_priv.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <stdlib.h>
#include <string.h>

#define PRV_LOG "vcs.proof_receiver"

struct vcs_proof_receiver *vcs_proof_receiver_new(void)
{
    struct vcs_proof_receiver *r =
        zcl_calloc(1, sizeof(*r), "proof_receiver");
    if (!r) LOG_RETURN(NULL, PRV_LOG, "receiver: out of memory");
    return r;
}

void vcs_proof_receiver_free(struct vcs_proof_receiver *r)
{
    if (!r) return;
    for (size_t i = 0; i < r->issuer_count; i++) free(r->issuers[i].cps);
    free(r->issuers);
    free(r->roots);
    free(r->keys);
    free(r->seqs);
    free(r->entries);
    free(r);
}

/* ── Retained tickets ───────────────────────────────────────────────── */

static size_t pr_hash(const uint8_t *bytes, size_t len)
{
    size_t h = (size_t)UINT64_C(1469598103934665603);
    for (size_t i = 0; i < len; i++) h = (h ^ bytes[i]) *
                                             (size_t)UINT64_C(1099511628211);
    return h;
}

static size_t pr_seq_hash(const uint8_t issuer[32], uint64_t seq)
{
    size_t h = pr_hash(issuer, 32);
    uint8_t sequence[8];
    zcl_write_u64_le(sequence, seq);
    for (unsigned i = 0; i < 8; i++)
        h = (h ^ sequence[i]) *
            (size_t)UINT64_C(1099511628211);
    return h;
}

static size_t pr_root_slot(const struct vcs_proof_receiver *r,
                           const uint8_t root[32])
{
    size_t slot = pr_hash(root, 32) & (r->index_cap - 1u);
    while (r->roots[slot] &&
           memcmp(r->entries[r->roots[slot] - 1u].observation_root,
                  root, 32) != 0)
        slot = (slot + 1u) & (r->index_cap - 1u);
    return slot;
}

static size_t pr_key_slot(const struct vcs_proof_receiver *r,
                          const uint8_t key[32])
{
    size_t slot = pr_hash(key, 32) & (r->index_cap - 1u);
    while (r->keys[slot].head &&
           memcmp(r->entries[r->keys[slot].head - 1u].input_key,
                  key, 32) != 0)
        slot = (slot + 1u) & (r->index_cap - 1u);
    return slot;
}

static size_t pr_seq_slot(const struct vcs_proof_receiver *r,
                          const uint8_t issuer[32], uint64_t seq)
{
    size_t slot = pr_seq_hash(issuer, seq) & (r->index_cap - 1u);
    while (r->seqs[slot].head) {
        const struct pr_entry *e = &r->entries[r->seqs[slot].head - 1u];
        if (e->issuer_seq == seq && memcmp(e->producer, issuer, 32) == 0)
            break;
        slot = (slot + 1u) & (r->index_cap - 1u);
    }
    return slot;
}

static void pr_index_entry(struct vcs_proof_receiver *r, size_t index)
{
    struct pr_entry *e = &r->entries[index];
    size_t one = index + 1u;
    r->roots[pr_root_slot(r, e->observation_root)] = one;
    struct pr_bucket *key = &r->keys[pr_key_slot(r, e->input_key)];
    if (key->tail) r->entries[key->tail - 1u].next_key = one;
    else key->head = one;
    key->tail = one;
    struct pr_bucket *seq = &r->seqs[pr_seq_slot(r, e->producer,
                                                  e->issuer_seq)];
    if (seq->tail) r->entries[seq->tail - 1u].next_seq = one;
    else seq->head = one;
    seq->tail = one;
}

struct pr_entry *pr_entry_find(const struct vcs_proof_receiver *r,
                               const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    if (!r || !r->index_cap) return NULL;
    size_t one = r->roots[pr_root_slot(r, root)];
    return one ? &r->entries[one - 1u] : NULL;
}

size_t pr_entry_key_first(const struct vcs_proof_receiver *r,
                          const uint8_t key[VCS_PROOF_ROOT_BYTES])
{
    return r && r->index_cap ? r->keys[pr_key_slot(r, key)].head : 0;
}

size_t pr_entry_seq_first(const struct vcs_proof_receiver *r,
                          const uint8_t issuer[32], uint64_t seq)
{
    return r && r->index_cap ? r->seqs[pr_seq_slot(r, issuer, seq)].head : 0;
}

static bool pr_index_reserve(struct vcs_proof_receiver *r, size_t needed)
{
    if (r->index_cap && needed < r->index_cap / 2u) return true;
    size_t index_cap = r->index_cap ? r->index_cap : 128u;
    while (needed >= index_cap / 2u) {
        if (index_cap > SIZE_MAX / 2u)
            LOG_RETURN(false, PRV_LOG, "receiver index capacity overflow");
        index_cap *= 2u;
    }
    size_t *roots = zcl_calloc(index_cap, sizeof(*roots), "proof_root_index");
    struct pr_bucket *keys = zcl_calloc(index_cap, sizeof(*keys),
                                         "proof_key_index");
    struct pr_bucket *seqs = zcl_calloc(index_cap, sizeof(*seqs),
                                         "proof_seq_index");
    if (!roots || !keys || !seqs) {
        free(roots); free(keys); free(seqs);
        LOG_RETURN(false, PRV_LOG, "receiver indexes: out of memory");
    }
    free(r->roots); free(r->keys); free(r->seqs);
    r->roots = roots; r->keys = keys; r->seqs = seqs;
    r->index_cap = index_cap;
    for (size_t i = 0; i < r->count; i++) {
        r->entries[i].next_key = 0;
        r->entries[i].next_seq = 0;
        pr_index_entry(r, i);
    }
    return true;
}

static bool pr_entries_reserve(struct vcs_proof_receiver *r, size_t additional)
{
    if (additional > SIZE_MAX - r->count)
        LOG_RETURN(false, PRV_LOG, "receiver ticket count overflow");
    size_t needed = r->count + additional;
    if (needed > r->cap) {
        size_t cap = r->cap ? r->cap : 64u;
        while (cap < needed) {
            if (cap > SIZE_MAX / 2u) {
                cap = needed;
                break;
            }
            cap *= 2u;
        }
        if (cap > SIZE_MAX / sizeof(struct pr_entry))
            LOG_RETURN(false, PRV_LOG, "receiver ticket capacity overflow");
        struct pr_entry *grown = zcl_realloc(
            r->entries, cap * sizeof(*grown), "proof_receiver_entries");
        if (!grown) LOG_RETURN(false, PRV_LOG, "receiver: out of memory");
        r->entries = grown;
        r->cap = cap;
    }
    return pr_index_reserve(r, needed);
}

struct pr_entry *pr_entry_put(struct vcs_proof_receiver *r,
                              const uint8_t *wire,
                              const struct vcs_proof_ticket_v1 *t,
                              const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    struct pr_entry *e = pr_entry_find(r, root);
    if (e) return e;
    if (!pr_entries_reserve(r, 1)) return NULL;
    e = &r->entries[r->count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->input_key, t->input_key, VCS_PROOF_ROOT_BYTES);
    memcpy(e->observation_root, root, VCS_PROOF_ROOT_BYTES);
    memcpy(e->producer, t->producer_pubkey, VCS_PROOF_PUBKEY_BYTES);
    e->issuer_seq = t->issuer_seq;
    memcpy(e->wire, wire, VCS_PROOF_TICKET_WIRE_BYTES);
    pr_index_entry(r, r->count - 1u);
    return e;
}

static bool pr_signed_seq_fork(const struct vcs_proof_receiver *r,
                               const struct vcs_proof_ticket_v1 *t,
                               const uint8_t root[32])
{
    size_t one = pr_entry_seq_first(r, t->producer_pubkey, t->issuer_seq);
    if (!one || !vcs_proof_ticket_signature_valid(t)) return false;
    for (; one; one = r->entries[one - 1u].next_seq) {
        const struct pr_entry *other = &r->entries[one - 1u];
        if (memcmp(other->observation_root, root, 32) == 0) continue;
        struct vcs_proof_ticket_v1 previous;
        if (vcs_proof_ticket_decode(other->wire,
                                     VCS_PROOF_TICKET_WIRE_BYTES,
                                     &previous) &&
            vcs_proof_ticket_signature_valid(&previous))
            return true;
    }
    return false;
}

bool vcs_proof_receiver_add_ticket(struct vcs_proof_receiver *r,
                                   const uint8_t *wire, size_t len,
                                   bool *added)
{
    if (added) *added = false;
    if (!r || !wire)
        LOG_RETURN(false, PRV_LOG, "receiver add: null argument");
    struct vcs_proof_ticket_v1 t;
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    if (!vcs_proof_ticket_decode(wire, len, &t) ||
        !vcs_proof_ticket_observation_root(wire, len, root))
        LOG_RETURN(false, PRV_LOG, "receiver add: undecodable ticket");
    struct pr_issuer *fork_issuer = NULL;
    if (pr_signed_seq_fork(r, &t, root)) {
        fork_issuer = pr_issuer_get(r, t.producer_pubkey);
        if (!fork_issuer) return false;
    }
    size_t before = r->count;
    if (!pr_entry_put(r, wire, &t, root)) return false;
    if (added) *added = r->count > before;
    if (fork_issuer) {
        fork_issuer->equivocating = true;
        LOG_WARN(PRV_LOG, "issuer signed conflicting tickets at one sequence");
    }
    return true;
}

size_t vcs_proof_receiver_lookup(const struct vcs_proof_receiver *r,
                                 const uint8_t input_key[VCS_PROOF_ROOT_BYTES],
                                 const uint8_t **wires, size_t cap)
{
    if (!r || !input_key) return 0;
    size_t total = 0;
    for (size_t one = pr_entry_key_first(r, input_key); one;
         one = r->entries[one - 1u].next_key) {
        if (wires && total < cap) wires[total] = r->entries[one - 1u].wire;
        total++;
    }
    return total;
}

size_t vcs_proof_receiver_ticket_count(const struct vcs_proof_receiver *r)
{
    return r ? r->count : 0;
}

/* ── Issuers ────────────────────────────────────────────────────────── */

const struct pr_issuer *pr_issuer_find(const struct vcs_proof_receiver *r,
                                       const uint8_t pubkey[32])
{
    for (size_t i = 0; r && i < r->issuer_count; i++)
        if (memcmp(r->issuers[i].pubkey, pubkey, 32) == 0)
            return &r->issuers[i];
    return NULL;
}

struct pr_issuer *pr_issuer_get(struct vcs_proof_receiver *r,
                                const uint8_t pubkey[32])
{
    struct pr_issuer *found = (struct pr_issuer *)pr_issuer_find(r, pubkey);
    if (found) return found;
    if (r->issuer_count == r->issuer_cap) {
        size_t cap = r->issuer_cap ? r->issuer_cap * 2u : 8u;
        struct pr_issuer *grown = zcl_realloc(
            r->issuers, cap * sizeof(*grown), "proof_receiver_issuers");
        if (!grown) LOG_RETURN(NULL, PRV_LOG, "receiver issuers: out of memory");
        r->issuers = grown;
        r->issuer_cap = cap;
    }
    struct pr_issuer *is = &r->issuers[r->issuer_count++];
    memset(is, 0, sizeof(*is));
    memcpy(is->pubkey, pubkey, 32);
    mmr_init(&is->mmr);
    return is;
}

uint64_t vcs_proof_receiver_issuer_leaves(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES])
{
    const struct pr_issuer *is = issuer ? pr_issuer_find(r, issuer) : NULL;
    return is ? is->mmr.num_leaves : 0;
}

bool vcs_proof_receiver_issuer_equivocating(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES])
{
    const struct pr_issuer *is = issuer ? pr_issuer_find(r, issuer) : NULL;
    return is && is->equivocating;
}

bool vcs_proof_receiver_issuer_history_incomplete(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES])
{
    const struct pr_issuer *is = issuer ? pr_issuer_find(r, issuer) : NULL;
    return is && is->history_incomplete;
}

const char *vcs_proof_receiver_rebuild_refusal(
    const struct vcs_proof_receiver *r)
{
    return r ? r->rebuild_refusal : NULL;
}

size_t vcs_proof_receiver_issuer_checkpoints(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES])
{
    const struct pr_issuer *is = issuer ? pr_issuer_find(r, issuer) : NULL;
    return is ? is->cp_count : 0;
}

/* ── Sync ───────────────────────────────────────────────────────────── */

struct pr_sync {
    struct vcs_proof_receiver *r;
    struct pr_issuer *is;
    struct vcs_proof_checkpoint_v1 c;
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    const uint8_t *const *delta;
    const size_t *lens;
    size_t n;
    struct vcs_proof_sync_report *out;
};

static bool pr_done(struct vcs_proof_sync_report *out,
                    enum vcs_proof_sync_outcome outcome, const char *why)
{
    out->outcome = outcome;
    out->reason = why;
    return true;
}

static bool pr_retain(struct pr_issuer *is, const struct pr_sync *s,
                      bool verified)
{
    for (size_t i = 0; i < is->cp_count; i++)
        if (memcmp(is->cps[i].root, s->root, VCS_PROOF_ROOT_BYTES) == 0)
            return true;
    if (is->cp_count == is->cp_cap) {
        size_t cap = is->cp_cap ? is->cp_cap * 2u : 8u;
        struct pr_checkpoint *grown =
            zcl_realloc(is->cps, cap * sizeof(*grown), "proof_checkpoints");
        if (!grown) LOG_RETURN(false, PRV_LOG, "checkpoints: out of memory");
        is->cps = grown;
        is->cp_cap = cap;
    }
    struct pr_checkpoint *cp = &is->cps[is->cp_count++];
    cp->verified = verified;
    cp->leaf_count = s->c.leaf_count;
    memcpy(cp->mmr_root, s->c.mmr_root, VCS_PROOF_ROOT_BYTES);
    memcpy(cp->prev, s->c.prev_checkpoint_root, VCS_PROOF_ROOT_BYTES);
    memcpy(cp->root, s->root, VCS_PROOF_ROOT_BYTES);
    memcpy(cp->wire, s->wire, VCS_PROOF_CHECKPOINT_WIRE_BYTES);
    return true;
}

static bool pr_equivocate(struct pr_sync *s)
{
    s->is->equivocating = true;
    LOG_WARN(PRV_LOG, "issuer signed contradictory checkpoints at %llu leaves",
             (unsigned long long)s->c.leaf_count);
    if (!pr_retain(s->is, s, false))
        return pr_done(s->out, VCS_PROOF_SYNC_EQUIVOCATION,
                       VCS_PROOF_SYNC_WHY_RESOURCES);
    return pr_done(s->out, VCS_PROOF_SYNC_EQUIVOCATION,
                   VCS_PROOF_SYNC_WHY_EQUIVOCATION);
}

static const struct pr_checkpoint *pr_verified_at(const struct pr_issuer *is,
                                                  uint64_t leaf_count)
{
    for (size_t i = 0; i < is->cp_count; i++)
        if (is->cps[i].verified && is->cps[i].leaf_count == leaf_count)
            return &is->cps[i];
    return NULL;
}

static bool pr_verified_prev(const struct pr_issuer *is,
                             const uint8_t prev[VCS_PROOF_ROOT_BYTES])
{
    for (size_t i = 0; i < is->cp_count; i++)
        if (is->cps[i].verified &&
            memcmp(is->cps[i].prev, prev, VCS_PROOF_ROOT_BYTES) == 0)
            return true;
    return false;
}

static bool pr_verified_root(const struct pr_issuer *is,
                             const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    for (size_t i = 0; i < is->cp_count; i++)
        if (is->cps[i].verified &&
            memcmp(is->cps[i].root, root, VCS_PROOF_ROOT_BYTES) == 0)
            return true;
    return false;
}

/* Check each delta ticket is this issuer's, at its position. Fills roots. */
static bool pr_delta_shape(const struct pr_sync *s, uint8_t (*roots)[32],
                           struct vcs_proof_ticket_v1 *tickets)
{
    uint64_t base = s->is->mmr.num_leaves;
    for (size_t i = 0; i < s->n; i++) {
        struct vcs_proof_ticket_v1 *t = &tickets[i];
        if (!s->delta[i] ||
            !vcs_proof_ticket_decode(s->delta[i], s->lens[i], t) ||
            !vcs_proof_ticket_signature_valid(t) ||
            memcmp(t->producer_pubkey, s->c.issuer_pubkey, 32) != 0 ||
            t->issuer_seq != base + i ||
            !vcs_proof_ticket_observation_root(s->delta[i], s->lens[i],
                                               roots[i]))
            return false;
    }
    return true;
}

static bool pr_prefix_matches(const struct pr_sync *s, uint8_t (*roots)[32],
                              struct mmr *next)
{
    *next = s->is->mmr;
    for (size_t i = 0; i < s->n; i++) mmr_append(next, roots[i]);
    uint8_t root[VCS_PROOF_ROOT_BYTES], peaks[VCS_PROOF_ROOT_BYTES];
    mmr_root(next, root);
    return vcs_proof_checkpoint_peaks_root(next, peaks) &&
           memcmp(root, s->c.mmr_root, VCS_PROOF_ROOT_BYTES) == 0 &&
           memcmp(peaks, s->c.peaks_root, VCS_PROOF_ROOT_BYTES) == 0;
}

static bool pr_commit(struct pr_sync *s, const struct mmr *next,
                      const struct vcs_proof_ticket_v1 *tickets,
                      uint8_t (*roots)[32])
{
    /* No covered ticket or verified checkpoint becomes visible unless all
     * receiver storage needed by this delta is available. */
    if (!pr_entries_reserve(s->r, s->n))
        return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_RESOURCES);
    if (!pr_retain(s->is, s, true))
        return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_RESOURCES);
    for (size_t i = 0; i < s->n; i++) {
        struct pr_entry *e = pr_entry_put(s->r, s->delta[i], &tickets[i],
                                          roots[i]);
        if (!e)
            return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                           VCS_PROOF_SYNC_WHY_RESOURCES);
        e->covered = true;
    }
    /* s->is may have moved if pr_entry_put grew entries; issuers are a
     * separate array, so the pointer is still valid. */
    s->is->mmr = *next;
    memcpy(s->is->last_root, s->root, VCS_PROOF_ROOT_BYTES);
    s->is->verified_count++;
    s->out->leaves_after = next->num_leaves;
    return pr_done(s->out, VCS_PROOF_SYNC_ADVANCED, VCS_PROOF_SYNC_WHY_OK);
}

/* The delta does not reproduce the signed root. When every delta ticket is
 * validly signed by the issuer at its position, the issuer signed both
 * sides: equivocation. Otherwise the relay supplied bad bytes: refuse. */
static bool pr_mismatch(struct pr_sync *s,
                        const struct vcs_proof_ticket_v1 *tickets)
{
    for (size_t i = 0; i < s->n; i++)
        if (!vcs_proof_ticket_signature_valid(&tickets[i]))
            return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                           VCS_PROOF_SYNC_WHY_DELTA);
    return pr_equivocate(s);
}

static bool pr_extend(struct pr_sync *s)
{
    if (s->n != s->c.leaf_count - s->is->mmr.num_leaves)
        return pr_done(s->out, VCS_PROOF_SYNC_REFUSED, VCS_PROOF_SYNC_WHY_COUNT);
    uint8_t (*roots)[32] = zcl_calloc(s->n ? s->n : 1u, 32,
                                    "proof_sync_roots");
    struct vcs_proof_ticket_v1 *tickets =
        zcl_calloc(s->n ? s->n : 1u, sizeof(*tickets), "proof_sync_tickets");
    bool ok;
    if (!roots || !tickets) {
        ok = pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                     VCS_PROOF_SYNC_WHY_RESOURCES);
    } else if (!pr_delta_shape(s, roots, tickets)) {
        ok = pr_done(s->out, VCS_PROOF_SYNC_REFUSED, VCS_PROOF_SYNC_WHY_DELTA);
    } else {
        struct mmr next;
        ok = pr_prefix_matches(s, roots, &next) ?
                 pr_commit(s, &next, tickets, roots) :
                 pr_mismatch(s, tickets);
    }
    free(roots);
    free(tickets);
    return ok;
}

static bool pr_classify(struct pr_sync *s)
{
    struct pr_issuer *is = s->is;
    if (is->equivocating) return pr_equivocate(s);
    if (pr_verified_root(is, s->root))
        return pr_done(s->out, VCS_PROOF_SYNC_CURRENT, VCS_PROOF_SYNC_WHY_OK);
    const struct pr_checkpoint *same = pr_verified_at(is, s->c.leaf_count);
    if (same && memcmp(same->mmr_root, s->c.mmr_root, 32) != 0)
        return pr_equivocate(s);
    if (is->verified_count > 0 &&
        memcmp(s->c.prev_checkpoint_root, is->last_root, 32) != 0)
        return pr_verified_prev(is, s->c.prev_checkpoint_root) ?
                   pr_equivocate(s) :
                   pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                           VCS_PROOF_SYNC_WHY_GAP);
    if (s->c.leaf_count < is->mmr.num_leaves)
        return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_UNVERIFIABLE);
    return pr_extend(s);
}

static size_t pr_bytes(size_t cp_len, const size_t *lens, size_t n)
{
    size_t total = cp_len;
    for (size_t i = 0; lens && i < n; i++) total += lens[i];
    return total;
}

bool vcs_proof_receiver_sync(struct vcs_proof_receiver *r,
                             const uint8_t *checkpoint, size_t checkpoint_len,
                             const uint8_t *const *delta,
                             const size_t *delta_lens, size_t delta_count,
                             struct vcs_proof_sync_report *out)
{
    if (!out) LOG_RETURN(false, PRV_LOG, "sync: no report buffer");
    memset(out, 0, sizeof(*out));
    out->outcome = VCS_PROOF_SYNC_REFUSED;
    out->reason = VCS_PROOF_SYNC_WHY_MALFORMED;
    if (!r || !checkpoint || (delta_count && (!delta || !delta_lens)))
        LOG_RETURN(false, PRV_LOG, "sync: null argument");
    out->bytes = pr_bytes(checkpoint_len, delta_lens, delta_count);
    struct pr_sync s = {.r = r, .delta = delta, .lens = delta_lens,
                        .n = delta_count, .out = out};
    if (!vcs_proof_checkpoint_decode(checkpoint, checkpoint_len, &s.c) ||
        !vcs_proof_checkpoint_root(checkpoint, checkpoint_len, s.root))
        return pr_done(out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_MALFORMED);
    if (!vcs_proof_checkpoint_signature_valid(&s.c))
        return pr_done(out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_SIGNATURE);
    memcpy(s.wire, checkpoint, VCS_PROOF_CHECKPOINT_WIRE_BYTES);
    s.is = pr_issuer_get(r, s.c.issuer_pubkey);
    if (!s.is)
        return pr_done(out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_RESOURCES);
    out->leaves_before = s.is->mmr.num_leaves;
    out->leaves_after = s.is->mmr.num_leaves;
    return pr_classify(&s);
}
