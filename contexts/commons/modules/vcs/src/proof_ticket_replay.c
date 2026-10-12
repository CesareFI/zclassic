/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Per-issuer replay of listed signed checkpoints during a
 *          receiver rebuild (ancestry, complete ticket branches, delta
 *          sync). A history that cannot replay isolates only its issuer. */

#include "proof_replay_priv.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define PTP_LOG "vcs.proof_replay"

bool pts_entry_signed(const struct pr_entry *e)
{
    struct vcs_proof_ticket_v1 t;
    return vcs_proof_ticket_decode(e->wire, sizeof(e->wire), &t) &&
           vcs_proof_ticket_signature_valid(&t);
}

static enum pts_verdict pts_isolate_why(const char *why)
{
    LOG_WARN(PTP_LOG, "rebuild: issuer history cannot replay: %s", why);
    return PTS_ISOLATE;
}

/* Select the same signature-valid ticket at each sequence regardless of CAS
 * arrival order. Ticket ingest already records signed sequence forks. */
static bool pts_delta(const struct vcs_proof_receiver *r,
                      const uint8_t issuer[32], uint64_t from, uint64_t to,
                      const uint8_t **wires, size_t *lens)
{
    for (uint64_t seq = from; seq < to; seq++) {
        const struct pr_entry *chosen = NULL;
        for (size_t one = pr_entry_seq_first(r, issuer, seq); one;
             one = r->entries[one - 1u].next_seq) {
            const struct pr_entry *e = &r->entries[one - 1u];
            if (!pts_entry_signed(e)) continue;
            if (!chosen || memcmp(e->observation_root,
                                  chosen->observation_root, 32) < 0)
                chosen = e;
        }
        if (!chosen) return false;
        wires[seq - from] = chosen->wire;
        lens[seq - from] = VCS_PROOF_TICKET_WIRE_BYTES;
    }
    return true;
}

static enum pts_verdict pts_replay_delta(struct vcs_proof_receiver *r,
                                         const struct pts_cp *cp,
                                         uint64_t from, size_t count,
                                         const uint8_t **wires, size_t *lens)
{
    const struct vcs_proof_checkpoint_v1 *c = &cp->decoded;
    if (!pts_delta(r, c->issuer_pubkey, from, from + count, wires, lens))
        return pts_isolate_why("checkpoint delta ticket absent");
    struct vcs_proof_sync_report rep;
    if (!vcs_proof_receiver_sync(r, cp->wire,
                                 VCS_PROOF_CHECKPOINT_WIRE_BYTES,
                                 (const uint8_t *const *)wires, lens,
                                 count, &rep))
        LOG_RETURN(PTS_FATAL, PTP_LOG, "rebuild: replay sync call refused");
    if (rep.reason && strcmp(rep.reason, VCS_PROOF_SYNC_WHY_RESOURCES) == 0)
        LOG_RETURN(PTS_FATAL, PTP_LOG, "rebuild: receiver resources exhausted");
    bool accepted = rep.outcome == VCS_PROOF_SYNC_ADVANCED ||
                    rep.outcome == VCS_PROOF_SYNC_CURRENT ||
                    (rep.outcome == VCS_PROOF_SYNC_EQUIVOCATION &&
                     rep.reason && strcmp(rep.reason,
                                          VCS_PROOF_SYNC_WHY_EQUIVOCATION) == 0);
    if (!accepted)
        return pts_isolate_why(rep.reason ? rep.reason : "sync refused");
    const struct pr_issuer *issuer = pr_issuer_find(r, c->issuer_pubkey);
    for (size_t i = 0; issuer && i < issuer->cp_count; i++)
        if (memcmp(issuer->cps[i].root, cp->root, 32) == 0) return PTS_KEEP;
    return pts_isolate_why("replayed checkpoint was not retained");
}

static enum pts_verdict pts_replay_one(struct vcs_proof_receiver *r,
                                       const struct pts_cps *cps, size_t k,
                                       size_t *replayed)
{
    const struct vcs_proof_checkpoint_v1 *c = &cps->items[k].decoded;
    if (!vcs_proof_checkpoint_signature_valid(c))
        return pts_isolate_why("checkpoint signature invalid");
    uint64_t from = vcs_proof_receiver_issuer_leaves(r, c->issuer_pubkey);
    if (c->leaf_count > from && c->leaf_count - from > SIZE_MAX)
        return pts_isolate_why("checkpoint delta exceeds size_t");
    size_t count = c->leaf_count > from ? (size_t)(c->leaf_count - from) : 0;
    const uint8_t **wires = count ? zcl_calloc(count, sizeof(*wires),
                                               "proof_rebuild_delta") : NULL;
    size_t *lens = count ? zcl_calloc(count, sizeof(*lens),
                                      "proof_rebuild_lens") : NULL;
    enum pts_verdict v = PTS_FATAL;
    if (count && (!wires || !lens))
        LOG_ERROR(PTP_LOG, "rebuild: checkpoint delta allocation failed");
    else
        v = pts_replay_delta(r, &cps->items[k], from, count, wires, lens);
    free(wires);
    free(lens);
    if (v == PTS_ISOLATE)
        LOG_WARN(PTP_LOG,
                 "rebuild: signed checkpoint cannot be reproduced at %llu leaves",
                 (unsigned long long)c->leaf_count);
    if (v == PTS_KEEP) (*replayed)++;
    return v;
}

static int pts_root_compare(const void *a, const void *b)
{
    const struct pts_cp *x = a, *y = b;
    return memcmp(x->root, y->root, VCS_PROOF_ROOT_BYTES);
}

static size_t pts_parent(const struct pts_cps *cps,
                         const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    size_t lo = 0, hi = cps->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = memcmp(cps->items[mid].root, root, VCS_PROOF_ROOT_BYTES);
        if (cmp < 0) lo = mid + 1u;
        else hi = mid;
    }
    if (lo == cps->count ||
        memcmp(cps->items[lo].root, root, VCS_PROOF_ROOT_BYTES) != 0)
        return SIZE_MAX;
    return lo;
}

static enum pts_verdict pts_ancestry_depth(struct pts_cps *cps)
{
    if (!cps->count) return PTS_KEEP;
    uint8_t *state = zcl_calloc(cps->count, 1u, "proof_cp_state");
    size_t *stack = zcl_calloc(cps->count, sizeof(*stack), "proof_cp_stack");
    if (!state || !stack) {
        free(state);
        free(stack);
        LOG_RETURN(PTS_FATAL, PTP_LOG, "rebuild: ancestry allocation failed");
    }
    enum pts_verdict v = PTS_KEEP;
    for (size_t k = 0; k < cps->count && v == PTS_KEEP; k++) {
        size_t cur = k, used = 0;
        while (cur != SIZE_MAX && state[cur] == 0) {
            state[cur] = 1;
            stack[used++] = cur;
            cur = cps->items[cur].parent;
        }
        if (cur != SIZE_MAX && state[cur] == 1) {
            v = pts_isolate_why("checkpoint ancestry cycle");
            break;
        }
        size_t depth = cur == SIZE_MAX ? 0u : cps->items[cur].depth + 1u;
        while (used) {
            size_t one = stack[--used];
            cps->items[one].depth = depth++;
            state[one] = 2;
        }
    }
    free(stack);
    free(state);
    return v;
}

/* `cps` is one issuer's range: a parent must be that issuer's own listed
 * checkpoint, no larger than its child. */
static enum pts_verdict pts_index_ancestry(struct pts_cps *cps)
{
    if (cps->count > 1u)
        qsort(cps->items, cps->count, sizeof(*cps->items), pts_root_compare);
    for (size_t k = 0; k < cps->count; k++) {
        struct pts_cp *cp = &cps->items[k];
        const uint8_t *prev = cp->decoded.prev_checkpoint_root;
        if (memcmp(prev, (const uint8_t[32]){0}, 32) == 0) {
            cp->parent = SIZE_MAX;
            continue;
        }
        cp->parent = pts_parent(cps, prev);
        if (cp->parent == SIZE_MAX)
            return pts_isolate_why("missing checkpoint ancestor");
        if (cps->items[cp->parent].decoded.leaf_count > cp->decoded.leaf_count)
            return pts_isolate_why("invalid checkpoint ancestor");
    }
    return pts_ancestry_depth(cps);
}

static int pts_cp_compare(const void *a, const void *b)
{
    const struct pts_cp *x = a, *y = b;
    if (x->decoded.leaf_count < y->decoded.leaf_count) return -1;
    if (x->decoded.leaf_count > y->decoded.leaf_count) return 1;
    if (x->depth < y->depth) return -1;
    if (x->depth > y->depth) return 1;
    return memcmp(x->wire, y->wire, sizeof(x->wire));
}

/* Branch search bounds. States and matched memory are per checkpoint and
 * per issuer; the step budget is shared by every issuer of one rebuild,
 * because a key costs nothing to mint and must not buy a budget. */
enum {
    PTS_FORK_STATES_MAX = 256,
    PTS_FORK_MATCHED_BYTES_MAX = 64 * 1024 * 1024,
};

static enum pts_verdict pts_work_exhausted(void)
{
    LOG_ERROR(PTP_LOG, "rebuild: checkpoint branch work exhausted (%u steps "
                       "shared by every issuer)",
              VCS_PROOF_REBUILD_BRANCH_WORK_MAX);
    return PTS_EXHAUSTED;
}

/* Rebuild may retain an issuer's signed forks, but an equivocating receiver
 * does not verify a later checkpoint's delta. Prove that every retained
 * checkpoint names at least one complete ticket branch before publication.
 * The scan retained only signature-valid tickets, so every entry at a
 * sequence is a real branch and none is re-verified per branch state. */
static enum pts_verdict pts_match_checkpoint(
    const struct vcs_proof_receiver *r, const struct pts_cp *cp,
    const struct mmr *seed, struct mmr *matched,
    struct mmr *states, struct mmr *next, uint64_t *work)
{
    const struct vcs_proof_checkpoint_v1 *c = &cp->decoded;
    if (seed->num_leaves > c->leaf_count ||
        c->leaf_count - seed->num_leaves > r->count)
        return pts_isolate_why("checkpoint ticket gap");
    states[0] = *seed;
    size_t count = 1;
    for (uint64_t seq = seed->num_leaves; seq < c->leaf_count; seq++) {
        size_t next_count = 0;
        for (size_t s = 0; s < count; s++) {
            for (size_t one = pr_entry_seq_first(r, c->issuer_pubkey, seq);
                 one; one = r->entries[one - 1u].next_seq) {
                if (++*work > VCS_PROOF_REBUILD_BRANCH_WORK_MAX)
                    return pts_work_exhausted();
                const struct pr_entry *entry = &r->entries[one - 1u];
                if (next_count == PTS_FORK_STATES_MAX)
                    return pts_isolate_why("checkpoint branch states exhausted");
                next[next_count] = states[s];
                if (mmr_append(&next[next_count], entry->observation_root) < 0)
                    return pts_isolate_why("checkpoint branch append failed");
                next_count++;
            }
        }
        if (!next_count) return pts_isolate_why("checkpoint ticket absent");
        memcpy(states, next, next_count * sizeof(*states));
        count = next_count;
    }
    for (size_t i = 0; i < count; i++) {
        uint8_t root[32], peaks[32];
        mmr_root(&states[i], root);
        if (memcmp(root, c->mmr_root, sizeof(root)) == 0 &&
            vcs_proof_checkpoint_peaks_root(&states[i], peaks) &&
            memcmp(peaks, c->peaks_root, sizeof(peaks)) == 0) {
            *matched = states[i];
            return PTS_KEEP;
        }
    }
    return pts_isolate_why("signed checkpoint has no complete ticket branch");
}

struct pts_verify {
    struct mmr *matched;
    struct mmr *states;
    struct mmr *next;
    size_t *stack;
    uint8_t *done;
    uint64_t *work;            /* shared by every issuer */
};

static enum pts_verdict pts_verify_path(const struct vcs_proof_receiver *r,
                                        const struct pts_cps *cps,
                                        struct pts_verify *v, size_t used)
{
    while (used) {
        size_t one = v->stack[--used];
        size_t parent = cps->items[one].parent;
        struct mmr empty;
        mmr_init(&empty);
        const struct mmr *seed = parent == SIZE_MAX ? &empty
                                                    : &v->matched[parent];
        enum pts_verdict got = pts_match_checkpoint(
            r, &cps->items[one], seed, &v->matched[one], v->states, v->next,
            v->work);
        if (got != PTS_KEEP) return got;
        v->done[one] = 1;
    }
    return PTS_KEEP;
}

/* Parent indices still refer to the root-sorted checkpoint range here. An
 * explicit path stack proves each parent before its child without recursion;
 * the later replay sort is free to move checkpoint records afterward. */
static enum pts_verdict pts_verify_checkpoints(
    const struct vcs_proof_receiver *r, const struct pts_cps *cps,
    uint64_t *work)
{
    if (!cps->count) return PTS_KEEP;
    if (cps->count > PTS_FORK_MATCHED_BYTES_MAX / sizeof(struct mmr))
        return pts_isolate_why("checkpoint verification memory bound");
    struct pts_verify v = {
        .matched = zcl_calloc(cps->count, sizeof(struct mmr),
                              "proof_cp_matched"),
        .states = zcl_calloc(PTS_FORK_STATES_MAX, sizeof(struct mmr),
                             "proof_cp_states"),
        .next = zcl_calloc(PTS_FORK_STATES_MAX, sizeof(struct mmr),
                           "proof_cp_next"),
        .stack = zcl_calloc(cps->count, sizeof(size_t),
                            "proof_cp_verify_stack"),
        .done = zcl_calloc(cps->count, 1u, "proof_cp_verified"),
        .work = work,
    };
    enum pts_verdict got = PTS_KEEP;
    if (!v.matched || !v.states || !v.next || !v.stack || !v.done) {
        LOG_ERROR(PTP_LOG, "rebuild: checkpoint verifier allocation");
        got = PTS_FATAL;
    }
    for (size_t i = 0; got == PTS_KEEP && i < cps->count; i++) {
        size_t cur = i, used = 0;
        while (cur != SIZE_MAX && !v.done[cur]) {
            v.stack[used++] = cur;
            cur = cps->items[cur].parent;
        }
        if (used) got = pts_verify_path(r, cps, &v, used);
    }
    free(v.done);
    free(v.stack);
    free(v.next);
    free(v.states);
    free(v.matched);
    return got;
}

/* Leaf count and signed ancestry together determine one issuer's replay
 * order. Issuers are independent: each owns its prefix and coverage. */
static enum pts_verdict pts_replay_issuer(struct vcs_proof_receiver *r,
                                          struct pts_cps *own,
                                          size_t *replayed, uint64_t *work)
{
    enum pts_verdict v = pts_index_ancestry(own);
    if (v == PTS_KEEP) v = pts_verify_checkpoints(r, own, work);
    if (v != PTS_KEEP) return v;
    if (own->count > 1u)
        qsort(own->items, own->count, sizeof(*own->items), pts_cp_compare);
    for (size_t k = 0; v == PTS_KEEP && k < own->count; k++)
        v = pts_replay_one(r, own, k, replayed);
    return v;
}

static int pts_issuer_compare(const void *a, const void *b)
{
    const struct pts_cp *x = a, *y = b;
    int cmp = memcmp(x->decoded.issuer_pubkey, y->decoded.issuer_pubkey,
                     VCS_PROOF_PUBKEY_BYTES);
    return cmp ? cmp : memcmp(x->root, y->root, VCS_PROOF_ROOT_BYTES);
}

/* An anchored issuer's head must replay from the store itself, so its
 * live state is never carried in place of that proof. */
static bool pts_anchored(const struct pts_scope *scope, const uint8_t key[32])
{
    for (size_t i = 0; i < scope->anchor_count; i++)
        if (memcmp(scope->anchors[i].issuer_pubkey, key, 32) == 0)
            return true;
    return false;
}

struct pts_carry {
    uint8_t (*keys)[VCS_PROOF_PUBKEY_BYTES];
    size_t count;
    size_t cap;
};

static bool pts_carry_add(struct pts_carry *carry, const uint8_t key[32])
{
    if (carry->count == carry->cap) {
        size_t cap = carry->cap ? carry->cap * 2u : 8u;
        if (cap < carry->cap || cap > SIZE_MAX / sizeof(*carry->keys))
            LOG_RETURN(false, PTP_LOG, "rebuild: carried issuer overflow");
        uint8_t (*grown)[VCS_PROOF_PUBKEY_BYTES] = zcl_realloc(
            carry->keys, cap * sizeof(*carry->keys), "proof_carried_issuers");
        if (!grown)
            LOG_RETURN(false, PTP_LOG, "rebuild: carried issuers: out of memory");
        carry->keys = grown;
        carry->cap = cap;
    }
    memcpy(carry->keys[carry->count++], key, VCS_PROOF_PUBKEY_BYTES);
    return true;
}

static bool pts_listed(const uint8_t (*keys)[VCS_PROOF_PUBKEY_BYTES],
                       size_t count, const uint8_t key[32])
{
    for (size_t i = 0; keys && i < count; i++)
        if (memcmp(keys[i], key, VCS_PROOF_PUBKEY_BYTES) == 0) return true;
    return false;
}

/* Under a trust policy only its unrevoked verifiers and the anchored
 * issuers have branches worth searching: no other key's ticket can ever be
 * eligible, and anyone can mint such keys. Without a policy, every issuer
 * replays. */
static bool pts_replays(const struct pts_scope *scope, const uint8_t key[32])
{
    const struct vcs_proof_reuse_policy *trust = scope->evidence_trust;
    if (!trust || pts_anchored(scope, key)) return true;
    return pts_listed(trust->verifiers, trust->verifier_count, key) &&
           !pts_listed(trust->revoked, trust->revoked_count, key);
}

/* Isolate an issuer whose history did not replay, or that was only
 * scanned for forks; its contradictions are still marked. */
static bool pts_isolate_range(const struct vcs_proof_receiver *prior,
                              struct vcs_proof_receiver *r,
                              struct pts_cp *items, size_t count,
                              bool replayed, struct pts_counts *n,
                              const struct pts_scope *scope,
                              struct pts_carry *carry)
{
    uint8_t key[VCS_PROOF_PUBKEY_BYTES]; /* pii_isolate reorders items */
    memcpy(key, items[0].decoded.issuer_pubkey, sizeof(key));
    bool carried = false;
    if (!pii_isolate(prior, r, items, count, !pts_anchored(scope, key),
                     &carried))
        return false;
    if (replayed) n->isolated++;
    else n->unreplayed++;
    if (!carried) return true;
    n->carried++;
    return pts_carry_add(carry, key);
}

static bool pts_replay_range(const struct vcs_proof_receiver *prior,
                             struct vcs_proof_receiver *r,
                             struct pts_cp *items, size_t count,
                             struct pts_counts *n,
                             const struct pts_scope *scope,
                             struct pts_carry *carry)
{
    uint8_t key[VCS_PROOF_PUBKEY_BYTES];
    memcpy(key, items[0].decoded.issuer_pubkey, sizeof(key));
    if (!pts_replays(scope, key))
        return pts_isolate_range(prior, r, items, count, false, n, scope,
                                 carry);
    struct pts_cps own = {items, count, count};
    size_t replayed = 0;
    enum pts_verdict v = pts_replay_issuer(r, &own, &replayed,
                                           &n->branch_work);
    if (v == PTS_EXHAUSTED) n->refusal = VCS_PROOF_REBUILD_WHY_BRANCH_WORK;
    if (v == PTS_FATAL || v == PTS_EXHAUSTED) return false;
    if (v == PTS_KEEP) {
        n->checkpoints += replayed;
        return true;
    }
    return pts_isolate_range(prior, r, items, count, true, n, scope, carry);
}

bool pts_replay(const struct vcs_proof_receiver *prior,
                struct vcs_proof_receiver *r, struct pts_cps *cps,
                struct pts_counts *n, const struct pts_scope *scope)
{
    if (cps->count > 1u)
        qsort(cps->items, cps->count, sizeof(*cps->items), pts_issuer_compare);
    struct pts_carry carry = {0};
    bool ok = true;
    size_t hi = 0;
    for (size_t lo = 0; ok && lo < cps->count; lo = hi) {
        for (hi = lo + 1u; hi < cps->count &&
             memcmp(cps->items[hi].decoded.issuer_pubkey,
                    cps->items[lo].decoded.issuer_pubkey,
                    VCS_PROOF_PUBKEY_BYTES) == 0;
             hi++) {
        }
        ok = pts_replay_range(prior, r, cps->items + lo, hi - lo, n, scope,
                              &carry);
    }
    ok = ok && pii_carry_tickets(prior, r,
                                 (const uint8_t (*)[VCS_PROOF_PUBKEY_BYTES])
                                     carry.keys, carry.count);
    free(carry.keys);
    if (ok && n->isolated)
        LOG_WARN(PTP_LOG, "rebuild: isolated %zu issuers whose stored history "
                          "is incomplete; kept %zu as the live receiver had "
                          "verified them", n->isolated, n->carried);
    if (ok && n->unreplayed)
        LOG_INFO(PTP_LOG, "rebuild: scanned %zu untrusted issuers for forks "
                          "only; their checkpoint branches were not replayed",
                 n->unreplayed);
    return ok;
}
