/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Isolation of one issuer whose stored proof history cannot be
 *          replayed on rebuild: its coverage is withdrawn (or the live
 *          receiver's verified state is kept), while any signed checkpoint
 *          contradiction it left is still recorded as equivocation. */

#include "proof_replay_priv.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define PII_LOG "vcs.proof_isolation"

/* Withdraw what a partial replay verified: coverage of the issuer's
 * committed prefix, its verified checkpoints and its high-water mark.
 * Equivocation and checkpoints retained as its evidence stay. */
static void pii_reset(struct vcs_proof_receiver *r, struct pr_issuer *is)
{
    for (uint64_t seq = 0; seq < is->mmr.num_leaves; seq++)
        for (size_t one = pr_entry_seq_first(r, is->pubkey, seq); one;
             one = r->entries[one - 1u].next_seq)
            r->entries[one - 1u].covered = false;
    size_t kept = 0;
    for (size_t i = 0; i < is->cp_count; i++)
        if (!is->cps[i].verified) is->cps[kept++] = is->cps[i];
    is->cp_count = kept;
    mmr_init(&is->mmr);
    memset(is->last_root, 0, sizeof(is->last_root));
    is->verified_count = 0;
}

static bool pii_has_root(const struct pr_issuer *is,
                         const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    for (size_t i = 0; i < is->cp_count; i++)
        if (memcmp(is->cps[i].root, root, VCS_PROOF_ROOT_BYTES) == 0)
            return true;
    return false;
}

static bool pii_append(struct pr_issuer *is, const struct pr_checkpoint *cp)
{
    if (pii_has_root(is, cp->root)) return true;
    if (is->cp_count == is->cp_cap) {
        size_t cap = is->cp_cap ? is->cp_cap * 2u : 8u;
        if (cap < is->cp_cap || cap > SIZE_MAX / sizeof(*is->cps))
            LOG_RETURN(false, PII_LOG, "isolated checkpoints: overflow");
        struct pr_checkpoint *grown =
            zcl_realloc(is->cps, cap * sizeof(*grown), "proof_checkpoints");
        if (!grown)
            LOG_RETURN(false, PII_LOG, "isolated checkpoints: out of memory");
        is->cps = grown;
        is->cp_cap = cap;
    }
    is->cps[is->cp_count++] = *cp;
    return true;
}

/* Keep one listed checkpoint, unverified, as signed evidence. */
static bool pii_retain(struct pr_issuer *is, const struct pts_cp *item)
{
    struct pr_checkpoint cp = {.verified = false,
                               .leaf_count = item->decoded.leaf_count};
    memcpy(cp.mmr_root, item->decoded.mmr_root, sizeof(cp.mmr_root));
    memcpy(cp.prev, item->decoded.prev_checkpoint_root, sizeof(cp.prev));
    memcpy(cp.root, item->root, sizeof(cp.root));
    memcpy(cp.wire, item->wire, sizeof(cp.wire));
    return pii_append(is, &cp);
}

/* The live receiver verified `was` from signed data it held, so a store
 * that lost part of that data keeps it rather than forgetting it. Evidence
 * the partial replay retained is merged back in. */
static bool pii_carry_state(const struct pr_issuer *was, struct pr_issuer *is)
{
    struct pr_checkpoint *evidence = is->cps;
    size_t evidence_count = is->cp_count;
    is->cps = NULL;
    is->cp_count = 0;
    is->cp_cap = 0;
    bool ok = true;
    for (size_t i = 0; ok && i < was->cp_count; i++)
        ok = pii_append(is, &was->cps[i]);
    for (size_t i = 0; ok && i < evidence_count; i++)
        ok = pii_append(is, &evidence[i]);
    free(evidence);
    if (!ok) return false;
    is->mmr = was->mmr;
    memcpy(is->last_root, was->last_root, sizeof(is->last_root));
    is->verified_count = was->verified_count;
    is->equivocating = is->equivocating || was->equivocating;
    is->history_incomplete = was->history_incomplete ||
                             was->verified_count == 0;
    return true;
}

/* ── signed checkpoint contradictions without a replayable history ─── */

static int pii_by_prev(const void *a, const void *b)
{
    const struct pts_cp *x = a, *y = b;
    int cmp = memcmp(x->decoded.prev_checkpoint_root,
                     y->decoded.prev_checkpoint_root, VCS_PROOF_ROOT_BYTES);
    return cmp ? cmp : memcmp(x->root, y->root, VCS_PROOF_ROOT_BYTES);
}

static int pii_by_size(const void *a, const void *b)
{
    const struct pts_cp *x = a, *y = b;
    if (x->decoded.leaf_count != y->decoded.leaf_count)
        return x->decoded.leaf_count < y->decoded.leaf_count ? -1 : 1;
    int cmp = memcmp(x->decoded.mmr_root, y->decoded.mmr_root,
                     VCS_PROOF_ROOT_BYTES);
    return cmp ? cmp : memcmp(x->root, y->root, VCS_PROOF_ROOT_BYTES);
}

/* Order of a listed checkpoint against a kept one, by the rule's key. */
static int pii_prev_key(const struct pts_cp *item,
                        const struct pr_checkpoint *kept)
{
    return memcmp(item->decoded.prev_checkpoint_root, kept->prev,
                  VCS_PROOF_ROOT_BYTES);
}

static int pii_size_key(const struct pts_cp *item,
                        const struct pr_checkpoint *kept)
{
    if (item->decoded.leaf_count == kept->leaf_count) return 0;
    return item->decoded.leaf_count < kept->leaf_count ? -1 : 1;
}

/* Two signed checkpoints under one key contradict when they name the same
 * parent but differ (two children of one head), or cover the same number
 * of tickets with different logs. The receiver's sync treats both the
 * same way. */
static bool pii_prev_conflict(const struct pr_checkpoint *kept,
                              const struct pts_cp *item)
{
    return memcmp(kept->root, item->root, VCS_PROOF_ROOT_BYTES) != 0;
}

static bool pii_size_conflict(const struct pr_checkpoint *kept,
                              const struct pts_cp *item)
{
    return memcmp(kept->mmr_root, item->decoded.mmr_root,
                  VCS_PROOF_ROOT_BYTES) != 0;
}

struct pii_rule {
    int (*order)(const void *, const void *);
    int (*key)(const struct pts_cp *, const struct pr_checkpoint *);
    bool (*conflict)(const struct pr_checkpoint *, const struct pts_cp *);
};

static const struct pii_rule pii_rules[] = {
    {pii_by_prev, pii_prev_key, pii_prev_conflict},
    {pii_by_size, pii_size_key, pii_size_conflict},
};

static void pii_as_kept(const struct pts_cp *item, struct pr_checkpoint *out)
{
    memset(out, 0, sizeof(*out));
    out->leaf_count = item->decoded.leaf_count;
    memcpy(out->mmr_root, item->decoded.mmr_root, sizeof(out->mmr_root));
    memcpy(out->prev, item->decoded.prev_checkpoint_root, sizeof(out->prev));
    memcpy(out->root, item->root, sizeof(out->root));
}

/* Runs of listed checkpoints equal under the rule's key: a run whose ends
 * conflict is retained whole. `items` is sorted by the rule. */
static bool pii_scan_runs(struct pr_issuer *is, const struct pts_cp *items,
                          size_t count, const struct pii_rule *rule,
                          bool *forked)
{
    size_t hi = 0;
    for (size_t lo = 0; lo < count; lo = hi) {
        struct pr_checkpoint first;
        pii_as_kept(&items[lo], &first);
        for (hi = lo + 1u; hi < count && rule->key(&items[hi], &first) == 0;
             hi++) {
        }
        if (!rule->conflict(&first, &items[hi - 1u])) continue;
        *forked = true;
        for (size_t k = lo; k < hi; k++)
            if (!pii_retain(is, &items[k])) return false;
    }
    return true;
}

static size_t pii_lower(const struct pts_cp *items, size_t count,
                        const struct pii_rule *rule,
                        const struct pr_checkpoint *kept)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (rule->key(&items[mid], kept) < 0) lo = mid + 1u;
        else hi = mid;
    }
    return lo;
}

/* A listed checkpoint that contradicts one the issuer keeps verified. */
static bool pii_scan_kept(struct pr_issuer *is, const struct pts_cp *items,
                          size_t count, const struct pii_rule *rule,
                          bool *forked)
{
    size_t kept_count = is->cp_count;
    for (size_t j = 0; j < kept_count; j++) {
        if (!is->cps[j].verified) continue;
        struct pr_checkpoint kept = is->cps[j];
        for (size_t k = pii_lower(items, count, rule, &kept);
             k < count && rule->key(&items[k], &kept) == 0; k++) {
            if (!rule->conflict(&kept, &items[k])) continue;
            *forked = true;
            if (!pii_retain(is, &items[k])) return false;
        }
    }
    return true;
}

static bool pii_mark_contradictions(struct pr_issuer *is,
                                    struct pts_cp *items, size_t count)
{
    bool forked = false;
    for (size_t i = 0; i < sizeof(pii_rules) / sizeof(pii_rules[0]); i++) {
        const struct pii_rule *rule = &pii_rules[i];
        if (count > 1u) qsort(items, count, sizeof(*items), rule->order);
        if (!pii_scan_runs(is, items, count, rule, &forked) ||
            !pii_scan_kept(is, items, count, rule, &forked))
            return false;
    }
    if (forked) {
        is->equivocating = true;
        LOG_WARN(PII_LOG, "isolated issuer signed contradictory checkpoints");
    }
    return true;
}

bool pii_isolate(const struct vcs_proof_receiver *prior,
                 struct vcs_proof_receiver *r, struct pts_cp *items,
                 size_t count, bool may_carry, bool *carried)
{
    *carried = false;
    if (!count) return true;
    struct pr_issuer *is = pr_issuer_get(r, items[0].decoded.issuer_pubkey);
    if (!is) return false;
    pii_reset(r, is);
    const struct pr_issuer *was =
        may_carry && prior ? pr_issuer_find(prior, is->pubkey) : NULL;
    if (was) {
        if (!pii_carry_state(was, is)) return false;
        *carried = true;
    } else {
        is->history_incomplete = true;
    }
    return pii_mark_contradictions(is, items, count);
}

static int pii_key_compare(const void *a, const void *b)
{
    return memcmp(a, b, VCS_PROOF_PUBKEY_BYTES);
}

bool pii_carry_tickets(const struct vcs_proof_receiver *prior,
                       struct vcs_proof_receiver *r,
                       const uint8_t (*keys)[VCS_PROOF_PUBKEY_BYTES],
                       size_t count)
{
    for (size_t i = 0; count && prior && i < prior->count; i++) {
        const struct pr_entry *e = &prior->entries[i];
        if (!bsearch(e->producer, keys, count, sizeof(*keys),
                     pii_key_compare))
            continue;
        if (!vcs_proof_receiver_add_ticket(r, e->wire, sizeof(e->wire), NULL))
            return false;
        if (!e->covered) continue;
        struct pr_entry *now = pr_entry_find(r, e->observation_root);
        if (!now) return false;
        now->covered = true;
    }
    if (count)
        LOG_WARN(PII_LOG, "rebuild kept %zu issuers' verified history "
                          "from the live receiver; the store no longer "
                          "holds all of it",
                 count);
    return true;
}
