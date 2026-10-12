/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pin each equivocating trusted proof issuer's minimal signed
 *          evidence, so compaction cannot make a restarted receiver trust it. */

#include "proof_reuse_priv.h"

#include "vcs/blob_store.h"
#include "vcs/package_store.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define PFE_LOG "vcs.proof_fork_evidence"

/* Per issuer: whether its evidence is wanted (equivocating and trusted),
 * the pair chosen for it, and whether some pair of its signed conflicting
 * blobs is already pinned (then nothing more is). */
struct pfe_issuer {
    bool wanted;
    bool durable;
    bool chosen;
    uint8_t pair[2][VCS_PROOF_ROOT_BYTES];
    bool pair_pinned[2];
};

struct pfe_member {
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    bool pinned;
};

static bool pfe_pinned(struct vcs_package_store *store,
                       const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    struct vcs_package_store_status st;
    return vcs_package_store_package_status(store, root, &st) &&
           st.tracked && st.pinned;
}

static bool pfe_signed_ticket(const struct pr_entry *e)
{
    struct vcs_proof_ticket_v1 t;
    return vcs_proof_ticket_decode(e->wire, sizeof(e->wire), &t) &&
           vcs_proof_ticket_signature_valid(&t) &&
           memcmp(t.producer_pubkey, e->producer, VCS_PROOF_PUBKEY_BYTES) == 0;
}

static bool pfe_signed_checkpoint(const struct pr_checkpoint *cp,
                                  const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES])
{
    struct vcs_proof_checkpoint_v1 c;
    return vcs_proof_checkpoint_decode(cp->wire, sizeof(cp->wire), &c) &&
           vcs_proof_checkpoint_signature_valid(&c) &&
           memcmp(c.issuer_pubkey, issuer, VCS_PROOF_PUBKEY_BYTES) == 0;
}

/* One group of mutually conflicting blobs signed by one issuer. Two pinned
 * members already make the fork durable; otherwise the first group seen
 * supplies the pair, pinned members first so a pin is never wasted. */
static void pfe_consider(struct pfe_issuer *is, const struct pfe_member *m,
                         size_t count)
{
    size_t pinned = 0;
    for (size_t i = 0; i < count; i++)
        if (m[i].pinned) pinned++;
    if (pinned >= 2u) {
        is->durable = true;
        return;
    }
    if (is->chosen || count < 2u) return;
    size_t first = 0;
    for (size_t i = 0; i < count; i++)
        if (m[i].pinned) first = i;
    size_t second = first == 0 ? 1u : 0u;
    memcpy(is->pair[0], m[first].root, VCS_PROOF_ROOT_BYTES);
    memcpy(is->pair[1], m[second].root, VCS_PROOF_ROOT_BYTES);
    is->pair_pinned[0] = m[first].pinned;
    is->pair_pinned[1] = m[second].pinned;
    is->chosen = true;
}

static size_t pfe_issuer_index(const struct vcs_proof_receiver *view,
                               const uint8_t pubkey[VCS_PROOF_PUBKEY_BYTES])
{
    const struct pr_issuer *is = pr_issuer_find(view, pubkey);
    return is ? (size_t)(is - view->issuers) : SIZE_MAX;
}

/* The signature-valid tickets at one (issuer, sequence) chain. */
static bool pfe_ticket_chain(const struct vcs_proof_receiver *view,
                             struct vcs_package_store *store, size_t head,
                             struct pfe_member **members, size_t *cap,
                             size_t *count)
{
    *count = 0;
    for (size_t one = head; one; one = view->entries[one - 1u].next_seq) {
        const struct pr_entry *e = &view->entries[one - 1u];
        if (!pfe_signed_ticket(e)) continue;
        if (*count == *cap) {
            size_t grown_cap = *cap ? *cap * 2u : 8u;
            struct pfe_member *grown = zcl_realloc(
                *members, grown_cap * sizeof(*grown), "proof_fork_members");
            if (!grown)
                LOG_RETURN(false, PFE_LOG, "evidence: out of memory");
            *members = grown;
            *cap = grown_cap;
        }
        struct pfe_member *m = &(*members)[(*count)++];
        if (!vcs_blob_root(e->wire, sizeof(e->wire), m->root))
            LOG_RETURN(false, PFE_LOG, "evidence: ticket blob root failed");
        m->pinned = pfe_pinned(store, m->root);
    }
    return true;
}

/* Every (issuer, sequence) chain holding two signed tickets of an
 * equivocating trusted issuer, visited once from its head. */
static bool pfe_scan_tickets(const struct vcs_proof_receiver *view,
                             struct vcs_package_store *store,
                             struct pfe_issuer *state)
{
    struct pfe_member *members = NULL;
    size_t cap = 0, count = 0;
    bool ok = true;
    for (size_t i = 0; ok && i < view->count; i++) {
        const struct pr_entry *e = &view->entries[i];
        if (!e->next_seq ||
            pr_entry_seq_first(view, e->producer, e->issuer_seq) != i + 1u)
            continue;
        size_t k = pfe_issuer_index(view, e->producer);
        if (k == SIZE_MAX || !state[k].wanted ||
            state[k].durable)
            continue;
        ok = pfe_ticket_chain(view, store, i + 1u, &members, &cap, &count);
        if (ok) pfe_consider(&state[k], members, count);
    }
    free(members);
    return ok;
}

struct pfe_cp_ref {
    const struct pr_checkpoint *cp;
};

static int pfe_prev_compare(const void *a, const void *b)
{
    const struct pfe_cp_ref *x = a, *y = b;
    int c = memcmp(x->cp->prev, y->cp->prev, VCS_PROOF_ROOT_BYTES);
    return c ? c : memcmp(x->cp->root, y->cp->root, VCS_PROOF_ROOT_BYTES);
}

/* Two signed checkpoints that name one parent: an honest log never does. */
static bool pfe_scan_checkpoints(const struct pr_issuer *is,
                                 struct vcs_package_store *store,
                                 struct pfe_issuer *state)
{
    if (is->cp_count < 2u) return true;
    struct pfe_cp_ref *refs = zcl_calloc(is->cp_count, sizeof(*refs),
                                         "proof_fork_cp_refs");
    struct pfe_member *members = zcl_calloc(is->cp_count, sizeof(*members),
                                            "proof_fork_cp_members");
    if (!refs || !members) {
        free(refs);
        free(members);
        LOG_RETURN(false, PFE_LOG, "evidence: out of memory");
    }
    size_t n = 0;
    for (size_t i = 0; i < is->cp_count; i++)
        if (pfe_signed_checkpoint(&is->cps[i], is->pubkey))
            refs[n++].cp = &is->cps[i];
    qsort(refs, n, sizeof(*refs), pfe_prev_compare);
    bool ok = true;
    for (size_t lo = 0; ok && lo < n && !state->durable;) {
        size_t hi = lo;
        size_t count = 0;
        while (ok && hi < n &&
               memcmp(refs[hi].cp->prev, refs[lo].cp->prev,
                      VCS_PROOF_ROOT_BYTES) == 0) {
            ok = vcs_blob_root(refs[hi].cp->wire, sizeof(refs[hi].cp->wire),
                               members[count].root);
            members[count].pinned = ok && pfe_pinned(store,
                                                     members[count].root);
            count++;
            hi++;
        }
        if (ok) pfe_consider(state, members, count);
        lo = hi;
    }
    free(members);
    free(refs);
    if (!ok) LOG_ERROR(PFE_LOG, "evidence: checkpoint blob root failed");
    return ok;
}

static size_t pfe_pin_chosen(const struct vcs_proof_receiver *view,
                             struct vcs_package_store *store,
                             const struct pfe_issuer *state)
{
    size_t pinned = 0;
    for (size_t k = 0; k < view->issuer_count; k++) {
        const struct pfe_issuer *is = &state[k];
        if (is->durable || !is->chosen) continue;
        bool both = true;
        for (int j = 0; j < 2; j++) {
            if (is->pair_pinned[j]) continue;
            enum vcs_package_store_result r =
                vcs_package_store_pin(store, is->pair[j], true);
            if (r != VCS_PACKAGE_STORE_OK) {
                LOG_ERROR(PFE_LOG, "evidence: equivocation pin refused: %s",
                          vcs_package_store_result_string(r));
                both = false;
            }
        }
        if (both) pinned++;
    }
    return pinned;
}

static bool pfe_listed(const uint8_t (*keys)[VCS_PROOF_PUBKEY_BYTES],
                       size_t count, const uint8_t key[VCS_PROOF_PUBKEY_BYTES])
{
    for (size_t i = 0; keys && i < count; i++)
        if (memcmp(keys[i], key, VCS_PROOF_PUBKEY_BYTES) == 0) return true;
    return false;
}

/* Only a trusted, unrevoked verifier's ticket can ever be eligible, so only
 * its fork can ever matter to a HIT; a stranger cannot spend these pins. */
static size_t pfe_mark_wanted(const struct vcs_proof_receiver *view,
                              const struct vcs_proof_reuse_policy *trust,
                              struct pfe_issuer *state)
{
    size_t wanted = 0;
    for (size_t k = 0; k < view->issuer_count; k++) {
        const struct pr_issuer *is = &view->issuers[k];
        state[k].wanted =
            is->equivocating &&
            pfe_listed(trust->verifiers, trust->verifier_count, is->pubkey) &&
            !pfe_listed(trust->revoked, trust->revoked_count, is->pubkey);
        if (state[k].wanted) wanted++;
    }
    return wanted;
}

size_t pr_fork_evidence_pin(const struct vcs_proof_receiver *view,
                            struct vcs_package_store *store,
                            const struct vcs_proof_reuse_policy *trust)
{
    if (!view || !store || !trust || !view->issuer_count) return 0;
    struct pfe_issuer *state = zcl_calloc(view->issuer_count, sizeof(*state),
                                          "proof_fork_evidence");
    if (!state) LOG_RETURN(0, PFE_LOG, "evidence: out of memory");
    bool ok = pfe_mark_wanted(view, trust, state) > 0 &&
              pfe_scan_tickets(view, store, state);
    for (size_t k = 0; ok && k < view->issuer_count; k++)
        if (state[k].wanted && !state[k].durable)
            ok = pfe_scan_checkpoints(&view->issuers[k], store, &state[k]);
    size_t pinned = ok ? pfe_pin_chosen(view, store, state) : 0;
    free(state);
    if (pinned)
        LOG_WARN(PFE_LOG, "pinned signed equivocation evidence for %zu "
                          "trusted issuers", pinned);
    return pinned;
}
