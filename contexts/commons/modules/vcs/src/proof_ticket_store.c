/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: CAS placement of proof tickets, checkpoints and key preimages,
 *          and the receiver rebuilt as a projection over those blobs. */

#include "proof_replay_priv.h"

#include "vcs/blob_store.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define PTS_LOG "vcs.proof_ticket_store"
#define PTS_BLOB_MAX VCS_CPK_WIRE_BYTES

bool vcs_proof_ticket_store_put(struct vcs_package_store *store,
                                const uint8_t *wire, size_t len,
                                uint8_t blob_root[VCS_PROOF_ROOT_BYTES])
{
    if (!store || !wire || !blob_root)
        LOG_RETURN(false, PTS_LOG, "store put: null argument");
    enum vcs_blob_result r = vcs_blob_put_to(store, wire, len, blob_root);
    if (r != VCS_BLOB_OK)
        LOG_RETURN(false, PTS_LOG, "store put (%zu bytes): %s", len,
                   vcs_blob_result_string(r));
    return true;
}

bool vcs_proof_ticket_store_put_no_evict(
    struct vcs_package_store *store, const uint8_t *wire, size_t len,
    uint8_t blob_root[VCS_PROOF_ROOT_BYTES])
{
    if (!store || !wire || !blob_root)
        LOG_RETURN(false, PTS_LOG, "no-evict store put: null argument");
    enum vcs_blob_result r = vcs_blob_put_to_no_evict(
        store, wire, len, blob_root);
    if (r != VCS_BLOB_OK)
        LOG_RETURN(false, PTS_LOG, "no-evict store put (%zu bytes): %s", len,
                   vcs_blob_result_string(r));
    return true;
}

bool vcs_proof_checkpoint_store_load(
    struct vcs_package_store *store,
    const uint8_t blob_root[VCS_PROOF_ROOT_BYTES],
    const uint8_t issuer_pubkey[VCS_PROOF_PUBKEY_BYTES],
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES],
    uint8_t checkpoint_root[VCS_PROOF_ROOT_BYTES])
{
    if (!store || !blob_root || !issuer_pubkey || !wire || !checkpoint_root)
        LOG_RETURN(false, PTS_LOG, "checkpoint load: null argument");
    uint8_t loaded[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    size_t len = 0;
    enum vcs_blob_result got =
        vcs_blob_get_from(store, blob_root, loaded, sizeof(loaded), &len);
    if (got != VCS_BLOB_OK)
        LOG_RETURN(false, PTS_LOG, "checkpoint load: %s",
                   vcs_blob_result_string(got));
    struct vcs_proof_checkpoint_v1 decoded;
    uint8_t derived_blob[VCS_PROOF_ROOT_BYTES];
    uint8_t derived_checkpoint[VCS_PROOF_ROOT_BYTES];
    if (len != sizeof(loaded) ||
        !vcs_blob_root(loaded, len, derived_blob) ||
        memcmp(derived_blob, blob_root, sizeof(derived_blob)) != 0 ||
        !vcs_proof_checkpoint_decode(loaded, len, &decoded) ||
        !vcs_proof_checkpoint_signature_valid(&decoded) ||
        memcmp(decoded.issuer_pubkey, issuer_pubkey,
               VCS_PROOF_PUBKEY_BYTES) != 0 ||
        !vcs_proof_checkpoint_root(loaded, len, derived_checkpoint))
        LOG_RETURN(false, PTS_LOG, "checkpoint load: invalid signed head");
    memcpy(wire, loaded, sizeof(loaded));
    memcpy(checkpoint_root, derived_checkpoint, sizeof(derived_checkpoint));
    return true;
}

bool vcs_component_proof_key_load(struct vcs_package_store *store,
                                  const uint8_t preimage_root[32],
                                  struct vcs_component_proof_key_v1 *out)
{
    if (!store || !preimage_root || !out)
        LOG_RETURN(false, PTS_LOG, "preimage load: null argument");
    uint8_t wire[VCS_CPK_WIRE_BYTES + 1u];
    size_t len = 0;
    enum vcs_blob_result r =
        vcs_blob_get_from(store, preimage_root, wire, sizeof(wire), &len);
    if (r != VCS_BLOB_OK)
        LOG_RETURN(false, PTS_LOG, "preimage load: %s",
                   vcs_blob_result_string(r));
    if (!vcs_component_proof_key_decode(wire, len, out))
        LOG_RETURN(false, PTS_LOG, "preimage load: blob is not a key preimage");
    uint8_t again[VCS_PROOF_ROOT_BYTES];
    if (!vcs_component_proof_key_preimage_root(out, again) ||
        memcmp(again, preimage_root, VCS_PROOF_ROOT_BYTES) != 0)
        LOG_RETURN(false, PTS_LOG, "preimage load: root does not re-derive");
    return true;
}

/* ── Rebuild ────────────────────────────────────────────────────────── */

struct pts_chunks {
    uint8_t (*hashes)[32];
    size_t count;
    size_t cap;
};

static bool pts_chunk_add(struct pts_chunks *chunks,
                          const uint8_t *wire, size_t len)
{
    if (chunks->count == chunks->cap) {
        size_t cap = chunks->cap ? chunks->cap * 2u : 32u;
        if (cap < chunks->cap || cap > SIZE_MAX / sizeof(*chunks->hashes))
            LOG_RETURN(false, PTS_LOG, "rebuild: chunk guard capacity overflow");
        uint8_t (*grown)[32] = zcl_realloc(
            chunks->hashes, cap * sizeof(*chunks->hashes), "proof_chunks");
        if (!grown)
            LOG_RETURN(false, PTS_LOG, "rebuild: chunk guard allocation failed");
        chunks->hashes = grown;
        chunks->cap = cap;
    }
    /* Every accepted proof blob is below the store's one-chunk limit. */
    if (!vcs_package_chunk_hash(wire, len, chunks->hashes[chunks->count]))
        LOG_RETURN(false, PTS_LOG, "rebuild: chunk guard hash failed");
    chunks->count++;
    return true;
}

static bool pts_take_cp(struct pts_cps *cps, const uint8_t *blob, size_t len,
                        struct pts_counts *n, bool *retained)
{
    struct vcs_proof_checkpoint_v1 decoded;
    if (!vcs_proof_checkpoint_decode(blob, len, &decoded) ||
        !vcs_proof_checkpoint_signature_valid(&decoded)) {
        n->skipped++;
        return true;
    }
    if (cps->count == cps->cap) {
        size_t cap = cps->cap ? cps->cap * 2u : 32u;
        if (cap < cps->cap || cap > SIZE_MAX / sizeof(*cps->items))
            LOG_RETURN(false, PTS_LOG, "rebuild: checkpoint capacity overflow");
        struct pts_cp *grown = zcl_realloc(
            cps->items, cap * sizeof(*grown), "proof_cps");
        if (!grown)
            LOG_RETURN(false, PTS_LOG, "rebuild: checkpoint allocation failed");
        cps->items = grown;
        cps->cap = cap;
    }
    struct pts_cp *item = &cps->items[cps->count++];
    item->decoded = decoded;
    memcpy(item->wire, blob, len);
    if (!vcs_proof_checkpoint_root(blob, len, item->root))
        LOG_RETURN(false, PTS_LOG, "rebuild: checkpoint root failed");
    *retained = true;
    return true;
}

static bool pts_take(struct vcs_proof_receiver *r, struct pts_cps *cps,
                     const uint8_t *blob, size_t len, struct pts_counts *n,
                     bool *retained)
{
    *retained = false;
    bool added = false;
    struct vcs_proof_ticket_v1 t;
    if (len == VCS_PROOF_TICKET_WIRE_BYTES &&
        memcmp(blob, "Z23PTK1\0", 8) == 0 &&
        vcs_proof_ticket_decode(blob, len, &t)) {
        /* An unsigned copy proves nothing and never enters a branch
         * search: counted, not retained, and checked here only once. */
        if (!vcs_proof_ticket_signature_valid(&t)) {
            n->skipped++;
            n->unsigned_tickets++;
            return true;
        }
        if (!vcs_proof_receiver_add_ticket(r, blob, len, &added))
            return false;
        *retained = true;
        if (added) n->tickets++;
        return true;
    }
    if (len == VCS_PROOF_CHECKPOINT_WIRE_BYTES &&
        memcmp(blob, "Z23PCK1\0", 8) == 0)
        return pts_take_cp(cps, blob, len, n, retained);
    n->skipped++;
    return true;
}

struct pts_publish {
    struct vcs_proof_issuer_log **live;
    struct vcs_proof_issuer_log *replacement;
    struct vcs_proof_issuer_log *old;
    bool approved;
};

static void pts_approve_restore(void *context)
{
    struct pts_publish *publish = context;
    if (publish->live) {
        publish->old = *publish->live;
        *publish->live = publish->replacement;
    }
    publish->approved = true;
}

struct pts_restore {
    struct vcs_package_store *store;
    struct vcs_proof_receiver *receiver;
    struct vcs_proof_issuer_log *fresh;
    struct vcs_proof_issuer_log *result;
    const uint8_t **wires;
    size_t *lens;
    uint8_t (*chunks)[32];
    uint8_t pubkey[VCS_PROOF_PUBKEY_BYTES];
    uint8_t head_wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t head_root[VCS_PROOF_ROOT_BYTES];
    struct vcs_proof_checkpoint_v1 head;
    size_t count;
    uint64_t generation;
};

static bool pts_rebuild_bounded(struct vcs_proof_receiver *r,
                                struct vcs_package_store *store,
                                size_t max_catalog_rows, size_t *tickets,
                                size_t *checkpoints, size_t *skipped,
                                uint64_t *generation_out,
                                const struct pts_scope *scope);

static void pts_restore_free(struct pts_restore *s)
{
    free(s->chunks);
    free(s->wires);
    free(s->lens);
    vcs_proof_issuer_log_free(s->fresh);
    vcs_proof_receiver_free(s->receiver);
}

static bool pts_restore_begin(struct pts_restore *s, const uint8_t seed[32],
                              size_t max_catalog_rows)
{
    s->receiver = vcs_proof_receiver_new();
    if (!s->receiver) return false;
    s->fresh = vcs_proof_issuer_log_new(seed);
    if (!s->fresh) return false;
    vcs_proof_issuer_log_pubkey(s->fresh, s->pubkey);
    static const struct pts_scope read_only = {NULL, 0, NULL};
    return pts_rebuild_bounded(s->receiver, s->store, max_catalog_rows,
                               NULL, NULL, NULL, &s->generation, &read_only);
}

static bool pts_restore_empty(struct pts_restore *s)
{
    /* An isolated history still proves this key signed something: a
     * checkpoint whose tickets or parent the store lost. Never reissue its
     * sequences from an empty log. */
    const struct pr_issuer *issuer = pr_issuer_find(s->receiver, s->pubkey);
    if (issuer && (issuer->cp_count || issuer->history_incomplete))
        return false;
    for (size_t i = 0; i < s->receiver->count; i++) {
        const struct pr_entry *entry = &s->receiver->entries[i];
        if (memcmp(entry->producer, s->pubkey, sizeof(s->pubkey)) == 0 &&
            pts_entry_signed(entry))
            return false;
    }
    s->result = s->fresh;
    s->fresh = NULL;
    return true;
}

static bool pts_restore_no_tail(const struct pts_restore *s)
{
    /* A signed tail has authority even when it has not yet been checkpointed.
     * Never reuse its sequence after a crash. */
    for (size_t i = 0; i < s->receiver->count; i++) {
        const struct pr_entry *entry = &s->receiver->entries[i];
        if (memcmp(entry->producer, s->pubkey, sizeof(s->pubkey)) == 0 &&
            entry->issuer_seq >= s->head.leaf_count && pts_entry_signed(entry))
            return false;
    }
    return true;
}

static bool pts_restore_head_valid(struct pts_restore *s,
                                   const uint8_t blob_root[32],
                                   size_t max_tickets)
{
    if (!vcs_proof_checkpoint_store_load(s->store, blob_root, s->pubkey,
                                          s->head_wire, s->head_root) ||
        !vcs_proof_checkpoint_decode(s->head_wire, sizeof(s->head_wire),
                                      &s->head) ||
        s->head.leaf_count == 0 || s->head.leaf_count > max_tickets ||
        s->head.leaf_count > SIZE_MAX / sizeof(*s->wires) - 1u ||
        s->head.leaf_count > SIZE_MAX / sizeof(*s->chunks) - 1u)
        return false;
    s->count = (size_t)s->head.leaf_count;
    const struct pr_issuer *issuer = pr_issuer_find(s->receiver, s->pubkey);
    return issuer && !issuer->equivocating && !issuer->history_incomplete &&
           issuer->mmr.num_leaves == s->head.leaf_count &&
           issuer->cp_count == issuer->verified_count &&
           memcmp(issuer->last_root, s->head_root,
                  sizeof(s->head_root)) == 0 && pts_restore_no_tail(s);
}

static bool pts_restore_select_wires(struct pts_restore *s)
{
    for (size_t seq = 0; seq < s->count; seq++) {
        for (size_t one = pr_entry_seq_first(s->receiver, s->pubkey, seq); one;
             one = s->receiver->entries[one - 1u].next_seq) {
            const struct pr_entry *entry = &s->receiver->entries[one - 1u];
            if (!pts_entry_signed(entry)) continue;
            if (s->wires[seq] || !entry->covered) return false;
            s->wires[seq] = entry->wire;
            s->lens[seq] = sizeof(entry->wire);
        }
        if (!s->wires[seq]) return false;
    }
    return true;
}

static bool pts_restore_head(struct pts_restore *s, const uint8_t seed[32],
                             const uint8_t blob_root[32], size_t max_tickets)
{
    if (!pts_restore_head_valid(s, blob_root, max_tickets)) return false;
    s->wires = zcl_calloc(s->count, sizeof(*s->wires),
                          "proof_restore_store_wires");
    s->lens = zcl_calloc(s->count, sizeof(*s->lens),
                         "proof_restore_store_lens");
    if (!s->wires || !s->lens || !pts_restore_select_wires(s)) return false;
    s->result = vcs_proof_issuer_log_restore(seed, s->wires, s->lens, s->count,
                                               max_tickets, s->head_wire,
                                               sizeof(s->head_wire), s->head_root);
    return s->result != NULL;
}

static bool pts_restore_recheck(struct pts_restore *s,
                                struct vcs_proof_issuer_log **live,
                                struct vcs_proof_issuer_log **old)
{
    if (s->count) {
        s->chunks = zcl_calloc(s->count + 1u, sizeof(*s->chunks),
                               "proof_restore_store_chunks");
        if (!s->chunks) return false;
        for (size_t i = 0; i < s->count; i++)
            if (!vcs_package_chunk_hash(s->wires[i], s->lens[i],
                                        s->chunks[i]))
                return false;
        if (!vcs_package_chunk_hash(s->head_wire, sizeof(s->head_wire),
                                    s->chunks[s->count]))
            return false;
    }
    struct pts_publish guarded = {.live = live, .replacement = s->result};
    if (vcs_package_store_publish_checked(s->store, s->generation,
                                           (const uint8_t (*)[32])s->chunks,
                                           s->count ? s->count + 1u : 0u,
                                           pts_approve_restore, &guarded) !=
        VCS_PACKAGE_STORE_PAGE_OK)
        return false;
    if (old) *old = guarded.old;
    return guarded.approved;
}

static void pts_restore_take_guard(struct pts_restore *s,
                                   uint64_t *generation_out,
                                   uint8_t (**chunk_hashes_out)[32],
                                   size_t *chunk_count_out)
{
    if (!s->result) return;
    if (generation_out) *generation_out = s->generation;
    if (chunk_hashes_out && chunk_count_out) {
        *chunk_hashes_out = s->chunks;
        *chunk_count_out = s->count ? s->count + 1u : 0u;
        s->chunks = NULL;
    }
}

static struct vcs_proof_issuer_log *pts_restore_from_store(
    const uint8_t seed[32], struct vcs_package_store *store,
    const uint8_t expected_head_blob_root[VCS_PROOF_ROOT_BYTES],
    size_t max_catalog_rows, size_t max_tickets,
    struct vcs_proof_issuer_log **live,
    struct vcs_proof_issuer_log **old, uint64_t *generation_out,
    uint8_t (**chunk_hashes_out)[32], size_t *chunk_count_out)
{
    if (generation_out) *generation_out = 0;
    if (chunk_hashes_out) *chunk_hashes_out = NULL;
    if (chunk_count_out) *chunk_count_out = 0;
    if (!seed || !store)
        LOG_RETURN(NULL, PTS_LOG, "issuer store restore: null seed or store");
    struct pts_restore s = {.store = store};
    if (!pts_restore_begin(&s, seed, max_catalog_rows) ||
        !(expected_head_blob_root ?
          pts_restore_head(&s, seed, expected_head_blob_root, max_tickets) :
          pts_restore_empty(&s)) ||
        !pts_restore_recheck(&s, live, old)) {
        LOG_ERROR(PTS_LOG,
                  "issuer store restore: incomplete, stale, or contradictory history");
        vcs_proof_issuer_log_free(s.result);
        s.result = NULL;
    }
    struct vcs_proof_issuer_log *result = s.result;
    pts_restore_take_guard(&s, generation_out, chunk_hashes_out,
                           chunk_count_out);
    pts_restore_free(&s);
    return result;
}

bool vcs_proof_issuer_log_restore_publish_from_store(
    const uint8_t seed[32], struct vcs_package_store *store,
    const uint8_t expected_head_blob_root[VCS_PROOF_ROOT_BYTES],
    size_t max_catalog_rows, size_t max_tickets,
    struct vcs_proof_issuer_log **live)
{
    if (!live)
        LOG_RETURN(false, PTS_LOG, "issuer publish: null live projection");
    struct vcs_proof_issuer_log *old = NULL;
    struct vcs_proof_issuer_log *fresh = pts_restore_from_store(
        seed, store, expected_head_blob_root, max_catalog_rows,
        max_tickets, live, &old, NULL, NULL, NULL);
    if (!fresh) return false;
    vcs_proof_issuer_log_free(old);
    return true;
}

struct vcs_proof_issuer_log *vcs_proof_issuer_log_restore_from_store(
    const uint8_t seed[32], struct vcs_package_store *store,
    const uint8_t expected_head_blob_root[VCS_PROOF_ROOT_BYTES],
    size_t max_catalog_rows, size_t max_tickets)
{
    return pts_restore_from_store(
        seed, store, expected_head_blob_root, max_catalog_rows,
        max_tickets, NULL, NULL, NULL, NULL, NULL);
}

struct vcs_proof_issuer_log *vcs_proof_issuer_log_restore_from_store_at_generation(
    const uint8_t seed[32], struct vcs_package_store *store,
    const uint8_t expected_head_blob_root[VCS_PROOF_ROOT_BYTES],
    size_t max_catalog_rows, size_t max_tickets, uint64_t *generation_out,
    uint8_t (**chunk_hashes_out)[32], size_t *chunk_count_out)
{
    if (!generation_out || !chunk_hashes_out || !chunk_count_out)
        LOG_RETURN(NULL, PTS_LOG, "issuer restore guard outputs missing");
    return pts_restore_from_store(
        seed, store, expected_head_blob_root, max_catalog_rows,
        max_tickets, NULL, NULL, generation_out,
        chunk_hashes_out, chunk_count_out);
}

static bool pts_scan_one(struct vcs_proof_receiver *r,
                         struct vcs_package_store *store,
                         struct pts_cps *cps, struct pts_counts *n,
                         struct pts_chunks *chunks, const uint8_t root[32])
{
    uint8_t blob[PTS_BLOB_MAX + 1u];
    size_t len = 0;
    enum vcs_blob_result got = vcs_blob_get_from(
        store, root, blob, sizeof(blob), &len);
    if (got == VCS_BLOB_OK) {
        bool retained = false;
        if (!pts_take(r, cps, blob, len, n, &retained)) return false;
        return !retained || pts_chunk_add(chunks, blob, len);
    }
    if (got == VCS_BLOB_ERR_SHAPE || got == VCS_BLOB_ERR_CAPACITY) {
        n->skipped++;
        return true;
    }
    LOG_RETURN(false, PTS_LOG, "rebuild: listed CAS blob cannot be read: %s",
               vcs_blob_result_string(got));
}

static bool pts_scan(struct vcs_proof_receiver *r,
                     struct vcs_package_store *store, struct pts_cps *cps,
                     struct pts_counts *n, struct pts_chunks *chunks,
                     uint64_t *generation, size_t max_catalog_rows)
{
    struct vcs_package_store_summary *rows =
        zcl_calloc(VCS_PACKAGE_STORE_PAGE_MAX, sizeof(*rows),
                   "proof_rebuild_rows");
    if (!rows) LOG_RETURN(false, PTS_LOG, "rebuild: out of memory");
    uint8_t cursor[32];
    bool resume = false;
    bool done = false;
    bool ok = true;
    size_t scanned = 0;
    while (ok && !done) {
        size_t remaining = max_catalog_rows - scanned;
        if (remaining == 0) {
            LOG_ERROR(PTS_LOG,
                      "rebuild: catalog row budget exhausted before complete scan");
            ok = false;
            break;
        }
        size_t page_limit = remaining < VCS_PACKAGE_STORE_PAGE_MAX
                          ? remaining : VCS_PACKAGE_STORE_PAGE_MAX;
        struct vcs_package_store_page page;
        enum vcs_package_store_page_result result =
            vcs_package_store_page_summaries(store, resume ? cursor : NULL,
                                             page_limit,
                                             resume ? *generation : 0,
                                             rows, &page);
        if (result != VCS_PACKAGE_STORE_PAGE_OK) {
            LOG_ERROR(PTS_LOG, "rebuild: package catalog page refused (%d)",
                      (int)result);
            ok = false;
            break;
        }
        if (page.count > max_catalog_rows - scanned) {
            LOG_ERROR(PTS_LOG,
                      "rebuild: catalog row budget exhausted before complete scan");
            ok = false;
            break;
        }
        scanned += page.count;
        *generation = page.generation;
        for (size_t i = 0; ok && i < page.count; i++)
            ok = pts_scan_one(r, store, cps, n, chunks, rows[i].root);
        if (page.has_more && page.count == 0) ok = false;
        memcpy(cursor, page.next_root, sizeof(cursor));
        resume = true;
        done = !page.has_more;
    }
    free(rows);
    return ok;
}

#ifdef ZCL_TESTING
static void (*pts_before_recheck_hook)(void *);
static void *pts_before_recheck_context;
static void (*pts_after_recheck_hook)(void *);
static void *pts_after_recheck_context;
void vcs_proof_receiver_test_before_recheck(void (*hook)(void *), void *context)
{
    pts_before_recheck_hook = hook;
    pts_before_recheck_context = context;
}
void vcs_proof_receiver_test_after_recheck(void (*hook)(void *), void *context)
{
    pts_after_recheck_hook = hook;
    pts_after_recheck_context = context;
}
#endif

struct pts_publish_context {
    struct vcs_proof_receiver *live;
    struct vcs_proof_receiver *staged;
};

static void pts_publish(void *context)
{
    struct pts_publish_context *p = context;
    struct vcs_proof_receiver old = *p->live;
    *p->live = *p->staged;
    *p->staged = old;
}

static bool pts_publish_rechecked(struct vcs_proof_receiver *live,
                                  struct vcs_proof_receiver *staging,
                                  struct vcs_package_store *store,
                                  const struct pts_chunks *chunks,
                                  uint64_t generation)
{
#ifdef ZCL_TESTING
    if (pts_before_recheck_hook)
        pts_before_recheck_hook(pts_before_recheck_context);
#endif
#ifdef ZCL_TESTING
    if (pts_after_recheck_hook)
        pts_after_recheck_hook(pts_after_recheck_context);
#endif
    struct pts_publish_context p = {live, staging};
    return vcs_package_store_publish_checked(
        store, generation, (const uint8_t (*)[32])chunks->hashes,
        chunks->count, pts_publish, &p) == VCS_PACKAGE_STORE_PAGE_OK;
}

static bool pts_empty_issuer(const struct pr_issuer *was)
{
    return was->cp_count == 0 && was->verified_count == 0 &&
           was->mmr.num_leaves == 0 && !was->equivocating;
}

static bool pts_preserves_issuer(const struct pr_issuer *was,
                                 const struct vcs_proof_receiver *next)
{
    const struct pr_issuer *now = pr_issuer_find(next, was->pubkey);
    if (!now && pts_empty_issuer(was))
        return true; /* a refused sync created no prior evidence */
    if (!now || now->mmr.num_leaves < was->mmr.num_leaves)
        LOG_RETURN(false, PTS_LOG, "rebuild: issuer high-water regressed");
    if (was->equivocating && !now->equivocating)
        LOG_RETURN(false, PTS_LOG, "rebuild: issuer fork disappeared");
    for (size_t j = 0; j < was->cp_count; j++) {
        bool found = false;
        bool verified = false;
        for (size_t k = 0; k < now->cp_count; k++)
            if (memcmp(was->cps[j].root, now->cps[k].root, 32) == 0) {
                found = true;
                verified = now->cps[k].verified;
                break;
            }
        if (!found)
            LOG_RETURN(false, PTS_LOG, "rebuild: prior checkpoint disappeared");
        if (was->cps[j].verified && !verified)
            LOG_RETURN(false, PTS_LOG,
                       "rebuild: prior checkpoint lost verification");
    }
    return true;
}

/* A live receiver is also an anchor: a rebuilt view may extend it but may
 * not silently forget a ticket, checkpoint, or signed fork it already saw. */
static bool pts_preserves_prior(const struct vcs_proof_receiver *old,
                                const struct vcs_proof_receiver *next)
{
    for (size_t i = 0; i < old->count; i++) {
        const struct pr_entry *entry =
            pr_entry_find(next, old->entries[i].observation_root);
        if (!entry)
            LOG_RETURN(false, PTS_LOG, "rebuild: prior ticket disappeared");
        if (old->entries[i].covered && !entry->covered)
            LOG_RETURN(false, PTS_LOG, "rebuild: prior ticket lost coverage");
    }
    for (size_t i = 0; i < old->issuer_count; i++)
        if (!pts_preserves_issuer(&old->issuers[i], next)) return false;
    return true;
}

/* A live receiver may have verified a checkpoint before it learned that the
 * same issuer signed a second ticket at one sequence. Replaying a complete
 * CAS from an empty receiver sees the fork first and conservatively marks
 * that earlier checkpoint unverified. Carry the old verification forward
 * only when the replay retained its exact signed checkpoint and every
 * previously covered ticket. The issuer stays equivocating, so this cannot
 * turn conflicting evidence into a reuse hit. */
static struct pr_issuer *pts_find_issuer(struct vcs_proof_receiver *receiver,
                                         const uint8_t pubkey[32])
{
    for (size_t i = 0; i < receiver->issuer_count; i++)
        if (memcmp(receiver->issuers[i].pubkey, pubkey, 32) == 0)
            return &receiver->issuers[i];
    return NULL;
}

static bool pts_anchor_checkpoints(const struct pr_issuer *was,
                                    struct pr_issuer *now, bool *lost)
{
    *lost = false;
    for (size_t j = 0; j < was->cp_count; j++) {
        const struct pr_checkpoint *prior = &was->cps[j];
        if (!prior->verified) continue;
        struct pr_checkpoint *found = NULL;
        for (size_t k = 0; k < now->cp_count; k++)
            if (memcmp(now->cps[k].root, prior->root, 32) == 0) {
                found = &now->cps[k];
                break;
            }
        if (!found || memcmp(found->wire, prior->wire,
                             sizeof(prior->wire)) != 0)
            LOG_RETURN(false, PTS_LOG,
                       "rebuild: anchored checkpoint absent from CAS");
        if (!found->verified) *lost = true;
    }
    return true;
}

static bool pts_anchor_tickets(const struct vcs_proof_receiver *old,
                                const struct pr_issuer *was,
                                struct vcs_proof_receiver *next)
{
    for (size_t j = 0; j < old->count; j++) {
        const struct pr_entry *prior = &old->entries[j];
        if (!prior->covered ||
            memcmp(prior->producer, was->pubkey, 32) != 0)
            continue;
        struct pr_entry *found =
            pr_entry_find(next, prior->observation_root);
        if (!found || memcmp(found->wire, prior->wire,
                             sizeof(prior->wire)) != 0)
            LOG_RETURN(false, PTS_LOG,
                       "rebuild: anchored ticket absent from CAS");
        found->covered = true;
    }
    return true;
}

static void pts_anchor_verification(const struct pr_issuer *was,
                                     struct pr_issuer *now)
{
    for (size_t j = 0; j < was->cp_count; j++) {
        const struct pr_checkpoint *prior = &was->cps[j];
        if (!prior->verified) continue;
        for (size_t k = 0; k < now->cp_count; k++)
            if (memcmp(now->cps[k].root, prior->root, 32) == 0) {
                now->cps[k].verified = true;
                break;
            }
    }
    now->mmr = was->mmr;
    memcpy(now->last_root, was->last_root, sizeof(now->last_root));
    now->verified_count = was->verified_count;
}

static bool pts_restore_anchored_fork(const struct vcs_proof_receiver *old,
                                      struct vcs_proof_receiver *next)
{
    for (size_t i = 0; i < old->issuer_count; i++) {
        const struct pr_issuer *was = &old->issuers[i];
        if (!was->verified_count) continue;
        struct pr_issuer *now = pts_find_issuer(next, was->pubkey);
        /* Only a newly observed ticket fork may use this anchor. A known or
         * newly listed checkpoint fork keeps the existing explicit refusal:
         * choosing a branch after replay would change verified ancestry. */
        if (!now || !now->equivocating ||
            was->cp_count != was->verified_count ||
            now->cp_count != was->cp_count)
            continue;
        bool lost = false;
        if (!pts_anchor_checkpoints(was, now, &lost)) return false;
        if (!lost) continue;
        if (!pts_anchor_tickets(old, was, next)) return false;
        pts_anchor_verification(was, now);
    }
    return true;
}

/* A signed fork is self-certifying: two signature-valid tickets at one
 * sequence, or two checkpoints of one size, under one key. When a complete
 * scan finds one for an issuer the live receiver already holds, but the
 * rebuilt view as a whole must be refused, the live receiver still records
 * that distrust. Marking an issuer equivocating only removes eligibility;
 * it can never create a HIT, and nothing else in the live view changes. */
struct pts_fork_marks {
    struct vcs_proof_receiver *live;
    const struct vcs_proof_receiver *staging;
    size_t marked;
};

static bool pts_fork_unmarked(const struct vcs_proof_receiver *live,
                              const struct vcs_proof_receiver *staging,
                              size_t i)
{
    const struct pr_issuer *was = &live->issuers[i];
    const struct pr_issuer *now = pr_issuer_find(staging, was->pubkey);
    return !was->equivocating && now && now->equivocating;
}

static void pts_mark_forks(void *context)
{
    struct pts_fork_marks *m = context;
    for (size_t i = 0; i < m->live->issuer_count; i++)
        if (pts_fork_unmarked(m->live, m->staging, i)) {
            m->live->issuers[i].equivocating = true;
            m->marked++;
        }
}

static void pts_record_forks(struct vcs_proof_receiver *live,
                             const struct vcs_proof_receiver *staging,
                             struct vcs_package_store *store,
                             const struct pts_chunks *chunks,
                             uint64_t generation)
{
    bool any = false;
    for (size_t i = 0; !any && i < live->issuer_count; i++)
        any = pts_fork_unmarked(live, staging, i);
    if (!any) return;
    struct pts_fork_marks m = {live, staging, 0};
    if (vcs_package_store_publish_checked(
            store, generation, (const uint8_t (*)[32])chunks->hashes,
            chunks->count, pts_mark_forks, &m) != VCS_PACKAGE_STORE_PAGE_OK) {
        LOG_ERROR(PTS_LOG, "rebuild: signed fork evidence changed before it "
                           "could be recorded");
        return;
    }
    LOG_WARN(PTS_LOG, "rebuild refused; recorded %zu equivocating signed "
                      "issuers in the live receiver", m.marked);
}

static void pts_report_counts(const struct pts_counts *n, size_t *tickets,
                              size_t *checkpoints, size_t *skipped)
{
    if (tickets) *tickets = n->tickets;
    if (checkpoints) *checkpoints = n->checkpoints;
    if (skipped) *skipped = n->skipped;
}

static bool pts_anchor_head_verified(
    const struct vcs_proof_receiver *staging,
    struct vcs_package_store *store,
    const struct vcs_proof_receiver_anchor *anchor)
{
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    if (!vcs_proof_checkpoint_store_load(
            store, anchor->checkpoint_blob_root, anchor->issuer_pubkey,
            wire, root))
        LOG_RETURN(false, PTS_LOG, "rebuild: anchored head missing from CAS");
    const struct pr_issuer *issuer =
        pr_issuer_find(staging, anchor->issuer_pubkey);
    if (!issuer || issuer->equivocating || issuer->verified_count == 0 ||
        memcmp(issuer->last_root, root, sizeof(root)) != 0)
        LOG_RETURN(false, PTS_LOG,
                   "rebuild: anchored head is absent, stale or forked");
    for (size_t i = 0; i < issuer->cp_count; i++) {
        const struct pr_checkpoint *cp = &issuer->cps[i];
        if (cp->verified && memcmp(cp->root, root, sizeof(root)) == 0 &&
            memcmp(cp->wire, wire, sizeof(wire)) == 0 &&
            cp->leaf_count == issuer->mmr.num_leaves)
            return true;
    }
    LOG_RETURN(false, PTS_LOG, "rebuild: anchored head lost verification");
}

static bool pts_verify_anchor_heads(
    const struct vcs_proof_receiver *staging,
    struct vcs_package_store *store,
    const struct vcs_proof_receiver_anchor *anchors, size_t anchor_count)
{
    for (size_t i = 0; i < anchor_count; i++)
        if (!pts_anchor_head_verified(staging, store, &anchors[i]))
            return false;
    return true;
}

/* After the view is published or refused, make any trusted signer's fork
 * the complete scan found durable, so compaction cannot erase it before the
 * next start. This runs after the guarded publication because a pin moves
 * the store generation. */
static void pts_keep_evidence(const struct vcs_proof_receiver *published,
                              const struct vcs_proof_receiver *refused,
                              struct vcs_package_store *store, bool ok,
                              const struct pts_scope *scope)
{
    if (scope->evidence_trust)
        (void)pr_fork_evidence_pin(ok ? published : refused, store,
                                   scope->evidence_trust);
}

/* One line for the whole scan, however many unsigned copies it skipped,
 * and the typed reason a refused rebuild leaves on the caller's receiver. */
static void pts_note_outcome(struct vcs_proof_receiver *r, bool ok,
                             const struct pts_counts *n)
{
    if (n->unsigned_tickets)
        LOG_WARN(PTS_LOG, "rebuild: skipped %zu listed tickets whose "
                          "signature does not verify", n->unsigned_tickets);
    r->rebuild_refusal = NULL;
    if (!ok)
        r->rebuild_refusal =
            n->refusal ? n->refusal : VCS_PROOF_REBUILD_WHY_REFUSED;
}

static bool pts_rebuild_bounded(struct vcs_proof_receiver *r,
                                struct vcs_package_store *store,
                                size_t max_catalog_rows, size_t *tickets,
                                size_t *checkpoints, size_t *skipped,
                                uint64_t *generation_out,
                                const struct pts_scope *scope)
{
    struct pts_counts n = {0};
    pts_report_counts(&n, tickets, checkpoints, skipped);
    if (generation_out) *generation_out = 0;
    if (!r || !store)
        LOG_RETURN(false, PTS_LOG, "rebuild: null argument");
    struct vcs_proof_receiver *staging = vcs_proof_receiver_new();
    if (!staging)
        LOG_RETURN(false, PTS_LOG, "rebuild: cannot allocate staging receiver");
    struct pts_cps cps = {0};
    struct pts_chunks chunks = {0};
    uint64_t generation = 0;
    bool scanned = pts_scan(staging, store, &cps, &n, &chunks, &generation,
                            max_catalog_rows);
    bool ok = scanned &&
              pts_replay(r, staging, &cps, &n, scope) &&
              pts_restore_anchored_fork(r, staging) &&
              pts_preserves_prior(r, staging) &&
              pts_verify_anchor_heads(staging, store, scope->anchors,
                                      scope->anchor_count);
    free(cps.items);
    if (ok) ok = pts_publish_rechecked(r, staging, store, &chunks, generation);
    else if (scanned)
        pts_record_forks(r, staging, store, &chunks, generation);
    if (scanned) pts_keep_evidence(r, staging, store, ok, scope);
    if (ok && generation_out) *generation_out = generation;
    pts_note_outcome(r, ok, &n);
    if (!ok)
        n = (struct pts_counts){0};
    vcs_proof_receiver_free(staging);
    free(chunks.hashes);
    pts_report_counts(&n, tickets, checkpoints, skipped);
    return ok;
}

static void pts_refuse_outputs(size_t *tickets, size_t *checkpoints,
                               size_t *skipped, uint64_t *generation_out)
{
    if (tickets) *tickets = 0;
    if (checkpoints) *checkpoints = 0;
    if (skipped) *skipped = 0;
    if (generation_out) *generation_out = 0;
}

bool vcs_proof_receiver_rebuild_bounded(
    struct vcs_proof_receiver *r, struct vcs_package_store *store,
    size_t max_catalog_rows, size_t *tickets, size_t *checkpoints,
    size_t *skipped)
{
    const struct pts_scope scope = {NULL, 0, NULL};
    return pts_rebuild_bounded(r, store, max_catalog_rows, tickets,
                               checkpoints, skipped, NULL, &scope);
}

bool vcs_proof_receiver_rebuild_anchored_bounded(
    struct vcs_proof_receiver *r, struct vcs_package_store *store,
    const struct vcs_proof_receiver_anchor *anchors, size_t anchor_count,
    size_t max_catalog_rows, size_t *tickets, size_t *checkpoints,
    size_t *skipped, uint64_t *generation_out)
{
    if (!anchors || anchor_count == 0) {
        pts_refuse_outputs(tickets, checkpoints, skipped, generation_out);
        LOG_RETURN(false, PTS_LOG, "rebuild: anchored head set is empty");
    }
    return vcs_proof_receiver_rebuild_with_policy(
        r, store, NULL, anchors, anchor_count, max_catalog_rows, tickets,
        checkpoints, skipped, generation_out);
}

bool vcs_proof_receiver_rebuild_with_policy(
    struct vcs_proof_receiver *r, struct vcs_package_store *store,
    const struct vcs_proof_reuse_policy *trust,
    const struct vcs_proof_receiver_anchor *anchors, size_t anchor_count,
    size_t max_catalog_rows, size_t *tickets, size_t *checkpoints,
    size_t *skipped, uint64_t *generation_out)
{
    if ((anchor_count && !anchors) || anchor_count > max_catalog_rows) {
        pts_refuse_outputs(tickets, checkpoints, skipped, generation_out);
        LOG_RETURN(false, PTS_LOG,
                   "rebuild: anchored head set is invalid or over budget");
    }
    const struct pts_scope scope = {anchors, anchor_count, trust};
    return pts_rebuild_bounded(r, store, max_catalog_rows, tickets,
                               checkpoints, skipped, generation_out, &scope);
}
