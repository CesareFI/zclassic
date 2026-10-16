/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: compare two admitted offline UTXO streams, never repair a store. */
#include "config/utxo_copy_compare.h"
#include "utxo_copy_capture_internal.h"
#include "coins/utxo_commitment.h"
#include "core/amount.h"
#include "script/script.h"
#include "crypto/sha3.h"
#include <limits.h>
#include <string.h>

struct ucc_stream {
    struct coins_kv_read_snapshot_row row;
    uint8_t last_txid[32]; uint32_t last_vout;
    uint64_t count;
    struct sha3_256_ctx root;
    bool have_last, done;
};
static bool ucc_nonzero(const uint8_t bytes[32])
{
    uint8_t any = 0;
    for (unsigned i = 0; i < 32; i++) any |= bytes[i];
    return any != 0;
}
static bool ucc_text(const char *s)
{
    if (!s || !s[0]) return false;
    for (size_t i = 0; i < 512; i++) if (!s[i]) return true;
    return false;
}
static bool ucc_cancelled(const struct utxo_copy_compare_inputs *in)
{
    return in->cancelled && in->cancelled(in->cancel_ctx);
}
static bool ucc_increment(uint64_t *n)
{
    if (*n == UINT64_MAX) return false;
    ++*n; return true;
}
static int ucc_key(const struct coins_kv_read_snapshot_row *a,
                   const struct coins_kv_read_snapshot_row *b)
{
    int cmp = memcmp(a->txid, b->txid, 32);
    return cmp ? cmp : a->vout < b->vout ? -1 : a->vout > b->vout ? 1 : 0;
}
/* Both adapters already validate SQLite storage classes; the core additionally
 * enforces semantic shape/order before counting or hashing typed rows. */
static bool ucc_row(struct ucc_stream *s, int32_t frontier)
{
    struct coins_kv_read_snapshot_row *r = &s->row;
    int order = s->have_last ? memcmp(r->txid, s->last_txid, 32) : 1;
    if (!MoneyRange(r->value) || r->script_len > MAX_SCRIPT_SIZE ||
        (r->script_len && !r->script) || r->height < 0 || r->height >= frontier ||
        (s->have_last && (order < 0 || (order == 0 && r->vout <= s->last_vout))) ||
        !ucc_increment(&s->count)) return false;
    utxo_commitment_sha3_write_record(&s->root, r->txid, r->vout, r->value,
        r->script, (uint32_t)r->script_len, (uint32_t)r->height, (uint8_t)r->is_coinbase);
    memcpy(s->last_txid, r->txid, 32); s->last_vout = r->vout; s->have_last = true;
    return true;
}
static bool ucc_next_authority(struct consensus_state_artifact_coins *it,
                               struct ucc_stream *s, int32_t frontier)
{
    enum coins_kv_read_snapshot_step step = consensus_state_artifact_coins_next(it, &s->row);
    if (step == COINS_KV_READ_SNAPSHOT_DONE) { s->done = true; return true; }
    return step == COINS_KV_READ_SNAPSHOT_ROW && ucc_row(s, frontier);
}
static bool ucc_next_projection(struct utxo_mirror_read_snapshot *it,
                                struct ucc_stream *s, int32_t frontier)
{
    enum coins_kv_read_snapshot_step step = utxo_mirror_read_snapshot_next(it, &s->row);
    if (step == COINS_KV_READ_SNAPSHOT_DONE) { s->done = true; return true; }
    return step == COINS_KV_READ_SNAPSHOT_ROW && ucc_row(s, frontier);
}
static uint32_t ucc_fields(const struct coins_kv_read_snapshot_row *a,
                            const struct coins_kv_read_snapshot_row *p)
{
    uint32_t fields = 0;
    if (a->value != p->value) fields |= UTXO_COPY_FIELD_VALUE;
    if (a->script_len != p->script_len ||
        (a->script_len && memcmp(a->script, p->script, a->script_len) != 0))
        fields |= UTXO_COPY_FIELD_SCRIPT;
    if (a->height != p->height) fields |= UTXO_COPY_FIELD_HEIGHT;
    if (a->is_coinbase != p->is_coinbase) fields |= UTXO_COPY_FIELD_COINBASE;
    return fields;
}
static void ucc_script(const struct coins_kv_read_snapshot_row *row,
                        int64_t *value, uint64_t *len, uint8_t digest[32])
{
    *value = row->value; *len = row->script_len;
    struct sha3_256_ctx ctx; sha3_256_init(&ctx);
    if (row->script_len) sha3_256_write(&ctx, row->script, row->script_len);
    sha3_256_finalize(&ctx, digest);
}
static void ucc_example(struct utxo_copy_compare_report *r, unsigned limit,
                         enum utxo_copy_example_kind kind, uint32_t fields,
                         const struct coins_kv_read_snapshot_row *a,
                         const struct coins_kv_read_snapshot_row *p)
{
    if (r->example_count == limit) { r->examples_truncated = true; return; }
    struct utxo_copy_compare_example *e = &r->examples[r->example_count++];
    e->kind = kind; e->fields = fields;
    const struct coins_kv_read_snapshot_row *key = a ? a : p;
    memcpy(e->txid, key->txid, 32); e->vout = key->vout;
    if (a) ucc_script(a, &e->authority_value, &e->authority_script_len, e->authority_script_sha3);
    if (p) ucc_script(p, &e->projection_value, &e->projection_script_len, e->projection_script_sha3);
}
static bool ucc_capture_identity(const struct utxo_copy_capture_assertion *c)
{
    return c && c->manifest_validated && c->binding == UTXO_COPY_CAPTURE_EXTERNALLY_ATTESTED &&
        ucc_text(c->capture_id) && ucc_text(c->owner_evidence_ref) && c->generation_present;
}
static bool ucc_capture_frontier(const struct utxo_copy_capture_assertion *c,
                                  const struct consensus_state_bundle_manifest *m)
{
    return m->height >= 0 && m->height != INT32_MAX &&
        c->next_height == m->height + 1 && c->last_applied_height == m->height;
}
static bool ucc_capture_branch(const struct utxo_copy_capture_assertion *c,
                                const struct consensus_state_bundle_manifest *m)
{
    return ucc_nonzero(c->block_hash) && memcmp(c->block_hash, m->block_hash, 32) == 0 &&
        c->projection_branch_present && c->projection_branch_height == m->height &&
        memcmp(c->projection_branch_hash, m->block_hash, 32) == 0;
}
static enum utxo_copy_compare_failure ucc_capture(
    const struct utxo_copy_capture_assertion *c,
    const struct consensus_state_bundle_manifest *m, const uint8_t file[32])
{
    if (!ucc_capture_identity(c)) return UTXO_COPY_FAILURE_CAPTURE;
    if (!ucc_nonzero(c->network_genesis) ||
        memcmp(c->network_genesis, c->expected_network_genesis, 32) != 0)
        return UTXO_COPY_FAILURE_NETWORK;
    if (!ucc_capture_frontier(c, m)) return UTXO_COPY_FAILURE_FRONTIER;
    if (!ucc_capture_branch(c, m)) return UTXO_COPY_FAILURE_BRANCH;
    if (memcmp(c->authority_file_sha3, file, 32) != 0 ||
        memcmp(c->artifact_digest, m->artifact_digest, 32) != 0)
        return UTXO_COPY_FAILURE_ARTIFACT;
    return UTXO_COPY_FAILURE_NONE;
}
static enum utxo_copy_compare_status ucc_failure(
    const struct utxo_copy_compare_inputs *in, struct consensus_state_artifact_coins *it,
    struct utxo_copy_compare_report *out, enum utxo_copy_compare_status status,
    enum utxo_copy_compare_failure failure)
{
    if (it) consensus_state_artifact_coins_abort(it);
    if (in && in->projection && *in->projection &&
        !utxo_mirror_read_snapshot_abort(in->projection)) {
        status = UTXO_COPY_COMPARE_ERROR; failure = UTXO_COPY_FAILURE_CLEANUP;
    }
    if (out) {
        memset(out, 0, sizeof(*out)); out->status = status; out->failure = failure;
    }
    return status;
}
/* One call owns these temporary streams/results. Checked finish clears the
 * iterator immediately; failure aborts any remaining iterator through the
 * existing cleanup path. Outer artifact evidence remains caller-owned. */
struct ucc_run {
    const struct utxo_copy_capture_assertion *capture;
    struct consensus_state_bundle_manifest manifest;
    uint8_t file[32];
    struct consensus_state_artifact_coins *iterator;
    struct ucc_stream authority, projection;
    struct utxo_copy_compare_report result;
    struct utxo_mirror_read_result finished_projection;
};
static bool ucc_inputs_valid(const struct utxo_copy_compare_inputs *in,
                               const struct utxo_copy_compare_report *out)
{
    return in && out && in->authority && in->projection && *in->projection &&
        in->example_limit <= UTXO_COPY_COMPARE_EXAMPLE_MAX;
}
static enum utxo_copy_compare_failure ucc_admit(
    const struct utxo_copy_compare_inputs *in, struct ucc_run *run,
    enum utxo_copy_compare_status *status)
{
    if (!in->capture) {
        *status = UTXO_COPY_COMPARE_NOT_COMPARABLE;
        return UTXO_COPY_FAILURE_CAPTURE;
    }
    run->capture = utxo_copy_capture_bound_fields(in->capture, in->authority, *in->projection);
    if (!run->capture) return UTXO_COPY_FAILURE_INPUT;
    if (!consensus_state_artifact_evidence_manifest_copy(in->authority, &run->manifest) ||
        !consensus_state_artifact_evidence_file_digest(in->authority, run->file))
        return UTXO_COPY_FAILURE_ARTIFACT;
    enum utxo_copy_compare_failure failure = ucc_capture(run->capture, &run->manifest, run->file);
    if (failure != UTXO_COPY_FAILURE_NONE) *status = UTXO_COPY_COMPARE_NOT_COMPARABLE;
    return failure;
}
static enum utxo_copy_compare_failure ucc_begin(
    const struct utxo_copy_compare_inputs *in, struct ucc_run *run)
{
    if (!consensus_state_artifact_coins_begin(in->authority, &run->iterator))
        return UTXO_COPY_FAILURE_AUTHORITY_BEGIN;
    sha3_256_init(&run->authority.root); sha3_256_init(&run->projection.root);
    if (!ucc_next_authority(run->iterator, &run->authority, run->manifest.height + 1))
        return UTXO_COPY_FAILURE_AUTHORITY_NEXT;
    if (!ucc_next_projection(*in->projection, &run->projection, run->manifest.height + 1))
        return UTXO_COPY_FAILURE_PROJECTION_NEXT;
    return UTXO_COPY_FAILURE_NONE;
}
static bool ucc_classify(struct ucc_run *run, unsigned limit, int key)
{
    struct utxo_copy_compare_report *r = &run->result;
    const struct coins_kv_read_snapshot_row *a = &run->authority.row, *p = &run->projection.row;
    uint64_t *counter;
    if (key < 0) {
        counter = &r->authority_only;
        ucc_example(r, limit, UTXO_COPY_AUTHORITY_ONLY, 0, a, NULL);
    } else if (key > 0) {
        counter = &r->projection_only;
        ucc_example(r, limit, UTXO_COPY_PROJECTION_ONLY, 0, NULL, p);
    } else {
        uint32_t fields = ucc_fields(a, p);
        counter = fields ? &r->shared_different : &r->shared_equal;
        if (fields) {
            r->shared_fields |= fields;
            ucc_example(r, limit, UTXO_COPY_SHARED_DIFFERENT, fields, a, p);
        }
    }
    return ucc_increment(counter);
}
static enum utxo_copy_compare_failure ucc_merge(
    const struct utxo_copy_compare_inputs *in, struct ucc_run *run)
{
    struct ucc_stream *a = &run->authority, *p = &run->projection;
    while (!a->done || !p->done) {
        if (ucc_cancelled(in)) return UTXO_COPY_FAILURE_CANCEL;
        int key = a->done ? 1 : p->done ? -1 : ucc_key(&a->row, &p->row);
        if (!ucc_classify(run, in->example_limit, key)) return UTXO_COPY_FAILURE_COUNTER;
        if (key <= 0 && !ucc_next_authority(run->iterator, a, run->manifest.height + 1))
            return UTXO_COPY_FAILURE_AUTHORITY_NEXT;
        if (key >= 0 && !ucc_next_projection(*in->projection, p, run->manifest.height + 1))
            return UTXO_COPY_FAILURE_PROJECTION_NEXT;
    }
    sha3_256_finalize(&a->root, run->result.authority_root);
    sha3_256_finalize(&p->root, run->result.projection_root);
    return UTXO_COPY_FAILURE_NONE;
}
static bool ucc_result_bound(const struct utxo_copy_compare_inputs *in,
                               const struct ucc_run *run)
{
    const struct utxo_mirror_read_result *p = &run->finished_projection;
    return run->authority.count == run->manifest.utxo_count &&
        memcmp(run->result.authority_root, run->manifest.utxo_root, 32) == 0 &&
        p->count == run->projection.count && p->next_height == run->capture->next_height &&
        memcmp(p->root, run->result.projection_root, 32) == 0 &&
        memcmp(p->file_sha3, run->capture->projection_file_sha3, 32) == 0 &&
        consensus_state_artifact_evidence_revalidate(in->authority);
}
static enum utxo_copy_compare_failure ucc_finish(
    const struct utxo_copy_compare_inputs *in, struct ucc_run *run)
{
    if (ucc_cancelled(in)) return UTXO_COPY_FAILURE_CANCEL;
    bool finished = consensus_state_artifact_coins_finish(run->iterator);
    run->iterator = NULL; /* consumed even on failure */
    if (!finished) return UTXO_COPY_FAILURE_AUTHORITY_FINISH;
    if (!utxo_mirror_read_snapshot_finish(in->projection, &run->finished_projection))
        return UTXO_COPY_FAILURE_PROJECTION_FINISH;
    if (ucc_cancelled(in)) return UTXO_COPY_FAILURE_CANCEL;
    if (!ucc_result_bound(in, run)) return UTXO_COPY_FAILURE_RESULT_BINDING;
    return UTXO_COPY_FAILURE_NONE;
}
static void ucc_complete(struct ucc_run *run)
{
    struct utxo_copy_compare_report *r = &run->result;
    const struct utxo_copy_capture_assertion *c = run->capture;
    r->authority_count = run->authority.count; r->projection_count = run->projection.count;
    r->count_delta_negative = r->authority_only > r->projection_only;
    r->count_delta_magnitude = r->count_delta_negative ?
        r->authority_only - r->projection_only : r->projection_only - r->authority_only;
    r->status = r->authority_only || r->projection_only || r->shared_different ?
        UTXO_COPY_COMPARE_DIFFERENT : UTXO_COPY_COMPARE_EQUAL;
    r->capture_binding = UTXO_COPY_CAPTURE_EXTERNALLY_ATTESTED;
    r->complete = true; r->counts_valid = true; r->roots_valid = true;
    r->next_height = c->next_height; r->last_applied_height = run->manifest.height;
    memcpy(r->authority_file_sha3, run->file, 32);
    memcpy(r->projection_file_sha3, run->finished_projection.file_sha3, 32);
    memcpy(r->artifact_digest, run->manifest.artifact_digest, 32);
    memcpy(r->network_genesis, c->network_genesis, 32);
    memcpy(r->block_hash, run->manifest.block_hash, 32);
    r->authority_generation = c->authority_generation;
}
enum utxo_copy_compare_status utxo_copy_compare_run(
    const struct utxo_copy_compare_inputs *in, struct utxo_copy_compare_report *out)
{
    struct ucc_run run = {0};
    enum utxo_copy_compare_status status = UTXO_COPY_COMPARE_ERROR;
    enum utxo_copy_compare_failure failure = UTXO_COPY_FAILURE_INPUT;
    if (out) memset(out, 0, sizeof(*out));
    if (!ucc_inputs_valid(in, out)) goto failed;
    failure = ucc_admit(in, &run, &status);
    if (failure != UTXO_COPY_FAILURE_NONE) goto failed;
    if (ucc_cancelled(in)) { failure = UTXO_COPY_FAILURE_CANCEL; goto failed; }
    failure = ucc_begin(in, &run);
    if (failure != UTXO_COPY_FAILURE_NONE) goto failed;
    failure = ucc_merge(in, &run);
    if (failure != UTXO_COPY_FAILURE_NONE) goto failed;
    failure = ucc_finish(in, &run);
    if (failure != UTXO_COPY_FAILURE_NONE) goto failed;
    ucc_complete(&run);
    /* Final revalidation may hash a large artifact. Poll again before any
     * completed report can escape after that noninterruptible work. */
    if (ucc_cancelled(in)) { failure = UTXO_COPY_FAILURE_CANCEL; goto failed; }
    *out = run.result;
    return out->status;
failed:
    if (failure == UTXO_COPY_FAILURE_CANCEL) status = UTXO_COPY_COMPARE_CANCELLED;
    return ucc_failure(in, run.iterator, out, status, failure);
}
