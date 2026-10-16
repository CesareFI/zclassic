/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: validate exact accepted capture statements against admitted inputs. */
#include "utxo_copy_capture_internal.h"
#include "json/json.h"
#include "base/hex.h"
#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include "storage/consensus_state_bundle_codec.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define UCV_MANIFEST_MAX 16384u
struct ucv_claim {
    int32_t next, last, projection_next, branch;
    uint64_t projection_size;
    enum utxo_mirror_byte_order producer_order;
};
struct utxo_copy_capture {
    struct ucv_claim claim;
    struct json_value manifest;
    struct utxo_copy_capture_assertion fields;
    const struct consensus_state_artifact_evidence *authority;
    struct utxo_mirror_read_snapshot *projection;
    struct utxo_mirror_read_attestation admitted;
};
/* Flat spelling of contract.json/capture_manifest.required_fields. No trust
 * flags are legal members. All fields required; unavailable branch uses null
 * height/hash and yields NOT_COMPARABLE, never inferred branch identity. */
static const char *const ucv_keys[] = {
    "schema", "network_genesis", "capture_id", "capture_method", "producer_id", "producer_byte_order",
    "owner_evidence_ref", "quiescence_start_us", "quiescence_end_us",
    "quiescence_scope", "overlay_disposition", "authority_generation",
    "authority_file_sha3", "artifact_digest", "projection_file_sha3",
    "projection_size", "authority_next_height", "authority_last_applied_height",
    "authority_block_hash", "projection_next_height", "projection_branch_height",
    "projection_branch_hash", "authority_source_object_id", "projection_source_object_id",
    "authority_wal_disposition", "authority_shm_disposition", "authority_journal_disposition",
    "projection_wal_disposition", "projection_shm_disposition", "projection_journal_disposition", "backup_completion_ref"
};
static bool ucv_shape(const struct json_value *v)
{
    size_t count = sizeof(ucv_keys) / sizeof(ucv_keys[0]);
    if (v->type != JSON_OBJ || v->num_children != count) return false;
    for (size_t i = 0; i < count; i++) {
        if (!v->keys[i]) return false;
        bool known = false;
        for (size_t j = 0; j < count; j++)
            if (strcmp(v->keys[i], ucv_keys[j]) == 0) known = true;
        if (!known) return false;
        for (size_t j = 0; j < i; j++)
            if (strcmp(v->keys[i], v->keys[j]) == 0) return false;
        enum json_type t = v->children[i].type;
        if (t != JSON_STR && t != JSON_INT && t != JSON_NULL) return false;
    }
    return true;
}
static const char *ucv_text(const struct json_value *v, const char *key)
{
    const struct json_value *s = json_get(v, key);
    if (!s || s->type != JSON_STR || !s->val.s) return NULL;
    size_t n = strlen(s->val.s);
    if (!n || n > 511) return NULL;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s->val.s[i] < 32 || (unsigned char)s->val.s[i] == 127)
            return NULL;
    return s->val.s;
}
static bool ucv_equal(const struct json_value *v, const char *key, const char *text)
{
    const char *s = ucv_text(v, key);
    return s && strcmp(s, text) == 0;
}
/* Canonical uint64 decimal strings avoid JSON_INT's signed-64 limit. */
static bool ucv_u64(const struct json_value *v, const char *key, uint64_t *out)
{
    const char *s = ucv_text(v, key);
    if (!s || strlen(s) > 20 || (s[0] == '0' && s[1])) return false;
    uint64_t n = 0;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        unsigned d = (unsigned)(s[i] - '0');
        if (n > (UINT64_MAX - d) / 10) return false;
        n = n * 10 + d;
    }
    *out = n; return true;
}
static bool ucv_int(const struct json_value *v, const char *key, int64_t max, int64_t *out)
{
    const struct json_value *n = json_get(v, key);
    if (!n || n->type != JSON_INT || n->val.i < 0 || n->val.i > max) return false;
    *out = n->val.i; return true;
}
/* Hash strings encode byte[0] first, lowercase only. For genesis/block hashes
 * these are uint256.data/bundle BLOB byte order, NOT display-hash order.
 * SHA3 strings likewise encode digest bytes, without reversal. */
static bool ucv_hash(const struct json_value *v, const char *key, uint8_t out[32])
{
    const char *s = ucv_text(v, key);
    if (!s || strlen(s) != 64) return false;
    /* The canonical decoder checks lowercase alphabet and exact length,
     * zeroing output on refusal. Do not maintain a second nibble codec. */
    return zcl_hex_decode_lower(s, out, 32);
}
static bool ucv_text_fields(struct utxo_copy_capture *c)
{
    const char *const required[] = {
        "capture_id", "owner_evidence_ref", "capture_method", "producer_id",
        "producer_byte_order", "quiescence_scope", "overlay_disposition",
        "authority_source_object_id", "projection_source_object_id", "backup_completion_ref"
    };
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++)
        if (!ucv_text(&c->manifest, required[i])) return false;
    c->fields.capture_id = ucv_text(&c->manifest, "capture_id");
    c->fields.owner_evidence_ref = ucv_text(&c->manifest, "owner_evidence_ref");
    return true;
}
static bool ucv_interval(const struct json_value *v)
{
    int64_t start, end;
    return ucv_int(v, "quiescence_start_us", INT64_MAX, &start) &&
        ucv_int(v, "quiescence_end_us", INT64_MAX, &end) && start <= end;
}
static bool ucv_frontiers(struct utxo_copy_capture *c)
{
    const struct json_value *v = &c->manifest;
    int64_t next, last, projection_next;
    if (!ucv_int(v, "authority_next_height", INT32_MAX, &next) ||
        !ucv_int(v, "authority_last_applied_height", INT32_MAX, &last) ||
        !ucv_int(v, "projection_next_height", INT32_MAX, &projection_next) ||
        !ucv_u64(v, "authority_generation", &c->fields.authority_generation) ||
        !ucv_u64(v, "projection_size", &c->claim.projection_size)) return false;
    c->claim.next = (int32_t)next; c->claim.last = (int32_t)last;
    c->claim.projection_next = (int32_t)projection_next;
    return true;
}
static bool ucv_hash_fields(struct utxo_copy_capture *c)
{
    const struct json_value *v = &c->manifest;
    struct utxo_copy_capture_assertion *f = &c->fields;
    return ucv_hash(v, "network_genesis", f->network_genesis) &&
        ucv_hash(v, "authority_file_sha3", f->authority_file_sha3) &&
        ucv_hash(v, "artifact_digest", f->artifact_digest) &&
        ucv_hash(v, "projection_file_sha3", f->projection_file_sha3) &&
        ucv_hash(v, "authority_block_hash", f->block_hash);
}
static enum utxo_copy_capture_status ucv_branch(struct utxo_copy_capture *c)
{
    const struct json_value *v = &c->manifest;
    const struct json_value *height = json_get(v, "projection_branch_height");
    const struct json_value *hash = json_get(v, "projection_branch_hash");
    /* Shape already established both required members. */
    if (height->type == JSON_NULL && hash->type == JSON_NULL)
        return UTXO_COPY_CAPTURE_NOT_COMPARABLE;
    int64_t branch;
    if (!ucv_int(v, "projection_branch_height", INT32_MAX, &branch) ||
        !ucv_hash(v, "projection_branch_hash", c->fields.projection_branch_hash))
        return UTXO_COPY_CAPTURE_ERROR;
    c->claim.branch = (int32_t)branch;
    return UTXO_COPY_CAPTURE_VALIDATED;
}
static bool ucv_order(struct utxo_copy_capture *c)
{
    if (ucv_equal(&c->manifest, "producer_byte_order", "little"))
        c->claim.producer_order = UTXO_MIRROR_LITTLE_ENDIAN;
    else if (ucv_equal(&c->manifest, "producer_byte_order", "big"))
        c->claim.producer_order = UTXO_MIRROR_BIG_ENDIAN;
    else return false;
    return true;
}
static bool ucv_sidecars(const struct json_value *v)
{
    const char *const names[] = {
        "authority_wal_disposition", "authority_shm_disposition", "authority_journal_disposition",
        "projection_wal_disposition", "projection_shm_disposition", "projection_journal_disposition"
    };
    /* Finalized INPUT subset only. No assertion here that a live producer
     * lacked WAL. Backup evidence must attest committed source WAL inclusion.
     * Copied projection siblings are also mechanically checked by reader. */
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (!ucv_equal(v, names[i], "absent")) return false;
    return true;
}
static bool ucv_capture_dispositions(const struct json_value *v)
{
    bool method = ucv_equal(v, "capture_method", "quiesced_copy") ||
        ucv_equal(v, "capture_method", "completed_backup");
    bool overlay = ucv_equal(v, "overlay_disposition", "absent") ||
        ucv_equal(v, "overlay_disposition", "flushed");
    return method && overlay && ucv_sidecars(v);
}
static bool ucv_claim_matches_reader(const struct utxo_copy_capture *c)
{
    const struct ucv_claim *q = &c->claim;
    const struct utxo_mirror_read_attestation *p = &c->admitted;
    /* Widen before +1: malformed INT32_MAX last height must not overflow. */
    return (int64_t)q->next == (int64_t)q->last + 1 &&
        q->projection_next == q->next && q->branch == q->last &&
        p->next_height == q->next && p->producer_order == q->producer_order &&
        p->schema_profile == UTXO_MIRROR_SCHEMA_V1 && p->sidecars_all_absent &&
        p->file.size == q->projection_size &&
        memcmp(p->file_sha3, c->fields.projection_file_sha3, 32) == 0 &&
        memcmp(c->fields.projection_branch_hash, c->fields.block_hash, 32) == 0;
}
static void ucv_publish_fields(struct utxo_copy_capture *c)
{
    c->fields.next_height = c->claim.next;
    c->fields.last_applied_height = c->claim.last;
    c->fields.projection_branch_height = c->claim.branch;
    c->fields.projection_branch_present = true;
    c->fields.generation_present = true;
}
static enum utxo_copy_capture_status ucv_parse(struct utxo_copy_capture *c)
{
    if (!ucv_shape(&c->manifest) ||
        !ucv_equal(&c->manifest, "schema", "zcl.utxo_copy_capture.v1"))
        return UTXO_COPY_CAPTURE_ERROR;
    if (!ucv_text_fields(c) || !ucv_interval(&c->manifest)) return UTXO_COPY_CAPTURE_ERROR;
    if (!ucv_frontiers(c) || !ucv_hash_fields(c) || !ucv_order(c)) return UTXO_COPY_CAPTURE_ERROR;
    enum utxo_copy_capture_status branch = ucv_branch(c);
    if (branch != UTXO_COPY_CAPTURE_VALIDATED) return branch;
    if (!ucv_capture_dispositions(&c->manifest)) return UTXO_COPY_CAPTURE_NOT_COMPARABLE;
    if (!ucv_claim_matches_reader(c)) return UTXO_COPY_CAPTURE_NOT_COMPARABLE;
    ucv_publish_fields(c);
    return UTXO_COPY_CAPTURE_VALIDATED;
}
static bool ucv_projection_bound(const struct utxo_copy_capture *c)
{
    struct utxo_mirror_read_attestation now;
    if (!utxo_mirror_read_snapshot_attestation(c->projection, &now)) return false;
    return now.next_height == c->admitted.next_height &&
        now.producer_order == c->admitted.producer_order &&
        now.schema_profile == UTXO_MIRROR_SCHEMA_V1 && now.sidecars_all_absent &&
        platform_positioned_file_snapshot_equal(&now.file, &c->admitted.file) &&
        memcmp(now.file_sha3, c->fields.projection_file_sha3, 32) == 0;
}
static enum utxo_copy_capture_status ucv_artifact_bound(const struct utxo_copy_capture *c)
{
    struct consensus_state_bundle_manifest m;
    uint8_t file[32];
    if (!consensus_state_artifact_evidence_manifest_copy(c->authority, &m) ||
        !consensus_state_artifact_evidence_file_digest(c->authority, file))
        return UTXO_COPY_CAPTURE_ERROR;
    if (m.height != c->fields.last_applied_height ||
        memcmp(m.block_hash, c->fields.block_hash, 32) != 0 ||
        memcmp(m.artifact_digest, c->fields.artifact_digest, 32) != 0 ||
        memcmp(file, c->fields.authority_file_sha3, 32) != 0)
        return UTXO_COPY_CAPTURE_NOT_COMPARABLE;
    return UTXO_COPY_CAPTURE_VALIDATED;
}
const struct utxo_copy_capture_assertion *utxo_copy_capture_bound_fields(
    const struct utxo_copy_capture *c,
    const struct consensus_state_artifact_evidence *a,
    struct utxo_mirror_read_snapshot *p)
{
    if (!c || c->authority != a || c->projection != p) return NULL;
    if (!ucv_projection_bound(c)) return NULL;
    if (ucv_artifact_bound(c) != UTXO_COPY_CAPTURE_VALIDATED) return NULL;
    return &c->fields;
}
static bool ucv_request_valid(const struct utxo_copy_capture_request *r)
{
    return r && r->manifest && r->manifest_len && r->manifest_len <= UCV_MANIFEST_MAX &&
        r->network && r->authority && r->projection;
}
static enum utxo_copy_capture_status ucv_accepted(const struct utxo_copy_capture_request *r)
{
    if (!r->accepted_manifest_sha3) return UTXO_COPY_CAPTURE_NOT_COMPARABLE;
    uint8_t digest[32]; struct sha3_256_ctx ctx;
    sha3_256_init(&ctx); sha3_256_write(&ctx, (const unsigned char *)r->manifest, r->manifest_len);
    sha3_256_finalize(&ctx, digest);
    if (memcmp(digest, r->accepted_manifest_sha3, 32) != 0) return UTXO_COPY_CAPTURE_NOT_COMPARABLE;
    return UTXO_COPY_CAPTURE_VALIDATED;
}
static enum utxo_copy_capture_status ucv_admit(struct utxo_copy_capture *c,
                                             const struct utxo_copy_capture_request *r)
{
    if (!json_read(&c->manifest, r->manifest, r->manifest_len)) return UTXO_COPY_CAPTURE_ERROR;
    if (!utxo_mirror_read_snapshot_attestation(r->projection, &c->admitted))
        return UTXO_COPY_CAPTURE_ERROR;
    enum utxo_copy_capture_status status = ucv_parse(c);
    if (status != UTXO_COPY_CAPTURE_VALIDATED) return status;
    memcpy(c->fields.expected_network_genesis, r->network->consensus.hashGenesisBlock.data, 32);
    if (memcmp(c->fields.expected_network_genesis, c->fields.network_genesis, 32) != 0)
        return UTXO_COPY_CAPTURE_NOT_COMPARABLE;
    status = ucv_artifact_bound(c);
    if (status != UTXO_COPY_CAPTURE_VALIDATED) return status;
    if (!ucv_projection_bound(c)) return UTXO_COPY_CAPTURE_ERROR;
    return UTXO_COPY_CAPTURE_VALIDATED;
}
enum utxo_copy_capture_status utxo_copy_capture_open(
    const struct utxo_copy_capture_request *r, struct utxo_copy_capture **out)
{
    if (!out) return UTXO_COPY_CAPTURE_ERROR;
    *out = NULL;
    if (!ucv_request_valid(r)) return UTXO_COPY_CAPTURE_ERROR;
    enum utxo_copy_capture_status status = ucv_accepted(r);
    if (status != UTXO_COPY_CAPTURE_VALIDATED) return status;
    struct utxo_copy_capture *c = zcl_calloc(1, sizeof(*c), "validated UTXO capture");
    if (!c) return UTXO_COPY_CAPTURE_ERROR;
    c->authority = r->authority; c->projection = r->projection;
    status = ucv_admit(c, r);
    if (status != UTXO_COPY_CAPTURE_VALIDATED) {
        utxo_copy_capture_free(c); return status;
    }
    c->fields.manifest_validated = true;
    c->fields.binding = UTXO_COPY_CAPTURE_EXTERNALLY_ATTESTED;
    *out = c; return UTXO_COPY_CAPTURE_VALIDATED;
}
void utxo_copy_capture_free(struct utxo_copy_capture *c)
{
    if (c) { json_free(&c->manifest); free(c); }
}
