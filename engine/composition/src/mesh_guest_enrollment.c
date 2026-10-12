/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Checked public enrollment records for the configured guest launch owner. */
#include "config/mesh_guest_service.h"
#include "codec/cursor.h"
#include "platform/positioned_file.h"
#include "base/log_macros.h"
#include "crypto/sha256.h"
#include <string.h>
#define GE_WIRE_BYTES 264u
static bool ge_refuse(const char *phase)
{
    LOG_WARN("guest.enrollment", "public enrollment refused during %s", phase);
    return false;
}
static bool ge_nonzero(const uint8_t bytes[32])
{
    uint8_t value = 0;
    for (size_t i = 0; i < 32; i++) value |= bytes[i];
    return value != 0;
}
static bool ge_fields(const struct mesh_guest_enrollment_record *r, bool initial)
{
    return r && ge_nonzero(r->guest_id) && ge_nonzero(r->kernel) &&
        ge_nonzero(r->root) && ge_nonzero(r->helper) && ge_nonzero(r->profile) &&
        ge_nonzero(r->owner_grant) && (initial || ge_nonzero(r->ssh_fingerprint)) &&
        r->volume_file && r->volume_bytes && r->generation;
}
static bool ge_handle(struct platform_private_file *file, uint64_t bytes,
    struct platform_positioned_file_snapshot *snapshot)
{
    if (!file || !file->locked) return false;
    struct platform_positioned_file view = {.native = file->native};
    return platform_positioned_file_is_private(&view) &&
        platform_positioned_file_is_current_user_only(&view) &&
        platform_positioned_file_snapshot(&view, snapshot) && snapshot->size == bytes;
}
bool mesh_guest_enrollment_handles(const struct mesh_guest_enrollment_admission *a,
    struct platform_positioned_file_snapshot *credential)
{
    struct platform_positioned_file_snapshot volume;
    return a && ge_handle(a->volume, a->expected.volume_bytes, &volume) &&
        volume.volume == a->expected.volume_device && volume.file_low == a->expected.volume_file &&
        volume.file_high == 0 && ge_handle(a->credential, 32, credential);
}
static bool ge_encode(const struct mesh_guest_enrollment_record *r, uint8_t wire[GE_WIRE_BYTES])
{
    struct zcl_codec_writer w;
    size_t written = 0;
    zcl_codec_writer_init(&w, wire, GE_WIRE_BYTES);
    return zcl_codec_write_u64le(&w, 1) &&
        zcl_codec_write_bytes(&w, r->guest_id, 32) &&
        zcl_codec_write_bytes(&w, r->ssh_fingerprint, 32) &&
        zcl_codec_write_bytes(&w, r->kernel, 32) && zcl_codec_write_bytes(&w, r->root, 32) &&
        zcl_codec_write_bytes(&w, r->helper, 32) && zcl_codec_write_bytes(&w, r->profile, 32) &&
        zcl_codec_write_bytes(&w, r->owner_grant, 32) &&
        zcl_codec_write_u64le(&w, r->volume_device) && zcl_codec_write_u64le(&w, r->volume_file) &&
        zcl_codec_write_u64le(&w, r->volume_bytes) && zcl_codec_write_u64le(&w, r->generation) &&
        zcl_codec_writer_finish(&w, &written) && written == GE_WIRE_BYTES;
}
static bool ge_decode(const uint8_t wire[GE_WIRE_BYTES], struct mesh_guest_enrollment_record *r, bool initial)
{
    struct zcl_codec_reader c;
    uint64_t version = 0;
    zcl_codec_reader_init(&c, wire, GE_WIRE_BYTES);
    return zcl_codec_read_u64le(&c, &version) && version == 1 &&
        zcl_codec_read_bytes(&c, r->guest_id, 32) &&
        zcl_codec_read_bytes(&c, r->ssh_fingerprint, 32) &&
        zcl_codec_read_bytes(&c, r->kernel, 32) && zcl_codec_read_bytes(&c, r->root, 32) &&
        zcl_codec_read_bytes(&c, r->helper, 32) && zcl_codec_read_bytes(&c, r->profile, 32) &&
        zcl_codec_read_bytes(&c, r->owner_grant, 32) &&
        zcl_codec_read_u64le(&c, &r->volume_device) && zcl_codec_read_u64le(&c, &r->volume_file) &&
        zcl_codec_read_u64le(&c, &r->volume_bytes) && zcl_codec_read_u64le(&c, &r->generation) &&
        zcl_codec_reader_finish(&c) && ge_fields(r, initial);
}
bool mesh_guest_enrollment_read(struct platform_private_file *file,
    struct mesh_guest_enrollment_record *out)
{
    uint8_t wire[GE_WIRE_BYTES];
    struct platform_positioned_file_snapshot before, after;
    struct mesh_guest_enrollment_record parsed = {0};
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !ge_handle(file, GE_WIRE_BYTES, &before) ||
        !platform_private_file_read_at(file, wire, sizeof(wire), 0) ||
        !ge_handle(file, GE_WIRE_BYTES, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after) || !ge_decode(wire, &parsed, false))
        return ge_refuse("retained record read");
    *out = parsed;
    return true;
}
bool mesh_guest_enrollment_equal(const struct mesh_guest_enrollment_record *a,
    const struct mesh_guest_enrollment_record *b)
{
    return a && b && !memcmp(a->guest_id, b->guest_id, 32) &&
        !memcmp(a->ssh_fingerprint, b->ssh_fingerprint, 32) &&
        !memcmp(a->kernel, b->kernel, 32) && !memcmp(a->root, b->root, 32) &&
        !memcmp(a->helper, b->helper, 32) && !memcmp(a->profile, b->profile, 32) &&
        !memcmp(a->owner_grant, b->owner_grant, 32) &&
        a->volume_device == b->volume_device && a->volume_file == b->volume_file &&
        a->volume_bytes == b->volume_bytes && a->generation == b->generation;
}
static bool ge_recover(const struct mesh_guest_enrollment_admission *a,
    struct mesh_guest_enrollment_record *record)
{
    if (a->initial_destination || !mesh_guest_enrollment_read(a->record, record) ||
        !mesh_guest_enrollment_equal(record, &a->expected)) return ge_refuse("recovery binding");
    return true;
}
bool mesh_guest_enrollment_admit(const struct mesh_guest_enrollment_admission *a,
    struct mesh_guest_enrollment_record *record,
    struct platform_positioned_file_snapshot *credential)
{
    if (!a || !record || !credential) return ge_refuse("missing owner admission");
    if (a->mode == MESH_GUEST_ENROLLMENT_OFF) return true;
    if (!ge_fields(&a->expected, a->mode == MESH_GUEST_ENROLLMENT_INITIAL) ||
        !mesh_guest_enrollment_handles(a, credential)) return ge_refuse("owner descriptor binding");
    if (a->mode == MESH_GUEST_ENROLLMENT_RECOVER) return ge_recover(a, record);
    if (a->mode != MESH_GUEST_ENROLLMENT_INITIAL || a->record ||
        ge_nonzero(a->expected.ssh_fingerprint) || !a->initial_destination ||
        !platform_private_path_absent(a->initial_destination)) return ge_refuse("initial enrollment only");
    *record = a->expected;
    return true;
}
bool mesh_guest_enrollment_publish(const char *destination,
    const struct mesh_guest_enrollment_record *record, struct platform_private_file *owned)
{
    char resolved[1024], parent[1024];
    uint8_t wire[GE_WIRE_BYTES];
    if (!destination || !record || !owned || !ge_fields(record, false) ||
        !ge_encode(record, wire) ||
        !platform_private_destination_resolve(destination, resolved, sizeof(resolved), parent, sizeof(parent)) ||
        !platform_private_file_create_locked(resolved, owned)) return ge_refuse("exclusive initial publication");
    if (!platform_private_file_write_at(owned, wire, sizeof(wire), 0) ||
        !platform_private_file_authority_flush(owned) || !platform_private_parent_flush(parent))
        return ge_refuse("durable initial publication; reconciliation required");
    return true;
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Separate protected codec; PUBLIC decoding retains its original framing.
 * Checksums describe bytes and never grant provider or image authority. */
#define GE_PROTECTED_PREFIX_BYTES 296u
static bool ge_protected_fields(const struct mesh_guest_protected_enrollment_extension *r)
{
    if (!r || !r->highest_reserved || r->revoked_through > r->highest_reserved)
        return false;
    bool initial = r->phase == MESH_GUEST_PROTECTED_INITIAL_ATTEMPTED;
    if (!initial && r->phase != MESH_GUEST_PROTECTED_READY) return false;
    return ge_fields(&r->enrollment, initial) &&
        (!initial || !ge_nonzero(r->enrollment.ssh_fingerprint));
}
static void ge_protected_hash(const uint8_t *wire, uint8_t out[32])
{
    struct sha256_ctx h;
    sha256_init(&h);
    sha256_write(&h, wire, GE_PROTECTED_PREFIX_BYTES);
    sha256_finalize(&h, out);
}
bool mesh_guest_protected_enrollment_encode(
    const struct mesh_guest_protected_enrollment_extension *r,
    uint8_t *out, size_t size)
{
    uint8_t wire[MESH_GUEST_PROTECTED_ENROLLMENT_WIRE_BYTES] = {0};
    uint8_t record[GE_WIRE_BYTES];
    if (!out || size != sizeof wire || !ge_protected_fields(r) ||
        !ge_encode(&r->enrollment, record)) return ge_refuse("protected encode fields");
    struct zcl_codec_writer w;
    size_t written = 0;
    zcl_codec_writer_init(&w, wire, GE_PROTECTED_PREFIX_BYTES);
    if (!zcl_codec_write_u64le(&w, 2) ||
        !zcl_codec_write_u32le(&w, (uint32_t)r->phase) ||
        !zcl_codec_write_u32le(&w, 0) ||
        !zcl_codec_write_bytes(&w, record, sizeof record) ||
        !zcl_codec_write_u64le(&w, r->highest_reserved) ||
        !zcl_codec_write_u64le(&w, r->revoked_through) ||
        !zcl_codec_writer_finish(&w, &written) || written != GE_PROTECTED_PREFIX_BYTES)
        return ge_refuse("protected encode framing");
    ge_protected_hash(wire, wire + GE_PROTECTED_PREFIX_BYTES);
    memcpy(out, wire, sizeof wire);
    return true;
}
static bool ge_protected_read(const uint8_t *wire, uint8_t record[GE_WIRE_BYTES],
    struct mesh_guest_protected_enrollment_extension *r)
{
    struct zcl_codec_reader c;
    uint64_t version = 0;
    uint32_t phase = 0, reserved = 0;
    zcl_codec_reader_init(&c, wire, GE_PROTECTED_PREFIX_BYTES);
    bool ok = zcl_codec_read_u64le(&c, &version) && version == 2 &&
        zcl_codec_read_u32le(&c, &phase) &&
        (phase == MESH_GUEST_PROTECTED_INITIAL_ATTEMPTED || phase == MESH_GUEST_PROTECTED_READY) &&
        zcl_codec_read_u32le(&c, &reserved) && reserved == 0 &&
        zcl_codec_read_bytes(&c, record, GE_WIRE_BYTES) &&
        zcl_codec_read_u64le(&c, &r->highest_reserved) &&
        zcl_codec_read_u64le(&c, &r->revoked_through) && zcl_codec_reader_finish(&c);
    if (ok) r->phase = (enum mesh_guest_protected_enrollment_phase)phase;
    return ok;
}
bool mesh_guest_protected_enrollment_decode(const uint8_t *wire, size_t size,
    struct mesh_guest_protected_enrollment_extension *out)
{
    struct mesh_guest_protected_enrollment_extension r = {0};
    uint8_t record[GE_WIRE_BYTES], checksum[32];
    if (out) memset(out, 0, sizeof(*out));
    if (!wire || !out || size != MESH_GUEST_PROTECTED_ENROLLMENT_WIRE_BYTES)
        return ge_refuse("protected decode size");
    ge_protected_hash(wire, checksum);
    if (memcmp(checksum, wire + GE_PROTECTED_PREFIX_BYTES, sizeof checksum))
        return ge_refuse("protected decode checksum");
    if (!ge_protected_read(wire, record, &r)) return ge_refuse("protected decode framing");
    if (!ge_decode(record, &r.enrollment, r.phase == MESH_GUEST_PROTECTED_INITIAL_ATTEMPTED) ||
        !ge_protected_fields(&r)) return ge_refuse("protected decode fields");
    *out = r;
    return true;
}
static_assert(GE_PROTECTED_PREFIX_BYTES == 8u + 4u + 4u + GE_WIRE_BYTES + 8u + 8u);
static_assert(MESH_GUEST_PROTECTED_ENROLLMENT_WIRE_BYTES == GE_PROTECTED_PREFIX_BYTES + 32u);
/* Owner serializes ALL extension writers using the
 * retained volume FD lock; no guest/credential I/O during this transaction.
 * UNKNOWN is sticky in this owner operation and never authorizes delivery.
 * Outputs are initialized closed; paths are owner-approved private siblings.
 * This does not provide rollback-resistant storage or failed-revoke reboot policy. */
static bool ge_protected_unknown(struct mesh_guest_protected_enrollment_operation *op, const char *why)
{
    if (op) op->unknown = true;
    return ge_refuse(why);
}
static bool ge_protected_volume(struct mesh_guest_protected_enrollment_operation *op)
{
    struct platform_positioned_file_snapshot s;
    return op && !op->unknown && ge_handle(op->volume, op->expected.volume_bytes, &s) &&
        s.volume == op->expected.volume_device && s.file_low == op->expected.volume_file &&
        s.file_high == 0;
}
static bool ge_protected_equal(const struct mesh_guest_protected_enrollment_extension *a,
    const struct mesh_guest_protected_enrollment_extension *b)
{
    return mesh_guest_enrollment_equal(&a->enrollment, &b->enrollment) &&
        a->phase == b->phase && a->highest_reserved == b->highest_reserved &&
        a->revoked_through == b->revoked_through;
}
static bool ge_protected_read_locked(struct platform_private_file *file,
    struct mesh_guest_protected_enrollment_extension *out)
{
    uint8_t wire[MESH_GUEST_PROTECTED_ENROLLMENT_WIRE_BYTES];
    struct platform_positioned_file_snapshot before, after;
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !ge_handle(file, sizeof wire, &before) ||
        !platform_private_file_read_at(file, wire, sizeof wire, 0) ||
        !ge_handle(file, sizeof wire, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after) ||
        !mesh_guest_protected_enrollment_decode(wire, sizeof wire, out))
        return ge_refuse("protected retained read");
    return true;
}
/* Keeps the reopened record locked on success. Does not adopt a cached inode
 * as serialization authority: the borrowed volume lock remains held throughout. */
static bool ge_protected_open_current(struct mesh_guest_protected_enrollment_operation *op,
    const char *path, struct platform_private_file *owned,
    struct mesh_guest_protected_enrollment_extension *out)
{
    if (!ge_protected_volume(op) || !platform_private_file_open_locked(path, owned) ||
        !ge_protected_read_locked(owned, out) ||
        !mesh_guest_enrollment_equal(&out->enrollment, &op->expected)) {
        platform_private_file_close(owned);
        return ge_protected_unknown(op, "protected current binding");
    }
    return true;
}
/* The caller has already read/validated the old state under the volume lock.
 * Fresh stage path is never reused. No cleanup/deletion on ambiguous failure. */
struct ge_protected_paths {
    char final[1024], parent[1024], stage[1024];
};
static bool ge_protected_paths_prepare(const char *destination, const char *stage_path,
    struct ge_protected_paths *paths)
{
    char stage_parent[1024];
    return platform_private_destination_resolve(destination, paths->final,
        sizeof paths->final, paths->parent, sizeof paths->parent) &&
        platform_private_destination_resolve(stage_path, paths->stage,
        sizeof paths->stage, stage_parent, sizeof stage_parent) &&
        !strcmp(paths->parent, stage_parent) && strcmp(paths->final, paths->stage);
}
static bool ge_protected_publish_stage(struct mesh_guest_protected_enrollment_operation *op,
    const struct ge_protected_paths *paths, bool initial, const uint8_t *wire,
    struct platform_private_file *staged)
{
    bool exists = false;
    if (!platform_private_file_write_at(staged, wire,
        MESH_GUEST_PROTECTED_ENROLLMENT_WIRE_BYTES, 0) ||
        !platform_private_file_authority_flush(staged) || !ge_protected_volume(op))
        return false;
    if (initial)
        return platform_private_file_publish_no_clobber(staged, paths->stage,
            paths->final, &exists) && !exists;
    return platform_private_file_replace(staged, paths->stage, paths->final);
}
static bool ge_protected_readback(struct mesh_guest_protected_enrollment_operation *op,
    const struct ge_protected_paths *paths,
    const struct mesh_guest_protected_enrollment_extension *next,
    struct platform_private_file *readback)
{
    struct mesh_guest_protected_enrollment_extension observed;
    if (!platform_private_parent_flush(paths->parent) ||
        !ge_protected_open_current(op, paths->final, readback, &observed) ||
        !ge_protected_equal(&observed, next) || !ge_protected_volume(op)) {
        platform_private_file_close(readback);
        return ge_protected_unknown(op, "protected durable publication; reconciliation required");
    }
    return true;
}
static bool ge_protected_store(struct mesh_guest_protected_enrollment_operation *op,
    const char *destination, const char *stage_path, bool initial,
    const struct mesh_guest_protected_enrollment_extension *next,
    struct platform_private_file *readback)
{
    struct ge_protected_paths paths;
    uint8_t wire[MESH_GUEST_PROTECTED_ENROLLMENT_WIRE_BYTES];
    struct platform_private_file staged;
    platform_private_file_init(&staged);
    if (!ge_protected_volume(op) || !next || !readback ||
        !mesh_guest_enrollment_equal(&next->enrollment, &op->expected) ||
        !mesh_guest_protected_enrollment_encode(next, wire, sizeof wire) ||
        !ge_protected_paths_prepare(destination, stage_path, &paths) ||
        !platform_private_file_create_locked(paths.stage, &staged))
        return ge_protected_unknown(op, "protected publication preflight");
    bool ok = ge_protected_publish_stage(op, &paths, initial, wire, &staged);
    platform_private_file_close(&staged);
    if (!ok) {
        platform_private_file_close(readback);
        return ge_protected_unknown(op, "protected durable publication; reconciliation required");
    }
    return ge_protected_readback(op, &paths, next, readback);
}
bool mesh_guest_protected_enrollment_reserve(struct mesh_guest_protected_enrollment_operation *op,
    const char *destination, const char *stage,
    struct platform_private_file *readback, uint64_t *reserved)
{
    struct mesh_guest_protected_enrollment_extension r;
    struct platform_private_file current;
    platform_private_file_init(&current);
    if (reserved) *reserved = 0;
    bool ok = reserved && ge_protected_open_current(op, destination, &current, &r);
    platform_private_file_close(&current);
    if (!ok || r.phase != MESH_GUEST_PROTECTED_READY || r.highest_reserved == UINT64_MAX)
        return ge_protected_unknown(op, "protected reservation binding or exhaustion");
    r.highest_reserved++;
    if (!ge_protected_store(op, destination, stage, false, &r, readback)) return false;
    *reserved = r.highest_reserved;
    return true;
}
bool mesh_guest_protected_enrollment_initial(struct mesh_guest_protected_enrollment_operation *op,
    const char *destination, const char *stage, struct platform_private_file *readback)
{
    struct mesh_guest_protected_enrollment_extension r = {0};
    if (!op) return ge_refuse("protected initial owner missing");
    r.enrollment = op->expected;
    r.phase = MESH_GUEST_PROTECTED_INITIAL_ATTEMPTED;
    r.highest_reserved = 1;
    return ge_protected_store(op, destination, stage, true, &r, readback);
}
/* Called only AFTER separately validated identity publication. The fingerprint
 * is not trusted because this helper received it; manager owns that evidence. */
bool mesh_guest_protected_enrollment_ready(struct mesh_guest_protected_enrollment_operation *op,
    const char *destination, const char *stage, const uint8_t fingerprint[32],
    struct platform_private_file *readback)
{
    struct platform_private_file current;
    struct mesh_guest_protected_enrollment_extension r;
    platform_private_file_init(&current);
    bool ok = fingerprint && ge_nonzero(fingerprint) &&
        ge_protected_open_current(op, destination, &current, &r);
    platform_private_file_close(&current);
    if (!ok || r.phase != MESH_GUEST_PROTECTED_INITIAL_ATTEMPTED ||
        r.highest_reserved != 1 || r.revoked_through != 0)
        return ge_protected_unknown(op, "protected ready transition");
    r.phase = MESH_GUEST_PROTECTED_READY;
    memcpy(r.enrollment.ssh_fingerprint, fingerprint, 32);
    /* Expected tuple changes only the fingerprint after verified identity. */
    struct mesh_guest_protected_enrollment_operation publication = *op;
    publication.expected = r.enrollment;
    if (!ge_protected_store(&publication, destination, stage, false, &r, readback))
        return ge_protected_unknown(op, "protected ready durability");
    op->expected = r.enrollment;
    return true;
}
/* Owner FIRST terminalizes live provider/prevents next drive. This helper does
 * not claim that action or lease drain; it only persists the revocation floor. */
bool mesh_guest_protected_enrollment_revoke(struct mesh_guest_protected_enrollment_operation *op,
    const char *destination, const char *stage, uint64_t generation,
    struct platform_private_file *readback)
{
    struct platform_private_file current;
    struct mesh_guest_protected_enrollment_extension r;
    platform_private_file_init(&current);
    bool ok = ge_protected_open_current(op, destination, &current, &r);
    platform_private_file_close(&current);
    if (!ok || !generation || generation != r.highest_reserved ||
        generation < r.revoked_through)
        return ge_protected_unknown(op, "protected revoke generation");
    r.revoked_through = generation;
    return ge_protected_store(op, destination, stage, false, &r, readback);
}
/* Metadata-only owner read; no provider/key authority. Closed initialized output. */
bool mesh_guest_protected_enrollment_read_current(
    struct mesh_guest_protected_enrollment_operation *op, const char *path,
    struct platform_private_file *owned,
    struct mesh_guest_protected_enrollment_extension *out)
{
    return ge_protected_open_current(op, path, owned, out);
}
