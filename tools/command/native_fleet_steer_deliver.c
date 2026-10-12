/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: fleet.steer.deliver and fleet.steer.inbox. A grant holder with the
 * deliver scope uploads one C source file in 16 KiB chunks into the inert
 * quarantine inbox (native_fleet_steer_inbox.c). Receipt compiles, executes,
 * dispatches and writes nothing outside that inbox. SHA3-512 proves exact
 * bytes, not C correctness or trust. */
#include "command/native_command.h"

#include "base/hex.h"
#include "command/native_fleet.h"
#include "command/native_fleet_steer_inbox.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define FD_LOG "fleet.steer.deliver"
#define FD_SHA_PREFIX 16
#define FD_IDENTITY_PREFIX 12

/* The credential a call speaks under; re-checked inside the commit. */
struct fd_auth {
    char grant[33];
    char from[65];
    char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
};

struct fd_in {
    const char *grant, *from, *ref, *upload_id, *name, *sha, *hex;
    long long size, offset;
    size_t n;
    unsigned char data[FSI_CHUNK];
};

/* Transient refusals: the same call may succeed later. */
static bool fd_retryable(const char *suffix)
{
    static const char *const names[] = {"STORE", "BUSY", "RATE", "BYTE_RATE",
                                        "OUTSTANDING", "BINDINGS"};
    size_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strcmp(suffix, names[i]) == 0)
            return true;
    return false;
}

static void fd_fail(struct zcl_command_reply *reply, const char *suffix,
                    const char *message, long long next_offset, bool mutated)
{
    char code[64], ev[96];
    if (strncmp(suffix, "STEER_", 6) == 0)
        (void)snprintf(code, sizeof(code), "%s", suffix);
    else
        (void)snprintf(code, sizeof(code), "STEER_DELIVER_%s", suffix);
    (void)snprintf(ev, sizeof(ev), "next_offset=%lld mutated=%s", next_offset,
                   mutated ? "true" : "uncertain");
    LOG_ERROR(FD_LOG, "%s: %s (%s)", code, message, ev);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute",
                           fd_retryable(suffix), mutated, message, ev);
}

#if !defined(_WIN32)

/* ── input ───────────────────────────────────────────────────────────────── */

static const char *fd_str(const struct json_value *in, const char *key)
{
    const struct json_value *v = json_get(in, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* Integers only: no float coercion, no string numbers. */
static bool fd_int(const struct json_value *in, const char *key,
                   long long *out)
{
    const struct json_value *v = json_get(in, key);
    if (!v || v->type != JSON_INT)
        return false;
    *out = (long long)json_get_int(v);
    return true;
}

static bool fd_keys_ok(const struct json_value *in)
{
    static const char *const allowed[] = {
        "grant", "from", "ref", "upload_id", "name",
        "size", "sha3_512", "offset", "data_hex"};
    size_t i, j, k;
    if (!in || in->type != JSON_OBJ)
        return false;
    for (i = 0; i < in->num_children; i++) {
        bool known = false;
        for (j = 0; j < sizeof(allowed) / sizeof(allowed[0]); j++)
            known = known || strcmp(in->keys[i], allowed[j]) == 0;
        for (k = i + 1; known && k < in->num_children; k++)
            known = strcmp(in->keys[i], in->keys[k]) != 0;
        if (!known)
            return false;
    }
    return true;
}

static bool fd_ref_ok(const char *s)
{
    size_t i, n = s ? strlen(s) : 0;
    if (n < 1 || n > 64)
        return false;
    for (i = 0; i < n; i++) {
        char c = s[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') || c == '_' || c == '.' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

static bool fd_alnum(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z');
}

/* Name characters: alphanumeric, underscore, hyphen, dot; no "..". */
static bool fd_name_chars_ok(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (!fd_alnum(s[i]) && s[i] != '_' && s[i] != '-' && s[i] != '.')
            return false;
        if (s[i] == '.' && i + 1 < n && s[i + 1] == '.')
            return false;
    }
    return true;
}

/* ASCII basename, .c or .h, display metadata only. */
static bool fd_name_ok(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n < 3 || n > 64 || !fd_alnum(s[0]))
        return false;
    if (s[n - 2] != '.' || (s[n - 1] != 'c' && s[n - 1] != 'h'))
        return false;
    return fd_name_chars_ok(s, n);
}

static bool fd_hex_ok(const char *s, size_t n)
{
    unsigned char scratch[64];
    return s && strlen(s) == n && n / 2 <= sizeof(scratch) &&
           zcl_hex_decode_lower(s, scratch, n / 2);
}

static const char *fd_fields(const struct json_value *in, struct fd_in *d)
{
    d->grant = fd_str(in, "grant");
    d->from = fd_str(in, "from");
    d->ref = fd_str(in, "ref");
    d->upload_id = fd_str(in, "upload_id");
    d->name = fd_str(in, "name");
    d->sha = fd_str(in, "sha3_512");
    d->hex = fd_str(in, "data_hex");
    if (!d->from || !d->ref || !d->upload_id || !d->name || !d->sha ||
        !d->hex || !fd_int(in, "size", &d->size) ||
        !fd_int(in, "offset", &d->offset))
        return "BAD_INPUT";
    if (!fd_ref_ok(d->ref) || !fd_name_ok(d->name) ||
        !fd_hex_ok(d->upload_id, FSI_ID_HEX) ||
        !fd_hex_ok(d->sha, FSI_SHA_HEX))
        return "BAD_INPUT";
    return NULL;
}

/* Reject bad schema, size, order and hex before any state is touched. */
static const char *fd_parse(const struct json_value *in, struct fd_in *d)
{
    long long left;
    const char *err;
    memset(d, 0, sizeof(*d));
    if (!fd_keys_ok(in))
        return "BAD_INPUT";
    err = fd_fields(in, d);
    if (err)
        return err;
    if (d->size < 1 || d->size > (long long)FSI_SIZE_MAX)
        return "SIZE";
    if (d->offset < 0 || d->offset % (long long)FSI_CHUNK != 0 ||
        d->offset >= d->size)
        return "OFFSET";
    left = d->size - d->offset;
    d->n = left > (long long)FSI_CHUNK ? FSI_CHUNK : (size_t)left;
    if (strlen(d->hex) != 2u * d->n)
        return "PART";
    return zcl_hex_decode_lower(d->hex, d->data, d->n) ? NULL : "BAD_INPUT";
}

/* ── authority ───────────────────────────────────────────────────────────── */

static const char *fd_admit(const struct fd_in *d, struct fd_auth *a)
{
    char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
    const char *err = zcl_fleet_steer_grant_sender(
        d->grant, "deliver", d->from, a->from, sizeof(a->from), binding,
        sizeof(binding));
    if (err)
        return err;
    snprintf(a->grant, sizeof(a->grant), "%s", d->grant);
    snprintf(a->binding, sizeof(a->binding), "%s", binding);
    return NULL;
}

/* Inside the commit critical section: same credential, same binding. */
static const char *fd_recheck(void *ctx)
{
    const struct fd_auth *a = ctx;
    char label[65], binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
    const char *err = zcl_fleet_steer_grant_sender(
        a->grant, "deliver", a->from, label, sizeof(label), binding,
        sizeof(binding));
    if (err)
        return err;
    return strcmp(binding, a->binding) == 0 ? NULL : "STEER_GRANT_UNKNOWN";
}

/* ── deliver ─────────────────────────────────────────────────────────────── */

static void fd_identity(const struct fsi_upload *u, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%.*s-%s", FD_IDENTITY_PREFIX, u->binding, u->id);
}

static void fd_reply(struct zcl_command_reply *reply,
                     const struct fsi_upload *u, bool dup)
{
    char identity[64];
    bool done = strcmp(u->meta.state, "quarantined") == 0;
    fd_identity(u, identity, sizeof(identity));
    (void)json_push_kv_str(&reply->data, "upload", identity);
    (void)json_push_kv_str(&reply->data, "ref", u->meta.ref);
    (void)json_push_kv_int(&reply->data, "size", u->meta.size);
    (void)json_push_kv_int(&reply->data, "next_offset", u->meta.offset);
    (void)json_push_kv_str(&reply->data, "upload_state",
                           done ? "quarantined" : "receiving");
    (void)json_push_kv_bool(&reply->data, "duplicate", dup);
    if (done)
        (void)json_push_kv_str(&reply->data, "verified_sha3_512",
                               u->meta.digest);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void fd_meta_from(const struct fd_in *d, struct fsi_meta *m)
{
    memset(m, 0, sizeof(*m));
    snprintf(m->ref, sizeof(m->ref), "%s", d->ref);
    snprintf(m->name, sizeof(m->name), "%s", d->name);
    snprintf(m->digest, sizeof(m->digest), "%s", d->sha);
    m->size = d->size;
}

/* True when the refusal of this call left a committed or unknown change: a
 * failed store is uncertain, and a digest mismatch found by this call has
 * already committed state "failed". */
static bool fd_mutated(const char *err, bool was_failed)
{
    return strcmp(err, "STORE") == 0 ||
           (strcmp(err, "HASH_MISMATCH") == 0 && !was_failed);
}

static void fd_store(const struct fd_in *d, const struct fd_auth *a,
                     struct fsi_upload *u, int root,
                     struct zcl_command_reply *reply)
{
    struct fsi_meta want;
    bool dup = false, was_failed;
    const char *err;
    fd_meta_from(d, &want);
    u->recheck = fd_recheck;
    u->recheck_ctx = (void *)a;
    err = fd_recheck(u->recheck_ctx);
    if (!err)
        err = fsi_begin(u, root, a->binding, d->upload_id, &want,
                        d->offset == 0, d->n);
    if (err) {
        fd_fail(reply, err, "the upload could not be opened", d->offset,
                false);
        return;
    }
    was_failed = strcmp(u->meta.state, "failed") == 0;
    err = fd_recheck(u->recheck_ctx);
    if (!err)
        err = fsi_append(u, d->offset, d->data, d->n, &dup);
    if (err)
        fd_fail(reply, err, "the chunk was not accepted", u->meta.offset,
                fd_mutated(err, was_failed));
    else
        fd_reply(reply, u, dup);
    fsi_end(u);
}

static void fd_deliver_run(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply)
{
    struct fd_in d;
    struct fd_auth a;
    struct fsi_upload u;
    const char *err;
    int root = -1;
    if (!request || !request->input) {
        fd_fail(reply, "BAD_INPUT", "request.input was missing", 0, false);
        return;
    }
    err = fd_parse(request->input, &d);
    if (err) {
        fd_fail(reply, err, "the input was refused before any write", 0,
                false);
        return;
    }
    err = fd_admit(&d, &a);
    if (!err)
        err = fsi_root_open(true, &root);
    if (err) {
        fd_fail(reply, err, "the call was not admitted", 0, false);
        return;
    }
    fd_store(&d, &a, &u, root, reply);
    fsi_root_close(root);
}

/* ── inbox (local reviewer view; never a gateway tool) ───────────────────── */

struct fd_list {
    struct json_value *rows;
    const char *show;
    bool found;
    unsigned damaged;
};

static void fd_row_json(struct json_value *o, const struct fsi_row *r,
                        bool full)
{
    char identity[64], path[4600], prefix[FD_SHA_PREFIX + 1];
    long long now = (long long)platform_time_wall_time_t();
    (void)snprintf(identity, sizeof(identity), "%.*s-%s", FD_IDENTITY_PREFIX,
                   r->binding, r->id);
    (void)json_push_kv_str(o, "upload", identity);
    (void)json_push_kv_str(o, "binding", r->binding);
    (void)json_push_kv_str(o, "ref", r->meta.ref);
    (void)json_push_kv_str(o, "name", r->meta.name);
    (void)json_push_kv_int(o, "size", r->meta.size);
    (void)snprintf(prefix, sizeof(prefix), "%s", r->meta.digest);
    if (strcmp(r->meta.state, "damaged") != 0)
        (void)json_push_kv_str(
            o, strcmp(r->meta.state, "quarantined") == 0 ? "verified_sha3_512"
                                                         : "declared_sha3_512",
            full ? r->meta.digest : prefix);
    (void)json_push_kv_str(o, "state", r->meta.state);
    (void)json_push_kv_int(o, "age_s", now - r->meta.created);
    if (full && fsi_root_path(path, sizeof(path))) {
        char file[4800];
        (void)snprintf(file, sizeof(file), "%s/%s/%s/payload", path,
                       r->binding, r->id);
        (void)json_push_kv_str(o, "payload_path", file);
    }
}

static bool fd_each(const struct fsi_row *r, void *ctx)
{
    struct fd_list *l = ctx;
    struct json_value o;
    char identity[64];
    (void)snprintf(identity, sizeof(identity), "%.*s-%s", FD_IDENTITY_PREFIX,
                   r->binding, r->id);
    if (l->show && strcmp(l->show, identity) != 0)
        return true;
    json_init(&o);
    json_set_object(&o);
    l->damaged += strcmp(r->meta.state, "damaged") == 0;
    fd_row_json(&o, r, l->show != NULL);
    (void)json_push_back(l->rows, &o);
    json_free(&o);
    l->found = true;
    return l->show == NULL;
}

static void fd_inbox_run(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply)
{
    struct json_value rows;
    struct fd_list l;
    unsigned skipped = 0;
    int root = -1;
    const char *err = fsi_root_open(false, &root);
    json_init(&rows);
    json_set_array(&rows);
    l.rows = &rows;
    l.show = request && request->input ? fd_str(request->input, "show") : NULL;
    l.found = false;
    l.damaged = 0;
    if (!err) {
        err = fsi_each(root, fd_each, &l, &skipped);
        fsi_root_close(root);
    }
    if (err && strcmp(err, "NOT_FOUND") != 0)
        fd_fail(reply, err, "the inbox could not be read", 0, false);
    else if (l.show && !l.found)
        fd_fail(reply, "NOT_FOUND", "no such upload", 0, false);
    else {
        (void)json_push_kv(&reply->data, l.show ? "upload" : "uploads",
                               l.show ? json_at(&rows, 0) : &rows);
        (void)json_push_kv_int(&reply->data, "damaged",
                               (long long)(l.damaged + skipped));
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
    }
    json_free(&rows);
}

/* ── drop (owner cleanup of one retained upload) ─────────────────────────── */

struct fd_find {
    const char *identity;
    struct fsi_row row;
    bool found;
};

static bool fd_find_each(const struct fsi_row *r, void *ctx)
{
    struct fd_find *f = ctx;
    char identity[64];
    (void)snprintf(identity, sizeof(identity), "%.*s-%s", FD_IDENTITY_PREFIX,
                   r->binding, r->id);
    if (strcmp(identity, f->identity) != 0)
        return true;
    f->row = *r;
    f->found = true;
    return false;
}

static void fd_drop_run(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    struct fd_find f;
    unsigned skipped = 0;
    int root = -1;
    const char *err;
    memset(&f, 0, sizeof(f));
    f.identity = request && request->input ? fd_str(request->input, "upload")
                                           : NULL;
    if (!f.identity) {
        fd_fail(reply, "BAD_INPUT", "upload names the identity to drop", 0,
                false);
        return;
    }
    err = fsi_root_open(false, &root);
    if (!err)
        err = fsi_each(root, fd_find_each, &f, &skipped);
    if (!err && !f.found)
        err = "NOT_FOUND";
    if (!err)
        err = fsi_drop(root, f.row.binding, f.row.id);
    if (root >= 0)
        fsi_root_close(root);
    if (err) {
        fd_fail(reply, err, "the upload was not dropped", 0, false);
        return;
    }
    (void)json_push_kv_str(&reply->data, "dropped", f.identity);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

#endif /* !_WIN32 */

void zcl_native_handle_fleet_steer_deliver(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)request;
    fd_fail(reply, "UNSUPPORTED", "the quarantine inbox is POSIX only", 0,
            false);
#else
    fd_deliver_run(request, reply);
#endif
}

void zcl_native_handle_fleet_steer_inbox(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)request;
    fd_fail(reply, "UNSUPPORTED", "the quarantine inbox is POSIX only", 0,
            false);
#else
    fd_inbox_run(request, reply);
#endif
}

void zcl_native_handle_fleet_steer_drop(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)request;
    fd_fail(reply, "UNSUPPORTED", "the quarantine inbox is POSIX only", 0,
            false);
#else
    fd_drop_run(request, reply);
#endif
}
