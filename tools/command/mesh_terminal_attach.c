/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the attach bridge for the mesh terminal lane; see
 * mesh_terminal_attach.h. One loop alternates a bounded output drain with a
 * bounded input wait, so the node RPC rate is set by the input timeout
 * (20 ms after activity, 100 ms idle) and never spins. Every RPC refusal is
 * kept verbatim and printed once, after raw mode is off. */

#include "command/mesh_terminal_attach.h"

#include "base/hex.h"
#include "json/json.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MTA_ID_HEX 64u
#define MTA_READ_MAX 8192u
#define MTA_WRITE_CHUNK 1024u
#define MTA_FIELDS_MAX (128u + 2u * MTA_WRITE_CHUNK)
#define MTA_PARAMS_MAX (MTA_FIELDS_MAX + 8u)
#define MTA_DRAIN_ROUNDS 8
#define MTA_POLL_ACTIVE_MS 20
#define MTA_POLL_IDLE_MS 100
#define MTA_OPEN_POLL_MS 100
#define MTA_EXIT_INTERRUPTED 130
#define MTA_EOT 0x04u
#define MTA_OPEN_WAIT_DEFAULT_S 35u
#define MTA_OPEN_WAIT_MAX_S 120u

struct mta_refusal {
    char code[48];
    char message[200];
};

struct mta_view {
    char state[16];
    char verdict[32];
    char close_reason[24];
    uint64_t bytes_in;
    uint64_t bytes_out;
    bool evidence;
    uint64_t evidence_in;
    uint64_t evidence_out;
    uint64_t evidence_duration_s;
    char evidence_reason[24];
};

enum mta_esc { MTA_ESC_BOL, MTA_ESC_TILDE, MTA_ESC_MID };
enum mta_end {
    MTA_END_LIVE,
    MTA_END_REMOTE,
    MTA_END_DETACH,
    MTA_END_STOP,
    MTA_END_FAILED
};
enum mta_pump { MTA_PUMP_IDLE, MTA_PUMP_MORE, MTA_PUMP_ENDED, MTA_PUMP_FAILED };
enum mta_in { MTA_IN_OK, MTA_IN_DETACH, MTA_IN_FAILED };

struct mta {
    const struct mesh_terminal_attach_config *config;
    mesh_terminal_attach_rpc_fn rpc;
    void *rpc_ctx;
    const struct mesh_terminal_attach_tty *tty;
    char id[MTA_ID_HEX + 1];
    int64_t open_deadline_ms;
    enum mta_esc esc;
    bool stdin_open;
    bool active;
    struct mta_refusal ref;
};

/* ── Exit classes ────────────────────────────────────────────────────── */

static const struct {
    const char *name;
    int exit_code;
} g_exit_table[] = {
    {"worker-exited", 0}, {"requested", 0},
    {"bad-request", 2}, {"bad_argument", 2},
    {"confinement-unavailable", 3}, {"noise_transport_disabled", 3},
    {"unavailable", 3}, {"identity_unavailable", 3},
    {"not-paired", 4}, {"not_paired", 4}, {"revoked", 4}, {"expired", 4},
    {"capability-unavailable", 4}, {"authority-changed", 4},
    {"delegation-invalid", 4}, {"session-mismatch", 4},
    {"peer_identity_unavailable", 4},
    {"concurrency-limit", 5}, {"busy", 5}, {"peer_not_connected", 5},
    {"send_failed", 5}, {"idle-timeout", 5}, {"lifetime-limit", 5},
    {"byte-limit", 5}, {"session-lost", 5}, {"shutdown", 5},
    {"NODE_UNAVAILABLE", 5}, {"OPEN_TIMEOUT", 5},
    {"internal", 6}, {"BAD_RPC_BODY", 6}, {"OUTPUT_FAILED", 6},
};

static int mta_exit_for(const char *name)
{
    if (strncmp(name, "INVALID_", 8) == 0)
        return 2;
    for (size_t i = 0; i < sizeof(g_exit_table) / sizeof(g_exit_table[0]); i++)
        if (strcmp(name, g_exit_table[i].name) == 0)
            return g_exit_table[i].exit_code;
    return 1;
}

/* ── JSON helpers ────────────────────────────────────────────────────── */

static const char *mta_cstr(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static void mta_copy_str(const struct json_value *obj, const char *key,
                         char *dst, size_t cap)
{
    const char *s = mta_cstr(obj, key);
    snprintf(dst, cap, "%s", s ? s : "");
}

static uint64_t mta_u64(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    int64_t n = v && v->type == JSON_INT ? json_get_int(v) : 0;
    return n > 0 ? (uint64_t)n : 0;
}

static void mta_set_ref(struct mta *s, const char *code, const char *message)
{
    snprintf(s->ref.code, sizeof(s->ref.code), "%s", code);
    snprintf(s->ref.message, sizeof(s->ref.message), "%s", message);
}

/* Records why a node answer was not an ok body, keeping the node's own
 * words: the lane's {"ok":false,"code","message"}, the RPC client's
 * {"error":{"message"}} transport envelope, or a bare RPC error object. */
static void mta_record_failure(struct mta *s, const struct json_value *body)
{
    const struct json_value *wrapped = json_get(body, "error");
    if (wrapped && wrapped->type == JSON_OBJ && mta_cstr(wrapped, "message")) {
        mta_set_ref(s, "NODE_UNAVAILABLE", mta_cstr(wrapped, "message"));
        return;
    }
    mta_copy_str(body, "code", s->ref.code, sizeof(s->ref.code));
    mta_copy_str(body, "message", s->ref.message, sizeof(s->ref.message));
    if (!s->ref.code[0])
        mta_set_ref(s, mta_cstr(body, "message") ? "RPC_ERROR" : "BAD_RPC_BODY",
                    mta_cstr(body, "message") ? mta_cstr(body, "message")
                                              : "the node refused without a code");
}

/* One RPC. On any failure the refusal (the node's own code and message
 * when it sent them) is recorded and false returned; on success `out` holds
 * the parsed body and the caller frees it. */
static bool mta_call(struct mta *s, const char *method, const char *fields,
                     struct json_value *out)
{
    char params[MTA_PARAMS_MAX];
    int n = snprintf(params, sizeof(params), "[{%s}]", fields);
    if (n < 0 || (size_t)n >= sizeof(params)) {
        mta_set_ref(s, "INVALID_REQUEST", "request exceeds the client bound");
        return false;
    }
    char *raw = s->rpc(s->rpc_ctx, method, params);
    if (!raw) {
        mta_set_ref(s, "NODE_UNAVAILABLE", "the running node did not answer");
        return false;
    }
    json_init(out);
    bool parsed = json_read(out, raw, strlen(raw));
    free(raw);
    if (!parsed || out->type != JSON_OBJ) {
        json_free(out);
        mta_set_ref(s, "BAD_RPC_BODY", "the node returned an unreadable body");
        return false;
    }
    const struct json_value *ok = json_get(out, "ok");
    if (ok && ok->type == JSON_BOOL && json_get_bool(ok))
        return true;
    mta_record_failure(s, out);
    json_free(out);
    return false;
}

static bool mta_call_id(struct mta *s, const char *method, const char *extra,
                        struct json_value *out)
{
    char fields[160];
    snprintf(fields, sizeof(fields), "\"terminal_id\":\"%s\"%s", s->id,
             extra ? extra : "");
    return mta_call(s, method, fields, out);
}

/* ── Session verbs ───────────────────────────────────────────────────── */

static bool mta_open(struct mta *s, uint16_t cols, uint16_t rows)
{
    char fields[160];
    int n = snprintf(fields, sizeof(fields), "\"pairing_id\":\"%s\"",
                     s->config->pairing_id);
    if (cols && rows)
        snprintf(fields + n, sizeof(fields) - (size_t)n,
                 ",\"cols\":%u,\"rows\":%u", (unsigned)cols, (unsigned)rows);
    struct json_value body;
    if (!mta_call(s, "mesh_terminal_open", fields, &body))
        return false;
    const char *id = mta_cstr(&body, "terminal_id");
    bool valid = id && strlen(id) == MTA_ID_HEX;
    if (valid) {
        memcpy(s->id, id, MTA_ID_HEX + 1u);
        uint64_t wait_s = mta_u64(&body, "receipt_timeout_seconds");
        if (wait_s == 0 || wait_s > MTA_OPEN_WAIT_MAX_S)
            wait_s = MTA_OPEN_WAIT_DEFAULT_S;
        s->open_deadline_ms =
            s->tty->now_ms(s->tty->ctx) + (int64_t)wait_s * 1000;
    } else {
        mta_set_ref(s, "BAD_RPC_BODY", "the open answer carried no terminal id");
    }
    json_free(&body);
    return valid;
}

static bool mta_poll(struct mta *s, struct mta_view *v)
{
    struct json_value body;
    if (!mta_call_id(s, "mesh_terminal_poll", NULL, &body))
        return false;
    memset(v, 0, sizeof(*v));
    mta_copy_str(&body, "state", v->state, sizeof(v->state));
    mta_copy_str(&body, "verdict", v->verdict, sizeof(v->verdict));
    mta_copy_str(&body, "close_reason", v->close_reason,
                 sizeof(v->close_reason));
    v->bytes_in = mta_u64(&body, "bytes_in");
    v->bytes_out = mta_u64(&body, "bytes_out");
    const struct json_value *ev = json_get(&body, "close_evidence");
    v->evidence = ev && ev->type == JSON_OBJ;
    if (v->evidence) {
        v->evidence_in = mta_u64(ev, "bytes_in");
        v->evidence_out = mta_u64(ev, "bytes_out");
        v->evidence_duration_s = mta_u64(ev, "duration_s");
        mta_copy_str(ev, "reason", v->evidence_reason,
                     sizeof(v->evidence_reason));
    }
    json_free(&body);
    return true;
}

static bool mta_resize(struct mta *s)
{
    uint16_t cols = 0, rows = 0;
    if (!s->tty->window(s->tty->ctx, &cols, &rows) || !cols || !rows)
        return false;
    char extra[48];
    snprintf(extra, sizeof(extra), ",\"cols\":%u,\"rows\":%u", (unsigned)cols,
             (unsigned)rows);
    struct json_value body;
    if (!mta_call_id(s, "mesh_terminal_resize", extra, &body))
        return false;
    json_free(&body);
    return true;
}

static void mta_close(struct mta *s)
{
    struct json_value body;
    if (s->id[0] && mta_call_id(s, "mesh_terminal_close", NULL, &body))
        json_free(&body);
}

/* Waits for the OK receipt inside the answer window. */
static enum mta_end mta_await_live(struct mta *s)
{
    for (;;) {
        struct mta_view v;
        if (!mta_poll(s, &v))
            return MTA_END_FAILED;
        if (strcmp(v.state, "live") == 0)
            return MTA_END_LIVE;
        if (strcmp(v.state, "ended") == 0)
            return MTA_END_REMOTE;
        if (strcmp(v.state, "refused") == 0) {
            mta_set_ref(s, v.verdict[0] ? v.verdict : "refused",
                        "the responder refused the terminal open");
            return MTA_END_FAILED;
        }
        if (s->tty->now_ms(s->tty->ctx) >= s->open_deadline_ms) {
            mta_set_ref(s, "OPEN_TIMEOUT",
                        "no open receipt arrived inside the answer window");
            return MTA_END_FAILED;
        }
        s->tty->pause_ms(s->tty->ctx, MTA_OPEN_POLL_MS);
    }
}

/* ── Output ──────────────────────────────────────────────────────────── */

static bool mta_emit_hex(struct mta *s, const char *hex, size_t *moved)
{
    uint8_t bytes[MTA_READ_MAX];
    size_t len = strlen(hex) / 2u;
    if (len > sizeof(bytes) || strlen(hex) % 2u != 0 ||
        !zcl_hex_decode_lower(hex, bytes, len)) {
        mta_set_ref(s, "BAD_RPC_BODY", "the node returned malformed output");
        return false;
    }
    if (len && !s->tty->write_output(s->tty->ctx, bytes, len)) {
        mta_set_ref(s, "OUTPUT_FAILED", "the local output stream failed");
        return false;
    }
    *moved = len;
    return true;
}

static bool mta_read_once(struct mta *s, size_t *moved, bool *ended)
{
    struct json_value body;
    char extra[40];
    snprintf(extra, sizeof(extra), ",\"max_bytes\":%u", MTA_READ_MAX);
    if (!mta_call_id(s, "mesh_terminal_read", extra, &body))
        return false;
    const char *state = mta_cstr(&body, "state");
    *ended = state && (strcmp(state, "ended") == 0 ||
                       strcmp(state, "refused") == 0);
    *moved = 0;
    const char *hex = mta_cstr(&body, "output_hex");
    bool ok = hex ? mta_emit_hex(s, hex, moved) : true;
    json_free(&body);
    return ok;
}

static enum mta_pump mta_pump_output(struct mta *s)
{
    size_t total = 0, moved = 0;
    bool ended = false;
    for (int round = 0; round < MTA_DRAIN_ROUNDS; round++) {
        if (!mta_read_once(s, &moved, &ended))
            return MTA_PUMP_FAILED;
        total += moved;
        if (moved < MTA_READ_MAX)
            break;
    }
    if (total)
        s->active = true;
    if (ended && moved < MTA_READ_MAX)
        return MTA_PUMP_ENDED;
    return total ? MTA_PUMP_MORE : MTA_PUMP_IDLE;
}

/* ── Input ───────────────────────────────────────────────────────────── */

static bool mta_send_chunk(struct mta *s, const uint8_t *bytes, size_t len)
{
    char fields[MTA_FIELDS_MAX];
    int n = snprintf(fields, sizeof(fields),
                     "\"terminal_id\":\"%s\",\"input_hex\":\"", s->id);
    zcl_hex_encode(bytes, len, fields + n);
    size_t used = (size_t)n + len * 2u;
    if (used + 2u > sizeof(fields)) {
        mta_set_ref(s, "INVALID_REQUEST", "input chunk exceeds the bound");
        return false;
    }
    fields[used] = '"';
    fields[used + 1u] = '\0';
    struct json_value body;
    if (!mta_call(s, "mesh_terminal_write", fields, &body))
        return false;
    json_free(&body);
    return true;
}

static bool mta_send(struct mta *s, const uint8_t *bytes, size_t len)
{
    while (len) {
        size_t chunk = len < MTA_WRITE_CHUNK ? len : MTA_WRITE_CHUNK;
        if (!mta_send_chunk(s, bytes, chunk))
            return false;
        bytes += chunk;
        len -= chunk;
    }
    return true;
}

/* The line-start escape: "~." detaches, "~~" sends one tilde, "~" before
 * any other byte is sent as typed. A tilde stays pending until the next
 * byte decides it. */
static size_t mta_filter(struct mta *s, const uint8_t *in, size_t n,
                         uint8_t *out, bool *detach)
{
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = in[i];
        if (s->esc == MTA_ESC_TILDE) {
            if (c == '.') {
                *detach = true;
                break;
            }
            out[m++] = '~';
            s->esc = MTA_ESC_MID;
            if (c == '~')
                continue;
        }
        if (s->esc == MTA_ESC_BOL && c == '~') {
            s->esc = MTA_ESC_TILDE;
            continue;
        }
        out[m++] = c;
        s->esc = (c == '\r' || c == '\n') ? MTA_ESC_BOL : MTA_ESC_MID;
    }
    return m;
}

static enum mta_in mta_forward(struct mta *s, const uint8_t *in, size_t n)
{
    uint8_t filtered[2u * MTA_WRITE_CHUNK];
    bool detach = false;
    const uint8_t *src = in;
    size_t m = n;
    if (s->config->interactive) {
        m = mta_filter(s, in, n, filtered, &detach);
        src = filtered;
    }
    if (m && !mta_send(s, src, m))
        return MTA_IN_FAILED;
    return detach ? MTA_IN_DETACH : MTA_IN_OK;
}

/* End of input detaches an interactive session; a piped one sends a single
 * end-of-transmission byte so the remote shell sees end of file. */
static enum mta_in mta_input_end(struct mta *s)
{
    s->stdin_open = false;
    if (s->config->interactive)
        return MTA_IN_DETACH;
    const uint8_t eot = MTA_EOT;
    return mta_send(s, &eot, 1u) ? MTA_IN_OK : MTA_IN_FAILED;
}

static enum mta_in mta_pump_input(struct mta *s)
{
    int wait = s->active ? MTA_POLL_ACTIVE_MS : MTA_POLL_IDLE_MS;
    s->active = false;
    if (!s->stdin_open) {
        s->tty->pause_ms(s->tty->ctx, wait);
        return MTA_IN_OK;
    }
    uint8_t buf[MTA_WRITE_CHUNK];
    long n = s->tty->read_input(s->tty->ctx, buf, sizeof(buf), wait);
    if (n == 0)
        return MTA_IN_OK;
    if (n < 0)
        return mta_input_end(s);
    s->active = true;
    return mta_forward(s, buf, (size_t)n);
}

static enum mta_end mta_loop(struct mta *s)
{
    for (;;) {
        if (s->tty->stop_requested(s->tty->ctx))
            return MTA_END_STOP;
        if (s->config->interactive && s->tty->take_resize(s->tty->ctx))
            (void)mta_resize(s);
        enum mta_pump pump = mta_pump_output(s);
        if (pump == MTA_PUMP_FAILED)
            return MTA_END_FAILED;
        if (pump == MTA_PUMP_ENDED)
            return MTA_END_REMOTE;
        enum mta_in in = mta_pump_input(s);
        if (in == MTA_IN_FAILED)
            return MTA_END_FAILED;
        if (in == MTA_IN_DETACH)
            return MTA_END_DETACH;
    }
}

static void mta_say(const struct mta *s, const char *fmt, ...)
{
    char line[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    /* Node and responder text is untrusted: no byte may reach the terminal
     * as a control sequence. */
    for (char *p = line; *p; p++)
        if ((unsigned char)*p < 0x20u || *p == 0x7f)
            *p = '?';
    s->tty->diagnostic(s->tty->ctx, line);
}

static enum mta_end mta_session(struct mta *s)
{
    enum mta_end end = mta_await_live(s);
    if (end != MTA_END_LIVE)
        return end;
    if (s->config->interactive) {
        mta_say(s, "z23: attached; type ~. at the start of a line to detach");
        s->tty->raw(s->tty->ctx, true);
    }
    end = mta_loop(s);
    if (s->config->interactive)
        s->tty->raw(s->tty->ctx, false);
    return end;
}

/* ── Conclusion: every diagnostic, after raw mode is off ─────────────── */

static int mta_conclude_failed(struct mta *s)
{
    struct mta_refusal ref = s->ref;
    mta_close(s);
    mta_say(s, "z23: refused: %s: %s", ref.code, ref.message);
    return mta_exit_for(ref.code);
}

static int mta_conclude_remote(struct mta *s)
{
    struct mta_view v;
    if (!mta_poll(s, &v))
        return mta_conclude_failed(s);
    if (v.evidence) {
        mta_say(s,
                "z23: terminal closed: reason=%s bytes_in=%llu bytes_out=%llu "
                "duration_s=%llu",
                v.evidence_reason, (unsigned long long)v.evidence_in,
                (unsigned long long)v.evidence_out,
                (unsigned long long)v.evidence_duration_s);
        return mta_exit_for(v.evidence_reason);
    }
    const char *reason = v.close_reason[0] ? v.close_reason : v.verdict;
    mta_say(s, "z23: terminal ended: reason=%s bytes_in=%llu bytes_out=%llu",
            reason, (unsigned long long)v.bytes_in,
            (unsigned long long)v.bytes_out);
    return mta_exit_for(reason);
}

static int mta_conclude_local(struct mta *s, bool interrupted)
{
    struct mta_view v;
    memset(&v, 0, sizeof(v));
    (void)mta_poll(s, &v);
    mta_close(s);
    mta_say(s, "z23: %s: bytes_in=%llu bytes_out=%llu",
            interrupted ? "interrupted" : "detached",
            (unsigned long long)v.bytes_in, (unsigned long long)v.bytes_out);
    return interrupted ? MTA_EXIT_INTERRUPTED : 0;
}

static int mta_conclude(struct mta *s, enum mta_end end)
{
    if (end == MTA_END_FAILED)
        return mta_conclude_failed(s);
    if (end == MTA_END_REMOTE)
        return mta_conclude_remote(s);
    return mta_conclude_local(s, end == MTA_END_STOP);
}

static bool mta_pairing_ok(const char *id)
{
    if (!id || strlen(id) != MTA_ID_HEX)
        return false;
    for (size_t i = 0; i < MTA_ID_HEX; i++)
        if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
            return false;
    return true;
}

int mesh_terminal_attach_run(const struct mesh_terminal_attach_config *config,
                             mesh_terminal_attach_rpc_fn rpc, void *rpc_ctx,
                             const struct mesh_terminal_attach_tty *tty)
{
    if (!config || !rpc || !tty)
        return 2;
    if (!mta_pairing_ok(config->pairing_id)) {
        tty->diagnostic(tty->ctx,
                        "z23: refused: INVALID_PAIRING_ID: pairing_id must be "
                        "64 lowercase hex chars");
        return 2;
    }
    struct mta s;
    memset(&s, 0, sizeof(s));
    s.config = config;
    s.rpc = rpc;
    s.rpc_ctx = rpc_ctx;
    s.tty = tty;
    s.stdin_open = true;
    s.esc = MTA_ESC_BOL;
    uint16_t cols = 0, rows = 0;
    if (config->interactive && !tty->window(tty->ctx, &cols, &rows))
        cols = rows = 0;
    enum mta_end end = mta_open(&s, cols, rows) ? mta_session(&s)
                                                : MTA_END_FAILED;
    return mta_conclude(&s, end);
}
