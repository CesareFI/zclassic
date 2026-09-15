/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: z23-fleet-gateway — the loopback Streamable-HTTP front for the
 *          fleet steering verbs (fleet.steer.brief/send/evidence).
 *
 * ── CONTRACT ─────────────────────────────────────────────────────────────
 *
 * WHY. ChatGPT cannot reach a shell, an onion address, or the node's
 * operator-private API. This binary is the smallest remote surface that
 * lets it steer: one HTTP endpoint speaking Streamable HTTP
 * (JSON-RPC over POST), dispatching each tool call to the TESTED node
 * binary over fork/exec with --input JSON, and returning the node's own
 * data envelope. It never re-implements a sibling store, never mints a
 * grant (owner creation stays in fleet.steer.grant, outside AI-callable
 * tools), and never touches wallet, deployment, deletion or soak paths.
 *
 * TRANSPORT (G1: loopback only). Binds 127.0.0.1 (or ::1) on a configured
 * port, refuses non-loopback peers with 403, serves plain HTTP. TLS
 * termination and OAuth live in front of it (host front path) and behind
 * it the node enforces every grant scope, expiry and revocation itself.
 * A bearer passed as a tool argument is carried (header or tool argument), never minted here, and
 * never logged. No credentials in chat, no private data made public.
 * Every tools/call needs exactly one credential (header or "grant"
 * argument); a call with none, or two that differ, is refused with a
 * typed error before the node is forked.
 *
 * TOOL SURFACE (frozen with the verbs). initialize / notifications /
 * tools.list / tools.call for steer_brief, steer_send, steer_evidence.
 * Stateless: no session ids. One JSON-RPC request per POST; parse,
 * invalid-request, method-not-found and invalid-params errors are typed.
 * GET /healthz answers readiness. Everything else is 404; GET on /steer
 * is 405 (writes are never disguised as reads).
 *
 * PROCESS RULE. One fork per connection, one fork/exec per tool call into
 * the configured node binary (default build/bin/z23). No threads, no
 * shell (argv exec only), no popen()/system(). Bounded buffers: 64 KiB
 * request headers, 1 MiB bodies, 4 MiB node replies. POSIX only: on
 * Windows main refuses (the node itself stays portable; the gateway
 * does not claim it).
 */

#if defined(_WIN32)
#include <stdio.h>
#else

#include "base/safe_alloc.h"
#include "json/json.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/os_proc.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GW_CAP_HEADERS (64u * 1024u)
#define GW_CAP_BODY (1024u * 1024u)
#define GW_CAP_REPLY (4u * 1024u * 1024u)
#define GW_CAP_RESP (5u * 1024u * 1024u)
#define GW_BACKLOG 16

static const char *gw_proto_versions[] = {"2025-06-18", "2025-11-25"};
static const char *gw_server_name = "z23-fleet-gateway";
static const char *gw_server_version = "0.1.0";

/* ── tiny output buffer ───────────────────────────────────────────────── */

struct gw_buf {
    char *p;
    size_t len;
    size_t cap;
    bool oom;
};

static void gw_buf_reserve(struct gw_buf *b, size_t extra)
{
    size_t need;
    char *np;
    if (!b || b->oom)
        return;
    need = b->len + extra;
    if (need <= b->cap)
        return;
    need = (need + 4095u) & ~(size_t)4095u;
    np = zcl_realloc(b->p, need, "fleet-gateway/buf");
    if (!np) {
        b->oom = true;
        return;
    }
    b->p = np;
    b->cap = need;
}

static void gw_buf_put(struct gw_buf *b, const char *s, size_t n)
{
    if (!b || b->oom || !s)
        return;
    gw_buf_reserve(b, n + 1);
    if (b->oom)
        return;
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void gw_buf_str(struct gw_buf *b, const char *s)
{
    if (s)
        gw_buf_put(b, s, strlen(s));
}

/* JSON string escape by arithmetic (no digit tables: hex-codec-single). */
static char gw_hex_digit(unsigned v)
{
    return (char)(v <= 9 ? ('0' + v) : ('a' + v - 10));
}

static void gw_buf_json_str(struct gw_buf *b, const char *s)
{
    const unsigned char *p;
    gw_buf_put(b, "\"", 1);
    if (!s) {
        gw_buf_put(b, "\"", 1);
        return;
    }
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') {
            gw_buf_put(b, "\\", 1);
            gw_buf_put(b, (const char *)p, 1);
        } else if (*p == '\n') {
            gw_buf_put(b, "\\n", 2);
        } else if (*p < 0x20) {
            char esc[7];
            esc[0] = '\\';
            esc[1] = 'u';
            esc[2] = '0';
            esc[3] = '0';
            esc[4] = gw_hex_digit((unsigned)((*p >> 4) & 0xf));
            esc[5] = gw_hex_digit((unsigned)(*p & 0xf));
            esc[6] = '\0';
            gw_buf_put(b, esc, 6);
        } else {
            gw_buf_put(b, (const char *)p, 1);
        }
    }
    gw_buf_put(b, "\"", 1);
}

static void gw_buf_free(struct gw_buf *b)
{
    if (b) {
        free(b->p);
        b->p = NULL;
        b->len = 0;
        b->cap = 0;
        b->oom = false;
    }
}

/* ── config (environment only; no files, no chat) ─────────────────────── */

struct gw_config {
    char bind[64];
    char port[16];
    char node[4096];
};

/* Own executable's directory: the default node binary is the sibling z23,
 * so the gateway works no matter which cwd the caller runs it from.
 * The path comes from the platform seam (os_proc_exe_path), never from
 * a raw /proc read in this leaf. */
static bool gw_exe_dir(char *buf, size_t cap) {
    char *slash;
    if (!os_proc_exe_path(buf, cap)) return false;
    /* Truncate the final path component in place (no dirname():
     * its return may alias buf, and copying overlapping %s is UB). */
    slash = strrchr(buf, '/');
    if (!slash || slash == buf) return false;
    *slash = '\0';
    return true;
}

static void gw_config(struct gw_config *c)
{
    const char *v;
    memset(c, 0, sizeof(*c));
    v = getenv("FLEET_GW_BIND");
    snprintf(c->bind, sizeof(c->bind), "%s",
             v && v[0] ? v : "127.0.0.1");
    v = getenv("FLEET_GW_PORT");
    snprintf(c->port, sizeof(c->port), "%s", v && v[0] ? v : "0");
    v = getenv("FLEET_GW_NODE");
    if (v && v[0]) {
        snprintf(c->node, sizeof(c->node), "%s", v);
    } else {
        char dir[4096];
        size_t dn = 0;
        if (gw_exe_dir(dir, sizeof dir)) dn = strlen(dir);
        if (dn > 0 && dn + 5 < sizeof(c->node)) {
            memcpy(c->node, dir, dn);
            memcpy(c->node + dn, "/z23", 5);
        } else {
            snprintf(c->node, sizeof(c->node), "%s", "build/bin/z23");
        }
    }
}

/* ── HTTP/1.1 request (headers + optional body, bounded) ──────────────── */

struct gw_http {
    char method[16];
    char path[256];
    size_t content_length;
    char *body;
    size_t body_len;
    bool bad;
    /* Captured "Authorization: Bearer <token>" credential, NUL-terminated
     * when auth_present. Overlong or non-token bytes set auth_bad instead;
     * both refuse a tool call before the node is forked. */
    char auth[96 + 1];
    bool auth_present;
    bool auth_bad;
};

/* Bearer [REDACTED] alphabet: grant ids are 32-hex today; OAuth bearer
 * tokens (base64url/JWT shapes) must also pass through untouched for the
 * node to rule on. Anything outside this set cannot be a credential. */
static bool gw_token_char(char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9'))
        return true;
    return c == '.' || c == '_' || c == '~' || c == '+' || c == '/' ||
           c == '-' || c == '=';
}

static bool gw_is_space(char c)
{
    return c == ' ' || c == '\t';
}

/* First line: METHOD SP PATH SP HTTP/1.x. False on any other shape. */
static bool gw_parse_request_line(struct gw_http *h, const char *line)
{
    size_t i = 0, j;
    memset(h->method, 0, sizeof(h->method));
    memset(h->path, 0, sizeof(h->path));
    for (j = 0; j + 1 < sizeof(h->method) && line[i] && !gw_is_space(line[i]);
         i++, j++)
        h->method[j] = line[i];
    if (!gw_is_space(line[i]))
        return false;
    while (gw_is_space(line[i]))
        i++;
    for (j = 0; j + 1 < sizeof(h->path) && line[i] && !gw_is_space(line[i]);
         i++, j++)
        h->path[j] = line[i];
    if (!gw_is_space(line[i]))
        return false;
    while (gw_is_space(line[i]))
        i++;
    if (strncmp(line + i, "HTTP/1.", 7) != 0)
        return false;
    return h->method[0] && h->path[0] && h->path[0] == '/';
}

/* Header-name match, case-insensitive, over the raw line. */
static bool gw_header_is(const char *line, const char *name)
{
    size_t i;
    for (i = 0; name[i]; i++) {
        char a = line[i];
        if (a == '\0')
            return false;
        if (a >= 'A' && a <= 'Z')
            a = (char)(a - 'A' + 'a');
        if (a != name[i])
            return false;
    }
    return line[i] == ':';
}

/* Capture "Authorization: Bearer <token>". Only the exact Bearer scheme
 * carries a credential; any other scheme leaves auth_present false so the
 * call fails closed as unauthenticated rather than half-authenticated. */
static void gw_parse_authorization(struct gw_http *h, const char *line)
{
    static const char bearer[] = "Bearer ";
    const char *v = line + strlen("authorization:");
    size_t n = 0;
    if (h->auth_present || h->auth_bad)
        return;
    while (gw_is_space(*v))
        v++;
    if (strncmp(v, bearer, sizeof(bearer) - 1) != 0)
        return;
    v += sizeof(bearer) - 1;
    while (v[n] && !gw_is_space(v[n])) {
        if (n >= sizeof(h->auth) - 1 || !gw_token_char(v[n])) {
            h->auth_bad = true;
            return;
        }
        h->auth[n] = v[n];
        n++;
    }
    if (n == 0) {
        /* "Bearer " with an empty token is no credential at all. */
        return;
    }
    h->auth[n] = '\0';
    h->auth_present = true;
}

/* One header line: Content-Length sizes the body; Authorization carries
 * the tool-call credential. Every other header is ignored. */
static void gw_parse_header(struct gw_http *h, const char *line)
{
    static const char *const cl = "content-length:";
    size_t k = strlen(cl), i;
    const char *v;
    unsigned long n = 0;
    if (gw_header_is(line, "authorization")) {
        gw_parse_authorization(h, line);
        return;
    }
    for (i = 0; i < k; i++) {
        char a = line[i];
        if (a == '\0')
            return;
        if (a >= 'A' && a <= 'Z')
            a = (char)(a - 'A' + 'a');
        if (a != cl[i])
            return;
    }
    v = line + k;
    while (gw_is_space(*v))
        v++;
    while (*v >= '0' && *v <= '9') {
        n = n * 10u + (unsigned long)(*v - '0');
        if (n > GW_CAP_BODY)
            break;
        v++;
    }
    h->content_length = (size_t)n;
}

/* Read until end-of-headers. Returns header byte count, or 0 when the
 * cap or EOF hits first. */
static size_t gw_read_headers(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    ssize_t r;
    while (n + 1 < cap) {
        r = read(fd, buf + n, 1);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (n >= 4 && memcmp(buf + n - 4, "\r\n\r\n", 4) == 0)
            return n;
    }
    return 0;
}

static bool gw_read_body(int fd, struct gw_http *h)
{
    size_t left;
    ssize_t r;
    if (h->content_length == 0)
        return true;
    if (h->content_length > GW_CAP_BODY)
        return false;
    h->body = zcl_malloc(h->content_length + 1, "fleet-gateway/body");
    if (!h->body)
        return false;
    left = h->content_length;
    h->body_len = 0;
    while (left > 0) {
        r = read(fd, h->body + h->body_len, left);
        if (r <= 0) {
            free(h->body);
            h->body = NULL;
            return false;
        }
        h->body_len += (size_t)r;
        left -= (size_t)r;
    }
    h->body[h->body_len] = '\0';
    return true;
}

static bool gw_http_read(int fd, struct gw_http *h, char *hbuf)
{
    char *eol, *line;
    memset(h, 0, sizeof(*h));
    if (gw_read_headers(fd, hbuf, GW_CAP_HEADERS) == 0) {
        h->bad = true;
        return false;
    }
    eol = strstr(hbuf, "\r\n");
    if (!eol) {
        h->bad = true;
        return false;
    }
    *eol = '\0';
    if (!gw_parse_request_line(h, hbuf)) {
        h->bad = true;
        return false;
    }
    line = eol + 2;
    while (line[0] != '\0') {
        char *nl = strstr(line, "\r\n");
        if (!nl)
            break;
        *nl = '\0';
        gw_parse_header(h, line);
        line = nl + 2;
    }
    return gw_read_body(fd, h);
}

/* ── node invocation (fork/exec argv, never a shell) ───────────────────── */

struct gw_node_out {
    char *text;
    size_t len;
    bool ok;
};

/* Run: <node> fleet steer <verb> --input=<json>. Stdout (the node's own
 * result envelope) is captured up to GW_CAP_REPLY. */
static struct gw_node_out gw_node_call(const char *node, const char *verb,
                                       const char *input_json)
{
    struct gw_node_out out;
    int fds[2];
    pid_t pid;
    char arg[GW_CAP_BODY + 32];
    int n;
    memset(&out, 0, sizeof(out));
    n = snprintf(arg, sizeof(arg), "--input=%s", input_json ? input_json : "{}");
    if (n <= 0 || (size_t)n >= sizeof(arg))
        return out;
    if (pipe(fds) != 0)
        return out;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return out;
    }
    if (pid == 0) {
        char *const argv[] = {
            (char *)node, (char *)"fleet", (char *)"steer", (char *)verb,
            arg, NULL
        };
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);
        execv(node, argv);
        _exit(127);
    }
    close(fds[1]);
    out.text = zcl_malloc(GW_CAP_REPLY + 1, "fleet-gateway/reply");
    if (!out.text) {
        close(fds[0]);
        waitpid(pid, NULL, 0);
        return out;
    }
    for (;;) {
        ssize_t r;
        if (out.len >= GW_CAP_REPLY)
            break;
        r = read(fds[0], out.text + out.len, GW_CAP_REPLY - out.len);
        if (r <= 0)
            break;
        out.len += (size_t)r;
    }
    out.text[out.len] = '\0';
    close(fds[0]);
    {
        int st = 0;
        waitpid(pid, &st, 0);
        out.ok = WIFEXITED(st) && WEXITSTATUS(st) == 0 && out.len > 0;
    }
    if (!out.ok) {
        free(out.text);
        out.text = NULL;
        out.len = 0;
    }
    return out;
}

/* ── tool mapping (frozen with the verbs) ──────────────────────────────── */

struct gw_tool {
    const char *name;
    const char *verb;
    const char *desc;
    const char *schema;
};

static const struct gw_tool gw_tools[] = {
    {"steer_brief", "brief",
     "Fleet situation: agents, work, blockers, capacity, candidates, evidence refs, changes since a cursor.",
     "{\"type\":\"object\",\"properties\":{\"grant\":{\"type\":\"string\"},\"since\":{\"type\":\"integer\"},\"limit\":{\"type\":\"integer\"}}}"},
    {"steer_send", "send",
     "One bounded batch of directives to named agents; retries with the same idempotency keys never duplicate.",
     "{\"type\":\"object\",\"required\":[\"items\"],\"properties\":{\"grant\":{\"type\":\"string\"},\"items\":{\"type\":\"array\",\"maxItems\":8},\"from\":{\"type\":\"string\"}}}"},
    {"steer_evidence", "evidence",
     "One bounded evidence object by exact reference; never a log.",
     "{\"type\":\"object\",\"required\":[\"type\",\"ref\"],\"properties\":{\"grant\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"ref\":{\"type\":\"string\"}}}"},
};

static const struct gw_tool *gw_tool_by_name(const char *name)
{
    size_t i;
    if (!name)
        return NULL;
    for (i = 0; i < sizeof(gw_tools) / sizeof(gw_tools[0]); i++) {
        if (strcmp(gw_tools[i].name, name) == 0)
            return &gw_tools[i];
    }
    return NULL;
}

static const char *gw_json_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = o ? json_get(o, key) : NULL;
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

/* Serialize one JSON value back to text (for embedding node .data). */
static void gw_json_write(struct gw_buf *b, const struct json_value *v);

static void gw_json_write_scalar(struct gw_buf *b, const struct json_value *v)
{
    switch (v->type) {
    case JSON_NULL:
        gw_buf_str(b, "null");
        break;
    case JSON_BOOL:
        gw_buf_str(b, v->val.b ? "true" : "false");
        break;
    case JSON_INT: {
        char n[32];
        snprintf(n, sizeof(n), "%lld", (long long)v->val.i);
        gw_buf_str(b, n);
        break;
    }
    case JSON_REAL: {
        char n[40];
        snprintf(n, sizeof(n), "%.17g", v->val.d);
        gw_buf_str(b, n);
        break;
    }
    default:
        gw_buf_json_str(b, v->val.s ? v->val.s : "");
        break;
    }
}

static void gw_json_write_arr(struct gw_buf *b, const struct json_value *v)
{
    size_t i;
    gw_buf_put(b, "[", 1);
    for (i = 0; i < v->num_children; i++) {
        if (i > 0)
            gw_buf_put(b, ",", 1);
        gw_json_write(b, &v->children[i]);
    }
    gw_buf_put(b, "]", 1);
}

static void gw_json_write_obj(struct gw_buf *b, const struct json_value *v)
{
    size_t i;
    gw_buf_put(b, "{", 1);
    for (i = 0; i < v->num_children; i++) {
        if (i > 0)
            gw_buf_put(b, ",", 1);
        gw_buf_json_str(b, v->keys[i] ? v->keys[i] : "");
        gw_buf_put(b, ":", 1);
        gw_json_write(b, &v->children[i]);
    }
    gw_buf_put(b, "}", 1);
}

static void gw_json_write(struct gw_buf *b, const struct json_value *v)
{
    if (!v) {
        gw_buf_str(b, "null");
        return;
    }
    switch (v->type) {
    case JSON_ARR:
        gw_json_write_arr(b, v);
        break;
    case JSON_OBJ:
        gw_json_write_obj(b, v);
        break;
    default:
        gw_json_write_scalar(b, v);
        break;
    }
}

/* ── JSON-RPC replies ──────────────────────────────────────────────────── */

static void gw_rpc_error(struct gw_buf *b, const struct json_value *id,
                         int code, const char *message)
{
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_json_write(b, id);
    gw_buf_str(b, ",\"error\":{\"code\":");
    {
        char n[16];
        snprintf(n, sizeof(n), "%d", code);
        gw_buf_str(b, n);
    }
    gw_buf_str(b, ",\"message\":");
    gw_buf_json_str(b, message ? message : "");
    gw_buf_str(b, "}}");
}

/* Protocol version: the client's when known, else the first we speak.
 * Never invent a version. */
static const char *gw_negotiate(const char *asked)
{
    size_t i;
    if (asked) {
        for (i = 0; i < sizeof(gw_proto_versions) / sizeof(gw_proto_versions[0]);
             i++) {
            if (strcmp(asked, gw_proto_versions[i]) == 0)
                return asked;
        }
    }
    return gw_proto_versions[0];
}

static void gw_reply_initialize(struct gw_buf *b,
                                const struct json_value *id,
                                const struct json_value *params)
{
    const struct json_value *v;
    const char *asked = NULL;
    v = params ? json_get(params, "protocolVersion") : NULL;
    if (v && v->type == JSON_STR)
        asked = json_get_str(v);
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_json_write(b, id);
    gw_buf_str(b, ",\"result\":{\"protocolVersion\":");
    gw_buf_json_str(b, gw_negotiate(asked));
    gw_buf_str(b, ",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":");
    gw_buf_json_str(b, gw_server_name);
    gw_buf_str(b, ",\"version\":");
    gw_buf_json_str(b, gw_server_version);
    gw_buf_str(b, "}}}");
}

static void gw_reply_tools_list(struct gw_buf *b, const struct json_value *id)
{
    size_t i;
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_json_write(b, id);
    gw_buf_str(b, ",\"result\":{\"tools\":[");
    for (i = 0; i < sizeof(gw_tools) / sizeof(gw_tools[0]); i++) {
        if (i > 0)
            gw_buf_put(b, ",", 1);
        gw_buf_str(b, "{\"name\":");
        gw_buf_json_str(b, gw_tools[i].name);
        gw_buf_str(b, ",\"description\":");
        gw_buf_json_str(b, gw_tools[i].desc);
        gw_buf_str(b, ",\"inputSchema\":");
        gw_buf_str(b, gw_tools[i].schema);
        gw_buf_put(b, "}", 1);
    }
    gw_buf_str(b, "]}}");
}

/* Serialize tool arguments back to the --input JSON the node takes. */
static void gw_args_input(struct gw_buf *b, const struct json_value *params)
{
    const struct json_value *args = params ? json_get(params, "arguments")
                                           : NULL;
    if (args && (args->type == JSON_OBJ || args->type == JSON_ARR))
        gw_json_write(b, args);
    else
        gw_buf_str(b, "{}");
}

/* Fail-closed credential rule. A tool call reaches the node only with
 * exactly one credential: the Authorization Bearer [REDACTED] the tool-argument
 * grant. Neither may be ambiguous, and the node is never forked for an
 * unauthenticated call — its operator authority stays local-only. Scope,
 * expiry and revocation remain node-enforced after forwarding. */
static bool gw_credential(struct gw_buf *b, const struct json_value *id,
                          const char *bearer, bool bearer_bad,
                          struct json_value *args)
{
    const struct json_value *g;
    const char *arg_grant = NULL;
    g = json_get(args, "grant");
    if (g && g->type == JSON_STR)
        arg_grant = json_get_str((struct json_value *)g);
    if (arg_grant && !arg_grant[0])
        arg_grant = NULL;
    if (bearer_bad) {
        gw_rpc_error(b, id, -32002, "bad grant credential");
        return false;
    }
    if (!bearer && !arg_grant) {
        gw_rpc_error(b, id, -32001, "grant required");
        return false;
    }
    if (bearer && arg_grant && strcmp(bearer, arg_grant) != 0) {
        gw_rpc_error(b, id, -32002, "conflicting grants");
        return false;
    }
    if (bearer && !arg_grant) {
        if (args->type != JSON_OBJ ||
            !json_push_kv_str(args, "grant", bearer)) {
            gw_rpc_error(b, id, -32602, "grant cannot be carried");
            return false;
        }
    }
    return true;
}

/* Serialize the tool arguments with the single credential carried as
 * the node-side "grant" input. False after emitting a typed error; the
 * node is never forked on that path. */
static bool gw_input_with_grant(struct gw_buf *b, const struct json_value *id,
                                const struct json_value *params,
                                const char *bearer, bool bearer_bad,
                                struct gw_buf *input)
{
    struct json_value args;
    memset(input, 0, sizeof(*input));
    gw_args_input(input, params);
    if (input->oom || !input->p) {
        gw_buf_free(input);
        gw_rpc_error(b, id, -32603, "arguments too large");
        return false;
    }
    json_init(&args);
    if (!json_read(&args, input->p, input->len)) {
        gw_buf_free(input);
        json_free(&args);
        gw_rpc_error(b, id, -32602, "arguments did not parse");
        return false;
    }
    if (!gw_credential(b, id, bearer, bearer_bad, &args)) {
        gw_buf_free(input);
        json_free(&args);
        return false;
    }
    gw_buf_free(input);
    memset(input, 0, sizeof(*input));
    gw_json_write(input, &args);
    json_free(&args);
    if (input->oom || !input->p) {
        gw_buf_free(input);
        gw_rpc_error(b, id, -32603, "arguments too large");
        return false;
    }
    return true;
}

/* Fork the node for one credentialed call and format its own envelope as
 * the tool result content (a node refusal is content with isError:true,
 * never a transport error). */
static void gw_forward_call(struct gw_buf *b, const struct json_value *id,
                            const struct gw_tool *t, const char *node,
                            const char *input_text)
{
    struct gw_node_out out;
    struct json_value env;
    const struct json_value *data;
    out = gw_node_call(node, t->verb, input_text);
    if (!out.ok) {
        gw_rpc_error(b, id, -32000, "node did not answer");
        return;
    }
    json_init(&env);
    if (!json_read(&env, out.text, out.len)) {
        json_free(&env);
        free(out.text);
        gw_rpc_error(b, id, -32000, "node answer did not parse");
        return;
    }
    free(out.text);
    /* The node's own data becomes the tool result content. A refused node
     * call (ok:false) is content, not a transport error: the caller sees
     * the exact typed refusal (the error object, never a bare null) and
     * its evidence. */
    {
        const struct json_value *okv = json_get(&env, "ok");
        bool ok = okv && okv->type == JSON_BOOL && okv->val.b;
        data = json_get(&env, ok ? "data" : "error");
    }
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_json_write(b, id);
    gw_buf_str(b, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    {
        struct gw_buf text;
        memset(&text, 0, sizeof(text));
        gw_json_write(&text, data);
        if (text.oom || !text.p)
            gw_buf_json_str(b, "");
        else
            gw_buf_json_str(b, text.p);
        gw_buf_free(&text);
    }
    gw_buf_str(b, "}],\"isError\":");
    {
        const struct json_value *okv = json_get(&env, "ok");
        bool ok = okv && okv->type == JSON_BOOL && okv->val.b;
        gw_buf_str(b, ok ? "false" : "true");
    }
    gw_buf_str(b, "}}");
    json_free(&env);
}

static void gw_reply_tool_call(struct gw_buf *b, const struct json_value *id,
                               const struct json_value *params,
                               const char *node, const char *bearer,
                               bool bearer_bad)
{
    const struct gw_tool *t;
    const char *name;
    struct gw_buf input;
    name = gw_json_str(params, "name");
    t = gw_tool_by_name(name);
    if (!t) {
        gw_rpc_error(b, id, -32602, "unknown tool");
        return;
    }
    if (!gw_input_with_grant(b, id, params, bearer, bearer_bad, &input))
        return;
    gw_forward_call(b, id, t, node, input.p);
    gw_buf_free(&input);
}

static void gw_dispatch_rpc(struct gw_buf *b, const char *body,
                            const char *node, const char *bearer,
                            bool bearer_bad)
{
    struct json_value req;
    const struct json_value *v;
    const char *method;
    const struct json_value *id, *params;
    json_init(&req);
    if (!body || !json_read(&req, body, strlen(body))) {
        json_free(&req);
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":null,"
                      "\"error\":{\"code\":-32700,"
                      "\"message\":\"parse error\"}}");
        return;
    }
    if (req.type != JSON_OBJ) {
        json_free(&req);
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":null,"
                      "\"error\":{\"code\":-32600,"
                      "\"message\":\"invalid request\"}}");
        return;
    }
    v = json_get(&req, "method");
    method = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
    id = json_get(&req, "id");
    params = json_get(&req, "params");
    if (!method) {
        json_free(&req);
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":null,"
                      "\"error\":{\"code\":-32600,"
                      "\"message\":\"invalid request\"}}");
        return;
    }
    if (!id || id->type == JSON_NULL) {
        /* Notifications carry no id and take no reply; the only one the
         * surface defines is initialized. Anything else is dropped. */
        json_free(&req);
        gw_buf_str(b, "");
        return;
    }
    if (strcmp(method, "initialize") == 0)
        gw_reply_initialize(b, id, params);
    else if (strcmp(method, "tools/list") == 0)
        gw_reply_tools_list(b, id);
    else if (strcmp(method, "tools/call") == 0)
        gw_reply_tool_call(b, id, params, node, bearer, bearer_bad);
    else if (strcmp(method, "ping") == 0) {
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
        gw_json_write(b, id);
        gw_buf_str(b, ",\"result\":{}}");
    } else
        gw_rpc_error(b, id, -32601, "method not found");
    json_free(&req);
}

/* ── HTTP replies ──────────────────────────────────────────────────────── */

static void gw_write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0)
            return;
        p += w;
        n -= (size_t)w;
    }
}

static void gw_reply(int fd, int status, const char *ctype, const char *body,
                     size_t n)
{
    char head[256];
    int hlen = snprintf(head, sizeof(head),
                        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                        "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                        status, status == 200 ? "OK" : "Error",
                        ctype ? ctype : "application/json", n);
    if (hlen > 0 && (size_t)hlen < sizeof(head))
        gw_write_all(fd, head, (size_t)hlen);
    if (body && n > 0)
        gw_write_all(fd, body, n);
}

static void gw_reply_json(int fd, struct gw_buf *b)
{
    if (b->oom || !b->p) {
        const char *e = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":"
                        "{\"code\":-32603,\"message\":\"internal error\"}}";
        gw_reply(fd, 500, "application/json", e, strlen(e));
    } else {
        gw_reply(fd, 200, "application/json", b->p, b->len);
    }
    gw_buf_free(b);
}

/* Loopback only: a non-local peer is refused before parsing, and a
 * tool call without exactly one credential never reaches the node. */
static bool gw_peer_is_loopback(int fd)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    struct sockaddr_in *v4;
    struct sockaddr_in6 *v6;
    memset(&ss, 0, sizeof(ss));
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0)
        return false;
    if (ss.ss_family == AF_INET) {
        v4 = (struct sockaddr_in *)&ss;
        return ntohl(v4->sin_addr.s_addr) == INADDR_LOOPBACK;
    }
    if (ss.ss_family == AF_INET6) {
        static const uint8_t loop[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 1};
        v6 = (struct sockaddr_in6 *)&ss;
        return memcmp(&v6->sin6_addr, loop, 16) == 0;
    }
    return false;
}

static void gw_serve(int fd, const struct gw_config *cfg)
{
    struct gw_http h;
    char *hbuf;
    struct gw_buf body;
    memset(&h, 0, sizeof(h));
    if (!gw_peer_is_loopback(fd)) {
        gw_reply(fd, 403, "application/json", "{\"error\":\"loopback only\"}",
                 24);
        return;
    }
    hbuf = zcl_malloc(GW_CAP_HEADERS, "fleet-gateway/headers");
    if (!hbuf) {
        gw_reply(fd, 500, "application/json", "{\"error\":\"no memory\"}",
                 20);
        return;
    }
    if (!gw_http_read(fd, &h, hbuf)) {
        free(hbuf);
        free(h.body);
        gw_reply(fd, 400, "application/json", "{\"error\":\"bad request\"}",
                 22);
        return;
    }
    free(hbuf);
    memset(&body, 0, sizeof(body));
    if (strcmp(h.method, "GET") == 0 && strcmp(h.path, "/healthz") == 0) {
        gw_buf_str(&body, "{\"ok\":true}");
        free(h.body);
        gw_reply_json(fd, &body);
        return;
    }
    if (strcmp(h.method, "POST") == 0 && strcmp(h.path, "/steer") == 0) {
        gw_dispatch_rpc(&body, h.body ? h.body : "", cfg->node,
                        h.auth_present ? h.auth : NULL, h.auth_bad);
        free(h.body);
        if (body.len == 0 && !body.oom) {
            /* A notification: 202 with no body. */
            gw_reply(fd, 202, "application/json", "", 0);
            gw_buf_free(&body);
        } else {
            gw_reply_json(fd, &body);
        }
        return;
    }
    free(h.body);
    gw_buf_free(&body);
    if (strcmp(h.path, "/steer") == 0)
        gw_reply(fd, 405, "application/json",
                 "{\"error\":\"POST only\"}", 20);
    else
        gw_reply(fd, 404, "application/json", "{\"error\":\"not found\"}",
                 21);
}

/* ── listen + fork per connection ──────────────────────────────────────── */

static int gw_listen(const struct gw_config *cfg)
{
    struct sockaddr_in v4;
    int fd, port, one = 1;
    long p;
    memset(&v4, 0, sizeof(v4));
    p = strtol(cfg->port, NULL, 10);
    port = (p > 0 && p < 65536) ? (int)p : 0;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    v4.sin_family = AF_INET;
    v4.sin_port = htons((uint16_t)port);
    if (strcmp(cfg->bind, "127.0.0.1") != 0 &&
        strcmp(cfg->bind, "localhost") != 0) {
        /* G1 binds loopback only; anything else is a misconfiguration. */
        close(fd);
        return -1;
    }
    v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&v4, sizeof(v4)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, GW_BACKLOG) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int gw_bound_port(int fd)
{
    struct sockaddr_in v4;
    socklen_t sl = sizeof(v4);
    memset(&v4, 0, sizeof(v4));
    if (getsockname(fd, (struct sockaddr *)&v4, &sl) != 0)
        return -1;
    return (int)ntohs(v4.sin_port);
}

int main(int argc, char **argv)
{
#if defined(_WIN32)
    /* POSIX only: on Windows the single main refuses (the node itself
     * stays portable; the gateway does not claim it). */
    (void)argc;
    (void)argv;
    fputs("z23-fleet-gateway: loopback gateway is unavailable on Windows\n",
          stderr);
    return 2;
#else
    struct gw_config cfg;
    int fd, port;
    (void)argc;
    (void)argv;
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    gw_config(&cfg);
    fd = gw_listen(&cfg);
    if (fd < 0) {
        fputs("z23-fleet-gateway: cannot bind loopback\n", stderr);
        return 1;
    }
    port = gw_bound_port(fd);
    printf("ready port=%d node=%s\n", port, cfg.node);
    fflush(stdout);
    for (;;) {
        int cfd = accept(fd, NULL, NULL);
        pid_t pid;
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        pid = fork();
        if (pid < 0) {
            close(cfd);
            continue;
        }
        if (pid == 0) {
            close(fd);
            gw_serve(cfd, &cfg);
            close(cfd);
            _exit(0);
        }
        close(cfd);
    }
    close(fd);
    return 0;
#endif
}
#endif /* _WIN32 */
