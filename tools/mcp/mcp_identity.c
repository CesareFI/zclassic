/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Identity of the checkout the local MCP adapter serves (see mcp_identity.h). */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "mcp_identity.h"

#if !defined(_WIN32)
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MCP_GIT_TIMEOUT_MS 10000
#define MCP_STATUS_CAP (256u * 1024u)

/* An inherited repository selector would point git at a different tree than
 * the one named by --checkout. */
static void scrub_git_env(void)
{
    static const char *const names[] = {
        "GIT_DIR",          "GIT_WORK_TREE",        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",   "GIT_OBJECT_DIRECTORY", "GIT_NAMESPACE",
        "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        unsetenv(names[i]);
}

static void trim_eol(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static bool refuse(struct mcp_refusal *why, const char *code,
                   const char *message)
{
    why->code = code;
    why->message = message;
    why->detail = NULL;
    return false;
}

static bool read_toplevel(const char *root, char out[PATH_MAX],
                          struct mcp_refusal *why)
{
    const char *argv[] = {"git", "-C", root, "rev-parse", "--show-toplevel",
                          NULL};
    char raw[PATH_MAX];
    if (zcl_spawn_capture(argv, raw, sizeof(raw), MCP_GIT_TIMEOUT_MS) != 0 ||
        !raw[0])
        return refuse(why, "CHECKOUT_NOT_GIT",
                      "--checkout is not inside a git work tree");
    trim_eol(raw);
    if (!realpath(raw, out))
        return refuse(why, "CHECKOUT_NOT_GIT", "git toplevel is unreadable");
    return true;
}

/* porcelain v2 with --branch: "# branch.oid <sha>" then one line per change. */
static bool read_head_and_dirty(const char *root, struct mcp_identity *id,
                                struct mcp_refusal *why)
{
    const char *argv[] = {"git",  "--no-optional-locks", "-C", root,
                          "status", "--porcelain=v2",    "--branch", NULL};
    char *buf = zcl_malloc(MCP_STATUS_CAP, "mcp-identity/status");
    bool ok = false;
    if (!buf)
        return refuse(why, "HEAD_UNREADABLE", "out of memory");
    if (zcl_spawn_capture(argv, buf, MCP_STATUS_CAP, MCP_GIT_TIMEOUT_MS) == 0 &&
        strncmp(buf, "# branch.oid ", 13) == 0) {
        const char *oid = buf + 13;
        const char *eol = strchr(oid, '\n');
        size_t n = eol ? (size_t)(eol - oid) : strlen(oid);
        if (n == 40 || n == 64) {
            memcpy(id->head, oid, n);
            id->head[n] = '\0';
            id->dirty = false;
            for (const char *p = eol; p && *p; p = strchr(p + 1, '\n'))
                if (p[1] && p[1] != '#') {
                    id->dirty = true;
                    break;
                }
            ok = true;
        }
    }
    free(buf);
    return ok ? true : refuse(why, "HEAD_UNREADABLE",
                              "git could not report HEAD (unborn branch?)");
}

static void read_fingerprint(struct mcp_identity *id)
{
    bool stale = false;
    uint8_t root[32];
    struct codeindex *ci = codeindex_open_readonly(id->root, &stale);
    if (!ci)
        return;
    if (codeindex_source_root_sha3(ci, root)) {
        zcl_hex_encode(root, sizeof(root), id->fingerprint);
        id->fingerprint_present = true;
        id->fingerprint_stale = stale;
    }
    codeindex_close(ci);
}

bool mcp_identity_resolve(const char *checkout, struct mcp_identity *id,
                          struct mcp_refusal *why)
{
    memset(id, 0, sizeof(*id));
    if (!checkout || !realpath(checkout, id->root))
        return refuse(why, "CHECKOUT_NOT_FOUND",
                      "--checkout does not name an existing directory");
    scrub_git_env();
    if (!read_toplevel(id->root, id->toplevel, why))
        return false;
    if (strcmp(id->root, id->toplevel) != 0)
        return refuse(why, "CHECKOUT_NOT_TOPLEVEL",
                      "--checkout must be the git toplevel of the work tree");
    if (!read_head_and_dirty(id->root, id, why))
        return false;
    read_fingerprint(id);
    return true;
}

size_t mcp_identity_json(const struct mcp_identity *id, char *out, size_t cap)
{
    struct mcp_buf b;
    size_t n = 0;
    mcp_buf_init(&b);
    mcp_buf_str(&b, "{\"checkout\":");
    mcp_buf_json_str(&b, id->root);
    mcp_buf_str(&b, ",\"git_toplevel\":");
    mcp_buf_json_str(&b, id->toplevel);
    mcp_buf_str(&b, ",\"head\":");
    mcp_buf_json_str(&b, id->head);
    mcp_buf_str(&b, id->dirty ? ",\"dirty\":true" : ",\"dirty\":false");
    mcp_buf_str(&b, ",\"source_root_sha3\":");
    if (id->fingerprint_present)
        mcp_buf_json_str(&b, id->fingerprint);
    else
        mcp_buf_str(&b, "null");
    if (id->fingerprint_present)
        mcp_buf_str(&b, id->fingerprint_stale ? ",\"index_stale\":true"
                                              : ",\"index_stale\":false");
    mcp_buf_str(&b, "}");
    if (!b.oom && b.len < cap) {
        memcpy(out, b.p, b.len + 1);
        n = b.len;
    }
    mcp_buf_free(&b);
    return n;
}

#endif /* !_WIN32 */
