/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: terminal hub wire pieces that need no socket — frame headers, the
 * keyed hello, and the 0600 key file. See session/mesh_terminal_hub.h. */

#include "session/mesh_terminal_hub.h"

#include "crypto/sha3.h"
#include "platform/rng.h"
#include "session/mesh_terminal_worker.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static const char hub_mac_domain[] = "z23.terminal.hub.hello.v1";
static const char hub_fp_domain[] = "z23.terminal.hub.key.fingerprint.v1";

static void hub_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t hub_get16(const uint8_t *p)
{
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}

static bool hub_type_known(uint8_t type)
{
    switch (type) {
    case MESH_TERMINAL_HUB_CHALLENGE:
    case MESH_TERMINAL_HUB_HELLO:
    case MESH_TERMINAL_HUB_READY:
    case MESH_TERMINAL_HUB_REFUSE:
    case MESH_TERMINAL_HUB_DATA:
    case MESH_TERMINAL_HUB_RESIZE:
    case MESH_TERMINAL_HUB_CLOSE:
    case MESH_TERMINAL_HUB_EXIT:
        return true;
    default:
        return false;
    }
}

size_t mesh_terminal_hub_frame_seal(uint8_t *frame, uint8_t type, size_t len)
{
    if (!frame || len > MESH_TERMINAL_HUB_PAYLOAD_MAX)
        return 0;
    frame[0] = type;
    hub_put16(frame + 1, (uint16_t)len);
    return MESH_TERMINAL_HUB_HEADER_BYTES + len;
}

bool mesh_terminal_hub_frame_header(const uint8_t *bytes, size_t have,
                                    uint8_t *type, size_t *payload_len)
{
    if (!bytes || !type || !payload_len || have < MESH_TERMINAL_HUB_HEADER_BYTES)
        return false;
    size_t len = hub_get16(bytes + 1);
    if (!hub_type_known(bytes[0]) || len > MESH_TERMINAL_HUB_PAYLOAD_MAX)
        return false;
    *type = bytes[0];
    *payload_len = len;
    return true;
}

/* The mac covers the nonce the server chose, so a recorded hello is useless,
 * and the geometry and name, so they cannot be altered on the loopback hop. */
static void hub_mac(const uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
                    const uint8_t nonce[MESH_TERMINAL_HUB_NONCE_BYTES],
                    const uint8_t *shape, size_t shape_len,
                    uint8_t out[MESH_TERMINAL_HUB_MAC_BYTES])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)hub_mac_domain, sizeof(hub_mac_domain) - 1u);
    sha3_256_write(&sha, key, MESH_TERMINAL_HUB_KEY_BYTES);
    sha3_256_write(&sha, nonce, MESH_TERMINAL_HUB_NONCE_BYTES);
    sha3_256_write(&sha, shape, shape_len);
    sha3_256_finalize(&sha, out);
}

static bool hub_name_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static size_t hub_name_clean(char *out, const char *in, size_t in_len)
{
    size_t n = 0;
    for (size_t i = 0; i < in_len && n < MESH_TERMINAL_HUB_NAME_MAX; i++)
        out[n++] = hub_name_char((unsigned char)in[i]) ? in[i] : '_';
    out[n] = '\0';
    return n;
}

/* argc u8 then argc x (len u16, bytes). 0 when it does not fit. */
static size_t hub_argv_put(uint8_t *p, const char *const *argv)
{
    size_t argc = 0, at = 1, bytes = 0;
    while (argv && argv[argc])
        argc++;
    if (argc > MESH_TERMINAL_HUB_ARGV_MAX)
        return 0;
    p[0] = (uint8_t)argc;
    for (size_t i = 0; i < argc; i++) {
        size_t n = strlen(argv[i]);
        bytes += n;
        if (bytes > MESH_TERMINAL_HUB_ARGV_BYTES)
            return 0;
        hub_put16(p + at, (uint16_t)n);
        memcpy(p + at + 2, argv[i], n);
        at += 2 + n;
    }
    return at;
}

size_t mesh_terminal_hub_hello_build(
    uint8_t *payload, const uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
    const uint8_t nonce[MESH_TERMINAL_HUB_NONCE_BYTES],
    const struct mesh_terminal_hub_request *rq)
{
    char clean[MESH_TERMINAL_HUB_NAME_MAX + 1];
    size_t n = hub_name_clean(clean, rq->name ? rq->name : "", rq->name ? strlen(rq->name) : 0);
    hub_put16(payload, rq->cols);
    hub_put16(payload + 2, rq->rows);
    payload[4] = rq->flags;
    payload[5] = (uint8_t)n;
    memcpy(payload + 6, clean, n);
    size_t argv_len = hub_argv_put(payload + 6 + n, rq->argv);
    if (!argv_len)
        return 0;
    size_t shape = 6 + n + argv_len;
    hub_mac(key, nonce, payload, shape, payload + shape);
    return shape + MESH_TERMINAL_HUB_MAC_BYTES;
}

static bool hub_equal_ct(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* Parses the argv block that sits between `at` and the trailing mac. */
static bool hub_argv_get(struct mesh_terminal_hub_hello *out, const uint8_t *p,
                         size_t at, size_t end)
{
    size_t argc, used = 0;
    if (at >= end)
        return false;
    argc = p[at++];
    if (argc > MESH_TERMINAL_HUB_ARGV_MAX)
        return false;
    for (size_t i = 0; i < argc; i++) {
        size_t n;
        if (end - at < 2)
            return false;
        n = hub_get16(p + at);
        at += 2;
        if (n > end - at || used + n > MESH_TERMINAL_HUB_ARGV_BYTES || memchr(p + at, 0, n))
            return false;
        out->argv[i] = out->argv_buf + used;
        memcpy(out->argv_buf + used, p + at, n);
        out->argv_buf[used + n] = '\0';
        used += n + 1;
        at += n;
    }
    out->argv[argc] = NULL;
    out->argc = (unsigned)argc;
    return at == end && (argc == 0 || out->argv[0][0] != '\0');
}

enum mesh_terminal_hub_hello_status mesh_terminal_hub_hello_verify(
    struct mesh_terminal_hub_hello *out, const uint8_t *payload, size_t len,
    const uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
    const uint8_t nonce[MESH_TERMINAL_HUB_NONCE_BYTES])
{
    if (!out || !payload || len < 7u + MESH_TERMINAL_HUB_MAC_BYTES)
        return MESH_TERMINAL_HUB_HELLO_MALFORMED;
    size_t name_len = payload[5], shape = len - MESH_TERMINAL_HUB_MAC_BYTES;
    if (name_len > MESH_TERMINAL_HUB_NAME_MAX || 6u + name_len >= shape)
        return MESH_TERMINAL_HUB_HELLO_MALFORMED;
    uint8_t expect[MESH_TERMINAL_HUB_MAC_BYTES];
    hub_mac(key, nonce, payload, shape, expect);
    if (!hub_equal_ct(expect, payload + shape, sizeof(expect)))
        return MESH_TERMINAL_HUB_HELLO_MAC;
    memset(out, 0, sizeof(*out));
    if (!hub_argv_get(out, payload, 6u + name_len, shape))
        return MESH_TERMINAL_HUB_HELLO_MALFORMED;
    out->cols = hub_get16(payload);
    out->rows = hub_get16(payload + 2);
    out->flags = payload[4];
    if (!geometry_in_bounds(out->cols, out->rows))
        return MESH_TERMINAL_HUB_HELLO_GEOMETRY;
    hub_name_clean(out->name, (const char *)payload + 6, name_len);
    return MESH_TERMINAL_HUB_HELLO_OK;
}

/* One argument as the audit line shows it: printable ASCII except space, '"'
 * and '\\' verbatim, everything else \xNN. Returns bytes written. */
static size_t hub_label_arg(char *out, size_t cap, const char *arg)
{
    size_t at = 0;
    for (; *arg && at + 4 < cap; arg++) {
        unsigned char c = (unsigned char)*arg;
        if (c > 0x20 && c < 0x7f && c != '"' && c != '\\')
            out[at++] = (char)c;
        else
            at += (size_t)snprintf(out + at, 5, "\\x%02x", c);
    }
    return at;
}

void mesh_terminal_hub_exec_label(char *out, size_t cap, const char *const *argv,
                                  unsigned argc)
{
    size_t at = 0, limit = MESH_TERMINAL_HUB_EXEC_LABEL_MAX;
    bool cut = false;
    if (!argc || cap < MESH_TERMINAL_HUB_EXEC_LABEL_MAX + 8u) {
        snprintf(out, cap, "-");
        return;
    }
    for (unsigned i = 0; i < argc && !cut; i++) {
        char piece[4u * 600u];
        size_t n = i ? 1u : 0u;
        if (i)
            piece[0] = ' ';
        n += hub_label_arg(piece + n, sizeof piece - n, argv[i]);
        cut = at + n > limit;
        memcpy(out + at, piece, cut ? limit - at : n);
        at = cut ? limit : at + n;
    }
    if (cut)
        at += (size_t)snprintf(out + at, 4, "...");
    out[at] = '\0';
}

void mesh_terminal_hub_key_fingerprint(
    const uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
    char out[MESH_TERMINAL_HUB_FINGERPRINT_HEX + 1])
{
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)hub_fp_domain, sizeof(hub_fp_domain) - 1u);
    sha3_256_write(&sha, key, MESH_TERMINAL_HUB_KEY_BYTES);
    sha3_256_finalize(&sha, digest);
    for (size_t i = 0; i < MESH_TERMINAL_HUB_FINGERPRINT_HEX / 2u; i++)
        snprintf(out + 2u * i, 3, "%02x", digest[i]);
}

static bool hub_why(char *why, size_t cap, const char *text)
{
    if (why && cap)
        snprintf(why, cap, "%s", text);
    return false;
}

#if defined(_WIN32)

static bool hub_key_load_arm(const char *path,
                                uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
                                char *why, size_t why_cap)
{
    (void)path; (void)key;
    return hub_why(why, why_cap, "terminal hub needs a POSIX key file");
}

static bool hub_key_init_arm(const char *path,
                                char fingerprint[MESH_TERMINAL_HUB_FINGERPRINT_HEX + 1],
                                char *why, size_t why_cap)
{
    (void)path; (void)fingerprint;
    return hub_why(why, why_cap, "terminal hub needs a POSIX key file");
}

#else

static bool hub_key_stat_ok(int fd, char *why, size_t cap)
{
    struct stat st;
    if (fstat(fd, &st) != 0)
        return hub_why(why, cap, "key file cannot be inspected");
    if (!S_ISREG(st.st_mode))
        return hub_why(why, cap, "key file is not a regular file");
    if (st.st_uid != geteuid())
        return hub_why(why, cap, "key file is not owned by this user");
    if ((st.st_mode & 07777) != 0600)
        return hub_why(why, cap, "key file mode must be exactly 0600");
    if (st.st_size != (off_t)MESH_TERMINAL_HUB_KEY_BYTES)
        return hub_why(why, cap, "key file must hold exactly 32 bytes");
    return true;
}

static bool hub_key_load_arm(const char *path,
                                uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
                                char *why, size_t why_cap)
{
    if (!path || !key)
        return hub_why(why, why_cap, "key file path required");
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return hub_why(why, why_cap, "key file cannot be opened (missing or a symlink)");
    bool ok = hub_key_stat_ok(fd, why, why_cap);
    ssize_t got = ok ? read(fd, key, MESH_TERMINAL_HUB_KEY_BYTES) : -1;
    close(fd);
    if (ok && got != (ssize_t)MESH_TERMINAL_HUB_KEY_BYTES)
        return hub_why(why, why_cap, "key file read failed");
    return ok;
}

static bool hub_key_init_arm(const char *path,
                                char fingerprint[MESH_TERMINAL_HUB_FINGERPRINT_HEX + 1],
                                char *why, size_t why_cap)
{
    uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES];
    if (!path || !fingerprint)
        return hub_why(why, why_cap, "key file path required");
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return hub_why(why, why_cap, errno == EEXIST
            ? "key file already exists; it is never overwritten"
            : "key file cannot be created");
    bool ok = fchmod(fd, 0600) == 0 && rng_fill(key, sizeof(key)) &&
              write(fd, key, sizeof(key)) == (ssize_t)sizeof(key) && fsync(fd) == 0;
    if (ok)
        mesh_terminal_hub_key_fingerprint(key, fingerprint);
    memset(key, 0, sizeof(key));
    close(fd);
    if (!ok)
        (void)unlink(path);
    return ok || hub_why(why, why_cap, "key file write failed");
}

#endif

bool mesh_terminal_hub_key_load(const char *path,
                                uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
                                char *why, size_t why_cap)
{
    return hub_key_load_arm(path, key, why, why_cap);
}

bool mesh_terminal_hub_key_init(const char *path,
                                char fingerprint[MESH_TERMINAL_HUB_FINGERPRINT_HEX + 1],
                                char *why, size_t why_cap)
{
    return hub_key_init_arm(path, fingerprint, why, why_cap);
}
