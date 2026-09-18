/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcl_fleet_front — a tiny, self-contained TLS terminator for z23-fleet-gateway.
 *
 * WHY THIS EXISTS
 * ---------------
 * A hosted AI client cannot reach a shell, an onion address, or the node's
 * operator-private API. z23-fleet-gateway speaks plain Streamable HTTP on
 * 127.0.0.1 only (see tools/fleet_gateway.c). Something must terminate
 * public TLS in front of it without rewriting a byte, without new packages
 * (no nginx/Caddy/stunnel on the box), and without touching the node or the
 * gateway. A per-connection openssl s_server respawn was tried first and
 * refused: every respawn rebinds, and rapid sequential clients land in the
 * rebind gap as refused connections. This binary holds ONE persistent listen
 * socket, so there is no gap, and forks one bounded child per connection.
 *
 * WHY IT ALSO ROUTES
 * ------------------
 * A hosted AI client's fetcher reaches port 443 and nothing else. A gateway
 * published on a high port is not "hard to reach", it is UNREACHABLE for the
 * one client the gateway exists to serve, and the failure it shows is an
 * opaque connect timeout. So the public MCP/OAuth surface has to live on the
 * apex at :443 — which the node's own HTTPS site already owns.
 *
 * Both can own it, because they own DISJOINT PATHS. With a site backend
 * configured this binary terminates TLS once, reads the request head, and
 * hands the connection to exactly one backend: the loopback gateway for the
 * MCP/OAuth paths, the node's HTTPS site for everything else. It still
 * rewrites no byte of either direction — the head it parsed is forwarded
 * verbatim, Host and all. Without a site backend it behaves exactly as
 * before: one gateway, no parsing, a dumb pipe.
 *
 * WHAT IT DOES
 * ------------
 *   zcl_fleet_front <listen-host> <listen-port> <gw-host> <gw-port> \
 *                   <cert> <key> [site-host:site-port]
 * Accepts public TLS (1.2+), relays the cleartext both ways to the selected
 * backend, closes when either side ends. It mints nothing, stores nothing,
 * enforces nothing, and logs no traffic and no credentials — every grant
 * scope, expiry and revocation check stays inside the node, exactly as on
 * direct loopback. Both backend hosts must be loopback (anything else is
 * refused here before bind, and the gateway would 403 it anyway).
 *
 * The site leg speaks TLS (the node's HTTPS listener is a TLS listener), so
 * the site half is TLS on both sides. It is a loopback leg to this same
 * box's node, so the client half does not verify a peer name: the trust
 * boundary is the loopback socket, not a certificate. SNI is set from the
 * request's Host header so a multi-name node front picks the same name the
 * public client asked for.
 *
 * DESIGN
 * ------
 * One accept loop, fork per connection (SIGCHLD ignored: no zombies), at
 * most 16 concurrent children — the 17th accepted socket is closed at once,
 * so processes stay bounded no matter what the public side sends. Each child
 * relays through two 64 KiB stack buffers with full-write loops; bodies of
 * any size stream through, so memory stays bounded regardless of body size.
 * Routing reads at most one 8 KiB head before choosing, and a head that
 * overruns that bound routes on the request line already in hand rather than
 * growing a buffer. Idle connections die after 120 s (poll timeout);
 * handshakes are covered by 120 s socket timeouts. No threads, no malloc in
 * the data path, no shell.
 * Dual-stack listen where the kernel allows (V6ONLY off), plus a separate v4
 * socket as fallback — the same pattern as tools/zcl_portfwd.c.
 *
 * BUILD (no Makefile target: like zcl_portfwd, the setup/qual harness
 * compiles it with plain cc so the high-contention build catalog is untouched):
 *   cc -O2 -Wall -Wextra -Werror -std=c2x -o build/bin/zcl-fleet-front \
 *      tools/zcl_fleet_front.c -lssl -lcrypto
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

/* Concurrency cap. 16 is right for a gateway-only front: one hosted AI
 * client, a handful of connections. It is NOT right for the apex front,
 * which also carries the public site — a single browser opens six
 * connections, so a 16-child cap there is a capacity ceiling, not a safety
 * bound. The cap therefore follows the role: FF_MAX_CHILDREN by default,
 * FF_MAX_CHILDREN_SITE when a site backend makes this front the apex, and
 * FRONT_MAX_CHILDREN overrides either up to FF_MAX_CHILDREN_CEIL. Each
 * child is one small process with two 64 KiB stack buffers, so even the
 * ceiling is bounded and cheap; what stays true at every setting is that
 * the count cannot grow with load. */
#define FF_MAX_CHILDREN 16
#define FF_MAX_CHILDREN_SITE 128
#define FF_MAX_CHILDREN_CEIL 512
#define FF_BUF_SZ (64u * 1024u)
#define FF_HEAD_SZ (8u * 1024u)
#define FF_IDLE_MS (120 * 1000)
#define FF_SOCK_TIMEOUT_S 120

/* Live children, maintained by the SIGCHLD handler (async-signal-safe:
 * waitpid is, and the counter is sig_atomic_t). The cap only ever
 * under-admits: a stale count refuses a connection the kernel backlog holds
 * for the next pass. */
static volatile sig_atomic_t g_children = 0;

static void ff_sigchld(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        if (g_children > 0)
            g_children--;
    }
}

struct ff_config {
    const char *listen_host;
    const char *listen_port;
    const char *gw_host;
    const char *gw_port;
    const char *cert;
    const char *key;
    /* Path routing is off unless a site backend is named: site_host[0] == 0
     * means "one backend, no parsing", the original contract. */
    char site_host[64];
    char site_port[8];
    int max_children;
};

static void ff_log(const char *msg)
{
    fprintf(stderr, "fleet-front: %s\n", msg);
}

/* Loopback only for every backend leg: fail closed before binding anything. */
static bool ff_backend_host_ok(const char *host)
{
    return host != NULL && (strcmp(host, "127.0.0.1") == 0 ||
            strcmp(host, "localhost") == 0 || strcmp(host, "::1") == 0);
}

static int ff_port_parse(const char *text)
{
    long port;
    char *end = NULL;
    if (text == NULL || text[0] == '\0')
        return -1;
    errno = 0;
    port = strtol(text, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || port <= 0 || port > 65535)
        return -1;
    return (int)port;
}

static void ff_sock_timeouts(int fd)
{
    struct timeval timeout;
    timeout.tv_sec = FF_SOCK_TIMEOUT_S;
    timeout.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

/* How many listen sockets the config needs: wildcard tries one dual-stack
 * socket and falls back to v4; an explicit host binds exactly its family. */
static int ff_bind_v6(const struct ff_config *cfg, int port, int *fd_out)
{
    struct sockaddr_in6 v6;
    int fd;
    int zero = 0;
    int one = 1;
    bool wildcard = cfg->listen_host[0] == '*' || cfg->listen_host[0] == '\0';
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons((uint16_t)port);
    if (wildcard) {
        v6.sin6_addr = in6addr_any;
    } else if (inet_pton(AF_INET6, cfg->listen_host, &v6.sin6_addr) != 1) {
        close(fd);
        return -1;
    }
    /* Wildcard: dual-stack where the kernel allows (one socket serves both).
     * Explicit host: v6-only. */
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, wildcard ? &zero : &one,
        sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)&v6, sizeof(v6)) != 0 || listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    *fd_out = fd;
    return 0;
}

static int ff_bind_v4(const struct ff_config *cfg, int port, int *fd_out)
{
    struct sockaddr_in v4;
    int fd;
    int one = 1;
    bool wildcard = cfg->listen_host[0] == '*' || cfg->listen_host[0] == '\0';
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&v4, 0, sizeof(v4));
    v4.sin_family = AF_INET;
    v4.sin_port = htons((uint16_t)port);
    if (wildcard) {
        v4.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, cfg->listen_host, &v4.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)&v4, sizeof(v4)) != 0 || listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    *fd_out = fd;
    return 0;
}

/* Bind the listen sockets: at most two (dual v6, or v6-only plus v4
 * fallback, or one explicit family). Returns the count, or -1. */
static int ff_listen(const struct ff_config *cfg, int *fds)
{
    int port = ff_port_parse(cfg->listen_port);
    bool wildcard;
    bool v6_literal;
    if (port < 0)
        return -1;
    wildcard = cfg->listen_host[0] == '*' || cfg->listen_host[0] == '\0';
    v6_literal = !wildcard && strchr(cfg->listen_host, ':') != NULL;
    if (wildcard) {
        if (ff_bind_v6(cfg, port, &fds[0]) == 0) {
            /* Dual-stack covers v4; if the kernel forced v6-only, add v4. */
            int only = 1;
            socklen_t len = sizeof(only);
            if (getsockopt(fds[0], IPPROTO_IPV6, IPV6_V6ONLY, &only, &len) == 0 && !only)
                return 1;
            if (ff_bind_v4(cfg, port, &fds[1]) == 0)
                return 2;
            return 1;
        }
        if (ff_bind_v4(cfg, port, &fds[0]) == 0)
            return 1;
        return -1;
    }
    if (v6_literal)
        return ff_bind_v6(cfg, port, &fds[0]) == 0 ? 1 : -1;
    return ff_bind_v4(cfg, port, &fds[0]) == 0 ? 1 : -1;
}

/* TLS context for this terminator: system defaults, TLS 1.2 floor, the
 * operator's chain + key, consistency checked. No peer verification: the
 * public client is a hosted AI client, authenticated by OAuth + grants. */
static SSL_CTX *ff_tls_ctx(const struct ff_config *cfg)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#ifdef SSL_OP_NO_RENEGOTIATION
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
#endif
    if (SSL_CTX_use_certificate_chain_file(ctx, cfg->cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, cfg->key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* Client context for the site leg. No peer verification by design: this leg
 * never leaves loopback, the name it would verify is the public name this
 * process is itself terminating, and the node front may legitimately serve a
 * self-signed pair there. The trust boundary is the loopback socket. */
static SSL_CTX *ff_site_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

/* Plain TCP to a loopback backend. Returns the fd, or -1. */
static int ff_backend_connect(const char *host, const char *port_text)
{
    int port = ff_port_parse(port_text);
    int fd;
    if (port < 0)
        return -1;
    if (strcmp(host, "::1") == 0) {
        struct sockaddr_in6 v6;
        fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        memset(&v6, 0, sizeof(v6));
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons((uint16_t)port);
        v6.sin6_addr = in6addr_loopback;
        if (connect(fd, (struct sockaddr *)&v6, sizeof(v6)) != 0) {
            close(fd);
            return -1;
        }
        return fd;
    } else {
        struct sockaddr_in v4;
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        memset(&v4, 0, sizeof(v4));
        v4.sin_family = AF_INET;
        v4.sin_port = htons((uint16_t)port);
        v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&v4, sizeof(v4)) != 0) {
            close(fd);
            return -1;
        }
        return fd;
    }
}

/* One side of the relay. ssl == NULL is a plain socket; the two read/write
 * helpers below are the ONLY places the difference is visible, so the relay
 * loop is identical for a plain gateway leg and a TLS site leg. */
struct ff_end {
    int fd;
    SSL *ssl;
    bool open;
};

static int ff_end_read(struct ff_end *end, char *buf, size_t cap)
{
    if (end->ssl != NULL)
        return SSL_read(end->ssl, buf, (int)cap);
    return (int)read(end->fd, buf, cap);
}

static int ff_end_write_all(struct ff_end *end, const char *buf, size_t len)
{
    while (len > 0) {
        int written = end->ssl != NULL ? SSL_write(end->ssl, buf, (int)len)
                                       : (int)write(end->fd, buf, len);
        if (written <= 0)
            return -1;
        buf += written;
        len -= (size_t)written;
    }
    return 0;
}

/* Decrypted-but-unread bytes poll() cannot see. Only a TLS end has them. */
static bool ff_end_pending(const struct ff_end *end)
{
    return end->ssl != NULL && SSL_pending(end->ssl) > 0;
}

/* ---- routing ---------------------------------------------------------- */

/* Does this path belong to the gateway rather than the node's site?
 *
 * The set is exactly the MCP endpoint plus the OAuth surface that endpoint
 * advertises, and it is matched as a PREFIX on purpose: clients probe
 * issuer-suffixed discovery variants (RFC 8414 §3.1 puts the resource path
 * after the well-known segment), and every such probe has to reach the one
 * component that knows the answer. Nothing else moves: the node's site keeps
 * every path it has today. */
static bool ff_path_is_gateway(const char *path)
{
    static const char *const owned[] = {
        "/steer",
        "/oauth/",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    };
    size_t i;
    for (i = 0; i < sizeof(owned) / sizeof(owned[0]); i++) {
        size_t n = strlen(owned[i]);
        if (strncmp(path, owned[i], n) != 0)
            continue;
        /* A prefix that already ends in '/' names a whole family and needs
         * no boundary. One that does not must land on a real segment
         * boundary, so "/steerage" is the site's, not the gateway's. */
        if (owned[i][n - 1] == '/' || path[n] == '\0' || path[n] == '/' ||
            path[n] == '?')
            return true;
    }
    return false;
}

/* Copy the request target out of an HTTP request line. False when the line
 * is not one (which routes to the site: the node front owns "not MCP"). */
static bool ff_request_path(const char *head, size_t len, char *out, size_t cap)
{
    size_t i = 0;
    size_t start;
    size_t n = 0;
    while (i < len && head[i] != ' ' && head[i] != '\r' && head[i] != '\n')
        i++;            /* method */
    if (i >= len || head[i] != ' ')
        return false;
    while (i < len && head[i] == ' ')
        i++;
    start = i;
    while (i < len && head[i] != ' ' && head[i] != '\r' && head[i] != '\n')
        i++;
    n = i - start;
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, head + start, n);
    out[n] = '\0';
    return true;
}

/* Copy the Host header's hostname (no port) out of a buffered head, for the
 * site leg's SNI. Absent or malformed leaves out[0] == 0 and SNI is skipped. */
static void ff_request_host(const char *head, size_t len, char *out, size_t cap)
{
    size_t i;
    out[0] = '\0';
    for (i = 0; i + 6 < len; i++) {
        size_t v;
        size_t n = 0;
        if (i != 0 && head[i - 1] != '\n')
            continue;
        if (strncasecmp(head + i, "Host:", 5) != 0)
            continue;
        v = i + 5;
        while (v < len && (head[v] == ' ' || head[v] == '\t'))
            v++;
        while (v + n < len && head[v + n] != '\r' && head[v + n] != '\n' &&
               head[v + n] != ':' && n + 1 < cap)
            n++;
        if (n > 0) {
            memcpy(out, head + v, n);
            out[n] = '\0';
        }
        return;
    }
}

/* Has this buffer reached the end of the request head?
 *
 * The terminator is searched for across the WHOLE buffer, not at its tail:
 * one read routinely returns the head AND the first body bytes together, and
 * a tail-only check would then keep reading for a head that already arrived
 * until the socket timed out. That is the difference between a POST that
 * works and a POST that hangs. */
static bool ff_head_complete(const char *head, size_t len)
{
    size_t i;
    for (i = 0; i + 1 < len; i++) {
        if (head[i] == '\n' && head[i + 1] == '\n')
            return true;
        if (i + 3 < len && head[i] == '\r' && head[i + 1] == '\n' &&
            head[i + 2] == '\r' && head[i + 3] == '\n')
            return true;
    }
    return false;
}

/* Read the request head (bounded) so the path can choose a backend. Returns
 * the bytes buffered, or 0 when the client sent nothing usable. The bytes
 * are forwarded verbatim afterwards: this reads, it never rewrites. */
static size_t ff_read_head(struct ff_end *client, char *head, size_t cap)
{
    size_t len = 0;
    while (len < cap) {
        int got = ff_end_read(client, head + len, cap - len);
        if (got <= 0)
            break;
        len += (size_t)got;
        if (ff_head_complete(head, len))
            break;
    }
    return len;
}

/* ---- relay ------------------------------------------------------------ */

struct ff_relay {
    struct ff_end client;
    struct ff_end back;
    char to_back[FF_BUF_SZ];
    char to_client[FF_BUF_SZ];
};

/* Drain already-decrypted bytes before blocking: poll cannot see them, and
 * waiting on it instead would stall the relay. */
static void ff_drain_pending(struct ff_relay *relay)
{
    while (relay->client.open && relay->back.open &&
           (ff_end_pending(&relay->client) || ff_end_pending(&relay->back))) {
        if (ff_end_pending(&relay->client)) {
            int got = ff_end_read(&relay->client, relay->to_back,
                                  sizeof(relay->to_back));
            if (got <= 0) {
                relay->client.open = false;
                break;
            }
            if (ff_end_write_all(&relay->back, relay->to_back,
                                 (size_t)got) != 0) {
                relay->back.open = false;
                break;
            }
        }
        if (ff_end_pending(&relay->back)) {
            int got = ff_end_read(&relay->back, relay->to_client,
                                  sizeof(relay->to_client));
            if (got <= 0) {
                relay->back.open = false;
                break;
            }
            if (ff_end_write_all(&relay->client, relay->to_client,
                                 (size_t)got) != 0) {
                relay->client.open = false;
                break;
            }
        }
    }
}

static void ff_pump_back_to_client(struct ff_relay *relay)
{
    int got = ff_end_read(&relay->back, relay->to_client,
                          sizeof(relay->to_client));
    if (got <= 0)
        relay->back.open = false;
    else if (ff_end_write_all(&relay->client, relay->to_client,
                              (size_t)got) != 0)
        relay->client.open = false;
}

static void ff_pump_client_to_back(struct ff_relay *relay)
{
    int got = ff_end_read(&relay->client, relay->to_back,
                          sizeof(relay->to_back));
    if (got <= 0)
        relay->client.open = false;
    else if (ff_end_write_all(&relay->back, relay->to_back, (size_t)got) != 0)
        relay->back.open = false;
}

/* Act on one poll result: pump whichever side has data (or a hangup that
 * read() must observe), and close a side whose socket reported an error. */
static void ff_relay_dispatch(struct ff_relay *relay, const struct pollfd *fds)
{
    if (relay->back.open && (fds[1].revents & (POLLIN | POLLHUP)) != 0)
        ff_pump_back_to_client(relay);
    if (relay->client.open && (fds[0].revents & (POLLIN | POLLHUP)) != 0)
        ff_pump_client_to_back(relay);
    if ((fds[0].revents & (POLLERR | POLLNVAL)) != 0)
        relay->client.open = false;
    if ((fds[1].revents & (POLLERR | POLLNVAL)) != 0)
        relay->back.open = false;
}

/* One relay pass. False when the connection is finished: both sides
 * closed, 120 s idle, a poll failure, or only stale signal left. */
static bool ff_relay_step(struct ff_relay *relay)
{
    struct pollfd fds[2];
    ff_drain_pending(relay);
    if (!relay->client.open && !relay->back.open)
        return false;
    fds[0].fd = relay->client.fd;
    fds[0].events = (short)(relay->client.open ? POLLIN : 0);
    fds[0].revents = 0;
    fds[1].fd = relay->back.fd;
    fds[1].events = (short)(relay->back.open ? POLLIN : 0);
    fds[1].revents = 0;
    if (poll(fds, 2, FF_IDLE_MS) <= 0)
        return false;
    /* Mask revents by the requested events: a persistent HUP on a
     * half-closed side whose events are already off is stale signal,
     * not work. Without this the loop spins on it until the idle
     * timeout instead of exiting. */
    fds[0].revents &= (short)(fds[0].events | POLLERR | POLLNVAL);
    fds[1].revents &= (short)(fds[1].events | POLLERR | POLLNVAL);
    if (fds[0].revents == 0 && fds[1].revents == 0)
        return false;
    ff_relay_dispatch(relay, fds);
    return true;
}

/* Relay until the BACKEND is done.
 *
 * A backend EOF ends the exchange in both directions: an HTTP response
 * delimited by close has nothing after it, and a client that keeps its half
 * open afterwards is only waiting to be told the same thing. Ending here is
 * what makes the client see the close promptly instead of at the 120 s idle
 * timeout. A client that closes FIRST does not end anything: the backend may
 * still be mid-response, so that half goes quiet and the response finishes.
 */
static void ff_relay_run(struct ff_relay *relay)
{
    while (relay->back.open && ff_relay_step(relay))
        ;
}

/* Open the site leg: loopback TCP plus a client TLS handshake, with SNI set
 * to the name the public client asked for. False leaves nothing open. */
static bool ff_site_open(struct ff_end *back, const struct ff_config *cfg,
                         SSL_CTX *site_ctx, const char *sni)
{
    back->fd = ff_backend_connect(cfg->site_host, cfg->site_port);
    if (back->fd < 0)
        return false;
    ff_sock_timeouts(back->fd);
    back->ssl = SSL_new(site_ctx);
    if (back->ssl == NULL) {
        close(back->fd);
        back->fd = -1;
        return false;
    }
    if (sni != NULL && sni[0] != '\0')
        (void)SSL_set_tlsext_host_name(back->ssl, sni);
    SSL_set_fd(back->ssl, back->fd);
    if (SSL_connect(back->ssl) != 1) {
        SSL_free(back->ssl);
        back->ssl = NULL;
        close(back->fd);
        back->fd = -1;
        return false;
    }
    back->open = true;
    return true;
}

/* Choose and open the backend for a buffered request head. */
static bool ff_backend_open(struct ff_relay *relay, const struct ff_config *cfg,
                            SSL_CTX *site_ctx, const char *head, size_t len)
{
    char path[2048];
    char host[256];
    bool to_gateway = !ff_request_path(head, len, path, sizeof(path)) ||
                      ff_path_is_gateway(path);
    if (to_gateway) {
        relay->back.fd = ff_backend_connect(cfg->gw_host, cfg->gw_port);
        if (relay->back.fd < 0)
            return false;
        ff_sock_timeouts(relay->back.fd);
        relay->back.open = true;
        return true;
    }
    ff_request_host(head, len, host, sizeof(host));
    return ff_site_open(&relay->back, cfg, site_ctx, host);
}

/* The only bytes this process ever authors: a bounded refusal when the
 * chosen backend is not answering. It carries no detail about which one. */
static void ff_reply_502(struct ff_end *client)
{
    static const char body[] =
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: 18\r\n"
        "Connection: close\r\n"
        "\r\n"
        "backend unavailable";
    (void)ff_end_write_all(client, body, sizeof(body) - 1);
}

/* Routing path: read the head, pick the backend, forward the head verbatim,
 * then relay. */
static void ff_serve_routed(struct ff_relay *relay, const struct ff_config *cfg,
                            SSL_CTX *site_ctx)
{
    char head[FF_HEAD_SZ];
    size_t len = ff_read_head(&relay->client, head, sizeof(head));
    if (len == 0)
        return;
    if (!ff_backend_open(relay, cfg, site_ctx, head, len)) {
        ff_log("backend connect failed");
        ff_reply_502(&relay->client);
        return;
    }
    if (ff_end_write_all(&relay->back, head, len) != 0)
        return;
    ff_relay_run(relay);
}

/* One connection: TLS handshake, then a bidirectional relay until either
 * side ends or 120 s pass with no movement. Bodies of any size stream
 * through the two fixed buffers; memory never grows with the body. */
static void ff_handle(int client_fd, const struct ff_config *cfg, SSL_CTX *ctx,
                      SSL_CTX *site_ctx)
{
    struct ff_relay relay;
    memset(&relay, 0, sizeof(relay));
    relay.client.fd = client_fd;
    relay.back.fd = -1;
    ff_sock_timeouts(client_fd);
    relay.client.ssl = SSL_new(ctx);
    if (relay.client.ssl == NULL)
        return;
    SSL_set_fd(relay.client.ssl, client_fd);
    if (SSL_accept(relay.client.ssl) != 1) {
        SSL_free(relay.client.ssl);
        return;
    }
    relay.client.open = true;
    if (cfg->site_host[0] != '\0') {
        ff_serve_routed(&relay, cfg, site_ctx);
    } else {
        /* No site backend: the original contract, one gateway, no parsing. */
        relay.back.fd = ff_backend_connect(cfg->gw_host, cfg->gw_port);
        if (relay.back.fd >= 0) {
            ff_sock_timeouts(relay.back.fd);
            relay.back.open = true;
            ff_relay_run(&relay);
        } else {
            ff_log("gateway connect failed; closing client");
        }
    }
    if (relay.back.ssl != NULL) {
        SSL_shutdown(relay.back.ssl);
        SSL_free(relay.back.ssl);
    }
    if (relay.back.fd >= 0)
        close(relay.back.fd);
    SSL_shutdown(relay.client.ssl);
    SSL_free(relay.client.ssl);
}

static int ff_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s <listen-host> <listen-port> <gw-host> <gw-port> <cert> <key>"
        " [site-host:site-port]\n"
        "  listen-host: * (dual-stack wildcard) or a literal IP\n"
        "  gw-host: loopback only (127.0.0.1, localhost, ::1)\n"
        "  site-host:site-port: optional loopback HTTPS site for every path\n"
        "    the gateway does not own; omitted (or empty) means no routing\n",
        prog != NULL ? prog : "zcl-fleet-front");
    return 2;
}

/* "host:port" -> the two config fields. False on anything malformed. */
static bool ff_site_parse(const char *spec, struct ff_config *cfg)
{
    const char *colon = strrchr(spec, ':');
    size_t hlen;
    if (colon == NULL)
        return false;
    hlen = (size_t)(colon - spec);
    if (hlen == 0 || hlen >= sizeof(cfg->site_host))
        return false;
    if (strlen(colon + 1) >= sizeof(cfg->site_port))
        return false;
    memcpy(cfg->site_host, spec, hlen);
    cfg->site_host[hlen] = '\0';
    snprintf(cfg->site_port, sizeof(cfg->site_port), "%s", colon + 1);
    return ff_backend_host_ok(cfg->site_host) &&
           ff_port_parse(cfg->site_port) >= 0;
}

/* argv -> config. 0 ok, else the process exit code (usage 2, refusal 1). */
static int ff_parse_args(int argc, char **argv, struct ff_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    if (argc != 7 && argc != 8)
        return ff_usage(argv[0]);
    cfg->listen_host = argv[1];
    cfg->listen_port = argv[2];
    cfg->gw_host = argv[3];
    cfg->gw_port = argv[4];
    cfg->cert = argv[5];
    cfg->key = argv[6];
    if (!ff_backend_host_ok(cfg->gw_host)) {
        ff_log("gateway host must be loopback");
        return 1;
    }
    if (ff_port_parse(cfg->listen_port) < 0 || ff_port_parse(cfg->gw_port) < 0) {
        ff_log("bad port");
        return 1;
    }
    /* An empty 8th argument is "no site backend", not a malformed one: a
     * unit file that always passes ${FRONT_SITE} must be able to leave it
     * unset without the front refusing to start. */
    if (argc == 8 && argv[7][0] != '\0' && strcmp(argv[7], "-") != 0 &&
        !ff_site_parse(argv[7], cfg)) {
        ff_log("site backend must be loopback-host:port");
        return 1;
    }
    /* Role-scaled, env-overridable, hard-ceilinged. An unparsable or
     * out-of-range FRONT_MAX_CHILDREN is ignored rather than fatal: a bad
     * tuning value must not be the reason the public front will not start. */
    cfg->max_children = cfg->site_host[0] != '\0' ? FF_MAX_CHILDREN_SITE
                                                  : FF_MAX_CHILDREN;
    {
        const char *tune = getenv("FRONT_MAX_CHILDREN");
        if (tune != NULL && tune[0] != '\0') {
            int want = ff_port_parse(tune);
            if (want > 0 && want <= FF_MAX_CHILDREN_CEIL)
                cfg->max_children = want;
            else
                ff_log("FRONT_MAX_CHILDREN out of range; keeping the default");
        }
    }
    return 0;
}

/* Child accounting via SIGCHLD; SIGPIPE ignored so a backend that vanishes
 * mid-relay ends the connection with EPIPE, not a signal. */
static bool ff_install_signals(void)
{
    struct sigaction sigchld;
    memset(&sigchld, 0, sizeof(sigchld));
    sigchld.sa_handler = ff_sigchld;
    sigemptyset(&sigchld.sa_mask);
    sigchld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sigchld, NULL) != 0)
        return false;
    signal(SIGPIPE, SIG_IGN);
    return true;
}

/* Wait on every listen socket and accept from the first that fires.
 * -1 when nothing was accepted this pass; -2 on a fatal poll error. */
static int ff_accept_next(const int *listen_fds, int listen_count)
{
    struct pollfd wait_fds[2];
    int i;
    for (i = 0; i < listen_count; i++) {
        wait_fds[i].fd = listen_fds[i];
        wait_fds[i].events = POLLIN;
        wait_fds[i].revents = 0;
    }
    if (poll(wait_fds, (nfds_t)listen_count, -1) < 0)
        return errno == EINTR ? -1 : -2;
    for (i = 0; i < listen_count; i++) {
        int client;
        if ((wait_fds[i].revents & POLLIN) == 0)
            continue;
        client = accept(listen_fds[i], NULL, NULL);
        if (client >= 0)
            return client;
    }
    return -1;
}

/* Fork one bounded child for an accepted client; the parent keeps only
 * the count. Over the cap the client is closed at once (the kernel
 * backlog holds later clients for the next pass). */
static void ff_spawn(int client, const int *listen_fds, int listen_count,
                     const struct ff_config *cfg, SSL_CTX *ctx,
                     SSL_CTX *site_ctx)
{
    pid_t pid;
    if (g_children >= cfg->max_children) {
        close(client);
        return;
    }
    pid = fork();
    if (pid < 0) {
        close(client);
        return;
    }
    if (pid == 0) {
        int j;
        for (j = 0; j < listen_count; j++)
            close(listen_fds[j]);
        /* Forked children share the parent's RNG state: reseed before
         * any TLS randomness (session ids, tickets) is drawn. */
        RAND_poll();
        ff_handle(client, cfg, ctx, site_ctx);
        close(client);
        _exit(0);
    }
    close(client);
    g_children++;
}

int main(int argc, char **argv)
{
    struct ff_config cfg;
    SSL_CTX *ctx = NULL;
    SSL_CTX *site_ctx = NULL;
    int listen_fds[2] = {-1, -1};
    int listen_count = 0;
    int rc = ff_parse_args(argc, argv, &cfg);
    if (rc != 0)
        return rc;
    ctx = ff_tls_ctx(&cfg);
    if (ctx == NULL) {
        ff_log("TLS context failed (cert/key unreadable or mismatched?)");
        return 1;
    }
    if (cfg.site_host[0] != '\0') {
        site_ctx = ff_site_ctx();
        if (site_ctx == NULL) {
            ff_log("site TLS context failed");
            SSL_CTX_free(ctx);
            return 1;
        }
    }
    listen_count = ff_listen(&cfg, listen_fds);
    if (listen_count <= 0 || !ff_install_signals()) {
        ff_log(listen_count <= 0 ? "bind failed" : "sigaction failed");
        SSL_CTX_free(ctx);
        if (site_ctx != NULL)
            SSL_CTX_free(site_ctx);
        return 1;
    }
    fprintf(stderr, "fleet-front: listen [%s]:%s -> gw %s:%s%s%s%s%s (%d socket%s, max %d children)\n",
        cfg.listen_host, cfg.listen_port, cfg.gw_host, cfg.gw_port,
        cfg.site_host[0] != 0 ? ", site " : "",
        cfg.site_host[0] != 0 ? cfg.site_host : "",
        cfg.site_host[0] != 0 ? ":" : "",
        cfg.site_host[0] != 0 ? cfg.site_port : "",
        listen_count, listen_count == 1 ? "" : "s", cfg.max_children);
    for (;;) {
        int client = ff_accept_next(listen_fds, listen_count);
        if (client == -2)
            break;
        if (client >= 0)
            ff_spawn(client, listen_fds, listen_count, &cfg, ctx, site_ctx);
    }
    SSL_CTX_free(ctx);
    if (site_ctx != NULL)
        SSL_CTX_free(site_ctx);
    return 1;
}
