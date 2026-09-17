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
 * WHAT IT DOES
 * ------------
 *   zcl_fleet_front <listen-host> <listen-port> <gw-host> <gw-port> <cert> <key>
 * Accepts public TLS (1.2+), relays the cleartext both ways to a loopback
 * gateway TCP connection, closes when either side ends. It is a dumb byte
 * pipe with TLS: it mints nothing, stores nothing, enforces nothing, and
 * logs no traffic and no credentials — every grant scope, expiry and
 * revocation check stays inside the node, exactly as on direct loopback.
 * The gateway host must be loopback (anything else is refused here before
 * bind, and would 403 at the gateway anyway).
 *
 * DESIGN
 * ------
 * One accept loop, fork per connection (SIGCHLD ignored: no zombies), at
 * most 16 concurrent children — the 17th accepted socket is closed at once,
 * so processes stay bounded no matter what the public side sends. Each child
 * relays through two 64 KiB stack buffers with full-write loops; bodies of
 * any size stream through, so memory stays bounded regardless of body size.
 * Idle connections die after 120 s (poll timeout); handshakes are covered by
 * 120 s socket timeouts. No threads, no malloc in the data path, no shell.
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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define FF_MAX_CHILDREN 16
#define FF_BUF_SZ (64u * 1024u)
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
};

static void ff_log(const char *msg)
{
    fprintf(stderr, "fleet-front: %s\n", msg);
}

/* Loopback only for the gateway leg: fail closed before binding anything. */
static bool ff_gw_host_ok(const char *host)
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

/* Plain TCP to the loopback gateway. Returns the fd, or -1. */
static int ff_gw_connect(const struct ff_config *cfg)
{
    int port = ff_port_parse(cfg->gw_port);
    int fd;
    if (port < 0)
        return -1;
    if (strcmp(cfg->gw_host, "::1") == 0) {
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

/* Write all bytes, or -1. */
static int ff_write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t written = write(fd, buf, len);
        if (written <= 0)
            return -1;
        buf += written;
        len -= (size_t)written;
    }
    return 0;
}

/* SSL_write all bytes, or -1. */
static int ff_ssl_write_all(SSL *ssl, const char *buf, size_t len)
{
    while (len > 0) {
        int written = SSL_write(ssl, buf, (int)len);
        if (written <= 0)
            return -1;
        buf += written;
        len -= (size_t)written;
    }
    return 0;
}

struct ff_relay {
    SSL *ssl;
    int gw_fd;
    char to_gw[FF_BUF_SZ];
    char to_client[FF_BUF_SZ];
    bool client_open;
    bool gw_open;
};

/* Drain already-decrypted bytes before blocking: poll cannot see them, and
 * waiting on it instead would stall the relay. */
static void ff_drain_pending(struct ff_relay *relay)
{
    while (relay->client_open && relay->gw_open && SSL_pending(relay->ssl) > 0) {
        int got = SSL_read(relay->ssl, relay->to_gw, sizeof(relay->to_gw));
        if (got <= 0) {
            relay->client_open = false;
            break;
        }
        if (ff_write_all(relay->gw_fd, relay->to_gw, (size_t)got) != 0) {
            relay->gw_open = false;
            break;
        }
    }
}

static void ff_pump_gw_to_client(struct ff_relay *relay)
{
    ssize_t got = read(relay->gw_fd, relay->to_client, sizeof(relay->to_client));
    if (got <= 0) {
        relay->gw_open = false;
    } else if (ff_ssl_write_all(relay->ssl, relay->to_client, (size_t)got) != 0) {
        relay->client_open = false;
    }
}

static void ff_pump_client_to_gw(struct ff_relay *relay)
{
    int got = SSL_read(relay->ssl, relay->to_gw, sizeof(relay->to_gw));
    if (got <= 0) {
        relay->client_open = false;
    } else if (ff_write_all(relay->gw_fd, relay->to_gw, (size_t)got) != 0) {
        relay->gw_open = false;
    }
}

/* Act on one poll result: pump whichever side has data (or a hangup that
 * read() must observe), and close a side whose socket reported an error. */
static void ff_relay_dispatch(struct ff_relay *relay, const struct pollfd *fds)
{
    if (relay->gw_open && (fds[1].revents & (POLLIN | POLLHUP)) != 0)
        ff_pump_gw_to_client(relay);
    if (relay->client_open && (fds[0].revents & (POLLIN | POLLHUP)) != 0)
        ff_pump_client_to_gw(relay);
    if ((fds[0].revents & (POLLERR | POLLNVAL)) != 0)
        relay->client_open = false;
    if ((fds[1].revents & (POLLERR | POLLNVAL)) != 0)
        relay->gw_open = false;
}

/* One relay pass. False when the connection is finished: both sides
 * closed, 120 s idle, a poll failure, or only stale signal left. */
static bool ff_relay_step(int client_fd, struct ff_relay *relay)
{
    struct pollfd fds[2];
    ff_drain_pending(relay);
    if (!relay->client_open && !relay->gw_open)
        return false;
    fds[0].fd = client_fd;
    fds[0].events = (short)(relay->client_open ? POLLIN : 0);
    fds[0].revents = 0;
    fds[1].fd = relay->gw_fd;
    fds[1].events = (short)(relay->gw_open ? POLLIN : 0);
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

/* One connection: TLS handshake, then a bidirectional relay until either
 * side ends or 120 s pass with no movement. Bodies of any size stream
 * through the two fixed buffers; memory never grows with the body. */
static void ff_handle(int client_fd, const struct ff_config *cfg, SSL_CTX *ctx)
{
    struct ff_relay relay;
    memset(&relay, 0, sizeof(relay));
    relay.client_open = true;
    relay.gw_open = true;
    ff_sock_timeouts(client_fd);
    relay.gw_fd = ff_gw_connect(cfg);
    if (relay.gw_fd < 0) {
        ff_log("gateway connect failed; closing client");
        return;
    }
    ff_sock_timeouts(relay.gw_fd);
    relay.ssl = SSL_new(ctx);
    if (relay.ssl == NULL)
        return;
    SSL_set_fd(relay.ssl, client_fd);
    if (SSL_accept(relay.ssl) != 1) {
        SSL_free(relay.ssl);
        return;
    }
    /* Both sockets stay blocking with 120 s timeouts: WANT_READ/WRITE
     * retries happen inside OpenSSL (or hit the timeout and end the
     * connection), so no userspace retry state can stall the relay. */
    while ((relay.client_open || relay.gw_open) &&
           ff_relay_step(client_fd, &relay))
        ;
    SSL_shutdown(relay.ssl);
    SSL_free(relay.ssl);
}

static int ff_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s <listen-host> <listen-port> <gw-host> <gw-port> <cert> <key>\n"
        "  listen-host: * (dual-stack wildcard) or a literal IP\n"
        "  gw-host: loopback only (127.0.0.1, localhost, ::1)\n",
        prog != NULL ? prog : "zcl-fleet-front");
    return 2;
}

/* argv -> config. 0 ok, else the process exit code (usage 2, refusal 1). */
static int ff_parse_args(int argc, char **argv, struct ff_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    if (argc != 7)
        return ff_usage(argv[0]);
    cfg->listen_host = argv[1];
    cfg->listen_port = argv[2];
    cfg->gw_host = argv[3];
    cfg->gw_port = argv[4];
    cfg->cert = argv[5];
    cfg->key = argv[6];
    if (!ff_gw_host_ok(cfg->gw_host)) {
        ff_log("gateway host must be loopback");
        return 1;
    }
    if (ff_port_parse(cfg->listen_port) < 0 || ff_port_parse(cfg->gw_port) < 0) {
        ff_log("bad port");
        return 1;
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
                     const struct ff_config *cfg, SSL_CTX *ctx)
{
    pid_t pid;
    if (g_children >= FF_MAX_CHILDREN) {
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
        ff_handle(client, cfg, ctx);
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
    listen_count = ff_listen(&cfg, listen_fds);
    if (listen_count <= 0 || !ff_install_signals()) {
        ff_log(listen_count <= 0 ? "bind failed" : "sigaction failed");
        SSL_CTX_free(ctx);
        return 1;
    }
    fprintf(stderr, "fleet-front: listen [%s]:%s -> %s:%s (%d socket%s)\n",
        cfg.listen_host, cfg.listen_port, cfg.gw_host, cfg.gw_port,
        listen_count, listen_count == 1 ? "" : "s");
    for (;;) {
        int client = ff_accept_next(listen_fds, listen_count);
        if (client == -2)
            break;
        if (client >= 0)
            ff_spawn(client, listen_fds, listen_count, &cfg, ctx);
    }
    SSL_CTX_free(ctx);
    return 1;
}
