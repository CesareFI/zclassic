/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zssh — allocation-free, sans-IO SSH-2 engine (public interface).
 *
 * One struct zssh_conn carries ONE outer SSH session between two peers and
 * forwards exactly ONE channel (RFC 4254 7.2 "direct-tcpip" to the fixed
 * target ZSSH_FWD_HOST:ZSSH_FWD_PORT; the server application maps that
 * channel to its real device port). No shell, no pty, no rekey. See README.md.
 *
 * Sans-IO contract. The engine never reads a socket, a clock or a random
 * device. The caller
 *   1. feeds received transport bytes to zssh_input(),
 *   2. drains zssh_output_peek()/zssh_output_consume() to the transport,
 *   3. moves application bytes with zssh_channel_send()/zssh_channel_recv(),
 * and calls them in any order, any number of times. Nothing blocks and
 * nothing allocates: every buffer lives inside the caller-owned struct
 * zssh_conn. Not thread safe: one thread (or one lock) per connection.
 *
 * Back-pressure. zssh_input() may stop early (*consumed < n) when the output
 * queue cannot hold the replies the next packet could require (status
 * NEED_OUTPUT). The caller drains output and calls zssh_input() again with the
 * unconsumed tail. The received-channel-data ring can never overflow (its size
 * equals the advertised window, which the engine enforces), so input is never
 * stalled for a full ring; unread channel data merely keeps the window closed
 * until zssh_channel_recv() frees it and the WINDOW_ADJUST is queued.
 *
 * ERROR MODEL (one model, three classes of call result):
 *  1. Per-call MISUSE (NULL pointer, n > 0 with NULL data, call in a state
 *     where the operation is not defined, output_consume beyond pending,
 *     send after our own EOF) returns ZSSH_BAD_CALL (status
 *     ZSSH_STATUS_BAD_CALL for input/pump). It changes NOTHING: no state, no
 *     sticky error, no queued byte; every *out count that can be written is
 *     written as 0. This is observable only through the return value.
 *  2. Protocol/crypto/RNG failure is STICKY: ZSSH_FAILED / ZSSH_STATUS_FAILED,
 *     state ZSSH_STATE_FAILED, zssh_error() holds the FIRST cause forever.
 *     The engine makes a best effort to queue an SSH_MSG_DISCONNECT first
 *     (not after ZSSH_E_RANDOM or ZSSH_E_TRUNCATED) and wipes all secret
 *     material (keys, seeds, kex state, unread channel data).
 *  3. TERMINAL TABLE (the single rule; every per-function doc below agrees
 *     with it). Result and counts per operation for a call MADE while the
 *     state is CLOSED (clean shutdown finished) or FAILED (sticky); a call
 *     that itself causes the failure is described under Transactions below
 *     and at the function. Nothing here changes the
 *     state or zssh_error() except where stated; "counts" are the *out values.
 *
 *     operation             state CLOSED                  state FAILED
 *     --------------------  ----------------------------  -------------------
 *     zssh_input            consumed 0; status CLOSED     consumed up to the
 *                           (STATUS_FAILED never)         fatal byte on the
 *                                                         failing call, else
 *                                                         0; STATUS_FAILED
 *     zssh_pump             input as above; output copy   same; output copy
 *                           still runs (drains the final  still runs; produced
 *                           DISCONNECT); produced exact   exact
 *     zssh_output_peek      OK, remaining queue           OK, remaining queue
 *     zssh_output_consume   OK (n <= pending, else        OK (n <= pending,
 *                           BAD_CALL)                     else BAD_CALL)
 *     zssh_channel_send     EOF, accepted 0               FAILED, accepted 0
 *     zssh_channel_recv     OK with unread ring data      FAILED, got 0 (the
 *                           (got > 0) until drained,      ring was wiped)
 *                           then EOF, got 0
 *     zssh_channel_send_eof OK, nothing queued            FAILED
 *     zssh_channel_close    OK, nothing queued            FAILED
 *                           (idempotent)
 *     zssh_transport_eof    OK, no-op (*)                 FAILED, error kept
 *                                                         (first error wins)
 *     (*) a transport EOF before CLOSED is itself a clean end (-> CLOSED, OK)
 *     only under the 4-part rule documented at zssh_transport_eof.
 *     zssh_wipe             stays CLOSED                  stays FAILED, error
 *                                                         kept
 *     getters (state, error, flags_get, session_info_get, state_name,
 *     error_name)           work, valid               work, valid
 *
 *     Any call with NULL/invalid arguments is BAD_CALL in every state (class
 *     1) and writes its counts as 0. The final DISCONNECT is already sealed
 *     ciphertext, so peek/consume need no key to drain it. After FAILED the
 *     only operations that still do useful work are peek/consume/pump's
 *     output copy, the getters and zssh_wipe.
 *
 * Transactions. Every message the engine originates (CHANNEL_DATA, WINDOW_
 * ADJUST, EOF, CLOSE, replies) is sealed and committed to the output queue as
 * ONE atomic whole packet. Any state change that the message announces (send
 * window charge, window credit, sent_eof, sent_close) is applied ONLY when
 * that commit succeeded; if the queue has no room nothing changes and the
 * call reports ZSSH_AGAIN so it can simply be retried after draining output.
 * Sealing a packet can also fail terminally, with ZSSH_E_RANDOM (padding
 * draw) or ZSSH_E_REKEY_LIMIT (session packet/byte limit); that fails the
 * session (sticky FAILED, secrets wiped) and the failing packet is NOT
 * committed. A call that commits several packets (zssh_channel_send) and
 * fails on a later one reports the exact prefix already committed (that
 * count is real and stays charged), returns ZSSH_FAILED and leaves the
 * session FAILED; likewise zssh_channel_recv reports in *got the bytes it
 * already copied out when the WINDOW_ADJUST that follows the read fails, and
 * returns ZSSH_FAILED (the failure is sticky).
 *
 * Physical transport. Transport EOF/reset is NOT an SSH event. A transport
 * that ends before zssh_state() == ZSSH_STATE_CLOSED is a truncation, never a
 * clean close: the caller must call zssh_transport_eof() (or zssh_wipe()),
 * must not report the session as cleanly closed, and must then drop the
 * transport. zssh_input(n = 0) is "no input", not EOF. */
#ifndef ZSSH_ZSSH_H
#define ZSSH_ZSSH_H

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Channel contract (fixed, one only). The outer session carries ONE relay channel
 * to port P of the far guest. We chose RFC 4254 7.2 "direct-tcpip" to the fixed
 * target ZSSH_FWD_HOST:ZSSH_FWD_PORT instead of a custom subsystem because it
 * is a standard channel type every OpenSSH client can open (`ssh -W`), so real
 * OpenSSH interop tests need no private extension, and the target carries no
 * authority: the server application ignores it and binds the channel to port P
 * itself. Because the label carries no authority, the CALLER must bind the
 * authenticated peer (its authorized user key) to the actual device port P
 * and must not derive any target from the label. Refused with
 * CHANNEL_OPEN_FAILURE / CHANNEL_FAILURE: forwarded-tcpip,
 * session, x11, exec/shell/subsystem/pty/env requests, global requests
 * (tcpip-forward), a second channel, and any other direct-tcpip target. Guest
 * sockets do not exist: the engine never touches a socket; the transport and
 * the device port are both byte pipes owned by the caller.
 *
 * Rekey LIMIT (interim, not acceptance for persistent sessions): there is no
 * rekey. A peer SSH_MSG_KEXINIT after the first NEWKEYS fails the connection
 * with ZSSH_E_REKEY_UNSUPPORTED after a best-effort DISCONNECT (reason
 * KEY_EXCHANGE_FAILED); reaching ZSSH_MAX_SESSION_* in either direction fails
 * with ZSSH_E_REKEY_LIMIT. A session therefore has a hard lifetime bound
 * (1 GiB or 2^31-1 packets per direction) and a caller needing a longer-lived
 * link MUST reconnect; this module is not fit for unbounded persistent
 * sessions until a later writer adds rekey behind these same two errors and
 * bumps zssh_session_info.kex_generation.
 *
 * Approvals: there is NO asynchronous approval in this API. The host key is
 * pinned in the configuration, so there is no pin decision to defer. Any future
 * approval hook MUST carry the current kex_generation and session_id prefix
 * and be rejected as stale otherwise. */

/* ---- bounds (all buffers are bounded by these named constants) ---------- */

/* RFC 4253 6.1: implementations MUST support packets of at least 35000 bytes
 * total; this is also our hard upper limit for the packet_length field. */
#define ZSSH_MAX_PACKET            35000u
/* Version line, RFC 4253 4.2: at most 255 bytes including CR LF. */
#define ZSSH_MAX_VERSION_LINE      255u
/* Peer pre-banner text lines tolerated before the version line (client role
 * only, RFC 4253 4.2); each is bounded by ZSSH_MAX_VERSION_LINE. */
#define ZSSH_MAX_PREBANNER_LINES   16u
/* Largest KEXINIT payload accepted from the peer (both lists + cookie). */
#define ZSSH_KEXINIT_MAX           4096u
/* Channel parameters we advertise and enforce. */
#define ZSSH_CHAN_WINDOW           32768u   /* initial window == rx ring size */
#define ZSSH_CHAN_MAX_PACKET       16384u   /* max CHANNEL_DATA payload we accept */
#define ZSSH_MAX_USER              64u      /* user name bytes, excl. NUL */
#define ZSSH_MAX_COMMENT           64u      /* version comment bytes, excl. NUL */
/* Evaluated publickey requests (signed requests AND unsigned probes, whether
 * answered FAILURE, PK_OK or SUCCESS) allowed per connection; the next one is
 * ZSSH_E_AUTH_REFUSED without evaluation. A normal client needs 2 (probe,
 * then signed). Method "none" requests are bounded separately by
 * ZSSH_MAX_AUTH_NONE. */
#define ZSSH_MAX_AUTH_ATTEMPTS     3u
#define ZSSH_MAX_AUTH_NONE         4u
/* Session limits (no rekey, so exceeding either fails ZSSH_E_REKEY_LIMIT).
 * Sequence numbers must never wrap (RFC 4253 6.4 / 9); bytes per RFC 4253 9.
 * Counted per direction since the last NEWKEYS: PACKETS = binary packets,
 * BYTES = total wire bytes of each packet (length field, body, tag). The
 * packet that would make a count exceed its limit is refused (the limit
 * itself is allowed). */
#define ZSSH_MAX_SESSION_PACKETS   0x7fffffffu
#define ZSSH_MAX_SESSION_BYTES     (1ull << 30)

/* Fixed forward target carried in the direct-tcpip CHANNEL_OPEN. It is a
 * label, never resolved: ".invalid" is reserved by RFC 6761 section 6.4. The
 * server accepts only this exact target and rejects everything else with
 * SSH_OPEN_ADMINISTRATIVELY_PROHIBITED. The originator is "0.0.0.0":0. */
#define ZSSH_FWD_HOST              "device.invalid"
#define ZSSH_FWD_PORT              1u

#define ZSSH_ED25519_SEED_LEN      32u
#define ZSSH_ED25519_PK_LEN        32u
#define ZSSH_FINGERPRINT_LEN       32u      /* SHA-256 of the host key blob */

/* Storage reserved for struct zssh_conn. zssh_internal.h static_asserts that
 * the real state fits; callers must treat the struct as opaque. */
#define ZSSH_CONN_STORAGE_SIZE     163840u

/* ---- configuration ------------------------------------------------------ */

enum zssh_role { ZSSH_ROLE_CLIENT = 1, ZSSH_ROLE_SERVER = 2 };

/* Key-exchange set (bitmask for zssh_config.kex_allowed). */
enum zssh_kex_bit {
    ZSSH_KEX_MLKEM768X25519_SHA256 = 1u << 0, /* "mlkem768x25519-sha256" */
    ZSSH_KEX_CURVE25519_SHA256     = 1u << 1  /* "curve25519-sha256" (RFC 8731) */
};

/* Fills out[0..n) with cryptographically secure random bytes; false on
 * failure (the engine then fails with ZSSH_E_RANDOM, terminal: state FAILED,
 * nothing derived from the draw is emitted, no DISCONNECT is queued). Required.
 * Lifetime: rand and rand_ctx must stay valid and usable until zssh_wipe() or
 * the end of the connection's storage (the engine keeps the pointers). The
 * engine calls it only from inside a zssh_* call on this conn, one call at a
 * time and never re-entrantly (the callback must not call back into any zssh_*
 * function of the same conn, and the caller serialises calls per conn). */
typedef bool (*zssh_rand_fn)(void *ctx, uint8_t *out, size_t n);

/* Exactly one identity block applies to each role; the other pointers must be
 * NULL (zssh_init fails with ZSSH_E_CONFIG otherwise):
 *   SERVER: host_seed + authorized_user_pk
 *   CLIENT: pinned_host_pk + user_seed
 * Seeds are RFC 8032 32-byte Ed25519 seeds. All pointed-to bytes are copied
 * into the connection by zssh_init; the caller wipes its own copy. There is
 * deliberately no trust-on-first-use: a client without a pinned host key
 * cannot be configured. */
struct zssh_config {
    enum zssh_role role;
    zssh_rand_fn   rand;
    void          *rand_ctx;

    const uint8_t *host_seed;          /* SERVER: 32-byte Ed25519 seed */
    const uint8_t *pinned_host_pk;     /* CLIENT: 32-byte host public key */
    const uint8_t *user_seed;          /* CLIENT: 32-byte Ed25519 seed */
    const uint8_t *authorized_user_pk; /* SERVER: 32-byte public key */

    /* User name, required and non-empty for BOTH roles (NULL or "" is refused
     * by zssh_init with ZSSH_BAD_CALL; there is no "any user" mode).
     * CLIENT: sent in USERAUTH_REQUEST. SERVER: the request's user must equal
     * this value. */
    const char *user;

    uint32_t kex_allowed;     /* OR of enum zssh_kex_bit; must be non-zero */
    bool     require_pq;      /* true: only MLKEM768X25519_SHA256 may be
                               * negotiated AND our KEXINIT offers ONLY
                               * "mlkem768x25519-sha256" (no classical fallback);
                               * a peer without it fails with
                               * ZSSH_E_KEX_NO_MATCH. If set, kex_allowed must
                               * include MLKEM768X25519_SHA256. */
    const char *version_comment; /* appended after "SSH-2.0-zssh_1 " ; NULL = none.
                                  * Printable ASCII 0x21..0x7e and space, no
                                  * CR/LF, <= ZSSH_MAX_COMMENT. */
};

/* ---- state, results, errors --------------------------------------------- */

enum zssh_state {
    ZSSH_STATE_VERSION = 0, /* exchanging identification strings */
    ZSSH_STATE_KEX,         /* KEXINIT .. NEWKEYS (strict KEX in force) */
    ZSSH_STATE_AUTH,        /* encrypted; ssh-userauth in progress */
    ZSSH_STATE_OPEN,        /* authenticated; channel open in flight */
    ZSSH_STATE_CHANNEL,     /* channel confirmed; data may flow */
    ZSSH_STATE_CLOSED,      /* clean shutdown finished (drain output); unread
                             * channel data stays readable until drained */
    ZSSH_STATE_FAILED       /* sticky; see zssh_error() */
};

enum zssh_result {
    ZSSH_OK = 0,      /* progress made or nothing needed */
    ZSSH_AGAIN,       /* would block, NOTHING changed, retry later: no queue
                       * room / no window / no data */
    ZSSH_EOF,         /* channel_recv: peer sent EOF and ring is empty;
                       * channel_send: the channel is gone (peer CLOSE seen or
                       * STATE_CLOSED) */
    ZSSH_FAILED,      /* sticky failure; zssh_error() says why */
    ZSSH_BAD_CALL     /* misuse of this call; nothing changed, zssh_error()
                       * unchanged, outputs written as 0 (appended value) */
};

enum zssh_error {
    ZSSH_E_NONE = 0,
    ZSSH_E_CONFIG,              /* zssh_init rejected the configuration */
    ZSSH_E_INTERNAL,            /* invariant violated / not implemented */
    ZSSH_E_RANDOM,              /* cfg.rand returned false */
    ZSSH_E_VERSION,             /* bad/unsupported identification string */
    ZSSH_E_PROTOCOL,            /* malformed or unexpected message */
    ZSSH_E_MAC,                 /* packet authentication tag mismatch */
    ZSSH_E_TOO_LARGE,           /* packet_length / field above a bound */
    ZSSH_E_KEX_NO_MATCH,        /* no common algorithm (or PQ required) */
    ZSSH_E_KEX_FAILED,          /* KEX math/hash/validation failure */
    ZSSH_E_STRICT_KEX_REQUIRED, /* peer lacks kex-strict-*-v00@openssh.com,
                                 * or broke strict-KEX ordering */
    ZSSH_E_HOST_KEY_MISMATCH,   /* server key != pinned key */
    ZSSH_E_HOST_SIG,            /* signature over H did not verify */
    ZSSH_E_AUTH_REFUSED,        /* userauth failed / attempts exhausted */
    ZSSH_E_CHANNEL_REFUSED,     /* CHANNEL_OPEN rejected / wrong target */
    ZSSH_E_WINDOW,              /* peer overran the advertised window/packet */
    ZSSH_E_REKEY_UNSUPPORTED,   /* peer KEXINIT after NEWKEYS */
    ZSSH_E_REKEY_LIMIT,         /* session packet/byte limit reached */
    ZSSH_E_PEER_DISCONNECT,     /* peer sent SSH_MSG_DISCONNECT (state FAILED
                                 * unless the channel had closed cleanly) */
    ZSSH_E_NOT_IMPLEMENTED,     /* stub layer; never in a finished module */
    ZSSH_E_TRUNCATED            /* transport ended before STATE_CLOSED
                                 * (zssh_transport_eof); appended value */
};

/* ---- connection --------------------------------------------------------- */

/* Opaque, caller-owned, fixed size. Declare it static or on a large stack;
 * ZSSH_CONN_STORAGE_SIZE bytes. Never copy or memcmp a live one. */
struct zssh_conn {
    alignas(16) unsigned char opaque[ZSSH_CONN_STORAGE_SIZE];
};

/* Zero the struct, validate cfg, copy identity material, derive the server's
 * host public key, and queue our identification string
 * "SSH-2.0-zssh_1[ comment]\r\n". Returns ZSSH_OK, or ZSSH_FAILED with
 * zssh_error() == ZSSH_E_CONFIG (every violation of the struct zssh_config
 * rules: NULL rand, role/identity mismatch, empty kex set, require_pq without
 * the hybrid, bad comment, over-long user) or ZSSH_E_RANDOM. On every failure
 * the conn is left in ZSSH_STATE_FAILED with that error observable, holding no
 * secret and no pending output. NULL conn or cfg, or a NULL/empty cfg->user
 * (either role): ZSSH_BAD_CALL (conn, if non-NULL, is untouched). Key hold: the
 * exchange secret K is kept until the peer's NEWKEYS is processed (the rx keys
 * are derived from it at that point) and is wiped then, and on any failure or
 * close path. */
/* Fail-closed RNG: any cfg.rand failure (at init, KEXINIT cookie, ephemeral
 * key, padding) moves the session to FAILED(ZSSH_E_RANDOM) and emits nothing
 * derived from the failed draw; secrets are wiped. */
enum zssh_result zssh_init(struct zssh_conn *conn, const struct zssh_config *cfg);

/* Overall progress status returned by zssh_input() and zssh_pump():
 *   NEED_INPUT    all offered input consumed; the engine waits for more bytes
 *                 (also the answer while output is empty and nothing else to do)
 *   NEED_OUTPUT   undrained output remains queued AFTER this call, or the
 *                 engine stopped consuming input (consumed < n) because the
 *                 queue lacks room for the replies the next packet could
 *                 cause. The caller drains output and calls again.
 *   CHANNEL_READY the forwarded channel is confirmed (STATE_CHANNEL), no
 *                 output is pending and nothing blocks; send/recv may proceed
 *   CLOSED        clean shutdown finished (STATE_CLOSED). Output may still be
 *                 pending (the final DISCONNECT): drain it with peek/consume.
 *   STATUS_FAILED sticky; zssh_error() says why
 *   STATUS_BAD_CALL  misuse; nothing changed, counts 0 (appended value)
 * The status is computed AFTER the whole call (for pump: after the output
 * copy), from the resulting state and queue, never from a pre-drain snapshot.
 * Precedence when several hold: STATUS_BAD_CALL (only for argument misuse),
 * STATUS_FAILED, CLOSED, NEED_OUTPUT, CHANNEL_READY, NEED_INPUT. Counts are
 * always exact, also on FAILED. After a full drain of an engine that is still
 * running the status is CHANNEL_READY in STATE_CHANNEL, otherwise NEED_INPUT. */
enum zssh_status {
    ZSSH_NEED_INPUT = 0,
    ZSSH_NEED_OUTPUT,
    ZSSH_CHANNEL_READY,
    ZSSH_CLOSED,
    ZSSH_STATUS_FAILED,
    ZSSH_STATUS_BAD_CALL
};

/* Feed n received bytes (any fragmentation, down to 1 byte per call, must
 * give the identical result as one big call). Sets *consumed (0..n) to the
 * exact prefix taken; unconsumed bytes must be offered again after draining
 * output. Partial packets are retained inside the conn. On FAILED, *consumed
 * counts bytes read up to and including the fatal one; the rest is dropped.
 * *consumed is always written (0 on BAD_CALL). In CLOSED consumed is 0.
 *
 * n == 0 (data may be NULL) is a RESUME: it consumes nothing but retries work
 * that was deferred for lack of queue room (a pending WINDOW_ADJUST, a reply
 * the engine owes), then returns the status. A caller that stopped on
 * NEED_OUTPUT drains output and then calls zssh_input(conn, NULL, 0, &c) or
 * re-offers the tail; both are correct. It is not a transport EOF. */
enum zssh_status zssh_input(struct zssh_conn *conn, const uint8_t *data,
                            size_t n, size_t *consumed);

/* Convenience combined step: input as above (including the n == 0 resume),
 * then copy up to out_cap pending bytes into out. *produced is the exact
 * number copied (<= out_cap; consumed <= in_len; both hold on every status,
 * also FAILED); the copied bytes are removed from the queue and the rest stays
 * queued. Packets are committed to the queue whole and atomically, but the
 * copy (and any transport) may take ANY prefix of the queue, including half a
 * packet; the suffix is retained byte-exact and continued by the next
 * pump/peek. out_cap == 0 copies nothing; the output side runs also in FAILED
 * and CLOSED, so a final DISCONNECT can be drained through pump. The returned
 * status is the post-drain status defined above. */
enum zssh_status zssh_pump(struct zssh_conn *conn,
                           const uint8_t *in, size_t in_len, size_t *consumed,
                           uint8_t *out, size_t out_cap, size_t *produced);

/* Contiguous pending output. Partially consumed packets are retained: a later peek
 * continues exactly where the last consume stopped. *p and *n are valid until the next call into this
 * engine for this conn; *n == 0 (and *p unspecified but non-NULL) when empty.
 * The bytes are ciphertext/ wire format only. Valid in every state including
 * FAILED/CLOSED (the final DISCONNECT may be pending); returns ZSSH_OK there,
 * never ZSSH_FAILED. NULL arguments: ZSSH_BAD_CALL. */
enum zssh_result zssh_output_peek(const struct zssh_conn *conn,
                                  const uint8_t **p, size_t *n);
/* Drop the first n pending bytes (n <= *n from the last peek). n larger than
 * pending is misuse: ZSSH_BAD_CALL, nothing dropped, zssh_error() unchanged.
 * Valid in every state including FAILED/CLOSED. */
enum zssh_result zssh_output_consume(struct zssh_conn *conn, size_t n);

/* Queue application bytes on the channel (binary-exact). *accepted is ALWAYS
 * written: the number of leading bytes of data that were queued (0..n). The
 * engine builds zero or more CHANNEL_DATA packets, each committed whole; the
 * send window is charged per committed packet by exactly its payload and
 * never for bytes not queued, so there is no partial charge. *accepted is
 * bounded by the peer window, the peer max packet, ZSSH_CHAN_MAX_PACKET and
 * free queue room (leaving the reply reserve). When queue room is the only
 * limit and would admit a DATA packet smaller than 1024 payload bytes, the
 * engine returns ZSSH_AGAIN instead of queueing that runt (drain the output,
 * then retry); this does not apply when the remaining data itself is smaller
 * than 1024 bytes. If a later packet of the same
 * call cannot be sealed (ZSSH_E_RANDOM or ZSSH_E_REKEY_LIMIT) after earlier
 * ones were committed, *accepted is exactly the committed prefix (> 0), the
 * result is ZSSH_FAILED and the session is FAILED; the caller must not resend
 * that prefix. Disposition:
 *   ZSSH_OK       *accepted > 0 (maybe < n: call again with the tail), or
 *                 n == 0 (no packet, *accepted 0);
 *   ZSSH_AGAIN    *accepted == 0: no window or no queue room; NOTHING
 *                 changed, including a deferred WINDOW_ADJUST of ours: the
 *                 engine queues that adjust only when it fits AND the DATA
 *                 packet this call then builds also fits behind it, so an
 *                 AGAIN never queues, seals, draws randomness or moves any
 *                 window; retry after the peer's WINDOW_ADJUST arrived or
 *                 the output was drained;
 *   ZSSH_EOF      *accepted == 0: the channel is gone (peer CHANNEL_CLOSE
 *                 seen, or STATE_CLOSED);
 *   ZSSH_BAD_CALL *accepted == 0: state is before CHANNEL, or our own EOF/
 *                 CLOSE was already sent (and the state is not yet CLOSED),
 *                 or NULL args; nothing changed, error unchanged. Peer EOF
 *                 does NOT stop sending (half-close);
 *   ZSSH_FAILED   connection already FAILED on entry (*accepted == 0), or a
 *                 later packet of this call failed (*accepted == committed
 *                 prefix, see above); sticky error. */
enum zssh_result zssh_channel_send(struct zssh_conn *conn, const uint8_t *data,
                                   size_t n, size_t *accepted);

/* Copy up to cap received channel bytes to buf; *got (always written) is
 * bytes copied. ZSSH_OK if got > 0 (cap == 0: ZSSH_OK, got 0); ZSSH_AGAIN if
 * none yet; ZSSH_EOF only when the peer sent EOF or CLOSE AND the ring is
 * empty (data already received stays readable first, also after peer CLOSE and
 * in STATE_CLOSED, until drained; a call made in FAILED returns ZSSH_FAILED
 * with got 0, the ring having been wiped). ZSSH_AGAIN and ZSSH_EOF (got 0)
 * change NOTHING: no WINDOW_ADJUST is queued, even a deferred one. Only a
 * call that returns data (ZSSH_OK) can queue one as a side effect: reading
 * frees window; the matching WINDOW_ADJUST is queued by the engine when due
 * and room exists, otherwise it stays deferred and is retried at the next
 * zssh_input/pump/channel_send call or channel_recv that returns data (the
 * data is still returned; window credit commits only
 * when the WINDOW_ADJUST is queued). If sealing that WINDOW_ADJUST fails
 * (ZSSH_E_RANDOM or ZSSH_E_REKEY_LIMIT) the bytes already copied out are
 * reported in *got (they are consumed, do not re-read them), the result is
 * ZSSH_FAILED and the session is FAILED. BAD_CALL for NULL args or state
 * before CHANNEL. */
enum zssh_result zssh_channel_recv(struct zssh_conn *conn, uint8_t *buf,
                                   size_t cap, size_t *got);

/* Begin orderly close: queue CHANNEL_EOF (if not yet sent) + CHANNEL_CLOSE as
 * ONE all-or-nothing step: if the queue lacks room for both, nothing changes
 * and ZSSH_AGAIN is returned. Idempotent: once sent_close is set it returns
 * ZSSH_OK without queueing. When both CLOSEs have been exchanged the engine
 * queues SSH_MSG_DISCONNECT (BY_APPLICATION) and enters STATE_CLOSED; drain
 * output afterwards. In STATE_CLOSED it returns ZSSH_OK and queues nothing; in
 * STATE_FAILED ZSSH_FAILED; before STATE_CHANNEL ZSSH_BAD_CALL. */
enum zssh_result zssh_channel_close(struct zssh_conn *conn);

/* Half-close, directional and explicit. zssh_channel_send_eof() queues
 * CHANNEL_EOF once (our send side ends; recv stays open; ZSSH_AGAIN with no
 * change if the queue lacks room; ZSSH_OK, nothing queued, if our EOF or
 * CLOSE was already sent, hence also in STATE_CLOSED; ZSSH_FAILED in
 * STATE_FAILED; ZSSH_BAD_CALL before STATE_CHANNEL). Peer EOF is
 * visible as ZSSH_EOF from zssh_channel_recv after the ring drains (the
 * peer's send side ended; ours stays open). No emulation: EOF never implies
 * CLOSE. The ONLY sender of CHANNEL_CLOSE on our initiative is
 * zssh_channel_close(); the single exception is the automatic reply: when the
 * peer's CHANNEL_CLOSE arrives and sent_close is not set, the engine queues
 * our CHANNEL_CLOSE itself exactly once (RFC 4254 5.3). That reply always
 * fits: input is admitted only while the reply reserve is free, so it cannot
 * be refused for room; if it nevertheless could not be queued that is an
 * engine invariant violation and fails the session with ZSSH_E_INTERNAL.
 * After both CLOSEs the engine queues DISCONNECT and enters STATE_CLOSED. */
struct zssh_channel_flags {
    bool sent_eof, recv_eof, sent_close, recv_close;
    uint32_t send_window;   /* bytes the peer still allows us to send */
    uint32_t recv_window;   /* bytes we still allow the peer to send */
};
enum zssh_result zssh_channel_send_eof(struct zssh_conn *conn);
/* Valid in every state (flags survive FAILED/CLOSED as evidence; before the
 * channel exists they are all zero). NULL args: ZSSH_BAD_CALL. */
enum zssh_result zssh_channel_flags_get(const struct zssh_conn *conn,
                                        struct zssh_channel_flags *out);

/* Getters are valid in every state and never change anything. A NULL conn
 * reads as STATE_FAILED / ZSSH_E_INTERNAL. */
enum zssh_state zssh_state(const struct zssh_conn *conn);
enum zssh_error zssh_error(const struct zssh_conn *conn);
const char *zssh_state_name(enum zssh_state s);
const char *zssh_error_name(enum zssh_error e);

/* Evidence for logs and pinning. Valid once the key exchange completed
 * (state >= AUTH); `valid` is false before that and after zssh_wipe(). It stays
 * valid after FAILED/CLOSED if the key exchange had completed (it holds only
 * public transcript values, no secret). Returns ZSSH_OK in every state with
 * out->valid telling whether it holds data; NULL args: ZSSH_BAD_CALL. */
struct zssh_session_info {
    bool    valid;
    bool    post_quantum;       /* hybrid ML-KEM-768 + X25519 was negotiated */
    uint32_t kex_generation; /* 0 = first key exchange; bumped by a future rekey */
    bool    strict_kex;         /* always true when valid; recorded as evidence */
    char    kex_name[32];       /* ACTUALLY negotiated kex name, never the
                                 * configured preference */
    char    peer_version[ZSSH_MAX_VERSION_LINE + 1]; /* NUL-terminated, no CRLF */
    uint8_t host_key[ZSSH_ED25519_PK_LEN];           /* server host public key */
    uint8_t host_key_sha256[ZSSH_FINGERPRINT_LEN];   /* SHA-256 of the SSH wire
                                                      * host key blob (OpenSSH
                                                      * "SHA256:" fingerprint
                                                      * before base64) */
};
enum zssh_result zssh_session_info_get(const struct zssh_conn *conn,
                                       struct zssh_session_info *out);

/* The physical transport ended (EOF, reset, timeout). Clean-end rule: the EOF
 * is a clean end (state CLOSED, error NONE, secrets wiped, unread channel data
 * stays readable, returns ZSSH_OK) iff ALL hold: (1) we queued our
 * CHANNEL_CLOSE, (2) the caller has taken our whole output queue, (3) the
 * peer's CHANNEL_EOF or CHANNEL_CLOSE was received (no peer data can be lost),
 * (4) no bytes of a partial packet are buffered. This covers peers such as
 * OpenSSH "ssh -W" that drop the transport after our CLOSE without sending
 * their own. If the peer CLOSEd first and our reply is queued, the state is
 * already CLOSED (a no-op here). Otherwise, if the state is not
 * CLOSED the session did NOT close cleanly: it becomes FAILED(ZSSH_E_TRUNCATED)
 * (first error wins if already FAILED), secrets and unread channel data are
 * wiped, no DISCONNECT is queued (the transport is gone), already-queued bytes
 * stay drainable. Returns ZSSH_OK only if the state was already CLOSED (no-op),
 * otherwise ZSSH_FAILED (an already FAILED conn keeps its error and stays
 * FAILED); NULL conn: ZSSH_BAD_CALL. The caller must never report
 * a clean SSH close unless zssh_state() == ZSSH_STATE_CLOSED. This is the only
 * disposition of an incomplete buffered packet at EOF: it is dropped. */
enum zssh_result zssh_transport_eof(struct zssh_conn *conn);

/* Wipe every secret in the connection, all unread channel data and all pending
 * output. State and error are preserved where they are already terminal: a
 * CLOSED conn stays CLOSED and a FAILED conn keeps its first (sticky) error;
 * only a conn that is neither CLOSED nor FAILED becomes FAILED(ZSSH_E_INTERNAL)
 * (use zssh_transport_eof first when the cause is transport loss, so the error
 * is ZSSH_E_TRUNCATED). Idempotent. Call before freeing/reusing the memory.
 * NULL conn is a no-op. */
void zssh_wipe(struct zssh_conn *conn);

#endif /* ZSSH_ZSSH_H */
