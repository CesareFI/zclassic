/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink punch state machine: after both peers hold each other's
 * candidate lists (directlink_offer.h), probe every remote candidate at a
 * paced interval, answer valid probes, and report the first remote address
 * that returned a valid reply, or a fallback to the onion path.
 *
 * Pure logic. The machine opens no socket and reads no clock: time and
 * datagram transmission come from the injected ops table, received datagrams
 * are passed to directlink_punch_on_datagram(), and directlink_punch_tick()
 * advances the schedule. The caller owns the socket and the keepalive timer.
 *
 * Probe datagram, 42 bytes, little-endian:
 *
 *   0   magic "ZDP"
 *   3   version  u8  1
 *   4   type     u8  1 = probe, 2 = reply
 *   5   role     u8  1 = initiator, 0 = responder (sender's role)
 *   6   session  16 bytes
 *   22  seq      u32 (a reply echoes the probe's seq)
 *   26  mac      16 bytes: HMAC-SHA3-256(key, bytes 0..25) truncated
 *
 * The key is supplied by the caller and derived from the paired session, so
 * only the two paired peers can produce a valid datagram. A datagram with a
 * wrong length, magic, version, session, role equal to our own (a reflected
 * datagram), or a MAC that does not verify is dropped and counted; it cannot
 * cause a reply, change the state, or select an address. A probe from an
 * address that was not in the candidate list is answered and the address is
 * added to the probe targets (at most DIRECTLINK_PUNCH_LEARNED_MAX), so a
 * peer behind a symmetric mapping is reached on the port it really uses. The
 * MAC, not the advertised list, authenticates the path (peer-reflexive
 * discovery).
 *
 * Failure is expected and cheap: a punch that does not complete within its
 * deadline reports DIRECTLINK_OUTCOME_FALLBACK_TO_ONION and never counts
 * against the peer.
 */

#ifndef ZCL_GAMELINK_DIRECTLINK_PUNCH_H
#define ZCL_GAMELINK_DIRECTLINK_PUNCH_H

#include "gamelink/directlink_addr.h"
#include "gamelink/directlink_offer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DIRECTLINK_PROBE_BYTES 42u
#define DIRECTLINK_PUNCH_LEARNED_MAX 4u
#define DIRECTLINK_PROBE_MAC_BYTES 16u
#define DIRECTLINK_PUNCH_DEFAULT_INTERVAL_MS 100
#define DIRECTLINK_PUNCH_DEFAULT_ROUNDS 20u
#define DIRECTLINK_PUNCH_DEFAULT_GRACE_MS 1000
#define DIRECTLINK_PUNCH_DEFAULT_KEEPALIVE_MS 15000

/* Bounds enforced by directlink_punch_start. A zero interval, round count or
 * grace selects its default; a non-zero value outside the bounds is refused.
 * The reply budget caps the replies one punch sends to probes, so a sender
 * holding the key cannot turn this node into a reflector of unbounded size. */
#define DIRECTLINK_PUNCH_INTERVAL_MIN_MS 20
#define DIRECTLINK_PUNCH_INTERVAL_MAX_MS 5000
#define DIRECTLINK_PUNCH_ROUNDS_MAX 100u
#define DIRECTLINK_PUNCH_GRACE_MAX_MS 10000
#define DIRECTLINK_PUNCH_REPLY_BUDGET 256u

/* Injected effects. `send` returns true when the datagram was handed to the
 * network; `now_ms` is a monotonic millisecond clock. */
struct directlink_punch_ops {
    bool (*send)(void *ctx, const struct directlink_addr *to,
                 const uint8_t *bytes, size_t len);
    int64_t (*now_ms)(void *ctx);
    void *ctx;
};

struct directlink_punch_config {
    uint8_t session_id[DIRECTLINK_OFFER_SESSION_BYTES];
    uint8_t key[32];
    bool initiator;
    struct directlink_addr remote[DIRECTLINK_OFFER_CANDIDATES_MAX];
    size_t remote_count;
    int64_t start_delay_ms;  /* from now; 0 starts at the first tick */
    int64_t interval_ms;     /* 0 selects the default */
    uint32_t max_rounds;     /* 0 selects the default */
    int64_t reply_grace_ms;  /* 0 selects the default */
    int64_t keepalive_ms;    /* 0 selects the default */
    /* The machine takes no scope decision of its own. The caller sets this
     * from the peer's scope: true only for intra_fleet. When false, private
     * and loopback remote candidates are refused at start, and a private or
     * loopback source is neither answered nor learned. Loopback sources are
     * never learned. */
    bool allow_internal;
};

enum directlink_punch_state {
    DIRECTLINK_PUNCH_IDLE = 0,
    DIRECTLINK_PUNCH_WAITING,
    DIRECTLINK_PUNCH_PROBING,
    DIRECTLINK_PUNCH_SUCCEEDED,
    DIRECTLINK_PUNCH_FAILED
};

enum directlink_outcome {
    DIRECTLINK_OUTCOME_PENDING = 0,
    DIRECTLINK_OUTCOME_DIRECT,
    DIRECTLINK_OUTCOME_FALLBACK_TO_ONION
};

struct directlink_punch_stats {
    uint32_t probes_sent;
    uint32_t replies_sent;
    uint32_t dropped_malformed;
    uint32_t dropped_session;
    uint32_t dropped_role;
    uint32_t dropped_mac;
    uint32_t dropped_unsolicited;
    uint32_t dropped_budget;
    uint32_t dropped_source;
    uint32_t learned;
    uint32_t send_failures;
};

struct directlink_punch {
    struct directlink_punch_ops ops;
    struct directlink_punch_config cfg;
    enum directlink_punch_state state;
    enum directlink_outcome outcome;
    struct directlink_addr working;
    struct directlink_addr learned[DIRECTLINK_PUNCH_LEARNED_MAX];
    size_t learned_count;
    int64_t start_at_ms;
    int64_t deadline_ms;
    int64_t next_send_ms;
    int64_t finished_ms;
    uint32_t round;
    uint32_t next_seq;
    struct directlink_punch_stats stats;
};

const char *directlink_outcome_label(enum directlink_outcome outcome);

/* Arm the machine. Fails (false) on NULL arguments, missing ops, zero or too
 * many remote candidates, or an invalid candidate address. Defaults are
 * applied to zero fields of `cfg`. */
bool directlink_punch_start(struct directlink_punch *punch,
                            const struct directlink_punch_ops *ops,
                            const struct directlink_punch_config *cfg);

/* Advance the schedule: begin probing when the start delay has elapsed, send
 * the next round when due, and declare failure at the deadline. */
void directlink_punch_tick(struct directlink_punch *punch);

/* Feed one received datagram and its source address. */
void directlink_punch_on_datagram(struct directlink_punch *punch,
                                  const struct directlink_addr *from,
                                  const uint8_t *bytes, size_t len);

/* The working remote address; valid only after DIRECTLINK_OUTCOME_DIRECT. */
bool directlink_punch_result(const struct directlink_punch *punch,
                             struct directlink_addr *remote);

/* Interval at which the caller should send keepalives on the working path. */
int64_t directlink_punch_keepalive_ms(const struct directlink_punch *punch);

#endif /* ZCL_GAMELINK_DIRECTLINK_PUNCH_H */
