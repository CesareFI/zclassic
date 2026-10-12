/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink channel: one direct UDP path between two paired nodes whose
 * datagrams are sealed under keys derived from a hybrid post-quantum
 * handshake secret and, inside one owner's fleet, a pairing secret.
 *
 * Composition, in order:
 *   1. Key derivation (directlink_channel_derive). Inputs are the handshake
 *      secret, a 32-byte pairing secret (psk), both peer identities and the
 *      per-attempt session id, all bound through HKDF-SHA3-256 under
 *      domain-separated labels. The pairing secret enters only through a
 *      one-way per-attempt derivation, so a channel key reveals nothing about
 *      it. The result is secret if EITHER the handshake secret OR the pairing
 *      secret is secret. The punch-probe MAC key is derived the same way and
 *      is unique per attempt.
 *   2. Punch (directlink_punch) with that probe key.
 *   3. Address confirmation: the working address carries no application
 *      data until each side has received one sealed CONFIRM datagram from it
 *      that only a holder of the channel keys can produce.
 *   4. Data: gamelink datagrams (ChaCha20-Poly1305, per-direction key, 64-bit
 *      counter nonce, 64-entry replay window). One type byte precedes the
 *      payload, so a datagram costs DIRECTLINK_CHANNEL_OVERHEAD bytes above
 *      the payload (IP and UDP headers excluded).
 *
 * The scope decides whether the pairing secret is mandatory: an intra_fleet
 * channel without one is refused by name; an inter_fleet channel may carry an
 * all-zero secret, meaning none.
 *
 * Rekey: application data sends stop with DIRECTLINK_CHANNEL_REKEY once a
 * direction has sent DIRECTLINK_CHANNEL_REKEY_DATAGRAMS datagrams. Control
 * frames (keepalive pings and pongs) continue until the session itself
 * refuses at the 64-bit nonce limit. The owner replaces the channel with a
 * fresh handshake and attempt id; there is no in-place rekey.
 *
 * The channel reads no clock of its own and opens no socket: the datagram
 * seam and the clock are injected, and the datagram source address is checked
 * against the confirmed working address. A path change needs a new attempt.
 */

#ifndef ZCL_GAMELINK_DIRECTLINK_CHANNEL_H
#define ZCL_GAMELINK_DIRECTLINK_CHANNEL_H

#include "gamelink/directlink_policy.h"
#include "gamelink/directlink_punch.h"
#include "gamelink/gamelink.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DIRECTLINK_CHANNEL_SECRET_BYTES 32u
#define DIRECTLINK_CHANNEL_HANDSHAKE_MIN 32u
#define DIRECTLINK_CHANNEL_HANDSHAKE_MAX 128u
#define DIRECTLINK_CHANNEL_MAX_PAYLOAD (GAMELINK_MAX_PAYLOAD - 1u)
#define DIRECTLINK_CHANNEL_OVERHEAD \
    (GAMELINK_HEADER_BYTES + 1u + GAMELINK_TAG_BYTES)
#define DIRECTLINK_CHANNEL_REKEY_DATAGRAMS (UINT64_C(1) << 32)
#define DIRECTLINK_CHANNEL_DEFAULT_CONFIRM_INTERVAL_MS 100
#define DIRECTLINK_CHANNEL_DEFAULT_CONFIRM_TIMEOUT_MS 3000

/* Both ends ping every keepalive interval (default 15 s, the punch default).
 * An OPEN channel that has received no authenticated datagram for this many
 * intervals is declared dead and moves to FALLBACK, so the caller returns to
 * the onion path. */
#define DIRECTLINK_CHANNEL_DEAD_INTERVALS 3

enum directlink_channel_status {
    DIRECTLINK_CHANNEL_OK = 0,
    DIRECTLINK_CHANNEL_ARGUMENT,    /* NULL, a length out of bounds, bad scope */
    DIRECTLINK_CHANNEL_NO_PSK,      /* intra_fleet without a pairing secret */
    DIRECTLINK_CHANNEL_DERIVE,      /* key derivation failed */
    DIRECTLINK_CHANNEL_SECRET_USED, /* the handshake secret is all zero: already consumed */
    DIRECTLINK_CHANNEL_ADDRESS,     /* the working address is not allowed */
    DIRECTLINK_CHANNEL_PUNCH,       /* the punch machine refused its config */
    DIRECTLINK_CHANNEL_LINK,        /* the datagram session refused to open */
    DIRECTLINK_CHANNEL_NOT_OPEN,    /* no confirmed path: punching, failed, closed */
    DIRECTLINK_CHANNEL_TOO_LARGE,   /* payload over DIRECTLINK_CHANNEL_MAX_PAYLOAD */
    DIRECTLINK_CHANNEL_REKEY,       /* the send limit is reached; replace the channel */
    DIRECTLINK_CHANNEL_SEND_FAILED  /* the datagram session refused the send */
};

const char *directlink_channel_status_label(enum directlink_channel_status status);

struct directlink_channel_secrets {
    enum directlink_scope scope;
    uint8_t *handshake; /* wiped by open and open_at */
    size_t handshake_len;
    uint8_t psk[DIRECTLINK_CHANNEL_SECRET_BYTES];
    uint8_t initiator_id[32];
    uint8_t responder_id[32];
    uint8_t attempt[DIRECTLINK_OFFER_SESSION_BYTES];
};

struct directlink_channel_keys {
    uint8_t material[32];  /* gamelink session material */
    uint8_t probe_key[32]; /* punch probe MAC key */
};

/* Pure derivation. Refuses DIRECTLINK_CHANNEL_NO_PSK for intra_fleet with an
 * all-zero pairing secret and DIRECTLINK_CHANNEL_ARGUMENT for a NULL, a
 * handshake secret outside 32..128 bytes or an unknown scope. */
enum directlink_channel_status directlink_channel_derive(
    const struct directlink_channel_secrets *in,
    struct directlink_channel_keys *out);

enum directlink_channel_state {
    DIRECTLINK_CHANNEL_IDLE = 0,
    DIRECTLINK_CHANNEL_PUNCHING,
    DIRECTLINK_CHANNEL_CONFIRMING,
    DIRECTLINK_CHANNEL_OPEN,
    DIRECTLINK_CHANNEL_FALLBACK, /* no direct path: stay on the onion path */
    DIRECTLINK_CHANNEL_CLOSED
};

struct directlink_channel_config {
    struct directlink_channel_secrets secrets;
    bool initiator;
    bool allow_loopback; /* only for a transport below the NAT layer */
    struct directlink_addr remote[DIRECTLINK_OFFER_CANDIDATES_MAX];
    size_t remote_count;
    int64_t punch_interval_ms;   /* 0 selects the punch default */
    uint32_t punch_rounds;       /* 0 selects the punch default */
    int64_t confirm_interval_ms; /* 0 selects the default */
    int64_t confirm_timeout_ms;  /* 0 selects the default */
    int64_t keepalive_ms;        /* 0 selects the punch default */
    struct gamelink_ops net;     /* the caller's datagram seam */
    const clock_iface_t *clock;  /* NULL selects the process clock */
};

struct directlink_channel_stats {
    uint32_t dropped_source;  /* from an address other than the working one */
    uint32_t dropped_early;   /* a datagram before the path could accept it */
    uint32_t dropped_unconfirmed; /* sealed data before the confirmation */
    uint32_t confirms_sent;
    uint32_t path_lost;       /* declared dead by the liveness check */
    uint32_t delivered;
};

struct directlink_channel {
    enum directlink_channel_state state;
    bool initiator;
    int64_t last_rx_ms;
    uint64_t seen_recv;
    uint8_t attempt[DIRECTLINK_OFFER_SESSION_BYTES];
    uint8_t material[32];
    struct gamelink_ops net;
    const clock_iface_t *clock;
    struct directlink_punch punch;
    struct gamelink link;
    struct directlink_addr working;
    int64_t confirm_interval_ms;
    int64_t confirm_timeout_ms;
    int64_t keepalive_ms;
    int64_t confirm_deadline_ms;
    int64_t next_confirm_ms;
    int64_t next_keepalive_ms;
    uint8_t pending[GAMELINK_MAX_DATAGRAM];
    size_t pending_len;
    struct directlink_addr pending_from;
    void (*deliver)(void *user, const uint8_t *payload, size_t len);
    void *deliver_user;
    struct directlink_channel_stats stats;
};

/* Derive the keys, arm the punch and start probing the remote candidates.
 *
 * Single use: a (handshake secret, attempt id) pair may key one channel only,
 * because a second channel under the same keys would restart the nonce
 * counters. open and open_at therefore CONSUME the secrets: on every return
 * path, success or failure, they wipe `cfg->secrets.psk` and the handshake
 * buffer. Opening again with the wiped, all-zero secret is refused with
 * DIRECTLINK_CHANNEL_SECRET_USED. On any failure `ch` is left CLOSED.
 *
 * The channel stores its own address in the punch and datagram seams, so the
 * struct must not be moved or copied after open. */
enum directlink_channel_status directlink_channel_open(
    struct directlink_channel *ch, struct directlink_channel_config *cfg);

/* Skip the punch and confirm `working` directly: for a peer whose address is
 * already known, and for a transport below the NAT layer such as loopback. The
 * confirmation and every later check are the same as after a punch. */
enum directlink_channel_status directlink_channel_open_at(
    struct directlink_channel *ch, struct directlink_channel_config *cfg,
    const struct directlink_addr *working);

typedef void (*directlink_channel_recv_fn)(void *user, const uint8_t *payload,
                                           size_t len);

/* Advance timers, drain the seam and deliver application payloads. Returns
 * the number of payloads delivered. */
size_t directlink_channel_poll(struct directlink_channel *ch,
                               directlink_channel_recv_fn fn, void *user);

/* Send one application payload; only on an OPEN channel. */
enum directlink_channel_status directlink_channel_send(
    struct directlink_channel *ch, const uint8_t *payload, size_t len);

enum directlink_channel_state directlink_channel_state(
    const struct directlink_channel *ch);

/* Zeroize the keys and refuse everything afterwards. Safe to repeat. */
void directlink_channel_close(struct directlink_channel *ch);

#endif /* ZCL_GAMELINK_DIRECTLINK_CHANNEL_H */
