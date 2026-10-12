/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zssh_internal.h — layer contracts and the connection state layout.
 *
 * Four layers are implemented by four independent writers against THIS file;
 * a fifth (CONN) is written last by the merge writer. Do not change a
 * prototype, struct field or constant here without the lead: the layers
 * compile against each other only through this header.
 *
 *   zssh_packet.c   wire helpers (rd/wr/txq/ct) + binary packet + ciphers
 *   zssh_kex.c      KEXINIT, negotiation, curve25519 / mlkem768x25519, H, keys
 *   zssh_auth.c     ssh-ed25519 blobs/signatures, host-key + userauth messages
 *   zssh_channel.c  the single direct-tcpip channel, windows, EOF/CLOSE
 *   zssh_conn.c     public API, state machine, dispatch
 *
 * Conventions common to every layer function below:
 *   - Return type enum zssh_error: ZSSH_E_NONE on success, a typed error
 *     otherwise. Each error return logs context (ZSSH_LOG) at the failing site.
 *     Layer functions never change connection state; CONN turns the returned
 *     error into zssh_conn_fail().
 *   - Inputs are byte buffers. Peer-controlled lengths are bounds-checked before
 *     use; no function reads past (ptr,len) or writes past (buf,cap).
 *   - No allocation, no globals, no static mutable state, no I/O, no clock.
 *   - On ANY failure a function writes NOTHING secret to a caller buffer: an
 *     output buffer is either untouched or zeroed (documented per function),
 *     and any local copy of secret material is memory_cleanse()d before return.
 *   - Output pointers may be NULL only where stated; input (ptr,len) with
 *     len == 0 may carry ptr == NULL.
 *   - Functions are not thread safe; they touch only their arguments.
 *   - Complexity cap 15 per function: split on message boundaries. */
#ifndef ZSSH_ZSSH_INTERNAL_H
#define ZSSH_ZSSH_INTERNAL_H

#include "zssh/zssh.h"

#include "base/cleanse.h"
#include "base/log_macros.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/ed25519.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "crypto/x25519_safe.h"
#include "mlkem/mlkem.h"

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Log one line and fall through (callers then `return <enum zssh_error>`).
 * The LOG_FAIL/LOG_ERR macros return bool/int, which does not fit a function
 * returning enum zssh_error, so this module logs through ZCL_LOG_EMIT. */
#define ZSSH_LOG(fmt, ...) \
    ZCL_LOG_EMIT("[zssh] %s:%d %s(): " fmt "\n", __FILE__, __LINE__, __func__ \
                 __VA_OPT__(,) __VA_ARGS__)
/* Log and return a typed error in one step. */
#define ZSSH_FAIL(err, fmt, ...) \
    do { ZSSH_LOG(fmt __VA_OPT__(,) __VA_ARGS__); return (err); } while (0)

/* ---- message numbers (RFC 4250 4.1.2, RFC 4253 12, RFC 4252 6, 4254 9) --- */
enum zssh_msg {
    ZSSH_MSG_DISCONNECT = 1, ZSSH_MSG_IGNORE = 2, ZSSH_MSG_UNIMPLEMENTED = 3,
    ZSSH_MSG_DEBUG = 4, ZSSH_MSG_SERVICE_REQUEST = 5, ZSSH_MSG_SERVICE_ACCEPT = 6,
    ZSSH_MSG_EXT_INFO = 7,
    ZSSH_MSG_KEXINIT = 20, ZSSH_MSG_NEWKEYS = 21,
    /* VERIFIED against OpenSSH V_10_0_P2 kexgen.c: both curve25519-sha256 and
     * mlkem768x25519-sha256 use SSH2_MSG_KEX_ECDH_INIT (30) / _REPLY (31). */
    ZSSH_MSG_KEX_INIT_30 = 30, ZSSH_MSG_KEX_REPLY_31 = 31,
    ZSSH_MSG_USERAUTH_REQUEST = 50, ZSSH_MSG_USERAUTH_FAILURE = 51,
    ZSSH_MSG_USERAUTH_SUCCESS = 52, ZSSH_MSG_USERAUTH_BANNER = 53,
    ZSSH_MSG_USERAUTH_PK_OK = 60,
    ZSSH_MSG_GLOBAL_REQUEST = 80, ZSSH_MSG_REQUEST_SUCCESS = 81,
    ZSSH_MSG_REQUEST_FAILURE = 82,
    ZSSH_MSG_CHANNEL_OPEN = 90, ZSSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    ZSSH_MSG_CHANNEL_OPEN_FAILURE = 92, ZSSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    ZSSH_MSG_CHANNEL_DATA = 94, ZSSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    ZSSH_MSG_CHANNEL_EOF = 96, ZSSH_MSG_CHANNEL_CLOSE = 97,
    ZSSH_MSG_CHANNEL_REQUEST = 98, ZSSH_MSG_CHANNEL_SUCCESS = 99,
    ZSSH_MSG_CHANNEL_FAILURE = 100
};

/* RFC 4253 11.1 disconnect reason codes we use. */
enum zssh_disconnect_reason {
    ZSSH_DISC_PROTOCOL_ERROR = 2, ZSSH_DISC_KEY_EXCHANGE_FAILED = 3,
    ZSSH_DISC_MAC_ERROR = 5, ZSSH_DISC_SERVICE_NOT_AVAILABLE = 7,
    ZSSH_DISC_HOST_KEY_NOT_VERIFIABLE = 9, ZSSH_DISC_BY_APPLICATION = 11,
    ZSSH_DISC_NO_MORE_AUTH_METHODS = 14
};

/* RFC 4254 5.1 open-failure reasons we use. */
enum { ZSSH_OPEN_ADMIN_PROHIBITED = 1, ZSSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
       ZSSH_OPEN_RESOURCE_SHORTAGE = 4 };

/* ---- derived sizes ------------------------------------------------------ */
#define ZSSH_LEN_FIELD             4u    /* packet_length */
#define ZSSH_PKT_HDR               5u    /* packet_length(4) + padding_length(1) */
#define ZSSH_TAG_LEN               16u   /* Poly1305 tag */
#define ZSSH_MIN_PAD               4u    /* RFC 4253 6: padding >= 4 */
#define ZSSH_PAD_RANDOM_MAX        16u   /* caller supplies this many pad bytes */
#define ZSSH_CIPHER_BLOCK          8u    /* alignment for none and chacha */
/* packet_length lower bounds (VERIFIED against OpenSSH packet.c
 * ssh_packet_send2_wrapped: padlen = 8 - (len % 8), +8 if < 4, where len
 * excludes the 4-byte length field for AEAD). Smallest packet = 1 byte payload
 * (NEWKEYS): padding_length(1) + payload(1) + padding(>=4) = 6 rounded up:
 *   AEAD (chacha): packet_length % 8 == 0           -> min 8
 *   NONE:         (4 + packet_length) % 8 == 0      -> min 12
 * OpenSSH really sends NEWKEYS with packet_length 8 under chacha, so a
 * bound of 16 would reject a conforming peer. ZSSH_MIN_PACKET_LENGTH is the
 * smaller of the two (AEAD); NONE code must use ZSSH_MIN_PACKET_LENGTH_NONE.
 * (VALUE CHANGED 16 -> 8.) */
#define ZSSH_MIN_PACKET_LENGTH_AEAD 8u
#define ZSSH_MIN_PACKET_LENGTH_NONE 12u
#define ZSSH_MIN_PACKET_LENGTH      ZSSH_MIN_PACKET_LENGTH_AEAD
#define ZSSH_MAX_PAD               11u   /* sealed padding is 4..11 for block 8 */
#define ZSSH_RX_BUF_SIZE           (ZSSH_LEN_FIELD + ZSSH_MAX_PACKET + ZSSH_TAG_LEN + 16u)

/* ---- output queue sizing (arithmetic; static_asserted below) -------------
 * Largest payload WE build: CHANNEL_DATA = 1 + 4 + 4 + ZSSH_CHAN_MAX_PACKET
 * = 16393 <= ZSSH_TX_MAX_PAYLOAD (16384 + 64 = 16448). Sealed worst case:
 *   PKT_HDR 5 + 16448 + padding <= 11 + tag 16 = 16480 bytes;
 * ZSSH_TX_MAX_WIRE (16485) uses the 16-byte pad buffer and is what a DATA
 * reservation must find contiguous. Control messages (KEXINIT ~250, KEX_REPLY
 * hybrid 1267, auth, DISCONNECT, CLOSE, ...) are all <= ZSSH_TX_CTRL_PAYLOAD
 * (2048), so a control packet is <= 5 + 2048 + 16 + 16 = 2085 wire bytes.
 * One accepted input packet causes at most ZSSH_TX_REPLY_PACKETS (4) control
 * packets (worst: KEX_INIT -> KEX_REPLY + NEWKEYS; peer CLOSE -> CLOSE +
 * DISCONNECT; failure -> DISCONNECT), so the reply reserve is
 *   ZSSH_TXQ_RESERVE = 4 * 2085 = 8340.
 * Admission rules (CONN):
 *   - input packet processed only while zssh_txq_room() >= ZSSH_TXQ_RESERVE;
 *   - an application packet (DATA, EOF, CLOSE, WINDOW_ADJUST) is built only if
 *     zssh_txq_room() - its_wire_size >= ZSSH_TXQ_RESERVE.
 * Queue 65536 >= RESERVE 8340 + TX_MAX_WIRE 16485 = 24825, so an EMPTY queue
 * always admits at least one maximal DATA packet (it admits 3). */
#define ZSSH_TXQ_SIZE             65536u /* wire output queue */
#define ZSSH_TX_MAX_PAYLOAD       (ZSSH_CHAN_MAX_PACKET + 64u) /* largest payload WE build */
#define ZSSH_TX_MAX_WIRE          (ZSSH_PKT_HDR + ZSSH_TX_MAX_PAYLOAD + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN)
#define ZSSH_TX_CTRL_PAYLOAD      2048u  /* bound for every non-DATA payload we build */
#define ZSSH_TX_CTRL_WIRE         (ZSSH_PKT_HDR + ZSSH_TX_CTRL_PAYLOAD + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN)
/* Largest app control packet queued by the channel API (EOF, CLOSE, WINDOW_ADJUST). */
#define ZSSH_TX_SMALL_WIRE        (ZSSH_PKT_HDR + 32u + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN)
#define ZSSH_TX_REPLY_PACKETS     4u
/* The conn processes an input packet only while the queue has at least this
 * much free room, so the replies one packet can cause always fit.
 * (VALUE CHANGED 65940 -> 8340; 65940 exceeded the 65536 queue.) */
#define ZSSH_TXQ_RESERVE          (ZSSH_TX_REPLY_PACKETS * ZSSH_TX_CTRL_WIRE)

static_assert(ZSSH_TXQ_RESERVE + ZSSH_TX_MAX_WIRE <= ZSSH_TXQ_SIZE,
              "an empty queue must admit one maximal packet beside the reserve");
static_assert(ZSSH_PAD_RANDOM_MAX >= ZSSH_MAX_PAD, "pad buffer covers max padding");
static_assert(1u + 4u + 4u + ZSSH_CHAN_MAX_PACKET <= ZSSH_TX_MAX_PAYLOAD,
              "DATA payload fits the payload cap");

#define ZSSH_ED25519_SIG_LEN       64u
#define ZSSH_ED25519_BLOB_LEN      (4u + 11u + 4u + ZSSH_ED25519_PK_LEN)   /* 51 */
#define ZSSH_ED25519_SIGBLOB_LEN   (4u + 11u + 4u + ZSSH_ED25519_SIG_LEN)  /* 83 */
#define ZSSH_X25519_LEN            32u
#define ZSSH_QC_MLKEM_LEN  (ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE + ZSSH_X25519_LEN) /* 1216 */
#define ZSSH_QS_MLKEM_LEN  (ZCL_MLKEM768_CIPHERTEXT_SIZE + ZSSH_X25519_LEN)        /* 1120 */
#define ZSSH_HASH_LEN              32u   /* SHA-256 (both KEX hashes) */
#define ZSSH_SESSION_ID_LEN        ZSSH_HASH_LEN
#define ZSSH_CIPHER_KEY_LEN        64u   /* chacha20-poly1305@openssh.com: 2 x 256 bit */
#define ZSSH_AUTH_SIGDATA_MAX      256u  /* userauth signed-data buffer */
#define ZSSH_VERSION_PREFIX        "SSH-2.0-zssh_1"

/* ======================================================================== *
 * W. WIRE HELPERS (implemented in zssh_packet.c, used by every layer)      *
 * ======================================================================== */

uint32_t zssh_get_u32(const uint8_t p[4]);            /* big-endian load */
void     zssh_put_u32(uint8_t p[4], uint32_t v);      /* big-endian store */
void     zssh_put_u64(uint8_t p[8], uint64_t v);

/* Constant-time equality over n bytes (no early exit, no data-dependent
 * branch or index). Returns true iff all n bytes match; n == 0 -> true. */
bool zssh_ct_eq(const uint8_t *a, const uint8_t *b, size_t n);

/* Bounds-checked reader with a sticky error flag: after the first overrun all
 * reads return zeros / empty and rd_ok() is false, so a parser may read a
 * whole message and test once. Zero-copy: strings point into the input. */
struct zssh_rd { const uint8_t *p; size_t len; size_t off; bool bad; };
void     zssh_rd_init(struct zssh_rd *r, const uint8_t *p, size_t len);
uint8_t  zssh_rd_u8(struct zssh_rd *r);
bool     zssh_rd_bool(struct zssh_rd *r);             /* any non-zero == true */
uint32_t zssh_rd_u32(struct zssh_rd *r);
/* RFC 4251 5 "string": uint32 length then bytes. A length above the bytes left
 * (or above ZSSH_MAX_PACKET) sets bad. *s and *n receive the slice (valid while
 * the input lives). Names/name-lists use the same call. */
void     zssh_rd_string(struct zssh_rd *r, const uint8_t **s, size_t *n);
void     zssh_rd_bytes(struct zssh_rd *r, const uint8_t **s, size_t n); /* raw n bytes */
size_t   zssh_rd_left(const struct zssh_rd *r);
bool     zssh_rd_ok(const struct zssh_rd *r);          /* !bad */
bool     zssh_rd_done(const struct zssh_rd *r);        /* !bad && nothing left */

/* Bounds-checked writer, sticky error flag, writes only within (p,cap).
 * Builder rule, followed by every layer: when a builder fails, the writer
 * offset is rolled back to its value at entry, the writer stays bad (sticky),
 * and the returned error enum is the result. Callers check the returned enum,
 * not zssh_wr_ok. */
struct zssh_wr { uint8_t *p; size_t cap; size_t off; bool bad; };
void zssh_wr_init(struct zssh_wr *w, uint8_t *p, size_t cap);
void zssh_wr_u8(struct zssh_wr *w, uint8_t v);
void zssh_wr_bool(struct zssh_wr *w, bool v);
void zssh_wr_u32(struct zssh_wr *w, uint32_t v);
void zssh_wr_bytes(struct zssh_wr *w, const uint8_t *b, size_t n);   /* raw */
void zssh_wr_string(struct zssh_wr *w, const uint8_t *b, size_t n);  /* len + bytes */
void zssh_wr_cstr(struct zssh_wr *w, const char *s);  /* string from NUL text; also
                                                        * a name-list written as
                                                        * "a,b,c" */
/* RFC 4251 5 mpint of the UNSIGNED big-endian magnitude be[0..n): leading
 * zero bytes stripped, a 0x00 prefix added when the top bit of the first
 * remaining byte is set, zero encodes as an empty string. */
void zssh_wr_mpint(struct zssh_wr *w, const uint8_t *be, size_t n);
bool zssh_wr_ok(const struct zssh_wr *w);

/* Name-list helpers (RFC 4251 5; a name-list entry never contains ',' or is
 * empty). Entries are compared byte-exactly. */
struct zssh_namelist { const uint8_t *p; size_t len; };
bool zssh_namelist_has(struct zssh_namelist l, const char *name);
/* RFC 4253 7.1 pick: first entry of `client` that also appears in `server`.
 * Returns the entry's index in `client` order or -1; *name and *n receive it. */
int  zssh_namelist_pick(struct zssh_namelist client, struct zssh_namelist server,
                        const uint8_t **name, size_t *n);

/* Bounded output queue (contiguous, compacting). Packets are sealed in place
 * at the tail; a packet is committed whole or not at all, and partial
 * consumption by the transport simply advances head, so a half-written packet
 * is retained and continued — the queue never reorders or drops bytes. */
struct zssh_txq { uint8_t buf[ZSSH_TXQ_SIZE]; size_t head, tail;
                  size_t reserved; /* size of the open reservation, 0 if none (NEW) */ };
void   zssh_txq_init(struct zssh_txq *q);
size_t zssh_txq_pending(const struct zssh_txq *q);              /* tail - head */
size_t zssh_txq_room(const struct zssh_txq *q);                 /* total free, after compaction */
void   zssh_txq_peek(const struct zssh_txq *q, const uint8_t **p, size_t *n);
/* false if n > pending (nothing changes). Empties -> head = tail = 0. */
bool   zssh_txq_consume(struct zssh_txq *q, size_t n);
/* Reserve `need` contiguous bytes at the tail (memmove-compacts if required).
 * Returns pointer or NULL when zssh_txq_room() < need. Reservation is not
 * visible to peek until zssh_txq_commit(q, used) with used <= need.
 * ATOMIC ADMISSION RECIPE (CONN): reserve ZSSH_TX_MAX_WIRE (or the control
 * size), build the payload at +ZSSH_PKT_HDR, zssh_pkt_seal into the
 * reservation (seq advances only on success), then zssh_txq_commit EXACTLY the
 * sealed *total. Any build or seal error commits nothing; the reservation is
 * simply abandoned (the next reserve replaces it, head/tail unchanged), so a
 * packet is queued whole or not at all.
 * zssh_txq_commit returns false and changes NOTHING when used exceeds the open
 * reservation (or there is none): that is misuse and CONN fails the session
 * with sticky ZSSH_E_INTERNAL. Because zssh_pkt_seal already advanced seq, a
 * failed commit cannot be retried: it is TERMINAL for the session.
 * (SIGNATURE CHANGED: was void and ignored it.) */
uint8_t *zssh_txq_reserve(struct zssh_txq *q, size_t need);
bool     zssh_txq_commit(struct zssh_txq *q, size_t used);
/* Append raw bytes (version line). false (nothing written) if no room, or if
 * b == NULL with n > 0 (fail closed, no dereference; CONN treats it as
 * ZSSH_E_INTERNAL). The same rule holds for zssh_wr_bytes / zssh_wr_string /
 * zssh_wr_mpint: a NULL pointer with n > 0 sets the sticky `bad` flag and
 * writes nothing; zssh_rd_* never dereference past len. */
bool     zssh_txq_append(struct zssh_txq *q, const uint8_t *b, size_t n);

/* ======================================================================== *
 * (a) PACKET: RFC 4253 6 framing and the ciphers                           *
 * ======================================================================== *
 *
 * Wire layout.
 *   none:  packet_length(4) | padding_length(1) | payload | padding
 *          (4 + packet_length) % 8 == 0 (the length field IS part of the
 *          aligned region, RFC 4253 6, block size 8 for "none"), padding >= 4,
 *          packet_length >= ZSSH_MIN_PACKET_LENGTH_NONE (12).
 *   chacha20-poly1305@openssh.com:
 *          enc(packet_length)(4) | enc(padding_length | payload | padding) | tag(16)
 *          packet_length counts padding_length..padding and NOT the length
 *          field or the tag; packet_length % 8 == 0 (the length field is
 *          EXCLUDED from alignment), padding >= 4, packet_length >=
 *          ZSSH_MIN_PACKET_LENGTH_AEAD (8).
 *   VERIFIED against OpenSSH V_10_0_P2 packet.c: send2_wrapped sets
 *   aadlen = 4 for authlen ciphers, `len -= aadlen`, padlen = block_size -
 *   (len % block_size), +block_size if < 4; the receiver tests
 *   need % block_size where need = 4 + packlen - block_size (none) or
 *   packlen (aadlen case). Peek (receive) and seal (send) use the SAME rule.
 *
 * IMPORTANT: this is NOT the IETF AEAD of RFC 8439 / RFC 7905. OpenSSH's
 * construction (PROTOCOL.chacha20poly1305) uses TWO independent 256-bit
 * ChaCha20 keys from one 512-bit SSH key, encrypts the 4-byte length with its
 * own keystream (so the length is never in the clear), and derives the
 * Poly1305 key from block 0 of the payload key:
 *   key[0..32)  = K_2 "main"   key (payload, and the Poly1305 key)
 *   key[32..64) = K_1 "header" key (length field only)
 *   nonce(12)   = 00 00 00 00 || BE64(sequence_number)   (64-bit seq nonce,
 *                 NOT a random/derived IV; IETF chacha20_block's 32-bit
 *                 counter + 96-bit nonce is bit-compatible with DJB's 64-bit
 *                 counter + 64-bit IV for counters < 2^32 with this layout)
 *   len keystream  = chacha20_block(K_1, counter 0, nonce)[0..4)
 *   poly key       = chacha20_block(K_2, counter 0, nonce)[0..32)
 *   payload stream = ChaCha20(K_2, counter 1.., nonce)
 *   tag            = Poly1305(polykey, enc(len) | enc(padlen|payload|padding))
 * Authentication is checked BEFORE decrypting anything past the length, and
 * the length field is decrypted only to learn how many bytes to read; it is
 * range-checked (cipher-specific minimum..ZSSH_MAX_PACKET, cipher-specific
 * alignment above) before use and is covered by the tag. Key halves VERIFIED
 * (cipher-chachapoly.c: main = key[0..32), header = key+32, nonce = BE64 seq
 * via POKE_U64); the packet writer MUST still add a KAT from an OpenSSH
 * capture. The tag compare uses zssh_ct_eq (constant time). */

enum zssh_cipher_kind { ZSSH_CIPHER_NONE = 0, ZSSH_CIPHER_CHACHA20_POLY1305 = 1 };

/* One direction. seq is the RFC 4253 6.4 implicit packet sequence number. */
struct zssh_pkt_dir {
    enum zssh_cipher_kind kind;
    uint8_t  key[ZSSH_CIPHER_KEY_LEN]; /* secret; zero when kind == NONE */
    uint32_t seq;                      /* next packet's sequence number */
    uint64_t packets;                  /* since the last NEWKEYS, for limits */
    uint64_t bytes;
};

/* Reset to ZSSH_CIPHER_NONE, seq 0, wipe key. */
void zssh_pkt_dir_init(struct zssh_pkt_dir *d);

/* Install the keys for a direction (derived in KEX) and RESET seq to 0 when
 * `strict` is true (kex-strict-{c,s}-v00@openssh.com, CVE-2023-48795). When
 * !strict the sequence number continues (RFC 4253 6.4); CONN passes
 * strict == true always because strict KEX is mandatory, but the parameter
 * keeps the rule testable. packets/bytes counters restart.
 * WHEN (exact points, CONN's duty):
 *   outbound: call this for `tx` right AFTER our NEWKEYS packet was sealed
 *     (with the OLD keys and old seq) and committed to the queue. It does NOT
 *     wait for the transport to drain: the queue holds already-sealed bytes,
 *     so the very next packet we seal uses the new key with seq 0.
 *   inbound: call this for `rx` when the peer's NEWKEYS has been opened and is
 *     being processed, BEFORE the next packet's length is peeked: CONN must
 *     finish dispatching one packet before it decides the next packet's length
 *     (bytes already buffered behind NEWKEYS are length-decoded with the NEW
 *     key, seq 0).
 * kind NONE: key is ignored (any pointer, including NULL) and the stored key is
 * wiped. kind CHACHA20_POLY1305 with key == NULL is ZSSH_E_INTERNAL, as is a
 * bad kind. */
enum zssh_error zssh_pkt_set_cipher(struct zssh_pkt_dir *d,
                                    enum zssh_cipher_kind kind,
                                    const uint8_t key[ZSSH_CIPHER_KEY_LEN],
                                    bool strict);

/* How many bytes the receiver must have buffered to decide the next packet's
 * total size. Always ZSSH_LEN_FIELD (4). */
size_t zssh_pkt_need_len(void);

/* Given the first 4 received bytes of a packet, compute the total number of
 * wire bytes of the packet (*total = 4 + packet_length [+ tag]). For chacha the
 * length is decrypted with K_1 keystream for the CURRENT d->seq; it does not
 * advance seq and does not authenticate (open does). Errors:
 *   ZSSH_E_TOO_LARGE — packet_length > ZSSH_MAX_PACKET
 *   ZSSH_E_PROTOCOL  — cipher-specific: AEAD: packet_length < 8 or
 *                      packet_length % 8 != 0; NONE: packet_length < 12 or
 *                      (4 + packet_length) % 8 != 0
 * On error *total is 0 and nothing else is written. The 4 bytes are not
 * modified. */
enum zssh_error zssh_pkt_peek_total(const struct zssh_pkt_dir *d,
                                    const uint8_t first4[4], size_t *total);

/* Verify and decrypt ONE complete packet IN PLACE. buf[0..total) holds exactly
 * the bytes counted by zssh_pkt_peek_total. On success: seq++ (and limits
 * bookkeeping), *payload points into buf at the payload, *payload_len is its
 * length (>= 1), padding validated (>= 4, padding_length+1 <= packet_length).
 * Errors: ZSSH_E_MAC (tag mismatch, checked in constant time before any
 * decryption — buf is left byte-for-byte UNCHANGED, seq unchanged),
 * ZSSH_E_PROTOCOL (bad padding), ZSSH_E_TOO_LARGE, ZSSH_E_REKEY_LIMIT
 * (refuses the packet that would make the per-direction packet count exceed
 * ZSSH_MAX_SESSION_PACKETS or the wire-byte sum (total incl. tag) exceed
 * ZSSH_MAX_SESSION_BYTES; reaching the limit exactly is allowed; same rule in
 * seal; this is interim, see the public Rekey LIMIT).
 * On any error *payload is NULL, *payload_len 0, and no plaintext is exposed. */
enum zssh_error zssh_pkt_open(struct zssh_pkt_dir *d, uint8_t *buf, size_t total,
                              const uint8_t **payload, size_t *payload_len);

/* Seal one packet IN PLACE. The caller has written the payload at
 * buf[ZSSH_PKT_HDR .. ZSSH_PKT_HDR+payload_len) (via zssh_txq_reserve), with
 * buf_cap >= ZSSH_PKT_HDR + payload_len + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN.
 * pad[ZSSH_PAD_RANDOM_MAX] are random bytes (zeros are acceptable under an
 * AEAD cipher; the NONE cipher uses them as padding as given) used as padding.
 * On success *total is the wire size to commit, seq++. Errors: ZSSH_E_TOO_LARGE
 * (payload_len == 0 or total > ZSSH_MAX_PACKET + overhead), ZSSH_E_REKEY_LIMIT,
 * ZSSH_E_INTERNAL (cap too small). On error buf content is unspecified but
 * holds only the caller's own payload (caller discards it); seq unchanged. */
enum zssh_error zssh_pkt_seal(struct zssh_pkt_dir *d, uint8_t *buf, size_t buf_cap,
                              size_t payload_len,
                              const uint8_t pad[ZSSH_PAD_RANDOM_MAX],
                              size_t *total);

/* Cipher/AEAD primitives exposed so the packet writer's KATs and the unit
 * tests of other layers can reach them; wrappers over chacha20_block,
 * chacha20_encrypt and poly1305_mac from crypto/chacha20poly1305.h. */
void zssh_chacha_nonce(uint8_t nonce[12], uint32_t seq);  /* 0,0,0,0 | BE64(seq) */

/* ======================================================================== *
 * (b) KEX: RFC 4253 7, RFC 8731, mlkem768x25519-sha256                     *
 * ======================================================================== */

#define ZSSH_KEX_NAME_MLKEM        "mlkem768x25519-sha256"
#define ZSSH_KEX_NAME_CURVE25519   "curve25519-sha256"
#define ZSSH_KEX_NAME_STRICT_C     "kex-strict-c-v00@openssh.com"
#define ZSSH_KEX_NAME_STRICT_S     "kex-strict-s-v00@openssh.com"
#define ZSSH_HOSTKEY_ALG           "ssh-ed25519"
#define ZSSH_CIPHER_NAME           "chacha20-poly1305@openssh.com"
#define ZSSH_MAC_PLACEHOLDER       "hmac-sha2-256"  /* ignored: AEAD cipher (RFC 4253 7.1
                                                     * requires a non-empty list on
                                                     * the wire; TODO(verify) with OpenSSH
                                                     * PROTOCOL.chacha20poly1305 intro) */
#define ZSSH_COMPRESSION_NAME      "none"

enum zssh_kex_alg { ZSSH_KEXALG_NONE = 0, ZSSH_KEXALG_MLKEM768X25519 = 1,
                    ZSSH_KEXALG_CURVE25519 = 2 };

/* What we offer / accept. require_pq => the KEXINIT lists ONLY the hybrid (plus
 * the strict marker) and negotiation never yields CURVE25519. */
struct zssh_kex_policy { enum zssh_role role; uint32_t allowed; bool require_pq; };

/* The 10 name-lists of a KEXINIT, in wire order (RFC 4253 7.1):
 * kex, host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c,
 * lang_c2s, lang_s2c. Slices point into the parsed payload. */
enum { ZSSH_KI_KEX, ZSSH_KI_HOSTKEY, ZSSH_KI_ENC_C2S, ZSSH_KI_ENC_S2C,
       ZSSH_KI_MAC_C2S, ZSSH_KI_MAC_S2C, ZSSH_KI_COMP_C2S, ZSSH_KI_COMP_S2C,
       ZSSH_KI_LANG_C2S, ZSSH_KI_LANG_S2C, ZSSH_KI_COUNT };
struct zssh_kexinit_view {
    uint8_t cookie[16];
    struct zssh_namelist list[ZSSH_KI_COUNT];
    bool first_kex_packet_follows;
};

/* The negotiated result. */
struct zssh_neg {
    enum zssh_kex_alg alg;
    bool strict;   /* both sides advertised their kex-strict-*-v00 marker */
};

/* Exchange state. I_C / I_S are the full KEXINIT PAYLOADS (starting with the
 * message-type byte 20) exactly as sent/received, as RFC 4253 8 hashes them. */
struct zssh_kex {
    enum zssh_role role;
    struct zssh_neg neg;
    uint32_t generation;                       /* 0 for the first (only) kex */
    uint8_t  v_c[ZSSH_MAX_VERSION_LINE], v_s[ZSSH_MAX_VERSION_LINE]; /* no CRLF */
    size_t   v_c_len, v_s_len;
    uint8_t  i_c[ZSSH_KEXINIT_MAX], i_s[ZSSH_KEXINIT_MAX];
    size_t   i_c_len, i_s_len;
    /* ephemeral secrets: wiped by zssh_kex_wipe, always after derive_keys */
    uint8_t  x25519_sk[ZSSH_X25519_LEN];
    uint8_t  mlkem_dk[ZCL_MLKEM768_DECAPSULATION_KEY_SIZE];   /* client only */
    /* public transcript values (Q_C / Q_S in H) */
    uint8_t  q_c[ZSSH_QC_MLKEM_LEN];  size_t q_c_len;
    uint8_t  q_s[ZSSH_QS_MLKEM_LEN];  size_t q_s_len;
    uint8_t  k[ZSSH_HASH_LEN];        /* shared secret K material (encoding: see compute_h) */
    size_t   k_len;                   /* 32 for hybrid; <= 32 raw X25519 output */
    uint8_t  h[ZSSH_HASH_LEN];        /* exchange hash H */
    uint8_t  session_id[ZSSH_SESSION_ID_LEN]; /* == H of the FIRST kex */
    uint8_t  host_blob[ZSSH_ED25519_BLOB_LEN]; /* K_S as received/sent */
    bool     have_h, have_session_id;
};

/* Keys for both directions, RFC 4253 7.2. Only the two cipher keys (letters C
 * and D) are used with an AEAD; IVs (A,B) and MAC keys (E,F) are not derived. */
struct zssh_keys {
    uint8_t c2s[ZSSH_CIPHER_KEY_LEN];   /* "C": client -> server */
    uint8_t s2c[ZSSH_CIPHER_KEY_LEN];   /* "D": server -> client */
};

/* Build OUR KEXINIT payload (type 20) into w. cookie16 is caller-supplied
 * random (CONN draws it; RNG failure is CONN's, fail-closed). Lists written:
 *   kex   : [mlkem768x25519-sha256][,curve25519-sha256], then the strict marker
 *           ("kex-strict-c-v00@openssh.com" for CLIENT, "-s-" for SERVER) —
 *           hybrid FIRST when both are allowed; ONLY the hybrid when
 *           require_pq (no classical name appears anywhere);
 *   host  : "ssh-ed25519"; enc both: chacha20-poly1305@openssh.com;
 *   mac   : placeholder; comp: "none"; lang: empty; first_kex_packet_follows 0;
 *   reserved uint32 0.
 * Errors: ZSSH_E_CONFIG (policy.allowed == 0 or require_pq without hybrid),
 * ZSSH_E_TOO_LARGE (w overflow). On error w contents are unspecified, no secret
 * involved. */
enum zssh_error zssh_kex_build_kexinit(const struct zssh_kex_policy *pol,
                                       const uint8_t cookie16[16],
                                       struct zssh_wr *w);

/* Parse a peer KEXINIT payload (including the type byte). Errors:
 * ZSSH_E_PROTOCOL (truncated/trailing bytes/not type 20), ZSSH_E_TOO_LARGE
 * (payload > ZSSH_KEXINIT_MAX). view slices alias payload. */
enum zssh_error zssh_kex_parse_kexinit(const uint8_t *payload, size_t len,
                                       struct zssh_kexinit_view *view);

/* RFC 4253 7.1 negotiation of OUR policy against the peer's view. Rules:
 *  - strict KEX is MANDATORY: the peer's kex list must contain the marker for
 *    its role (client "kex-strict-c-v00@openssh.com" / server "-s-"), else
 *    ZSSH_E_STRICT_KEX_REQUIRED;
 *  - kex: the first name in the CLIENT's list that the SERVER also supports
 *    (client list order decides; require_pq removes classical names from our
 *    side); none -> ZSSH_E_KEX_NO_MATCH;
 *  - host key must offer ssh-ed25519, enc both directions must offer
 *    chacha20-poly1305@openssh.com, compression must offer "none"; else
 *    ZSSH_E_KEX_NO_MATCH (mac/lang ignored);
 *  - unknown names in the peer's lists are ignored; in particular OpenSSH's
 *    "ext-info-c" / "ext-info-s" marker is tolerated (we neither act on it nor
 *    send EXT_INFO, so a peer EXT_INFO stays a protocol error);
 *  - view->first_kex_packet_follows == true -> ZSSH_E_PROTOCOL (we never guess
 *    and never implement guess-discard; TODO(verify) RFC 4253 7 against
 *    OpenSSH interop, which sends 0).
 * *out is zeroed on error. `we_are_client_list` is derived from pol->role. */
enum zssh_error zssh_kex_negotiate(const struct zssh_kex_policy *pol,
                                   const struct zssh_kexinit_view *peer,
                                   struct zssh_neg *out);

/* Name of an algorithm for session_info ("" for NONE). */
const char *zssh_kex_alg_name(enum zssh_kex_alg a);

/* CLIENT step 1: after both KEXINITs and negotiation, generate the ephemeral
 * (X25519, and ML-KEM-768 for the hybrid) via `rand`, store secrets in k, and
 * write the INIT payload into w:
 *   curve25519: byte 30, string Q_C (32-byte X25519 public key)       [RFC 8731 3]
 *   hybrid:     byte 30, string Q_C = mlkem_ek(1184) || x25519_pk(32)  (1216)
 * Q_C is also stored in k->q_c. (Order ek||x25519 and message 30 VERIFIED
 * against kexmlkem768x25519.c keypair and kexgen.c.)
 * Errors: ZSSH_E_RANDOM (rand false — fail closed: k secrets wiped, w not
 * committed), ZSSH_E_KEX_FAILED (mlkem keygen error), ZSSH_E_TOO_LARGE. */
enum zssh_error zssh_kex_client_init(struct zssh_kex *k, zssh_rand_fn rand,
                                     void *rand_ctx, struct zssh_wr *w);

/* SERVER step: process the client's INIT payload, run the key agreement,
 * compute K and H, sign H with the host key, and write the REPLY payload:
 *   byte 31, string K_S (ssh-ed25519 blob), string Q_S, string sig(H blob)
 *   curve25519: Q_S = 32-byte X25519 public key
 *   hybrid:     Q_S = mlkem_ciphertext(1088) || x25519_pk(32)  (1120)
 * Validation: Q_C length exact (32 / 1216); ML-KEM ek passes FIPS 203 7.2
 * (zcl_mlkem768_encaps does the check); X25519 output must not be all-zero
 * (x25519_safe false -> ZSSH_E_KEX_FAILED). Sets k->q_c/q_s/k/h (and
 * session_id on the first kex), k->host_blob. Errors: ZSSH_E_PROTOCOL
 * (malformed), ZSSH_E_KEX_FAILED, ZSSH_E_RANDOM, ZSSH_E_TOO_LARGE. On error
 * k->k/h/session_id are zeroed and nothing is written to w that depends on a
 * secret. */
enum zssh_error zssh_kex_server_reply(struct zssh_kex *k,
        const uint8_t *init_payload, size_t init_len,
        const uint8_t host_pk[ZSSH_ED25519_PK_LEN],
        const uint8_t host_sk[ZSSH_ED25519_SEED_LEN],
        zssh_rand_fn rand, void *rand_ctx, struct zssh_wr *w);

/* CLIENT step 2: process the server's REPLY payload. Order is part of the
 * contract — the client MUST NOT proceed to credentials unless ALL hold:
 *   (1) K_S parses as an ssh-ed25519 blob (zssh_auth_blob_parse);
 *   (2) K_S equals the pinned key blob, constant time (this pin comparison is
 *       done HERE, in KEX; AUTH supplies blob_parse and verify) -> else
 *       ZSSH_E_HOST_KEY_MISMATCH (checked BEFORE the math);
 *   (3) the ML-KEM/X25519 agreement succeeds (ZSSH_E_KEX_FAILED);
 *   (4) the signature over H verifies under the pinned key (ZSSH_E_HOST_SIG).
 * Only then k->h, k->k, k->host_blob are valid (set before return); on any error
 * they are zeroed. Other errors: ZSSH_E_PROTOCOL, ZSSH_E_TOO_LARGE. */
enum zssh_error zssh_kex_client_finish(struct zssh_kex *k,
        const uint8_t *reply_payload, size_t reply_len,
        const uint8_t pinned_host_pk[ZSSH_ED25519_PK_LEN]);

/* Exchange hash H (RFC 4253 8 / RFC 8731 3.1), SHA-256 over, in order:
 *   string V_C, string V_S, string I_C, string I_S, string K_S, string Q_C,
 *   string Q_S, K
 * (all "string" = uint32 length + bytes, from k->v_c .. k->q_s, k->host_blob).
 * ENCODING OF K:
 *   curve25519-sha256 (RFC 8731 3.1): K is the 32 X25519 output octets,
 *     used UNCHANGED as the big-endian magnitude of an *mpint*: NO byte
 *     reversal. Pass the raw x25519 output directly to zssh_wr_mpint (leading
 *     zero octets stripped, 0x00 prefix if the top bit is set). VERIFIED:
 *     OpenSSH kexc25519.c kexc25519_shared_key_ext does
 *     sshbuf_put_bignum2_bytes(out, shared_key, 32) with no reversal.
 *   mlkem768x25519-sha256: K = SHA-256(mlkem_ss(32) || x25519_ss(32 raw
 *     output bytes, unreversed)) and it is hashed as an SSH *string* of those
 *     32 bytes, NOT an mpint. VERIFIED against kexmlkem768x25519.c: buf =
 *     mlkem_key then kexc25519_shared_key_ext(...raw=1), digest, then
 *     sshbuf_put_string(hash); kexgen.c appends the already-encoded secret
 *     with sshbuf_putb. Message numbers 30/31 as for curve25519. Server
 *     reply Q_S = ciphertext(1088) || x25519_pk(32); client Q_C =
 *     ek(1184) || x25519_pk(32).
 * The curve25519 and hybrid encodings are different and NOT interchangeable.
 * Preconditions: have the transcript fields set. Writes k->h; the first call
 * also sets k->session_id = H. Errors: ZSSH_E_INTERNAL (missing fields),
 * ZSSH_E_TOO_LARGE. */
enum zssh_error zssh_kex_compute_h(struct zssh_kex *k);

/* RFC 4253 7.2 key derivation: for letter X in {'C','D'}:
 *   K1 = HASH(K || H || X || session_id); K2 = HASH(K || H || K1);
 *   key = (K1 || K2)[0..64)
 * where K is encoded exactly as in the exchange hash (mpint for curve25519
 * with NO byte reversal, string for the hybrid — see zssh_kex_compute_h) and
 * session_id is the FIRST kex's H. Errors: ZSSH_E_INTERNAL (no H/session id).
 * *out is zeroed on error. Does not wipe k; CONN calls zssh_kex_wipe next. */
enum zssh_error zssh_kex_derive_keys(const struct zssh_kex *k, struct zssh_keys *out);

/* Strict-KEX order enforcement lives in CONN (it sees message types), but the
 * rule set is part of this contract and CONN uses this predicate:
 * zssh_kex_msg_allowed(msg, phase) says whether `msg` may arrive in `phase`. */
enum zssh_kex_phase {
    ZSSH_KP_WAIT_KEXINIT,   /* first binary packet in each direction: ONLY KEXINIT */
    ZSSH_KP_WAIT_INIT,      /* server: after KEXINITs: only msg 30 */
    ZSSH_KP_WAIT_REPLY,     /* client: only msg 31 */
    ZSSH_KP_WAIT_NEWKEYS,   /* only NEWKEYS */
    ZSSH_KP_DONE            /* post-NEWKEYS: transport/auth/channel set; KEXINIT
                             * here is the rekey refusal case */
};
/* Under strict KEX, IGNORE, DEBUG, UNIMPLEMENTED, EXT_INFO and anything else
 * are NOT allowed before NEWKEYS (CVE-2023-48795): false => CONN fails with
 * ZSSH_E_STRICT_KEX_REQUIRED (in WAIT_KEXINIT) or ZSSH_E_PROTOCOL.
 * DISCONNECT (1) is allowed in every phase. */
bool zssh_kex_msg_allowed(uint8_t msg, enum zssh_kex_phase phase);

/* Wipe all secrets (x25519_sk, mlkem_dk, k); transcript stays for session_info. */
void zssh_kex_wipe(struct zssh_kex *k);

/* ======================================================================== *
 * (c) AUTH: ssh-ed25519 (RFC 8709) and ssh-userauth publickey (RFC 4252)   *
 * ======================================================================== */

#define ZSSH_SERVICE_USERAUTH     "ssh-userauth"
#define ZSSH_SERVICE_CONNECTION   "ssh-connection"

/* Host key blob (RFC 8709 4): string "ssh-ed25519" || string pk(32), 51 bytes.
 * Signature blob (RFC 8709 6): string "ssh-ed25519" || string sig(64), 83. */
void zssh_auth_blob_encode(const uint8_t pk[ZSSH_ED25519_PK_LEN],
                           uint8_t out[ZSSH_ED25519_BLOB_LEN]);
/* Strict parse: exact algorithm name, exact 32-byte key, no trailing bytes.
 * ZSSH_E_PROTOCOL otherwise; pk zeroed on error. */
enum zssh_error zssh_auth_blob_parse(const uint8_t *blob, size_t len,
                                     uint8_t pk[ZSSH_ED25519_PK_LEN]);
/* SHA-256 of the blob (the host key fingerprint evidence). */
void zssh_auth_fingerprint(const uint8_t blob[ZSSH_ED25519_BLOB_LEN],
                           uint8_t out[ZSSH_FINGERPRINT_LEN]);

/* Sign / verify raw `msg` (RFC 8709: the signature is over H for the host key;
 * over the userauth signed data for user auth) and (de)serialise the 83-byte
 * signature blob. sign: ZSSH_E_INTERNAL only on NULL args; out written fully
 * on success. verify: ZSSH_E_PROTOCOL (blob shape), ZSSH_E_HOST_SIG for the
 * host context / ZSSH_E_AUTH_REFUSED for the user context (the `host` flag
 * picks which typed error a bad signature raises). Uses ed25519_verify, which
 * rejects non-canonical S and the all-zero key. */
enum zssh_error zssh_auth_sign(const uint8_t seed[ZSSH_ED25519_SEED_LEN],
                               const uint8_t pk[ZSSH_ED25519_PK_LEN],
                               const uint8_t *msg, size_t msg_len,
                               uint8_t out[ZSSH_ED25519_SIGBLOB_LEN]);
enum zssh_error zssh_auth_verify(const uint8_t pk[ZSSH_ED25519_PK_LEN],
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sigblob, size_t sigblob_len,
                                 bool host);

/* Service negotiation messages. */
void zssh_auth_build_service_request(struct zssh_wr *w, const char *service);
void zssh_auth_build_service_accept(struct zssh_wr *w, const char *service);
/* Parse either; *service and *n alias payload. ZSSH_E_PROTOCOL on malformed. */
enum zssh_error zssh_auth_parse_service(const uint8_t *payload, size_t len,
                                        uint8_t expect_msg,
                                        struct zssh_namelist *service);

/* RFC 4252 7 signed data for method "publickey":
 *   string session_id, byte 50, string user, string "ssh-connection",
 *   string "publickey", boolean TRUE, string "ssh-ed25519", string pk_blob
 * written into out (cap >= ZSSH_AUTH_SIGDATA_MAX). *n receives the length.
 * ZSSH_E_TOO_LARGE if user > ZSSH_MAX_USER. */
enum zssh_error zssh_auth_signed_data(const uint8_t session_id[ZSSH_SESSION_ID_LEN],
                                      const char *user,
                                      const uint8_t pk[ZSSH_ED25519_PK_LEN],
                                      uint8_t *out, size_t cap, size_t *n);

/* CLIENT: build USERAUTH_REQUEST with a signature (has-signature TRUE; we
 * never send the unsigned "query" form). Callable only after the host key
 * and the signature over H were verified (zssh_kex_client_finish) — CONN
 * enforces; this function additionally requires have_session_id via the
 * caller passing the real id. The HOST PIN comparison belongs to
 * zssh_kex_client_finish (KEX layer); AUTH only supplies zssh_auth_blob_parse
 * and zssh_auth_verify to it. AUTH is STATELESS: the CONN layer counts auth
 * attempts (probes included) against ZSSH_MAX_AUTH_ATTEMPTS and "none"
 * requests against ZSSH_MAX_AUTH_NONE. */
enum zssh_error zssh_auth_build_request(struct zssh_wr *w, const char *user,
        const uint8_t session_id[ZSSH_SESSION_ID_LEN],
        const uint8_t user_seed[ZSSH_ED25519_SEED_LEN],
        const uint8_t user_pk[ZSSH_ED25519_PK_LEN]);

/* SERVER: a parsed USERAUTH_REQUEST. Slices alias the payload. */
enum zssh_auth_method { ZSSH_AUTH_NONE_METHOD, ZSSH_AUTH_PUBLICKEY, ZSSH_AUTH_OTHER };
struct zssh_auth_request {
    struct zssh_namelist user, service, method;
    enum zssh_auth_method kind;
    bool has_signature;                      /* publickey only */
    struct zssh_namelist alg, key_blob, sig; /* publickey only */
};
enum zssh_error zssh_auth_parse_request(const uint8_t *payload, size_t len,
                                        struct zssh_auth_request *out);
/* SERVER signed-request check. Succeeds iff: service == "ssh-connection"; user
 * matches (expected_user NULL/"" is refused: fail closed, never "any"); kind == PUBLICKEY; has_signature (an
 * unsigned probe is NEVER success here: ZSSH_E_AUTH_REFUSED); alg ==
 * "ssh-ed25519"; key_blob parses and equals authorized_pk (constant time);
 * and the signature verifies over zssh_auth_signed_data(session_id, user, pk).
 * The comparison and verification both run before returning (no early out
 * that leaks which check failed to the peer). CONN uses zssh_auth_server_decide
 * below; this stays as its signed branch. */
enum zssh_error zssh_auth_check_request(const struct zssh_auth_request *req,
        const uint8_t session_id[ZSSH_SESSION_ID_LEN], const char *expected_user,
        const uint8_t authorized_pk[ZSSH_ED25519_PK_LEN]);

/* SERVER decision incl. the unsigned publickey probe that OpenSSH clients send
 * before signing (RFC 4252 7; sshconnect2.c send_pubkey_test). Verdicts:
 *   SUCCESS  signed request valid per zssh_auth_check_request;
 *   PK_OK    unsigned probe whose service, user, alg and key blob all match the
 *            single authorized key: CONN answers zssh_auth_build_pk_ok; the
 *            session STAYS unauthenticated;
 *   FAILURE  anything else (CONN answers zssh_auth_build_failure; an
 *            unauthorized key never gets PK_OK).
 * Every publickey request (probe or signed) counts toward
 * ZSSH_MAX_AUTH_ATTEMPTS, counted by CONN. */
enum zssh_auth_verdict { ZSSH_AUTH_V_FAILURE = 0, ZSSH_AUTH_V_PK_OK = 1,
                         ZSSH_AUTH_V_SUCCESS = 2 };
enum zssh_auth_verdict zssh_auth_server_decide(const struct zssh_auth_request *req,
        const uint8_t session_id[ZSSH_SESSION_ID_LEN], const char *expected_user,
        const uint8_t authorized_pk[ZSSH_ED25519_PK_LEN]);
/* USERAUTH_PK_OK (60): byte 60, string algorithm, string key blob (echoed from
 * req). */
void zssh_auth_build_pk_ok(struct zssh_wr *w, const struct zssh_auth_request *req);
/* USERAUTH_FAILURE: name-list "publickey", partial_success false. */
void zssh_auth_build_failure(struct zssh_wr *w);
void zssh_auth_build_success(struct zssh_wr *w);
/* CLIENT: classify a post-request packet: SUCCESS -> E_NONE and *success true;
 * FAILURE -> ZSSH_E_AUTH_REFUSED; BANNER -> E_NONE, *success false, ignored;
 * PK_OK -> ZSSH_E_PROTOCOL (we never probe, so a PK_OK is unsolicited and is
 * not success); anything else ZSSH_E_PROTOCOL. */
enum zssh_error zssh_auth_client_result(const uint8_t *payload, size_t len,
                                        bool *success);
/* As above, but a well-formed PK_OK is E_NONE with *pk_ok true and *success
 * false. Our client never probes, so CONN treats pk_ok == true as
 * ZSSH_E_PROTOCOL (unsolicited); the function exists so the classification
 * stays in AUTH and a future probing client needs no wire change. */
enum zssh_error zssh_auth_client_result_ex(const uint8_t *payload, size_t len,
                                           bool *success, bool *pk_ok);

/* ======================================================================== *
 * (d) CHANNEL: exactly one direct-tcpip channel (RFC 4254 5, 7.2)          *
 * ======================================================================== *
 * Local id is always 0. Window and packet accounting is per direction:
 *   recv side: `recv_window` is what we still allow the peer to send; a DATA
 *     larger than it, or larger than ZSSH_CHAN_MAX_PACKET, is ZSSH_E_WINDOW.
 *     The rx ring holds exactly ZSSH_CHAN_WINDOW bytes, so a granted window
 *     can never overflow it. Reading from the ring frees window; WINDOW_ADJUST
 *     is due once >= ZSSH_CHAN_WINDOW/2 bytes were freed.
 *   send side: `send_window` is what the peer allows us; a DATA payload is
 *     <= min(send_window, send_maxpkt, ZSSH_CHAN_MAX_PACKET).
 * Half-close is explicit: sent_eof/recv_eof are independent of
 * sent_close/recv_close; no emulation (EOF is not CLOSE).
 * Payload convention (all parsers below): the payload passed in INCLUDES the
 * leading message-number byte; trailing bytes are ZSSH_E_PROTOCOL.
 * Policy: peer DATA and WINDOW_ADJUST are still accepted after WE sent CLOSE
 * until the peer's CLOSE arrives; empty DATA is accepted; a duplicate EOF or
 * CLOSE is ZSSH_E_PROTOCOL. After the peer's CLOSE the ring keeps its
 * unread bytes readable (zssh_chan_recv); only zssh_chan_scrub / _wipe zero
 * it. */

enum zssh_chan_state {
    ZSSH_CH_IDLE = 0,        /* nothing sent or received */
    ZSSH_CH_OPEN_SENT,       /* client: CHANNEL_OPEN sent, awaiting reply */
    ZSSH_CH_OPEN,            /* confirmed; data flows */
    ZSSH_CH_CLOSED           /* both CLOSEs exchanged */
};
struct zssh_chan {
    enum zssh_chan_state state;
    uint32_t remote_id;
    uint32_t recv_window;         /* peer may still send this many */
    uint32_t send_window;         /* we may still send this many */
    uint32_t send_maxpkt;         /* peer's advertised max packet */
    uint32_t freed_unreported;    /* ring bytes read but not yet WINDOW_ADJUSTed */
    bool sent_eof, recv_eof, sent_close, recv_close;
    uint8_t  ring[ZSSH_CHAN_WINDOW];
    uint32_t ring_head, ring_len;
};

void zssh_chan_init(struct zssh_chan *c);

/* Messages we send. All write the payload (message byte first) into w. */
void zssh_chan_build_open(struct zssh_wr *w);   /* client: "direct-tcpip", id 0,
        window ZSSH_CHAN_WINDOW, maxpkt ZSSH_CHAN_MAX_PACKET, host
        ZSSH_FWD_HOST, port ZSSH_FWD_PORT, originator "0.0.0.0", port 0 */
void zssh_chan_build_open_confirm(const struct zssh_chan *c, struct zssh_wr *w);
void zssh_chan_build_open_failure(uint32_t recipient, uint32_t reason, struct zssh_wr *w);
void zssh_chan_build_window_adjust(const struct zssh_chan *c, uint32_t add, struct zssh_wr *w);
void zssh_chan_build_eof(const struct zssh_chan *c, struct zssh_wr *w);
void zssh_chan_build_close(const struct zssh_chan *c, struct zssh_wr *w);
/* Builds CHANNEL_FAILURE (100, recipient = remote_id) for a CHANNEL_REQUEST
 * with want_reply. The REQUEST_FAILURE (82) answer to a GLOBAL_REQUEST is NOT
 * built here: CONN builds it (single byte 82). */
void zssh_chan_build_request_failure(const struct zssh_chan *c, struct zssh_wr *w);

/* Transaction marks. Build functions NEVER change channel state; CONN calls
 * the matching mark/commit ONLY after the message was sealed and committed to
 * the output queue, so a retryable queue refusal leaves the channel untouched:
 *   zssh_chan_send_commit(c, take)  send_window -= take (DATA queued)
 *   zssh_chan_mark_open_sent(c)     client: state IDLE -> OPEN_SENT
 *   zssh_chan_mark_eof_sent(c)      sent_eof = true
 *   zssh_chan_mark_close_sent(c)    sent_close = true; if recv_close is already
 *                                   set the state becomes CLOSED
 * (zssh_chan_window_adjust_sent is the same kind of mark.) The CLOSED
 * transition happens in whichever of mark_close_sent / on_close runs last. */
void zssh_chan_send_commit(struct zssh_chan *c, size_t take);
void zssh_chan_mark_open_sent(struct zssh_chan *c);
void zssh_chan_mark_eof_sent(struct zssh_chan *c);
void zssh_chan_mark_close_sent(struct zssh_chan *c);

/* SERVER: validate a CHANNEL_OPEN payload. Accepts only type "direct-tcpip"
 * with host == ZSSH_FWD_HOST, port == ZSSH_FWD_PORT, while c->state == IDLE;
 * records remote_id, send_window, send_maxpkt (maxpkt must be >= 1 and is
 * clamped to ZSSH_CHAN_MAX_PACKET), sets state OPEN, recv_window =
 * ZSSH_CHAN_WINDOW. Errors: ZSSH_E_PROTOCOL (malformed), ZSSH_E_CHANNEL_REFUSED
 * (*refuse_reason holds the RFC 4254 5.1 reason: wrong channel type -> 3
 * UNKNOWN_CHANNEL_TYPE, wrong target -> 1 ADMINISTRATIVELY_PROHIBITED, second
 * channel -> 4 RESOURCE_SHORTAGE; *remote_id the peer's sender id so CONN can
 * send OPEN_FAILURE;
 * CONN replies, then keeps the session alive for a first failure only if the
 * policy says so — default: it closes). State unchanged on error. */
enum zssh_error zssh_chan_server_open(struct zssh_chan *c, const uint8_t *payload,
        size_t len, uint32_t *remote_id, uint32_t *refuse_reason);
/* CLIENT: CHANNEL_OPEN_CONFIRMATION (recipient must be 0, state OPEN_SENT ->
 * OPEN) and CHANNEL_OPEN_FAILURE (-> ZSSH_E_CHANNEL_REFUSED, state CLOSED). */
enum zssh_error zssh_chan_client_confirm(struct zssh_chan *c,
                                         const uint8_t *payload, size_t len);
enum zssh_error zssh_chan_client_open_failure(struct zssh_chan *c,
                                              const uint8_t *payload, size_t len);

/* Peer messages in state OPEN. recipient must be 0 (ZSSH_E_PROTOCOL).
 *  on_data: string payload; ZSSH_E_WINDOW if > recv_window or > max packet or
 *    recv_eof/recv_close already set (data after EOF is a protocol error:
 *    ZSSH_E_PROTOCOL); copies into the ring and shrinks recv_window.
 *    CHANNEL_EXTENDED_DATA is not supported: CONN maps it to ZSSH_E_PROTOCOL.
 *  on_window_adjust: send_window += add; overflow past 2^32-1 is
 *    ZSSH_E_PROTOCOL (RFC 4254 5.2: must not exceed).
 *  on_eof: recv_eof (second EOF = ZSSH_E_PROTOCOL).
 *  on_close: recv_close (state -> CLOSED if sent_close is already set); CONN
 *    answers a peer CLOSE with OUR CLOSE exactly once when !sent_close (the
 *    automatic reply, the single exception to "only zssh_channel_close sends
 *    CLOSE"), built with zssh_chan_build_close and then
 *    zssh_chan_mark_close_sent after the queue commit. */
enum zssh_error zssh_chan_on_data(struct zssh_chan *c, const uint8_t *payload, size_t len);
enum zssh_error zssh_chan_on_window_adjust(struct zssh_chan *c, const uint8_t *payload, size_t len);
enum zssh_error zssh_chan_on_eof(struct zssh_chan *c, const uint8_t *payload, size_t len);
enum zssh_error zssh_chan_on_close(struct zssh_chan *c, const uint8_t *payload, size_t len);

/* Application side. recv copies from the ring (frees window: freed_unreported
 * += got). send_plan: how many of n bytes can go in ONE CHANNEL_DATA packet now
 * = min(n, send_window, send_maxpkt, ZSSH_CHAN_MAX_PACKET, room_for_payload);
 * 0 means would-block. room_for_payload is the maximum DATA BYTES: CONN
 * subtracts the 9-byte CHANNEL_DATA header (1 + 4 + 4) from the queue room
 * itself. send_build writes the DATA payload for exactly `take` bytes and does
 * NOT charge send_window (CHANGED: it used to); CONN calls
 * zssh_chan_send_commit(c, take) only after the packet is queued, so a refused
 * queue never costs window. Both fail with ZSSH_E_PROTOCOL if sent_eof or
 * sent_close or state != OPEN (use after local EOF). flags fills the
 * public flags. window_adjust_due returns the add (0 if < ZSSH_CHAN_WINDOW/2
 * freed) and, when CONN builds+queues the message, chan_window_adjust_sent
 * credits recv_window and clears freed_unreported. zssh_chan_scrub zeroes the
 * ring bytes and ring_head/ring_len but keeps state and flags (used on FAILED
 * so getters stay meaningful); zssh_chan_wipe zeroes everything. */
size_t zssh_chan_recv(struct zssh_chan *c, uint8_t *buf, size_t cap);
size_t zssh_chan_send_plan(const struct zssh_chan *c, size_t n, size_t room_for_payload);
enum zssh_error zssh_chan_send_build(struct zssh_chan *c, const uint8_t *data,
                                     size_t take, struct zssh_wr *w);
uint32_t zssh_chan_window_adjust_due(const struct zssh_chan *c);
void zssh_chan_window_adjust_sent(struct zssh_chan *c, uint32_t add);
void zssh_chan_flags(const struct zssh_chan *c, struct zssh_channel_flags *out);
void zssh_chan_scrub(struct zssh_chan *c);  /* zero ring bytes only (NEW) */
void zssh_chan_wipe(struct zssh_chan *c);  /* zero ring and state */

/* ======================================================================== *
 * (e) CONN: state layout, public entry points and the state machine        *
 * ======================================================================== *
 * Written last by the merge writer. The layers above never include state from
 * it. CONN owns: version exchange, the byte-granular input assembler, strict
 * KEX ordering, RNG-failure fail-closed, back-pressure, DISCONNECT, and
 * the following behaviour contracts:
 *   - rx assembler: bytes accumulate in rx[] one at a time (1-byte feeds work);
 *     a packet is dispatched only when zssh_pkt_peek_total says it is complete;
 *     the input is not consumed past a point where zssh_txq_room() <
 *     ZSSH_TXQ_RESERVE (status NEED_OUTPUT). The next packet's length is
 *     decided only after the previous packet was fully dispatched.
 *   - error model and transactions are those of zssh.h: BAD_CALL changes
 *     nothing; FAILED is sticky and wipes secrets (zssh_chan_scrub for the
 *     ring) but peek/consume/getters keep working; message state (send
 *     window, sent_eof/close, window credit, open_sent) is committed through
 *     the zssh_chan_* mark/commit functions only after the packet was
 *     committed to the queue; a queue refusal is AGAIN with no change.
 *   - RNG: rand/rand_ctx live as long as the conn; called only inside a
 *     public call, never re-entrantly; a false return before commit of the
 *     packet using it => zssh_conn_fail(ZSSH_E_RANDOM) with NO DISCONNECT.
 *   - first binary packet in each direction must be KEXINIT; any other message
 *     before NEWKEYS completes -> fail (zssh_kex_msg_allowed).
 *   - NEWKEYS (strict KEX, sequence numbers reset to 0 at exactly these
 *     points): OUTBOUND — seal our NEWKEYS with the old tx state, commit it to
 *     the queue, and in the same step install the new tx key and reset tx.seq
 *     (zssh_pkt_set_cipher(.., strict=true)); transport draining is irrelevant.
 *     INBOUND — when the peer's NEWKEYS is processed install the new rx key and
 *     reset rx.seq to 0 before the next length is peeked. The server's NEWKEYS
 *     is sent right after its KEX_REPLY.
 *   - peer CHANNEL_CLOSE: reply with our CLOSE exactly once if !sent_close
 *     (see zssh_channel_close doc); the reply fits in the reserve, so failing
 *     to queue it is ZSSH_E_INTERNAL (terminal). Unread ring data stays
 *     readable in STATE_CLOSED.
 *   - physical transport EOF: zssh_transport_eof (FAILED/E_TRUNCATED, wipe, no
 *     DISCONNECT); implemented here, no stub exists in the old zssh_conn.c.
 *   - client sends SERVICE_REQUEST(ssh-userauth) only after
 *     zssh_kex_client_finish succeeded (host key == pin AND signature over H
 *     verified) and NEWKEYS exchanged; it sends USERAUTH_REQUEST only after
 *     SERVICE_ACCEPT. No credential byte exists on the wire before that.
 *   - after NEWKEYS any KEXINIT -> ZSSH_E_REKEY_UNSUPPORTED (DISCONNECT then
 *     FAILED); packet/byte limits -> ZSSH_E_REKEY_LIMIT.
 *   - transport IGNORE/DEBUG are dropped after NEWKEYS; UNIMPLEMENTED and
 *     EXT_INFO are protocol errors; GLOBAL_REQUEST with want_reply gets
 *     REQUEST_FAILURE and is otherwise ignored; CHANNEL_REQUEST (any type)
 *     with want_reply gets CHANNEL_FAILURE; unknown message numbers are
 *     answered with UNIMPLEMENTED once then ignored (no state change) — except
 *     during KEX where they fail closed.
 *   - auth (server): each publickey request (unsigned probe or signed) is
 *     decided by zssh_auth_server_decide and counts in auth_failures;
 *     a request arriving when the count is already ZSSH_MAX_AUTH_ATTEMPTS is
 *     ZSSH_E_AUTH_REFUSED without evaluation (DISCONNECT
 *     NO_MORE_AUTH_METHODS). PK_OK (60) for the single authorized key keeps the
 *     session unauthenticated; unauthorized key => USERAUTH_FAILURE; only a
 *     verified signature authenticates. "none" requests get FAILURE and count
 *     in auth_none up to ZSSH_MAX_AUTH_NONE, then AUTH_REFUSED. The client
 *     treats any PK_OK as ZSSH_E_PROTOCOL (it never probes). AUTH is
 *     stateless; counting is CONN's.
 *   - RNG failure at any point: zssh_conn_fail(ZSSH_E_RANDOM) BEFORE the
 *     packet using that randomness is committed; secrets wiped.
 *   - the wipe on fail/close covers kex, both pkt dirs, keys, user seed, host
 *     seed (zssh_conn_wipe_secrets). */

struct zssh_impl {
    uint32_t magic;                        /* ZSSH_IMPL_MAGIC once initialised */
    enum zssh_role role;
    enum zssh_state state;
    enum zssh_error error;
    zssh_rand_fn rand;
    void *rand_ctx;
    struct zssh_kex_policy policy;

    /* identity (copied from the config; wiped on fail/close) */
    uint8_t host_seed[ZSSH_ED25519_SEED_LEN];       /* server */
    uint8_t host_pk[ZSSH_ED25519_PK_LEN];           /* server own / client pinned */
    uint8_t user_seed[ZSSH_ED25519_SEED_LEN];       /* client */
    uint8_t user_pk[ZSSH_ED25519_PK_LEN];           /* client own / server authorized */
    char    user[ZSSH_MAX_USER + 1];
    char    comment[ZSSH_MAX_COMMENT + 1];

    /* version exchange */
    uint8_t  peer_version[ZSSH_MAX_VERSION_LINE + 1];
    size_t   peer_version_len;
    unsigned prebanner_lines;
    bool     version_done;

    /* packet layer */
    struct zssh_pkt_dir tx, rx;
    uint8_t  rxbuf[ZSSH_RX_BUF_SIZE];
    size_t   rxlen;                        /* bytes assembled so far */
    size_t   rx_total;                     /* 0 until the length is known */
    struct zssh_txq txq;

    /* kex / auth / channel */
    struct zssh_kex kex;
    enum zssh_kex_phase kex_phase;
    bool sent_kexinit, recv_kexinit, sent_newkeys, recv_newkeys;
    bool service_accepted, authenticated;
    unsigned auth_failures;                /* publickey requests evaluated (probes too) */
    unsigned auth_none;                    /* "none" requests seen (NEW) */
    struct zssh_chan chan;
    bool disconnect_queued;
};
#define ZSSH_IMPL_MAGIC 0x5a535348u

static_assert(sizeof(struct zssh_impl) <= ZSSH_CONN_STORAGE_SIZE,
              "struct zssh_impl must fit struct zssh_conn storage");
static_assert(alignof(struct zssh_impl) <= 16, "zssh_conn alignment");

static inline struct zssh_impl *zssh_impl_of(struct zssh_conn *c)
{
    return (struct zssh_impl *)(void *)c->opaque;
}
static inline const struct zssh_impl *zssh_impl_of_const(const struct zssh_conn *c)
{
    return (const struct zssh_impl *)(const void *)c->opaque;
}

/* CONN-internal helpers (zssh_conn.c). */

/* Fail the connection: record err (first error wins), best-effort queue
 * DISCONNECT(reason) if room and tx cipher state allows (never for
 * ZSSH_E_RANDOM or ZSSH_E_TRUNCATED), wipe secrets (zssh_chan_scrub), set
 * ZSSH_STATE_FAILED. The queued bytes stay drainable. Always returns err. */
enum zssh_error zssh_conn_fail(struct zssh_impl *s, enum zssh_error err,
                               enum zssh_disconnect_reason reason);
/* Reserve a payload buffer for one outgoing DATA-capable message: w is
 * initialised over the queue's reserved area (payload offset ZSSH_PKT_HDR, cap
 * ZSSH_TX_MAX_PAYLOAD, reservation ZSSH_TX_MAX_WIRE). ZSSH_E_TOO_LARGE if the
 * queue lacks room. */
enum zssh_error zssh_conn_begin(struct zssh_impl *s, struct zssh_wr *w);
/* As begin, but for a control message: cap ZSSH_TX_CTRL_PAYLOAD, reservation
 * ZSSH_TX_CTRL_WIRE; this is what the reply reserve is sized for (NEW). */
enum zssh_error zssh_conn_begin_ctrl(struct zssh_impl *s, struct zssh_wr *w);
/* Seal the written payload with a fresh pad draw from rand (RNG failure ->
 * ZSSH_E_RANDOM and the reservation is dropped, nothing committed) and commit
 * it to the queue (atomic admission recipe at zssh_txq_reserve). A packet is
 * committed whole or not at all. */
enum zssh_error zssh_conn_commit(struct zssh_impl *s, const struct zssh_wr *w);
/* Dispatch one decrypted payload by message number and current phase. */
enum zssh_error zssh_conn_dispatch(struct zssh_impl *s, const uint8_t *payload, size_t len);
/* Wipe every secret in s (kex, keys, seeds); transcript/session-info survive. */
void zssh_conn_wipe_secrets(struct zssh_impl *s);

#endif /* ZSSH_ZSSH_INTERNAL_H */
