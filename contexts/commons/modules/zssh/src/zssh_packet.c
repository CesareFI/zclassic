/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zssh_packet — wire helpers, binary packet framing, chacha20-poly1305@openssh.com (layer a).
 *
 * References (pinned OpenSSH V_10_0_P2 source files):
 *   PROTOCOL.chacha20poly1305, cipher-chachapoly.c (chachapoly_crypt,
 *   chachapoly_get_length), packet.c (ssh_packet_send2_wrapped,
 *   ssh_packet_read_poll2), RFC 4253 6.
 *
 * Resolved TODO(verify):
 *   - Alignment for AEAD (aadlen == 4): packet.c:1220-1223 computes
 *     len -= aadlen, then padlen = block_size - (len % block_size), and adds
 *     block_size when padlen < 4; block_size is 8 for chacha. So
 *     (padding_length + payload + padding) % 8 == 0, i.e. the length field is
 *     excluded, and packet_length % 8 == 0. The receive side checks the same
 *     (packet.c:1646-1652, need % block_size).
 *   - For the NONE cipher the length field is included (aadlen == 0): the sum
 *     4 + packet_length is a multiple of 8, so packet_length % 8 == 4.
 *   - 64-bit-nonce vs IETF: cipher-chachapoly.c:76-77,98-107 sets the IV to
 *     the 8-byte BE sequence number (POKE_U64) and the counter to 0 for the
 *     poly key, 1 (little-endian "one") for the payload. The IETF 12-byte
 *     nonce 00000000||BE64(seq) with a 32-bit counter in word 12 yields the
 *     same state words (the high counter word is word 13 = nonce word 0 = 0
 *     for counter < 2^32). Checked by a spec-derived test KAT (an
 *     independent DJB ChaCha implementation); an OpenSSH interop capture is
 *     still outstanding (see the test file TODO).
 *   - Key halves (cipher-chachapoly.c:42-57 init): main_ctx uses key[0..32)
 *     (K_2), header_ctx uses key[32..64) (K_1).
 *   - Tag: Poly1305 over the ENCRYPTED length || encrypted body, no padding
 *     or length suffix (cipher-chachapoly.c:117-120), key = first 32 bytes of
 *     K_2 keystream block 0 (lines 82-86).
 *   - Per-cipher minimum packet_length (NEWKEYS-sized packet: 8 under chacha,
 *     12 under none) comes from ZSSH_MIN_PACKET_LENGTH_AEAD / _NONE. */

#include "zssh_internal.h"
#include "base/serialize_le.h"

#include <string.h>

/* ========================== wire helpers ================================ */

uint32_t zssh_get_u32(const uint8_t p[4])
{
    return zcl_read_u32_be(p);
}

void zssh_put_u32(uint8_t p[4], uint32_t v)
{
    zcl_write_u32_be(p, v);
}

void zssh_put_u64(uint8_t p[8], uint64_t v)
{
    zcl_write_u64_be(p, v);
}

bool zssh_ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* ---- reader ---- */

void zssh_rd_init(struct zssh_rd *r, const uint8_t *p, size_t len)
{
    r->p = p; r->len = len; r->off = 0; r->bad = (p == nullptr && len != 0);
}

size_t zssh_rd_left(const struct zssh_rd *r)
{
    return r->bad ? 0 : r->len - r->off;
}

bool zssh_rd_ok(const struct zssh_rd *r) { return !r->bad; }

bool zssh_rd_done(const struct zssh_rd *r)
{
    return !r->bad && r->off == r->len;
}

void zssh_rd_bytes(struct zssh_rd *r, const uint8_t **s, size_t n)
{
    if (s) *s = nullptr;
    if (r->bad || n > r->len - r->off) { r->bad = true; return; }
    if (s) *s = r->p ? r->p + r->off : nullptr;
    r->off += n;
}

uint8_t zssh_rd_u8(struct zssh_rd *r)
{
    const uint8_t *s;
    zssh_rd_bytes(r, &s, 1);
    return s ? s[0] : 0;
}

bool zssh_rd_bool(struct zssh_rd *r) { return zssh_rd_u8(r) != 0; }

uint32_t zssh_rd_u32(struct zssh_rd *r)
{
    const uint8_t *s;
    zssh_rd_bytes(r, &s, 4);
    return s ? zssh_get_u32(s) : 0;
}

void zssh_rd_string(struct zssh_rd *r, const uint8_t **s, size_t *n)
{
    if (s) *s = nullptr;
    if (n) *n = 0;
    uint32_t len = zssh_rd_u32(r);
    if (r->bad) return;
    if (len > ZSSH_MAX_PACKET || len > r->len - r->off) { r->bad = true; return; }
    const uint8_t *p;
    zssh_rd_bytes(r, &p, len);
    if (r->bad) return;
    if (s) *s = p;
    if (n) *n = len;
}

/* ---- writer ---- */

void zssh_wr_init(struct zssh_wr *w, uint8_t *p, size_t cap)
{
    w->p = p; w->cap = cap; w->off = 0; w->bad = (p == nullptr && cap != 0);
}

bool zssh_wr_ok(const struct zssh_wr *w) { return !w->bad; }

void zssh_wr_bytes(struct zssh_wr *w, const uint8_t *b, size_t n)
{
    if (w->bad) return;
    if (n > w->cap - w->off) { w->bad = true; return; }
    if (n != 0) {
        if (b == nullptr) { w->bad = true; return; }
        memcpy(w->p + w->off, b, n);
    }
    w->off += n;
}

void zssh_wr_u8(struct zssh_wr *w, uint8_t v) { zssh_wr_bytes(w, &v, 1); }
void zssh_wr_bool(struct zssh_wr *w, bool v) { zssh_wr_u8(w, v ? 1u : 0u); }

void zssh_wr_u32(struct zssh_wr *w, uint32_t v)
{
    uint8_t t[4];
    zssh_put_u32(t, v);
    zssh_wr_bytes(w, t, 4);
}

void zssh_wr_string(struct zssh_wr *w, const uint8_t *b, size_t n)
{
    if (n > UINT32_MAX || (b == nullptr && n != 0)) { w->bad = true; return; }
    zssh_wr_u32(w, (uint32_t)n);
    zssh_wr_bytes(w, b, n);
}

void zssh_wr_cstr(struct zssh_wr *w, const char *s)
{
    if (s == nullptr) { w->bad = true; return; }
    zssh_wr_string(w, (const uint8_t *)s, strlen(s));
}

void zssh_wr_mpint(struct zssh_wr *w, const uint8_t *be, size_t n)
{
    if (be == nullptr && n != 0) { w->bad = true; return; }
    while (n > 0 && be[0] == 0) { be++; n--; }
    if (n == 0) { zssh_wr_u32(w, 0); return; }
    bool pad = (be[0] & 0x80u) != 0;
    if (n > UINT32_MAX - 1u) { w->bad = true; return; }
    zssh_wr_u32(w, (uint32_t)(n + (pad ? 1u : 0u)));
    if (pad) zssh_wr_u8(w, 0);
    zssh_wr_bytes(w, be, n);
}

/* ---- name-lists ---- */

/* Next comma-delimited entry; returns false at the end of the list. */
static bool nl_next(struct zssh_namelist l, size_t *pos, const uint8_t **e, size_t *n)
{
    if (l.len == 0 || l.p == nullptr || *pos > l.len) return false;
    size_t start = *pos, i = start;
    while (i < l.len && l.p[i] != ',') i++;
    *e = l.p + start; *n = i - start;
    *pos = i + 1;
    return true;
}

bool zssh_namelist_has(struct zssh_namelist l, const char *name)
{
    if (name == nullptr || name[0] == '\0') return false;
    size_t want = strlen(name), pos = 0, n = 0;
    const uint8_t *e = nullptr;
    while (nl_next(l, &pos, &e, &n))
        if (n == want && memcmp(e, name, n) == 0) return true;
    return false;
}

int zssh_namelist_pick(struct zssh_namelist client, struct zssh_namelist server,
                       const uint8_t **name, size_t *n)
{
    if (name) *name = nullptr;
    if (n) *n = 0;
    size_t pos = 0, len = 0;
    const uint8_t *e = nullptr;
    for (int idx = 0; nl_next(client, &pos, &e, &len); idx++) {
        if (len == 0) continue;
        size_t spos = 0, slen = 0;
        const uint8_t *se = nullptr;
        while (nl_next(server, &spos, &se, &slen)) {
            if (slen != len || memcmp(se, e, len) != 0) continue;
            if (name) *name = e;
            if (n) *n = len;
            return idx;
        }
    }
    return -1;
}

/* ---- bounded output queue ---- */

void zssh_txq_init(struct zssh_txq *q) { q->head = 0; q->tail = 0; q->reserved = 0; }

size_t zssh_txq_pending(const struct zssh_txq *q) { return q->tail - q->head; }

size_t zssh_txq_room(const struct zssh_txq *q)
{
    return ZSSH_TXQ_SIZE - (q->tail - q->head);
}

void zssh_txq_peek(const struct zssh_txq *q, const uint8_t **p, size_t *n)
{
    if (p) *p = q->buf + q->head;
    if (n) *n = q->tail - q->head;
}

bool zssh_txq_consume(struct zssh_txq *q, size_t n)
{
    if (n > q->tail - q->head) return false;
    q->head += n;
    if (q->head == q->tail) {
        /* Emptying relocates the tail, so an open reservation no longer
         * points where its data was built: drop it. */
        q->head = 0; q->tail = 0; q->reserved = 0;
    }
    return true;
}

uint8_t *zssh_txq_reserve(struct zssh_txq *q, size_t need)
{
    q->reserved = 0;                      /* a new reserve replaces any open one */
    if (need > zssh_txq_room(q)) return nullptr;
    if (need > ZSSH_TXQ_SIZE - q->tail) {
        size_t pend = q->tail - q->head;
        memmove(q->buf, q->buf + q->head, pend);
        q->head = 0; q->tail = pend;
    }
    q->reserved = need;
    return q->buf + q->tail;
}

bool zssh_txq_commit(struct zssh_txq *q, size_t used)
{
    if (used > q->reserved || used > ZSSH_TXQ_SIZE - q->tail) {
        ZSSH_LOG("commit of %zu bytes exceeds the open reservation of %zu",
                 used, q->reserved);
        return false;
    }
    q->tail += used;
    q->reserved = 0;
    return true;
}

bool zssh_txq_append(struct zssh_txq *q, const uint8_t *b, size_t n)
{
    if (b == nullptr && n != 0) {
        ZSSH_LOG("append of %zu bytes from NULL", n);
        return false;
    }
    uint8_t *dst = zssh_txq_reserve(q, n);
    if (dst == nullptr) return false;
    if (n != 0) memcpy(dst, b, n);
    q->tail += n;
    q->reserved = 0;
    return true;
}

/* ========================== packet layer ================================ */

void zssh_chacha_nonce(uint8_t nonce[12], uint32_t seq)
{
    memset(nonce, 0, 4);
    zssh_put_u64(nonce + 4, seq);
}

void zssh_pkt_dir_init(struct zssh_pkt_dir *d)
{
    memory_cleanse(d->key, sizeof d->key);
    d->kind = ZSSH_CIPHER_NONE;
    d->seq = 0; d->packets = 0; d->bytes = 0;
}

enum zssh_error zssh_pkt_set_cipher(struct zssh_pkt_dir *d,
                                    enum zssh_cipher_kind kind,
                                    const uint8_t key[ZSSH_CIPHER_KEY_LEN],
                                    bool strict)
{
    if (d == nullptr) ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL direction");
    if (kind == ZSSH_CIPHER_CHACHA20_POLY1305) {
        if (key == nullptr) ZSSH_FAIL(ZSSH_E_INTERNAL, "chacha cipher needs a key");
        memcpy(d->key, key, ZSSH_CIPHER_KEY_LEN);
    } else if (kind == ZSSH_CIPHER_NONE) {
        memory_cleanse(d->key, sizeof d->key);
    } else {
        ZSSH_FAIL(ZSSH_E_INTERNAL, "unknown cipher kind %d", (int)kind);
    }
    d->kind = kind;
    d->packets = 0; d->bytes = 0;
    if (strict) d->seq = 0;
    return ZSSH_E_NONE;
}

size_t zssh_pkt_need_len(void) { return ZSSH_LEN_FIELD; }

/* Validate a (decrypted) packet_length for the given cipher kind. */
static enum zssh_error check_packet_length(enum zssh_cipher_kind kind, uint32_t pl)
{
    if (pl > ZSSH_MAX_PACKET)
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "packet_length %u above %u", pl, ZSSH_MAX_PACKET);
    bool aead = (kind == ZSSH_CIPHER_CHACHA20_POLY1305);
    uint32_t min = aead ? ZSSH_MIN_PACKET_LENGTH_AEAD : ZSSH_MIN_PACKET_LENGTH_NONE;
    uint32_t mod = aead ? 0u : ZSSH_LEN_FIELD;
    if (pl < min || (pl % ZSSH_CIPHER_BLOCK) != mod)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "bad packet_length %u", pl);
    return ZSSH_E_NONE;
}

/* Decrypt the 4-byte length with the K_1 keystream for sequence seq. */
static uint32_t chacha_length(const uint8_t key[ZSSH_CIPHER_KEY_LEN], uint32_t seq,
                              const uint8_t first4[4])
{
    uint8_t nonce[12], ks[64], clear[4];
    zssh_chacha_nonce(nonce, seq);
    chacha20_block(key + 32, 0, nonce, ks);
    for (int i = 0; i < 4; i++) clear[i] = (uint8_t)(first4[i] ^ ks[i]);
    uint32_t v = zssh_get_u32(clear);
    memory_cleanse(ks, sizeof ks);
    memory_cleanse(clear, sizeof clear);
    return v;
}

enum zssh_error zssh_pkt_peek_total(const struct zssh_pkt_dir *d,
                                    const uint8_t first4[4], size_t *total)
{
    if (total) *total = 0;
    if (d == nullptr || first4 == nullptr || total == nullptr)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    uint32_t pl = (d->kind == ZSSH_CIPHER_CHACHA20_POLY1305)
                      ? chacha_length(d->key, d->seq, first4)
                      : zssh_get_u32(first4);
    enum zssh_error e = check_packet_length(d->kind, pl);
    if (e != ZSSH_E_NONE) return e;
    *total = ZSSH_LEN_FIELD + (size_t)pl +
             (d->kind == ZSSH_CIPHER_CHACHA20_POLY1305 ? ZSSH_TAG_LEN : 0u);
    return ZSSH_E_NONE;
}

static enum zssh_error limits_ok(const struct zssh_pkt_dir *d, size_t total)
{
    if (d->seq >= ZSSH_MAX_SESSION_PACKETS)
        ZSSH_FAIL(ZSSH_E_REKEY_LIMIT, "packet limit reached (seq %u)", d->seq);
    if (d->bytes + total > ZSSH_MAX_SESSION_BYTES)
        ZSSH_FAIL(ZSSH_E_REKEY_LIMIT, "byte limit reached");
    return ZSSH_E_NONE;
}

/* Authenticate buf[0..4+pl) against the tag at buf+4+pl; touches nothing. */
static enum zssh_error chacha_verify(const struct zssh_pkt_dir *d, const uint8_t *buf,
                                     size_t pl)
{
    uint8_t nonce[12], blk[64], tag[ZSSH_TAG_LEN];
    zssh_chacha_nonce(nonce, d->seq);
    chacha20_block(d->key, 0, nonce, blk);
    poly1305_mac(buf, ZSSH_LEN_FIELD + pl, blk, tag);
    bool ok = zssh_ct_eq(tag, buf + ZSSH_LEN_FIELD + pl, ZSSH_TAG_LEN);
    memory_cleanse(blk, sizeof blk);
    memory_cleanse(tag, sizeof tag);
    if (!ok) ZSSH_FAIL(ZSSH_E_MAC, "tag mismatch at seq %u", d->seq);
    return ZSSH_E_NONE;
}

/* Validate padding in the decrypted body buf[4..4+pl) and publish the payload. */
static enum zssh_error finish_open(uint8_t *buf, size_t pl, const uint8_t **payload,
                                   size_t *payload_len)
{
    size_t padlen = buf[ZSSH_LEN_FIELD];
    if (padlen < ZSSH_MIN_PAD || padlen + 1u >= pl)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "bad padding_length %zu for packet_length %zu",
                  padlen, pl);
    *payload = buf + ZSSH_PKT_HDR;
    *payload_len = pl - 1u - padlen;
    return ZSSH_E_NONE;
}

/* Verify the tag, then decrypt the length field and body in place. */
static enum zssh_error chacha_open(const struct zssh_pkt_dir *d, uint8_t *buf,
                                   size_t total, size_t pl)
{
    enum zssh_error e = chacha_verify(d, buf, pl);
    if (e != ZSSH_E_NONE) return e;
    uint8_t nonce[12], ks[64];
    zssh_chacha_nonce(nonce, d->seq);
    chacha20_block(d->key + 32, 0, nonce, ks);
    for (int i = 0; i < 4; i++) buf[i] ^= ks[i];
    memory_cleanse(ks, sizeof ks);
    if (!chacha20_encrypt(d->key, 1, nonce, buf + ZSSH_LEN_FIELD, pl,
                          buf + ZSSH_LEN_FIELD)) {
        memory_cleanse(buf, total);
        ZSSH_FAIL(ZSSH_E_INTERNAL, "keystream exhausted");
    }
    return ZSSH_E_NONE;
}

enum zssh_error zssh_pkt_open(struct zssh_pkt_dir *d, uint8_t *buf, size_t total,
                              const uint8_t **payload, size_t *payload_len)
{
    if (payload) *payload = nullptr;
    if (payload_len) *payload_len = 0;
    if (d == nullptr || buf == nullptr || payload == nullptr || payload_len == nullptr)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    if (total < ZSSH_LEN_FIELD)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "short packet %zu", total);
    if (d->seq >= ZSSH_MAX_SESSION_PACKETS)
        ZSSH_FAIL(ZSSH_E_REKEY_LIMIT, "packet limit reached (seq %u)", d->seq);
    size_t want = 0;
    enum zssh_error e = zssh_pkt_peek_total(d, buf, &want);
    if (e != ZSSH_E_NONE) return e;
    if (want != total)
        ZSSH_FAIL(ZSSH_E_PROTOCOL, "buffer %zu != declared packet %zu", total, want);
    if ((e = limits_ok(d, total)) != ZSSH_E_NONE) return e;

    size_t pl = total - ZSSH_LEN_FIELD;
    if (d->kind == ZSSH_CIPHER_CHACHA20_POLY1305) {
        pl -= ZSSH_TAG_LEN;
        if ((e = chacha_open(d, buf, total, pl)) != ZSSH_E_NONE) return e;
    }
    if ((e = finish_open(buf, pl, payload, payload_len)) != ZSSH_E_NONE) {
        memory_cleanse(buf, total);
        *payload = nullptr; *payload_len = 0;
        return e;
    }
    d->seq++; d->packets++; d->bytes += total;
    return ZSSH_E_NONE;
}

/* Encrypt in place and append the tag: buf[0..4+pl) holds the plain framing. */
static enum zssh_error chacha_seal(const struct zssh_pkt_dir *d, uint8_t *buf, size_t pl)
{
    uint8_t nonce[12], blk[64], ks[64];
    zssh_chacha_nonce(nonce, d->seq);
    chacha20_block(d->key, 0, nonce, blk);
    bool ok = chacha20_encrypt(d->key, 1, nonce, buf + ZSSH_LEN_FIELD, pl,
                               buf + ZSSH_LEN_FIELD);
    if (ok) {
        chacha20_block(d->key + 32, 0, nonce, ks);
        for (int i = 0; i < 4; i++) buf[i] ^= ks[i];
        poly1305_mac(buf, ZSSH_LEN_FIELD + pl, blk, buf + ZSSH_LEN_FIELD + pl);
    }
    memory_cleanse(blk, sizeof blk);
    memory_cleanse(ks, sizeof ks);
    if (!ok) ZSSH_FAIL(ZSSH_E_INTERNAL, "keystream exhausted");
    return ZSSH_E_NONE;
}

/* AEAD: (1 + payload + pad) % 8 == 0; NONE: (4 + 1 + payload + pad) % 8 == 0. */
static size_t seal_padlen(bool aead, size_t payload_len)
{
    size_t unpadded = 1u + payload_len + (aead ? 0u : ZSSH_LEN_FIELD);
    size_t padlen = ZSSH_CIPHER_BLOCK - (unpadded % ZSSH_CIPHER_BLOCK);
    if (padlen < ZSSH_MIN_PAD) padlen += ZSSH_CIPHER_BLOCK;
    return padlen;
}

enum zssh_error zssh_pkt_seal(struct zssh_pkt_dir *d, uint8_t *buf, size_t buf_cap,
                              size_t payload_len,
                              const uint8_t pad[ZSSH_PAD_RANDOM_MAX],
                              size_t *total)
{
    if (total) *total = 0;
    if (d == nullptr || buf == nullptr || pad == nullptr || total == nullptr)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "NULL argument");
    bool aead = (d->kind == ZSSH_CIPHER_CHACHA20_POLY1305);
    if (payload_len == 0 || payload_len > ZSSH_MAX_PACKET)
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "payload length %zu", payload_len);
    size_t padlen = seal_padlen(aead, payload_len);
    size_t pl = 1u + payload_len + padlen;
    if (pl > ZSSH_MAX_PACKET)
        ZSSH_FAIL(ZSSH_E_TOO_LARGE, "packet_length %zu above %u", pl, ZSSH_MAX_PACKET);
    size_t wire = ZSSH_LEN_FIELD + pl + (aead ? ZSSH_TAG_LEN : 0u);
    enum zssh_error e = limits_ok(d, wire);
    if (e != ZSSH_E_NONE) return e;
    if (buf_cap < ZSSH_PKT_HDR + payload_len + ZSSH_PAD_RANDOM_MAX + ZSSH_TAG_LEN)
        ZSSH_FAIL(ZSSH_E_INTERNAL, "buffer cap %zu too small", buf_cap);

    zssh_put_u32(buf, (uint32_t)pl);
    buf[ZSSH_LEN_FIELD] = (uint8_t)padlen;
    memcpy(buf + ZSSH_PKT_HDR + payload_len, pad, padlen);
    if (aead && (e = chacha_seal(d, buf, pl)) != ZSSH_E_NONE) return e;
    d->seq++; d->packets++; d->bytes += wire;
    *total = wire;
    return ZSSH_E_NONE;
}
