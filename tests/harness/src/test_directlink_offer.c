/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink punch-coordination message: known-answer encoding, strict
 * decode, policy and scope filtering, the required peer identity, and the
 * replay cache. */

#include "test/test_core.h"

#include "gamelink/directlink_offer.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t k_kat[] = {
    0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
    0x02, 0x01, 0x88, 0x13, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x02, 0x01,
    0x04, 0x88, 0x13, 0xC0, 0xA8, 0x01, 0x05, 0x02, 0x04, 0x92, 0x10, 0x2D,
    0x14, 0x71, 0x07};

static struct directlink_addr v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                                 uint16_t port)
{
    struct directlink_addr addr;
    memset(&addr, 0, sizeof addr);
    addr.family = DIRECTLINK_V4;
    addr.ip[0] = a;
    addr.ip[1] = b;
    addr.ip[2] = c;
    addr.ip[3] = d;
    addr.port = port;
    return addr;
}

static struct directlink_offer sample_offer(void)
{
    struct directlink_offer o;
    memset(&o, 0, sizeof o);
    for (uint8_t i = 0; i < DIRECTLINK_OFFER_SESSION_BYTES; i++)
        o.session_id[i] = i;
    o.nonce = UINT64_C(0x0102030405060708);
    o.ttl_ms = 5000;
    o.start_delay_ms = 200;
    o.candidate_count = 2;
    o.candidate[0].kind = DIRECTLINK_CANDIDATE_HOST;
    o.candidate[0].addr = v4(192, 168, 1, 5, 5000);
    o.candidate[1].kind = DIRECTLINK_CANDIDATE_REFLEXIVE;
    o.candidate[1].addr = v4(45, 20, 113, 7, 4242);
    return o;
}

static struct directlink_peer make_peer(enum directlink_scope scope)
{
    struct directlink_peer p;
    memset(&p, 0, sizeof p);
    memset(p.identity, 0x42, sizeof p.identity);
    p.scope = scope;
    p.paired = true;
    return p;
}

static struct directlink_policy allow_all(void)
{
    struct directlink_policy pol;
    directlink_policy_default(&pol);
    pol.scope_setting[DIRECTLINK_SCOPE_INTRA_FLEET] =
        DIRECTLINK_SETTING_DIRECT_ALLOWED;
    pol.scope_setting[DIRECTLINK_SCOPE_INTER_FLEET] =
        DIRECTLINK_SETTING_DIRECT_ALLOWED;
    return pol;
}

static enum directlink_status decode(const struct directlink_peer *peer,
                                     const uint8_t *b, size_t n)
{
    struct directlink_policy pol = allow_all();
    struct directlink_offer sink;
    return directlink_offer_decode(&pol, peer, b, n, &sink, NULL);
}

/* Decode the first `n` bytes of `b` from an exact-size heap buffer, so a read
 * past the end is visible to the sanitizers. */
static enum directlink_status decode_prefix(const struct directlink_peer *peer,
                                            const uint8_t *b, size_t n)
{
    uint8_t *copy = malloc(n ? n : 1u);
    if (!copy)
        return DIRECTLINK_ERR_ARGUMENT;
    if (n)
        memcpy(copy, b, n);
    enum directlink_status st = decode(peer, copy, n);
    free(copy);
    return st;
}

static int dlo_case_known_answer(void)
{
    int failures = 0;
    TEST_CASE("directlink offer: known-answer encoding round-trips") {
        struct directlink_policy pol = allow_all();
        struct directlink_peer peer = make_peer(DIRECTLINK_SCOPE_INTRA_FLEET);
        struct directlink_offer o = sample_offer();
        uint8_t out[DIRECTLINK_OFFER_MAX_BYTES];
        size_t len = 0;
        ASSERT_EQ((int)directlink_offer_encode(&pol, &peer, &o, out, sizeof out,
                                               &len, NULL),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ(len, sizeof k_kat);
        ASSERT(memcmp(out, k_kat, sizeof k_kat) == 0);
        struct directlink_offer back;
        enum directlink_refusal why = DIRECTLINK_REFUSE_INVALID;
        ASSERT_EQ((int)directlink_offer_decode(&pol, &peer, k_kat, sizeof k_kat,
                                               &back, &why),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ((int)why, (int)DIRECTLINK_ALLOW);
        ASSERT_EQ(back.nonce, o.nonce);
        ASSERT_EQ(back.ttl_ms, (uint32_t)5000);
        ASSERT_EQ(back.start_delay_ms, (uint32_t)200);
        ASSERT_EQ((int)back.candidate_count, 2);
        ASSERT(memcmp(back.session_id, o.session_id, 16) == 0);
        ASSERT_EQ((int)back.candidate[1].kind, (int)DIRECTLINK_CANDIDATE_REFLEXIVE);
        ASSERT(directlink_addr_equal(&back.candidate[0].addr, &o.candidate[0].addr));
        ASSERT(directlink_addr_equal(&back.candidate[1].addr, &o.candidate[1].addr));
        /* Eight candidates fit the documented maximum. */
        for (uint8_t i = 0; i < DIRECTLINK_OFFER_CANDIDATES_MAX; i++) {
            o.candidate[i].kind = DIRECTLINK_CANDIDATE_MAPPED;
            o.candidate[i].addr = v4(45, 20, 113, (uint8_t)(10 + i), 4242);
        }
        o.candidate_count = DIRECTLINK_OFFER_CANDIDATES_MAX;
        ASSERT_EQ((int)directlink_offer_encode(&pol, &peer, &o, out, sizeof out,
                                               &len, NULL),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ(len, (size_t)(35u + 8u * 8u));
        ASSERT_EQ((int)decode(&peer, out, len), (int)DIRECTLINK_OK);
        o.candidate_count = DIRECTLINK_OFFER_CANDIDATES_MAX + 1;
        ASSERT_EQ((int)directlink_offer_encode(&pol, &peer, &o, out, sizeof out,
                                               &len, NULL),
                  (int)DIRECTLINK_ERR_FIELD);
    } TEST_END;
    return failures;
}

static int dlo_case_policy_refusal(void)
{
    int failures = 0;
    TEST_CASE("directlink offer: a refusing policy produces zero bytes") {
        struct directlink_policy off;
        directlink_policy_default(&off);
        struct directlink_peer peer = make_peer(DIRECTLINK_SCOPE_INTRA_FLEET);
        struct directlink_offer o = sample_offer();
        uint8_t out[DIRECTLINK_OFFER_MAX_BYTES];
        memset(out, 0x5A, sizeof out);
        size_t len = 77;
        enum directlink_refusal why = DIRECTLINK_ALLOW;
        ASSERT_EQ((int)directlink_offer_encode(&off, &peer, &o, out, sizeof out,
                                               &len, &why),
                  (int)DIRECTLINK_ERR_POLICY);
        ASSERT_EQ((int)why, (int)DIRECTLINK_REFUSE_SCOPE_OFF);
        ASSERT_EQ(len, (size_t)0);
        for (size_t i = 0; i < sizeof out; i++)
            ASSERT_EQ((int)out[i], 0x5A);
        struct directlink_policy pol = allow_all();
        peer.paired = false;
        ASSERT_EQ((int)directlink_offer_encode(&pol, &peer, &o, out, sizeof out,
                                               &len, &why),
                  (int)DIRECTLINK_ERR_POLICY);
        ASSERT_EQ((int)why, (int)DIRECTLINK_REFUSE_NOT_PAIRED);
        ASSERT_EQ(len, (size_t)0);
        peer.paired = true;
        peer.join_in_progress = true;
        ASSERT_EQ((int)directlink_offer_encode(&pol, &peer, &o, out, sizeof out,
                                               &len, &why),
                  (int)DIRECTLINK_ERR_POLICY);
        ASSERT_EQ((int)why, (int)DIRECTLINK_REFUSE_JOIN_IN_PROGRESS);
        ASSERT_EQ((int)out[0], 0x5A);
        /* The decoder refuses a sender the policy refuses, before parsing. */
        peer.join_in_progress = false;
        struct directlink_offer sink;
        ASSERT_EQ((int)directlink_offer_decode(&off, &peer, k_kat, sizeof k_kat,
                                               &sink, &why),
                  (int)DIRECTLINK_ERR_POLICY);
        ASSERT_EQ((int)why, (int)DIRECTLINK_REFUSE_SCOPE_OFF);
    } TEST_END;
    return failures;
}

static int dlo_case_peer_required(void)
{
    int failures = 0;
    TEST_CASE("directlink offer: an authenticated peer identity is required") {
        struct directlink_policy pol = allow_all();
        struct directlink_offer o = sample_offer();
        struct directlink_offer sink;
        uint8_t out[DIRECTLINK_OFFER_MAX_BYTES];
        size_t len = 0;
        ASSERT_EQ((int)directlink_offer_decode(&pol, NULL, k_kat, sizeof k_kat,
                                               &sink, NULL),
                  (int)DIRECTLINK_ERR_ARGUMENT);
        ASSERT_EQ((int)directlink_offer_encode(&pol, NULL, &o, out, sizeof out,
                                               &len, NULL),
                  (int)DIRECTLINK_ERR_ARGUMENT);
        struct directlink_peer anonymous;
        memset(&anonymous, 0, sizeof anonymous);
        anonymous.paired = true;
        ASSERT_EQ((int)directlink_offer_decode(&pol, &anonymous, k_kat,
                                               sizeof k_kat, &sink, NULL),
                  (int)DIRECTLINK_ERR_ARGUMENT);
        ASSERT_EQ((int)directlink_offer_encode(&pol, &anonymous, &o, out,
                                               sizeof out, &len, NULL),
                  (int)DIRECTLINK_ERR_ARGUMENT);
        ASSERT_EQ(len, (size_t)0);
        ASSERT_EQ((int)directlink_offer_decode(NULL, &anonymous, k_kat,
                                               sizeof k_kat, &sink, NULL),
                  (int)DIRECTLINK_ERR_ARGUMENT);
    } TEST_END;
    return failures;
}

static int dlo_case_scope_filtering(void)
{
    int failures = 0;
    TEST_CASE("directlink offer: internal candidates only for intra_fleet") {
        struct directlink_policy pol = allow_all();
        struct directlink_peer inter = make_peer(DIRECTLINK_SCOPE_INTER_FLEET);
        struct directlink_offer o = sample_offer();
        uint8_t out[DIRECTLINK_OFFER_MAX_BYTES];
        size_t len = 0;
        /* The private host candidate is dropped, the public one stays. */
        ASSERT_EQ((int)directlink_offer_encode(&pol, &inter, &o, out, sizeof out,
                                               &len, NULL),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ(len, (size_t)(35u + 8u));
        ASSERT_EQ((int)out[1], 1);
        struct directlink_offer back;
        ASSERT_EQ((int)directlink_offer_decode(&pol, &inter, out, len, &back, NULL),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ((int)back.candidate_count, 1);
        ASSERT_EQ((int)back.candidate[0].addr.port, 4242);
        /* Loopback and private only: nothing left to offer. */
        o.candidate_count = 2;
        o.candidate[1].addr = v4(127, 0, 0, 1, 4242);
        memset(out, 0x5A, sizeof out);
        ASSERT_EQ((int)directlink_offer_encode(&pol, &inter, &o, out, sizeof out,
                                               &len, NULL),
                  (int)DIRECTLINK_ERR_ADDRESS);
        ASSERT_EQ(len, (size_t)0);
        ASSERT_EQ((int)out[0], 0x5A);
        /* Intra-fleet keeps loopback and private. */
        struct directlink_peer intra = make_peer(DIRECTLINK_SCOPE_INTRA_FLEET);
        ASSERT_EQ((int)directlink_offer_encode(&pol, &intra, &o, out, sizeof out,
                                               &len, NULL),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ((int)decode(&intra, out, len), (int)DIRECTLINK_OK);
        /* An inter-fleet sender that includes a private candidate is rejected. */
        uint8_t hostile[sizeof k_kat];
        memcpy(hostile, k_kat, sizeof hostile);
        hostile[1] = 1;
        ASSERT_EQ((int)decode(&inter, hostile, sizeof hostile),
                  (int)DIRECTLINK_ERR_ADDRESS);
        /* The scope in the message must match the authenticated peer. */
        ASSERT_EQ((int)decode(&inter, k_kat, sizeof k_kat),
                  (int)DIRECTLINK_ERR_SCOPE);
        hostile[1] = 2;
        ASSERT_EQ((int)decode(&intra, hostile, sizeof hostile),
                  (int)DIRECTLINK_ERR_FIELD);
    } TEST_END;
    return failures;
}

static int dlo_case_malformed(void)
{
    int failures = 0;
    TEST_CASE("directlink offer: malformed input is rejected") {
        struct directlink_peer intra = make_peer(DIRECTLINK_SCOPE_INTRA_FLEET);
        for (size_t n = 0; n < sizeof k_kat; n++)
            ASSERT(decode_prefix(&intra, k_kat, n) != DIRECTLINK_OK);
        uint8_t m[sizeof k_kat + 1];
        memcpy(m, k_kat, sizeof k_kat);
        m[sizeof k_kat] = 0;
        ASSERT_EQ((int)decode(&intra, m, sizeof m), (int)DIRECTLINK_ERR_TRAILING);
        memcpy(m, k_kat, sizeof k_kat);
        m[0] = 2;
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_VERSION);
        memcpy(m, k_kat, sizeof k_kat);
        m[26] = m[27] = m[28] = m[29] = 0; /* ttl 0 */
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_FIELD);
        memcpy(m, k_kat, sizeof k_kat);
        m[26] = 0x31; /* ttl 30001 */
        m[27] = 0x75;
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_FIELD);
        memcpy(m, k_kat, sizeof k_kat);
        m[30] = 0x88; /* delay equals ttl */
        m[31] = 0x13;
        m[32] = m[33] = 0;
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_FIELD);
        memcpy(m, k_kat, sizeof k_kat);
        m[34] = 0; /* no candidates */
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_FIELD);
        m[34] = 9;
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_FIELD);
        memcpy(m, k_kat, sizeof k_kat);
        m[35] = 9; /* unknown candidate kind */
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_FIELD);
        memcpy(m, k_kat, sizeof k_kat);
        m[37] = m[38] = 0; /* port 0 */
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_PORT);
        memcpy(m, k_kat, sizeof k_kat);
        memset(m + 39, 0, 4); /* 0.0.0.0 */
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_ADDRESS);
        memcpy(m, k_kat, sizeof k_kat);
        memcpy(m + 43, m + 35, 8); /* duplicate candidate */
        ASSERT_EQ((int)decode(&intra, m, sizeof k_kat), (int)DIRECTLINK_ERR_FIELD);
    } TEST_END;
    return failures;
}

static struct directlink_offer with_nonce(uint64_t nonce)
{
    struct directlink_offer o = sample_offer();
    o.nonce = nonce;
    return o;
}

static int dlo_case_replay(void)
{
    int failures = 0;
    TEST_CASE("directlink offer: replay cache refuses repeats and stays bounded") {
        struct directlink_replay cache;
        directlink_replay_init(&cache);
        struct directlink_peer a = make_peer(DIRECTLINK_SCOPE_INTRA_FLEET);
        struct directlink_peer b = make_peer(DIRECTLINK_SCOPE_INTRA_FLEET);
        b.identity[0] = 0x43;
        struct directlink_offer o = with_nonce(1);
        ASSERT_EQ((int)directlink_replay_admit(&cache, &a, &o, 0), (int)DIRECTLINK_OK);
        ASSERT_EQ((int)directlink_replay_admit(&cache, &a, &o, 1000),
                  (int)DIRECTLINK_ERR_REPLAY);
        /* A different nonce, session or peer is a different offer. */
        struct directlink_offer n2 = with_nonce(2);
        ASSERT_EQ((int)directlink_replay_admit(&cache, &a, &n2, 0), (int)DIRECTLINK_OK);
        struct directlink_offer s2 = with_nonce(1);
        s2.session_id[0] ^= 0xFF;
        ASSERT_EQ((int)directlink_replay_admit(&cache, &a, &s2, 0), (int)DIRECTLINK_OK);
        ASSERT_EQ((int)directlink_replay_admit(&cache, &b, &o, 0), (int)DIRECTLINK_OK);
        /* After the retention window the entry is reclaimed. */
        ASSERT_EQ((int)directlink_replay_admit(&cache, &a, &o,
                                               DIRECTLINK_REPLAY_RETENTION_MS),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ((int)directlink_replay_admit(NULL, &a, &o, 0),
                  (int)DIRECTLINK_ERR_ARGUMENT);
        struct directlink_peer anonymous;
        memset(&anonymous, 0, sizeof anonymous);
        ASSERT_EQ((int)directlink_replay_admit(&cache, &anonymous, &o, 0),
                  (int)DIRECTLINK_ERR_ARGUMENT);
        /* One peer holds at most DIRECTLINK_REPLAY_PER_PEER entries, so it
         * cannot block another peer. */
        struct directlink_replay quota;
        directlink_replay_init(&quota);
        for (uint64_t i = 0; i < DIRECTLINK_REPLAY_PER_PEER; i++) {
            struct directlink_offer x = with_nonce(100 + i);
            ASSERT_EQ((int)directlink_replay_admit(&quota, &a, &x, 10),
                      (int)DIRECTLINK_OK);
        }
        struct directlink_offer extra = with_nonce(9999);
        ASSERT_EQ((int)directlink_replay_admit(&quota, &a, &extra, 11),
                  (int)DIRECTLINK_ERR_CACHE_FULL);
        struct directlink_offer first = with_nonce(100);
        ASSERT_EQ((int)directlink_replay_admit(&quota, &a, &first, 11),
                  (int)DIRECTLINK_ERR_REPLAY);
        ASSERT_EQ((int)directlink_replay_admit(&quota, &b, &extra, 11),
                  (int)DIRECTLINK_OK);
        ASSERT_EQ((int)directlink_replay_admit(
                      &quota, &a, &extra, 10 + DIRECTLINK_REPLAY_RETENTION_MS),
                  (int)DIRECTLINK_OK);
        /* Enough peers at quota fill the cache: it refuses, never evicts. */
        struct directlink_replay full;
        directlink_replay_init(&full);
        for (uint8_t p = 0; p < DIRECTLINK_REPLAY_SLOTS / DIRECTLINK_REPLAY_PER_PEER;
             p++) {
            struct directlink_peer who = make_peer(DIRECTLINK_SCOPE_INTRA_FLEET);
            who.identity[1] = p;
            for (uint64_t i = 0; i < DIRECTLINK_REPLAY_PER_PEER; i++) {
                struct directlink_offer x = with_nonce(i);
                ASSERT_EQ((int)directlink_replay_admit(&full, &who, &x, 10),
                          (int)DIRECTLINK_OK);
            }
        }
        struct directlink_peer late = make_peer(DIRECTLINK_SCOPE_INTRA_FLEET);
        late.identity[2] = 0x77;
        ASSERT_EQ((int)directlink_replay_admit(&full, &late, &extra, 11),
                  (int)DIRECTLINK_ERR_CACHE_FULL);
        ASSERT_EQ((int)directlink_replay_admit(
                      &full, &late, &extra, 10 + DIRECTLINK_REPLAY_RETENTION_MS),
                  (int)DIRECTLINK_OK);
    } TEST_END;
    return failures;
}

int test_directlink_offer(void)
{
    int failures = 0;
    failures += dlo_case_known_answer();
    failures += dlo_case_policy_refusal();
    failures += dlo_case_peer_required();
    failures += dlo_case_scope_filtering();
    failures += dlo_case_malformed();
    failures += dlo_case_replay();
    return failures;
}
