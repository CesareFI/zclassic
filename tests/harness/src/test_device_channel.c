/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: offline hybrid channel primitives, no socket or guest runtime. */
#include "test/test_core.h"
#include "services/device_channel.h"
static_assert(_Generic(device_channel_init(NULL, false, NULL, NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_init_guest(NULL, false, NULL, NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_guest_snapshot(NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_guest_write(NULL, NULL, NULL, 0, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_guest_read(NULL, NULL, NULL, 0, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_handshake_write(NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_handshake_read(NULL, NULL, 0), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_request(NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_accept_request(NULL, NULL, 0), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_respond(NULL, NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_channel_accept_status(NULL, NULL, 0, NULL), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
#include "crypto/curve25519.h"
#include <string.h>

struct channel_pair { struct device_channel client, server; };

static bool pair_init(struct channel_pair *pair, unsigned defect)
{
    uint8_t profile[32] = {1}, other_profile[32] = {2};
    uint8_t client_key[32] = {7}, server_key[32] = {9};
    uint8_t client_pin[32], server_pin[32], wrong_pin[32] = {11};
    if (!curve25519_scalarmult_base(client_pin, client_key) ||
        !curve25519_scalarmult_base(server_pin, server_key)) return false;
    return device_channel_init(&pair->client, true, profile, client_key,
                                client_pin, defect == 1 ? wrong_pin : server_pin).ok &&
           device_channel_init(&pair->server, false,
                                defect == 2 ? other_profile : profile,
                                server_key, server_pin,
                                defect == 3 ? wrong_pin : client_pin).ok;
}

static bool pair_handshake(struct channel_pair *pair)
{
    uint8_t wire[NOISE_MAX_MESSAGE];
    size_t size = 0;
    return device_channel_handshake_write(&pair->client, wire, &size).ok &&
           device_channel_handshake_read(&pair->server, wire, size).ok &&
           device_channel_handshake_write(&pair->server, wire, &size).ok &&
           device_channel_handshake_read(&pair->client, wire, size).ok &&
           device_channel_handshake_write(&pair->client, wire, &size).ok &&
           device_channel_handshake_read(&pair->server, wire, size).ok;
}

static void pair_close(struct channel_pair *pair)
{
    device_channel_close(&pair->client);
    device_channel_close(&pair->server);
}

static int roundtrip(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_channel: pinned hybrid status exchange and one-shot lifetime") {
        ASSERT(pair_init(&pair, 0));
        ASSERT(pair_handshake(&pair));
        uint8_t wire[SESSION_FRAME_MAX_WIRE];
        size_t size = 0;
        ASSERT(device_channel_request(&pair.client, wire, &size).ok);
        ASSERT(device_channel_accept_request(&pair.server, wire, size).ok);
        struct device_disk_status sent = {100, 1000, 500, 2000, 1500}, received;
        ASSERT(device_channel_respond(&pair.server, &sent, wire, &size).ok);
        ASSERT(device_channel_accept_status(&pair.client, wire, size, &received).ok);
        ASSERT_EQ(received.sampled_at, sent.sampled_at);
        ASSERT_EQ(received.root_total, sent.root_total);
        ASSERT_EQ(received.root_available, sent.root_available);
        ASSERT_EQ(received.home_total, sent.home_total);
        ASSERT_EQ(received.home_available, sent.home_available);
        ASSERT(!device_channel_accept_status(&pair.client, wire, size, &received).ok);
        ASSERT_EQ(received.sampled_at, 0);
        ASSERT_EQ(pair.client.phase, DEVICE_CHANNEL_CLOSED);
        ASSERT(!device_channel_request(&pair.server, wire, &size).ok);
    } TEST_END
    pair_close(&pair);
    return failures;
}

static int wrong_authority(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_channel: wrong pins and cross-profile handshakes fail closed") {
        for (unsigned defect = 1; defect <= 3; ++defect) {
            ASSERT(pair_init(&pair, defect));
            ASSERT(!pair_handshake(&pair));
            uint8_t wire[SESSION_FRAME_MAX_WIRE];
            size_t size = 123;
            struct device_disk_status status = {100, 1000, 500, 2000, 1500};
            ASSERT(!device_channel_respond(&pair.server, &status, wire, &size).ok);
            ASSERT_EQ(size, 0);
            pair_close(&pair);
        }
    } TEST_END
    pair_close(&pair);
    return failures;
}

static int bad_records(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_channel: tamper, truncation, oversize and replay terminate") {
        for (unsigned defect = 0; defect < 4; ++defect) {
            ASSERT(pair_init(&pair, 0));
            ASSERT(pair_handshake(&pair));
            uint8_t wire[SESSION_FRAME_MAX_WIRE + 1] = {0};
            size_t size = 0;
            ASSERT(device_channel_request(&pair.client, wire, &size).ok);
            if (defect == 0) wire[size - 1] ^= 1;
            if (defect == 1) --size;
            if (defect == 2) size = sizeof(wire);
            if (defect == 3)
                ASSERT(device_channel_accept_request(&pair.server, wire, size).ok);
            ASSERT(!device_channel_accept_request(&pair.server, wire, size).ok);
            ASSERT_EQ(pair.server.phase, DEVICE_CHANNEL_CLOSED);
            pair_close(&pair);
        }
    } TEST_END
    pair_close(&pair);
    return failures;
}

static int preauth_and_geometry(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_channel: no pre-auth status and invalid disk counters refused") {
        ASSERT(pair_init(&pair, 0));
        uint8_t wire[SESSION_FRAME_MAX_WIRE];
        size_t size = 0;
        ASSERT(!device_channel_request(&pair.client, wire, &size).ok);
        ASSERT_EQ(size, 0);
        pair_close(&pair);
        ASSERT(pair_init(&pair, 0));
        ASSERT(pair_handshake(&pair));
        ASSERT(device_channel_request(&pair.client, wire, &size).ok);
        ASSERT(device_channel_accept_request(&pair.server, wire, size).ok);
        struct device_disk_status invalid = {100, 1000, 1001, 2000, 1500};
        ASSERT(!device_channel_respond(&pair.server, &invalid, wire, &size).ok);
        ASSERT_EQ(size, 0);
    } TEST_END
    pair_close(&pair);
    return failures;
}


static bool erased(const struct device_channel *channel)
{
    const unsigned char *bytes = (const unsigned char *)channel;
    unsigned char combined = 0;
    for (size_t i = 0; i < sizeof(*channel); ++i) combined |= bytes[i];
    return combined == 0;
}

static int authenticated_rejections(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_channel: authenticated unsupported content and erased failure state") {
        for (unsigned defect = 0; defect < 4; ++defect) {
            ASSERT(pair_init(&pair, 0));
            ASSERT(pair_handshake(&pair));
            uint8_t wire[SESSION_FRAME_MAX_WIRE], payload[42] = {1, 1};
            size_t size = 0;
            if (defect < 3) {
                if (defect == 1) payload[0] = 2;
                if (defect == 2) payload[1] = 3;
                ASSERT(session_transport_encrypt(&pair.client.transport,
                    defect == 0 ? SESSION_CH_AUTH : SESSION_CH_DATA,
                    payload, 2, wire, &size));
                ASSERT(!device_channel_accept_request(&pair.server, wire, size).ok);
                ASSERT(erased(&pair.server));
            } else {
                ASSERT(device_channel_request(&pair.client, wire, &size).ok);
                ASSERT(device_channel_accept_request(&pair.server, wire, size).ok);
                payload[1] = 2;
                ASSERT(session_transport_encrypt(&pair.server.transport,
                    SESSION_CH_DATA, payload, sizeof(payload), wire, &size));
                struct device_disk_status status = {0};
                ASSERT(!device_channel_accept_status(&pair.client, wire, size, &status).ok);
                ASSERT(erased(&pair.client));
                ASSERT_EQ(status.sampled_at, 0);
            }
            pair_close(&pair);
        }
    } TEST_END
    pair_close(&pair);
    return failures;
}

static int handshake_rejections(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_channel: pre-auth payload, local pin mismatch and identity zero refused") {
        ASSERT(pair_init(&pair, 0));
        uint8_t wire[NOISE_MAX_MESSAGE], payload = 1;
        size_t size = 0;
        ASSERT(noise_hs_write_message(&pair.client.handshake, &payload, 1, wire, &size));
        ASSERT(!device_channel_handshake_read(&pair.server, wire, size).ok);
        ASSERT(erased(&pair.server));
        uint8_t profile[32] = {1}, key[32] = {7}, pin[32] = {9}, peer[32] = {11};
        ASSERT(!device_channel_init(&pair.client, true, profile, key, pin, peer).ok);
        ASSERT(erased(&pair.client));
        memset(profile, 0, sizeof(profile));
        ASSERT(!device_channel_init(&pair.client, true, profile, key, pin, peer).ok);
        ASSERT(erased(&pair.client));
    } TEST_END
    pair_close(&pair);
    return failures;
}



static bool guest_pair_init(struct channel_pair *pair, bool client_guest, bool server_guest)
{
    uint8_t profile[32] = {1}, client_key[32] = {7}, server_key[32] = {9};
    uint8_t client_pin[32], server_pin[32];
    if (!curve25519_scalarmult_base(client_pin, client_key) ||
        !curve25519_scalarmult_base(server_pin, server_key)) return false;
    bool ok = client_guest
        ? device_channel_init_guest(&pair->client, true, profile, client_key, client_pin, server_pin).ok
        : device_channel_init(&pair->client, true, profile, client_key, client_pin, server_pin).ok;
    return ok && (server_guest
        ? device_channel_init_guest(&pair->server, false, profile, server_key, server_pin, client_pin).ok
        : device_channel_init(&pair->server, false, profile, server_key, server_pin, client_pin).ok);
}

static int guest_session_roundtrip(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_guest: authenticated session binding and full bounded duplex frames") {
        struct device_guest_session client = {0}, server = {0};
        ASSERT(guest_pair_init(&pair, true, true));
        ASSERT(!device_channel_guest_snapshot(&pair.client, &client).ok);
        ASSERT_EQ(client.generation, 0);
        ASSERT(pair_handshake(&pair));
        ASSERT(device_channel_guest_snapshot(&pair.client, &client).ok);
        ASSERT(device_channel_guest_snapshot(&pair.server, &server).ok);
        ASSERT(client.generation && server.generation && client.generation != server.generation);
        ASSERT(client.initiator && !server.initiator);
        ASSERT(!memcmp(client.transcript_hash, server.transcript_hash, 32));
        ASSERT(!memcmp(client.local_key, server.peer, 32));
        ASSERT(!memcmp(client.peer, server.local_key, 32));
        ASSERT(!memcmp(client.profile, server.profile, 32));
        uint8_t payload[SESSION_MAX_PAYLOAD], wire[SESSION_FRAME_MAX_WIRE], out[SESSION_MAX_PAYLOAD];
        for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)i;
        size_t wire_len = 0, out_len = 0;
        ASSERT(device_channel_guest_write(&pair.client, &client, payload, sizeof(payload), wire, &wire_len).ok);
        ASSERT(device_channel_guest_read(&pair.server, &server, wire, wire_len, out, &out_len).ok);
        ASSERT_EQ(out_len, sizeof(payload));
        ASSERT(!memcmp(payload, out, out_len));
        ASSERT(device_channel_guest_write(&pair.server, &server, payload, 37, wire, &wire_len).ok);
        ASSERT(device_channel_guest_read(&pair.client, &client, wire, wire_len, out, &out_len).ok);
        ASSERT_EQ(out_len, 37);
        ASSERT(!memcmp(payload, out, out_len));
        ASSERT(!device_channel_guest_read(&pair.client, &client, wire, wire_len, out, &out_len).ok);
        ASSERT_EQ(out_len, 0);
        ASSERT_EQ(pair.client.phase, DEVICE_CHANNEL_CLOSED);
        ASSERT(!device_channel_guest_snapshot(&pair.client, &client).ok);
        ASSERT_EQ(client.generation, 0);
    } TEST_END
    pair_close(&pair);
    return failures;
}

static int guest_purpose_separation(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_guest: purpose is authenticated and status APIs cannot consume guest sessions") {
        for (unsigned role = 0; role < 2; ++role) {
            ASSERT(guest_pair_init(&pair, role == 0, role != 0));
            ASSERT(!pair_handshake(&pair));
            pair_close(&pair);
        }
        ASSERT(pair_init(&pair, 0));
        ASSERT(pair_handshake(&pair));
        struct device_guest_session session = {0};
        ASSERT(!device_channel_guest_snapshot(&pair.client, &session).ok);
        pair_close(&pair);
        ASSERT(guest_pair_init(&pair, true, true));
        ASSERT(pair_handshake(&pair));
        uint8_t wire[SESSION_FRAME_MAX_WIRE];
        size_t length = 0;
        ASSERT(!device_channel_request(&pair.client, wire, &length).ok);
        ASSERT_EQ(pair.client.phase, DEVICE_CHANNEL_CLOSED);
        pair_close(&pair);
        ASSERT(guest_pair_init(&pair, true, true));
        ASSERT(pair_handshake(&pair));
        ASSERT(device_channel_guest_snapshot(&pair.client, &session).ok);
        const uint8_t status_request[] = {1, 1};
        ASSERT(device_channel_guest_write(&pair.client, &session, status_request,
                                         sizeof(status_request), wire, &length).ok);
        ASSERT(!device_channel_accept_request(&pair.server, wire, length).ok);
        ASSERT_EQ(pair.server.phase, DEVICE_CHANNEL_CLOSED);
    } TEST_END
    pair_close(&pair);
    return failures;
}

static int guest_session_identity(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_guest: every binding field and replacement generation are required") {
        for (unsigned defect = 0; defect < 6; ++defect) {
            ASSERT(guest_pair_init(&pair, true, true));
            ASSERT(pair_handshake(&pair));
            struct device_guest_session expected;
            ASSERT(device_channel_guest_snapshot(&pair.client, &expected).ok);
            if (defect == 0) expected.profile[0] ^= 1;
            if (defect == 1) expected.local_key[0] ^= 1;
            if (defect == 2) expected.peer[0] ^= 1;
            if (defect == 3) expected.transcript_hash[0] ^= 1;
            if (defect == 4) expected.generation++;
            if (defect == 5) expected.initiator = !expected.initiator;
            uint8_t wire[SESSION_FRAME_MAX_WIRE], payload = 7;
            size_t length = 99;
            ASSERT(!device_channel_guest_write(&pair.client, &expected, &payload, 1, wire, &length).ok);
            ASSERT_EQ(length, 0);
            ASSERT_EQ(pair.client.phase, DEVICE_CHANNEL_CLOSED);
            pair_close(&pair);
        }
        ASSERT(guest_pair_init(&pair, true, true));
        ASSERT(pair_handshake(&pair));
        struct device_guest_session old, fresh;
        ASSERT(device_channel_guest_snapshot(&pair.client, &old).ok);
        pair_close(&pair);
        ASSERT(guest_pair_init(&pair, true, true));
        ASSERT(pair_handshake(&pair));
        ASSERT(device_channel_guest_snapshot(&pair.client, &fresh).ok);
        ASSERT(old.generation != fresh.generation);
        uint8_t wire[SESSION_FRAME_MAX_WIRE], payload = 7;
        size_t length = 0;
        ASSERT(!device_channel_guest_write(&pair.client, &old, &payload, 1, wire, &length).ok);
    } TEST_END
    pair_close(&pair);
    return failures;
}

static int guest_frame_refusals(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_guest: oversized writes and damaged authenticated records terminate") {
        for (unsigned defect = 0; defect < 3; ++defect) {
            ASSERT(guest_pair_init(&pair, true, true));
            ASSERT(pair_handshake(&pair));
            struct device_guest_session client, server;
            ASSERT(device_channel_guest_snapshot(&pair.client, &client).ok);
            ASSERT(device_channel_guest_snapshot(&pair.server, &server).ok);
            uint8_t payload[SESSION_MAX_PAYLOAD + 1] = {7};
            uint8_t wire[SESSION_FRAME_MAX_WIRE], out[SESSION_MAX_PAYLOAD];
            size_t length = 99, got = 99;
            if (defect == 0) {
                ASSERT(!device_channel_guest_write(&pair.client, &client, payload,
                                                    sizeof(payload), wire, &length).ok);
                ASSERT_EQ(length, 0);
                ASSERT_EQ(pair.client.phase, DEVICE_CHANNEL_CLOSED);
            } else {
                ASSERT(device_channel_guest_write(&pair.client, &client, payload, 37, wire, &length).ok);
                if (defect == 1) wire[length - 1] ^= 1;
                else --length;
                ASSERT(!device_channel_guest_read(&pair.server, &server, wire, length, out, &got).ok);
                ASSERT_EQ(got, 0);
                ASSERT_EQ(pair.server.phase, DEVICE_CHANNEL_CLOSED);
            }
            pair_close(&pair);
        }
    } TEST_END
    pair_close(&pair);
    return failures;
}

static int guest_output_aliases(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_guest: snapshot query preserves live state and aliased output refuses") {
        ASSERT(guest_pair_init(&pair, true, true));
        ASSERT(pair_handshake(&pair));
        struct device_guest_session session;
        ASSERT(device_channel_guest_snapshot(&pair.client, &session).ok);
        ASSERT(!device_channel_guest_snapshot(&pair.client, &pair.client.session).ok);
        ASSERT_EQ(pair.client.session.generation, session.generation);
        uint8_t wire[SESSION_FRAME_MAX_WIRE] = {7};
        size_t length = 99;
        ASSERT(!device_channel_guest_write(&pair.client, &session, wire, 1, wire, &length).ok);
        ASSERT_EQ(length, 99);
        ASSERT_EQ(wire[0], 7);
        ASSERT_EQ(pair.client.phase, DEVICE_CHANNEL_CLOSED);
        pair_close(&pair);
        ASSERT(guest_pair_init(&pair, true, true));
        ASSERT(pair_handshake(&pair));
        ASSERT(device_channel_guest_snapshot(&pair.client, &session).ok);
        uint8_t payload = 7;
        ASSERT(!device_channel_guest_write(&pair.client, &session, &payload, 1,
                                           wire, (size_t *)(void *)&pair.client).ok);
        ASSERT_EQ(pair.client.phase, DEVICE_CHANNEL_CLOSED);
    } TEST_END
    pair_close(&pair);
    return failures;
}


static int classical_handshake_refused(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    struct noise_handshake classical = {0};
    TEST_CASE("device_channel: either classical XX peer is refused without fallback") {
        for (unsigned role = 0; role < 2; ++role) {
            ASSERT(pair_init(&pair, 0));
            uint8_t key[32] = {0}, prologue[64] = {0};
            key[0] = role == 0 ? 7 : 9;
            static const char domain[] = "zcl.device.status-read.v1";
            memcpy(prologue, domain, sizeof(domain) - 1);
            prologue[sizeof(domain) - 1] = 1;
            ASSERT(noise_hs_init(&classical, noise_pattern_xx(), role == 0,
                prologue, sizeof(domain) - 1 + 32, key, NULL));
            struct device_channel *changed = role == 0 ? &pair.client : &pair.server;
            noise_hs_cleanse(&changed->handshake);
            changed->handshake = classical;
            memset(&classical, 0, sizeof(classical));
            uint8_t wire[NOISE_MAX_MESSAGE];
            size_t length = 0;
            ASSERT(device_channel_handshake_write(&pair.client, wire, &length).ok);
            ASSERT(!device_channel_handshake_read(&pair.server, wire, length).ok);
            ASSERT(erased(&pair.server));
            pair_close(&pair);
        }
    } TEST_END
    noise_hs_cleanse(&classical);
    pair_close(&pair);
    return failures;
}

static int guest_replay_refused(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_guest: a consumed authenticated frame cannot be replayed") {
        ASSERT(guest_pair_init(&pair, true, true));
        ASSERT(pair_handshake(&pair));
        struct device_guest_session client, server;
        ASSERT(device_channel_guest_snapshot(&pair.client, &client).ok);
        ASSERT(device_channel_guest_snapshot(&pair.server, &server).ok);
        const uint8_t payload[] = {3, 7, 9};
        uint8_t wire[SESSION_FRAME_MAX_WIRE], output[SESSION_MAX_PAYLOAD];
        size_t length = 0, got = 0;
        ASSERT(device_channel_guest_write(&pair.client, &client,
            payload, sizeof(payload), wire, &length).ok);
        ASSERT(device_channel_guest_read(&pair.server, &server,
            wire, length, output, &got).ok);
        ASSERT_EQ(got, sizeof(payload));
        ASSERT(!memcmp(payload, output, got));
        memset(output, 0xa5, sizeof(output));
        got = 99;
        ASSERT(!device_channel_guest_read(&pair.server, &server,
            wire, length, output, &got).ok);
        ASSERT_EQ(got, 0);
        ASSERT(erased(&pair.server));
        uint8_t zero[SESSION_MAX_PAYLOAD] = {0};
        ASSERT(!memcmp(output, zero, sizeof(output)));
    } TEST_END
    pair_close(&pair);
    return failures;
}

static bool guest_exchange(struct device_channel *sender,
    struct device_channel *receiver, const struct device_guest_session *send_session,
    const struct device_guest_session *recv_session,
    uint8_t wire[SESSION_FRAME_MAX_WIRE], size_t *length)
{
    const uint8_t payload[] = {2, 4, 6};
    uint8_t output[SESSION_MAX_PAYLOAD];
    size_t got = 0;
    return device_channel_guest_write(sender, send_session, payload,
        sizeof(payload), wire, length).ok &&
        device_channel_guest_read(receiver, recv_session, wire, *length, output, &got).ok &&
        got == sizeof(payload) && !memcmp(payload, output, sizeof(payload));
}

static bool guest_snapshot_equal(const struct device_guest_session *a,
                                  const struct device_guest_session *b)
{
    return a->generation == b->generation && a->initiator == b->initiator &&
        !memcmp(a->profile, b->profile, sizeof(a->profile)) &&
        !memcmp(a->local_key, b->local_key, sizeof(a->local_key)) &&
        !memcmp(a->peer, b->peer, sizeof(a->peer)) &&
        !memcmp(a->transcript_hash, b->transcript_hash, sizeof(a->transcript_hash));
}

static int guest_rekey_boundaries(void)
{
    int failures = 0;
    struct channel_pair pair = {0};
    TEST_CASE("device_guest: both directions rekey at frame and byte limits with stable identity") {
        for (unsigned direction = 0; direction < 2; ++direction) {
            for (unsigned threshold = 0; threshold < 2; ++threshold) {
                ASSERT(guest_pair_init(&pair, true, true));
                ASSERT(pair_handshake(&pair));
                struct device_channel *sender = direction ? &pair.server : &pair.client;
                struct device_channel *receiver = direction ? &pair.client : &pair.server;
                struct device_guest_session sent, received, after;
                ASSERT(device_channel_guest_snapshot(sender, &sent).ok);
                ASSERT(device_channel_guest_snapshot(receiver, &received).ok);
                uint8_t key[32];
                memcpy(key, sender->transport.send_key, sizeof(key));
                if (threshold == 0) {
                    sender->transport.send_n = SESSION_REKEY_FRAME_LIMIT - 1;
                    receiver->transport.recv_n = SESSION_REKEY_FRAME_LIMIT - 1;
                } else {
                    sender->transport.send_bytes_epoch = SESSION_REKEY_BYTE_LIMIT - 4;
                    receiver->transport.recv_bytes_epoch = SESSION_REKEY_BYTE_LIMIT - 4;
                }
                uint8_t before[SESSION_FRAME_MAX_WIRE], wire[SESSION_FRAME_MAX_WIRE];
                size_t before_length = 0, length = 0;
                ASSERT(guest_exchange(sender, receiver, &sent, &received, before, &before_length));
                ASSERT_EQ(sender->transport.send_epoch, 0);
                ASSERT_EQ(receiver->transport.recv_epoch, 0);
                ASSERT(guest_exchange(sender, receiver, &sent, &received, wire, &length));
                ASSERT_EQ(sender->transport.send_epoch, 1);
                ASSERT_EQ(receiver->transport.recv_epoch, 1);
                ASSERT_EQ(sender->transport.send_n, 1);
                ASSERT_EQ(receiver->transport.recv_n, 1);
                ASSERT(memcmp(key, sender->transport.send_key, sizeof(key)));
                ASSERT(device_channel_guest_snapshot(sender, &after).ok);
                ASSERT(guest_snapshot_equal(&sent, &after));
                ASSERT(device_channel_guest_snapshot(receiver, &after).ok);
                ASSERT(guest_snapshot_equal(&received, &after));
                uint8_t output[SESSION_MAX_PAYLOAD];
                size_t got = 99;
                ASSERT(!device_channel_guest_read(receiver, &received,
                    before, before_length, output, &got).ok);
                ASSERT_EQ(got, 0);
                ASSERT(erased(receiver));
                pair_close(&pair);
            }
        }
    } TEST_END
    pair_close(&pair);
    return failures;
}

int test_device_channel(void);
int test_device_channel(void)
{
    return roundtrip() + wrong_authority() + bad_records() + preauth_and_geometry() +
        authenticated_rejections() + handshake_rejections() +
        guest_session_roundtrip() + guest_purpose_separation() +
        guest_session_identity() + guest_frame_refusals() + guest_output_aliases() +
        classical_handshake_refused() + guest_replay_refused() + guest_rekey_boundaries();
}
