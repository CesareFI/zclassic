/* purpose: Implement pinned hybrid channels and authenticated bounded guest record exchange. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/device_channel.h"
#include "crypto/curve25519.h"
#include "base/serialize_le.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <string.h>
#include <stdatomic.h>

void device_channel_close(struct device_channel *channel)
{
    if (!channel) return;
    noise_hs_cleanse(&channel->handshake);
    session_transport_cleanse(&channel->transport);
    memory_cleanse(channel, sizeof(*channel));
}

static struct zcl_result refuse(struct device_channel *channel, const char *reason)
{
    device_channel_close(channel);
    LOG_RETURN(ZCL_ERR(-1, "%s", reason), "device_channel", "%s", reason);
}

static bool nonzero(const uint8_t value[32])
{
    uint8_t bits = 0;
    for (size_t i = 0; i < 32; ++i) bits |= value[i];
    return bits != 0;
}

static struct zcl_result channel_init(struct device_channel *channel, bool initiator,
                         enum device_channel_purpose purpose,
                         const uint8_t profile[32],
                         const uint8_t private_key[32],
                         const uint8_t local_pin[32],
                         const uint8_t peer_pin[32])
{
    if (!channel) LOG_RETURN(ZCL_ERR(-2, "missing channel"), "device_channel", "missing channel");
    device_channel_close(channel);
    if (!profile || !private_key || !local_pin || !peer_pin ||
        !nonzero(profile) || !nonzero(private_key) ||
        !nonzero(local_pin) || !nonzero(peer_pin) ||
        !memcmp(local_pin, peer_pin, 32))
        return refuse(channel, "invalid profile or identity");
    uint8_t public_key[32];
    bool matches = curve25519_scalarmult_base(public_key, private_key) &&
                   !memcmp(public_key, local_pin, 32);
    memory_cleanse(public_key, sizeof(public_key));
    if (!matches) return refuse(channel, "local identity does not match grant");
    const char *domain = purpose == DEVICE_CHANNEL_GUEST_STREAM
        ? "zcl.device.guest-stream.v1" : "zcl.device.status-read.v1";
    size_t domain_len = strlen(domain);
    uint8_t prologue[64];
    memcpy(prologue, domain, domain_len);
    memcpy(prologue + domain_len, profile, 32);
    if (!noise_hs_init(&channel->handshake, noise_pattern_xxhfs(), initiator,
                       prologue, domain_len + 32, private_key, NULL))
        return refuse(channel, "handshake initialization failed");
    memcpy(channel->peer, peer_pin, 32);
    memcpy(channel->session.profile, profile, 32);
    memcpy(channel->session.local_key, local_pin, 32);
    memcpy(channel->session.peer, peer_pin, 32);
    channel->session.initiator = initiator;
    channel->purpose = purpose;
    channel->initiator = initiator;
    channel->phase = DEVICE_CHANNEL_HANDSHAKE;
    return ZCL_OK;
}


struct zcl_result device_channel_init(struct device_channel *channel, bool initiator,
    const uint8_t profile[32], const uint8_t private_key[32],
    const uint8_t local_pin[32], const uint8_t peer_pin[32])
{
    return channel_init(channel, initiator, DEVICE_CHANNEL_STATUS,
                        profile, private_key, local_pin, peer_pin);
}

struct zcl_result device_channel_init_guest(struct device_channel *channel, bool initiator,
    const uint8_t profile[32], const uint8_t private_key[32],
    const uint8_t local_pin[32], const uint8_t peer_pin[32])
{
    return channel_init(channel, initiator, DEVICE_CHANNEL_GUEST_STREAM,
                        profile, private_key, local_pin, peer_pin);
}

static bool guest_generation(uint64_t *generation)
{
    static _Atomic uint64_t counter;
    uint64_t value = atomic_load_explicit(&counter, memory_order_relaxed);
    while (value != UINT64_MAX) {
        if (atomic_compare_exchange_weak_explicit(&counter, &value, value + 1,
                memory_order_relaxed, memory_order_relaxed)) {
            *generation = value + 1;
            return true;
        }
    }
    LOG_FAIL("device_channel", "guest connection generation exhausted");
}

static bool guest_buffers_overlap(const void *a, size_t a_len,
                                  const void *b, size_t b_len)
{
    uintptr_t ap = (uintptr_t)a, bp = (uintptr_t)b;
    return ap <= bp ? bp - ap < a_len : ap - bp < b_len;
}

static bool guest_output_geometry(const struct device_channel *channel,
    const struct device_guest_session *expected, const void *input, size_t input_len,
    void *output, size_t output_len, size_t *length)
{
    if (!output || !length) return false;
    if (guest_buffers_overlap(output, output_len, length, sizeof(*length))) return false;
    const void *protected[] = {channel, expected, input};
    const size_t sizes[] = {sizeof(*channel), sizeof(*expected), input_len};
    for (size_t i = 0; i < 3; ++i) {
        if (!protected[i]) continue;
        if (guest_buffers_overlap(output, output_len, protected[i], sizes[i]) ||
            guest_buffers_overlap(length, sizeof(*length), protected[i], sizes[i]))
            return false;
    }
    return true;
}

struct zcl_result device_channel_guest_snapshot(const struct device_channel *channel,
                                   struct device_guest_session *session)
{
    if (channel && session && guest_buffers_overlap(channel, sizeof(*channel),
                                                     session, sizeof(*session)))
        LOG_RETURN(ZCL_ERR(-2, "guest snapshot output overlaps live channel"), "device_channel", "guest snapshot output overlaps live channel");
    if (!channel || !session || channel->phase != DEVICE_CHANNEL_READY ||
        channel->purpose != DEVICE_CHANNEL_GUEST_STREAM || !channel->session.generation) {
        if (session) memset(session, 0, sizeof(*session));
        LOG_RETURN(ZCL_ERR(-3, "established guest session unavailable"), "device_channel", "established guest session unavailable");
    }
    *session = channel->session;
    return ZCL_OK;
}

static bool guest_matches(const struct device_channel *channel,
                           const struct device_guest_session *expected)
{
    const struct device_guest_session *live = channel ? &channel->session : NULL;
    return channel && expected && channel->phase == DEVICE_CHANNEL_READY &&
        channel->purpose == DEVICE_CHANNEL_GUEST_STREAM && live->generation &&
        live->generation == expected->generation && live->initiator == expected->initiator &&
        !memcmp(live->profile, expected->profile, 32) &&
        !memcmp(live->local_key, expected->local_key, 32) &&
        !memcmp(live->peer, expected->peer, 32) &&
        !memcmp(live->transcript_hash, expected->transcript_hash, 32);
}

struct zcl_result device_channel_guest_write(struct device_channel *channel,
    const struct device_guest_session *expected, const uint8_t *payload,
    size_t payload_len, uint8_t out[SESSION_FRAME_MAX_WIRE], size_t *length)
{
    if (!guest_output_geometry(channel, expected, payload, payload_len,
                               out, SESSION_FRAME_MAX_WIRE, length))
        return refuse(channel, "guest write output storage must be independent");
    *length = 0;
    if (!payload || !payload_len ||
        payload_len > SESSION_MAX_PAYLOAD || !guest_matches(channel, expected)) {
        if (out) memory_cleanse(out, SESSION_FRAME_MAX_WIRE);
        return refuse(channel, "guest write requires current session and separate bounded buffers");
    }
    if (!session_transport_encrypt(&channel->transport, SESSION_CH_DATA,
                                    payload, payload_len, out, length)) {
        memory_cleanse(out, SESSION_FRAME_MAX_WIRE);
        *length = 0;
        return refuse(channel, "guest frame encryption failed");
    }
    return ZCL_OK;
}

struct zcl_result device_channel_guest_read(struct device_channel *channel,
    const struct device_guest_session *expected, const uint8_t *wire,
    size_t wire_len, uint8_t out[SESSION_MAX_PAYLOAD], size_t *length)
{
    if (!guest_output_geometry(channel, expected, wire, wire_len,
                               out, SESSION_MAX_PAYLOAD, length))
        return refuse(channel, "guest read output storage must be independent");
    *length = 0;
    if (!wire || !wire_len ||
        wire_len > SESSION_FRAME_MAX_WIRE || !guest_matches(channel, expected)) {
        if (out) memory_cleanse(out, SESSION_MAX_PAYLOAD);
        return refuse(channel, "guest read requires current session and separate bounded buffers");
    }
    enum session_channel kind;
    if (!session_transport_decrypt(&channel->transport, &kind, wire, wire_len,
                                    out, length) || kind != SESSION_CH_DATA || !*length) {
        memory_cleanse(out, SESSION_MAX_PAYLOAD);
        *length = 0;
        return refuse(channel, "guest frame authentication or channel refused");
    }
    return ZCL_OK;
}

static struct zcl_result finish_handshake(struct device_channel *channel)
{
    if (!noise_hs_done(&channel->handshake)) return ZCL_OK;
    uint8_t peer[32], send[32] = {0}, receive[32] = {0};
    bool ok = noise_hs_remote_static(&channel->handshake, peer) &&
              !memcmp(peer, channel->peer, 32) &&
              noise_hs_transcript_hash(&channel->handshake, channel->session.transcript_hash) &&
              noise_hs_split(&channel->handshake, send, receive);
    if (ok && channel->purpose == DEVICE_CHANNEL_GUEST_STREAM)
        ok = guest_generation(&channel->session.generation);
    if (ok) {
        session_transport_init(&channel->transport, send, receive);
        channel->phase = DEVICE_CHANNEL_READY;
    }
    memory_cleanse(peer, sizeof(peer));
    memory_cleanse(send, sizeof(send));
    memory_cleanse(receive, sizeof(receive));
    noise_hs_cleanse(&channel->handshake);
    if (!ok) return refuse(channel, "peer pin or handshake completion failed");
    return ZCL_OK;
}

struct zcl_result device_channel_handshake_write(struct device_channel *channel,
                                    uint8_t out[NOISE_MAX_MESSAGE], size_t *length)
{
    if (length) *length = 0;
    if (!channel || !out || !length ||
        channel->phase != DEVICE_CHANNEL_HANDSHAKE)
        return refuse(channel, "invalid handshake write state");
    struct zcl_result result = noise_hs_write_message(&channel->handshake, NULL, 0, out, length)
        ? finish_handshake(channel) : refuse(channel, "handshake write refused");
    if (!result.ok) {
        memory_cleanse(out, NOISE_MAX_MESSAGE);
        *length = 0;
        return result;
    }
    return ZCL_OK;
}

struct zcl_result device_channel_handshake_read(struct device_channel *channel,
                                   const uint8_t *input, size_t length)
{
    uint8_t payload[NOISE_MAX_MESSAGE];
    size_t payload_length = 0;
    if (!channel || !input || !length || length > NOISE_MAX_MESSAGE ||
        channel->phase != DEVICE_CHANNEL_HANDSHAKE)
        return refuse(channel, "invalid handshake read state");
    bool ok = noise_hs_read_message(&channel->handshake, input, length,
                                    payload, &payload_length);
    memory_cleanse(payload, sizeof(payload));
    if (!ok || payload_length)
        return refuse(channel, "handshake or pre-authentication payload refused");
    return finish_handshake(channel);
}

struct zcl_result device_channel_request(struct device_channel *channel,
                            uint8_t out[SESSION_FRAME_MAX_WIRE], size_t *length)
{
    static const uint8_t request[] = {1, 1};
    if (length) *length = 0;
    if (!channel || !out || !length || !channel->initiator ||
        channel->purpose != DEVICE_CHANNEL_STATUS ||
        channel->phase != DEVICE_CHANNEL_READY)
        return refuse(channel, "request requires authenticated initiator");
    if (!session_transport_encrypt(&channel->transport, SESSION_CH_DATA,
                                    request, sizeof(request), out, length))
        return refuse(channel, "request encryption failed");
    channel->phase = DEVICE_CHANNEL_REQUESTED;
    return ZCL_OK;
}

static struct zcl_result read_record(struct device_channel *channel, const uint8_t *input,
                        size_t length, uint8_t out[SESSION_MAX_PAYLOAD],
                        size_t *out_length)
{
    enum session_channel kind;
    if (!input || !length || length > SESSION_FRAME_MAX_WIRE ||
        !session_transport_decrypt(&channel->transport, &kind, input, length,
                                    out, out_length) || kind != SESSION_CH_DATA)
        return refuse(channel, "invalid authenticated record");
    return ZCL_OK;
}

struct zcl_result device_channel_accept_request(struct device_channel *channel,
                                   const uint8_t *input, size_t length)
{
    uint8_t payload[SESSION_MAX_PAYLOAD];
    size_t size = 0;
    if (!channel || channel->initiator ||
        channel->purpose != DEVICE_CHANNEL_STATUS ||
        channel->phase != DEVICE_CHANNEL_READY)
        return refuse(channel, "request requires authenticated responder");
    ZCL_CHECK(read_record(channel, input, length, payload, &size));
    if (size != 2 || payload[0] != 1 || payload[1] != 1)
        return refuse(channel, "unsupported status request");
    channel->phase = DEVICE_CHANNEL_REQUESTED;
    return ZCL_OK;
}


static bool status_valid(const struct device_disk_status *status)
{
    return status && status->sampled_at && status->root_total &&
           status->home_total && status->root_available <= status->root_total &&
           status->home_available <= status->home_total;
}

struct zcl_result device_channel_respond(struct device_channel *channel,
                            const struct device_disk_status *status,
                            uint8_t out[SESSION_FRAME_MAX_WIRE], size_t *length)
{
    if (length) *length = 0;
    if (!channel || !out || !length || channel->initiator ||
        channel->purpose != DEVICE_CHANNEL_STATUS ||
        channel->phase != DEVICE_CHANNEL_REQUESTED || !status_valid(status))
        return refuse(channel, "invalid status response state or sample");
    uint8_t payload[42] = {1, 2};
    zcl_write_u64_le(payload + 2, status->sampled_at);
    zcl_write_u64_le(payload + 10, status->root_total);
    zcl_write_u64_le(payload + 18, status->root_available);
    zcl_write_u64_le(payload + 26, status->home_total);
    zcl_write_u64_le(payload + 34, status->home_available);
    bool ok = session_transport_encrypt(&channel->transport, SESSION_CH_DATA,
                                         payload, sizeof(payload), out, length);
    if (!ok) return refuse(channel, "status encryption failed");
    session_transport_cleanse(&channel->transport);
    channel->phase = DEVICE_CHANNEL_FINISHED;
    return ZCL_OK;
}

struct zcl_result device_channel_accept_status(struct device_channel *channel,
                                  const uint8_t *input, size_t length,
                                  struct device_disk_status *status)
{
    if (status) memset(status, 0, sizeof(*status));
    if (!channel || !status || !channel->initiator ||
        channel->purpose != DEVICE_CHANNEL_STATUS ||
        channel->phase != DEVICE_CHANNEL_REQUESTED)
        return refuse(channel, "status requires an outstanding request");
    uint8_t payload[SESSION_MAX_PAYLOAD];
    size_t size = 0;
    ZCL_CHECK(read_record(channel, input, length, payload, &size));
    if (size != 42 || payload[0] != 1 || payload[1] != 2)
        return refuse(channel, "unsupported status response");
    struct device_disk_status parsed = {
        .sampled_at = zcl_read_u64_le(payload + 2),
        .root_total = zcl_read_u64_le(payload + 10),
        .root_available = zcl_read_u64_le(payload + 18),
        .home_total = zcl_read_u64_le(payload + 26),
        .home_available = zcl_read_u64_le(payload + 34)
    };
    if (!status_valid(&parsed)) return refuse(channel, "invalid disk counters");
    *status = parsed;
    session_transport_cleanse(&channel->transport);
    channel->phase = DEVICE_CHANNEL_FINISHED;
    return ZCL_OK;
}
