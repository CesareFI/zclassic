/* purpose: Define pinned hybrid device channels and authenticated guest-scoped records. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_CHANNEL_H
#define ZCL_SERVICES_DEVICE_CHANNEL_H
#include "base/result.h"
#include "noise/noise_handshake.h"
#include "noise/session_transport.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A separate owner-approved profile; never an anchored-mesh fallback.
 * The owner supplies both exact pins and a shared public profile identifier.
 * Fallible operations return a contextual zcl_result; success has code zero.
 * Callers serialize current grant validation with frame release, enforce a
 * monotonic connection deadline, and close on every failed result.
 * Initialization, handshake and status APIs require independent storage:
 * inputs and outputs must not overlap the live channel or each other;
 * output buffers, length storage and status storage must be disjoint.
 * These are caller preconditions; guest frame APIs check their geometry. */
enum device_channel_phase {
    DEVICE_CHANNEL_CLOSED, DEVICE_CHANNEL_HANDSHAKE,
    DEVICE_CHANNEL_READY, DEVICE_CHANNEL_REQUESTED, DEVICE_CHANNEL_FINISHED
};
enum device_channel_purpose {
    DEVICE_CHANNEL_STATUS, DEVICE_CHANNEL_GUEST_STREAM
};
/* Public binding only. Generation is process-local and never reused after
 * exhaustion; this object contains no transport keys or mutable nonce state. */
struct device_guest_session {
    uint8_t profile[32], local_key[32], peer[32], transcript_hash[32];
    uint64_t generation;
    bool initiator;
};
struct device_channel {
    struct noise_handshake handshake;
    struct session_transport transport;
    uint8_t peer[32];
    struct device_guest_session session;
    enum device_channel_purpose purpose;
    enum device_channel_phase phase;
    bool initiator;
};
struct device_disk_status {
    uint64_t sampled_at;
    uint64_t root_total, root_available;
    uint64_t home_total, home_available;
};
struct zcl_result device_channel_init(struct device_channel *channel, bool initiator,
                         const uint8_t profile[32],
                         const uint8_t private_key[32],
                         const uint8_t local_pin[32],
                         const uint8_t peer_pin[32]);
/* Guest transport uses a distinct authenticated domain. This does not grant
 * guest authority: the receiver must hold its current capability guard around
 * dispatch and encrypted frame release, and enforce its connection deadline. */
struct zcl_result device_channel_init_guest(struct device_channel *channel, bool initiator,
    const uint8_t profile[32], const uint8_t private_key[32],
    const uint8_t local_pin[32], const uint8_t peer_pin[32]);
/* Query output must not overlap the live channel. */
struct zcl_result device_channel_guest_snapshot(const struct device_channel *channel,
                                   struct device_guest_session *session);
/* One complete frame, at most SESSION_MAX_PAYLOAD bytes; no fragmentation.
 * Output and length storage must be independent of each other, input, channel
 * and expected snapshot. On a geometry refusal only the channel is cleared;
 * other refusals also clear valid output storage. The expected snapshot must
 * still match. No refusal releases a frame. */
struct zcl_result device_channel_guest_write(struct device_channel *channel,
    const struct device_guest_session *expected, const uint8_t *payload,
    size_t payload_len, uint8_t out[SESSION_FRAME_MAX_WIRE], size_t *length);
struct zcl_result device_channel_guest_read(struct device_channel *channel,
    const struct device_guest_session *expected, const uint8_t *wire,
    size_t wire_len, uint8_t out[SESSION_MAX_PAYLOAD], size_t *length);
struct zcl_result device_channel_handshake_write(struct device_channel *channel,
                                    uint8_t out[NOISE_MAX_MESSAGE], size_t *length);
struct zcl_result device_channel_handshake_read(struct device_channel *channel,
                                   const uint8_t *input, size_t length);
struct zcl_result device_channel_request(struct device_channel *channel,
                            uint8_t out[SESSION_FRAME_MAX_WIRE], size_t *length);
struct zcl_result device_channel_accept_request(struct device_channel *channel,
                                   const uint8_t *input, size_t length);
struct zcl_result device_channel_respond(struct device_channel *channel,
                            const struct device_disk_status *status,
                            uint8_t out[SESSION_FRAME_MAX_WIRE], size_t *length);
struct zcl_result device_channel_accept_status(struct device_channel *channel,
                                  const uint8_t *input, size_t length,
                                  struct device_disk_status *status);
void device_channel_close(struct device_channel *channel);
#endif
