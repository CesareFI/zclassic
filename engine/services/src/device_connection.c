/* purpose: Exchange authenticated device status under current pairing guards and deadlines. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/device_connection.h"
#include "services/device_connection_io.h"
#include "platform/clock.h"
#include "platform/disk_space.h"
#include <string.h>

static const uint8_t device_magic[8] = {'Z','2','3','D','E','V',1,0};


static uint64_t wall_now(void)
{
    int64_t now = clock_now_wall_ms();
    return now > 0 ? (uint64_t)now / 1000 : 0;
}

static struct zcl_result channel_open(const struct device_identity *identity,
    const uint8_t peer[32], bool initiator, struct device_pairing_store *store,
    struct device_channel *channel)
{
    ZCL_CHECK(device_identity_pair_store(identity, peer, store));
    struct device_pairing_guard guard = {0};
    struct zcl_result result = device_pairing_guard_acquire(store, peer, wall_now(), &guard)
        ? device_channel_init(channel, initiator, store->profile,
                              identity->private_key, identity->public_key, peer)
        : ZCL_ERR(2, "device status-read pairing unavailable");
    device_pairing_guard_release(&guard);
    return result;
}

static struct zcl_result send_request(struct device_pairing_store *store,
    const uint8_t peer[32], struct device_channel *channel,
    platform_socket_t socket, int64_t deadline)
{
    struct device_pairing_guard guard = {0};
    uint8_t wire[NOISE_MAX_MESSAGE];
    size_t size = 0;
    struct zcl_result result = device_pairing_guard_acquire(store, peer, wall_now(), &guard)
        ? device_channel_request(channel, wire, &size)
        : ZCL_ERR(2, "device request pairing unavailable");
    if (result.ok)
        result = device_io_record_granted(socket, wire, &size, true, deadline,
                                         guard.row.paired_at, guard.row.expires_at);
    device_pairing_guard_release(&guard);
    return result;
}

static struct zcl_result receive_status(struct device_pairing_store *store,
    const uint8_t peer[32], struct device_channel *channel,
    platform_socket_t socket, int64_t deadline, struct device_disk_status *status)
{
    uint8_t wire[NOISE_MAX_MESSAGE];
    size_t size = 0;
    ZCL_CHECK(device_io_record(socket, wire, &size, false, deadline));
    struct device_pairing_guard guard = {0};
    struct zcl_result result = device_pairing_guard_acquire(store, peer, wall_now(), &guard)
        ? device_channel_accept_status(channel, wire, size, status)
        : ZCL_ERR(2, "device status pairing unavailable");
    if (result.ok) {
        uint64_t now = wall_now();
        if (now < guard.row.paired_at || now >= guard.row.expires_at)
            result = ZCL_ERR(2, "device status grant expired or not yet valid after decoding");
    }
    device_pairing_guard_release(&guard);
    if (!result.ok) memset(status, 0, sizeof(*status));
    return result;
}

struct zcl_result device_connection_probe(const struct device_identity *identity,
    const uint8_t peer[32], platform_socket_t socket, int64_t deadline_ns,
    struct device_disk_status *status)
{
    if (!identity || !peer || !status)
        return ZCL_ERR(1, "missing device probe argument");
    memset(status, 0, sizeof(*status));
    struct device_pairing_store store;
    struct device_channel channel = {0};
    ZCL_CHECK(channel_open(identity, peer, true, &store, &channel));
    uint8_t hello[40];
    memcpy(hello, device_magic, 8);
    memcpy(hello + 8, identity->public_key, 32);
    struct zcl_result result = ZCL_OK;
    if (!platform_socket_set_nonblocking(socket, true)) {
        int error = platform_socket_last_error();
        result = ZCL_ERR(error ? -error : -4, "cannot prepare device probe socket (error=%d)", error);
    }
    if (result.ok) result = device_io_transfer(socket, hello, sizeof(hello), true, deadline_ns);
    if (result.ok) result = device_io_handshake(socket, &channel, deadline_ns);
    if (result.ok) result = send_request(&store, peer, &channel, socket, deadline_ns);
    if (result.ok) result = receive_status(&store, peer, &channel, socket, deadline_ns, status);
    device_channel_close(&channel);
    return result;
}

static struct zcl_result respond_status(struct device_pairing_store *store,
    struct device_channel *channel, platform_socket_t socket,
    int64_t deadline, const char *root, const char *home)
{
    uint8_t wire[NOISE_MAX_MESSAGE];
    size_t size = 0;
    ZCL_CHECK(device_io_record(socket, wire, &size, false, deadline));
    ZCL_CHECK(device_channel_accept_request(channel, wire, size));
    struct device_disk_status status = {.sampled_at = wall_now()};
    if (!platform_disk_space(root, &status.root_available, &status.root_total) ||
        !platform_disk_space(home, &status.home_available, &status.home_total))
        return ZCL_ERR(4, "cannot observe device response disk space");
    struct device_pairing_guard guard = {0};
    struct zcl_result result = device_pairing_guard_acquire(store, channel->peer, wall_now(), &guard)
        ? device_channel_respond(channel, &status, wire, &size)
        : ZCL_ERR(2, "device response pairing unavailable");
    if (result.ok)
        result = device_io_record_granted(socket, wire, &size, true, deadline,
                                         guard.row.paired_at, guard.row.expires_at);
    device_pairing_guard_release(&guard);
    return result;
}

struct zcl_result device_connection_respond(const struct device_identity *identity,
    platform_socket_t socket, int64_t deadline_ns,
    const char *root_path, const char *home_path)
{
    if (!identity || !root_path || !home_path)
        return ZCL_ERR(1, "missing device responder argument");
    if (!platform_socket_set_nonblocking(socket, true)) {
        int error = platform_socket_last_error();
        return ZCL_ERR(error ? -error : -4, "cannot prepare device responder socket (error=%d)", error);
    }
    uint8_t hello[40];
    ZCL_CHECK(device_io_transfer(socket, hello, sizeof(hello), false, deadline_ns));
    if (memcmp(hello, device_magic, 8))
        return ZCL_ERR(3, "invalid device preamble");
    struct device_pairing_store store;
    struct device_channel channel = {0};
    ZCL_CHECK(channel_open(identity, hello + 8, false, &store, &channel));
    struct zcl_result result = device_io_handshake(socket, &channel, deadline_ns);
    if (result.ok) result = respond_status(&store, &channel, socket, deadline_ns, root_path, home_path);
    device_channel_close(&channel);
    return result;
}
