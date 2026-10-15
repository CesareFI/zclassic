/* purpose: Perform bounded framed socket transfers with post-readiness authority interval checks. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/device_connection_io.h"
#include "platform/clock.h"
#include "util/log_macros.h"

static int remaining_ms(int64_t deadline, uint64_t paired_at, uint64_t expires_at)
{
    int64_t now = clock_now_monotonic_ns();
    if (now < 0 || deadline <= now) return 0;
    int64_t left = deadline - now;
    if (left > INT64_C(10000000000)) return 0;
    if (paired_at || expires_at) {
        int64_t wall = clock_now_wall_ms();
        if (!paired_at || expires_at <= paired_at || wall <= 0 ||
            expires_at > (uint64_t)INT64_MAX / 1000 ||
            (uint64_t)wall < paired_at * 1000 ||
            expires_at * 1000 <= (uint64_t)wall) return 0;
        uint64_t wall_left = expires_at * 1000 - (uint64_t)wall;
        if (wall_left <= 10000 && left > (int64_t)wall_left * 1000000)
            left = (int64_t)wall_left * 1000000;
    }
    return (int)((left + 999999) / 1000000);
}

static bool retry_socket_io(int count, int error)
{
    return count < 0 && (platform_socket_error_would_block(error) ||
                         platform_socket_error_interrupted(error));
}

static struct zcl_result wait_for_transfer(platform_socket_t socket,
    bool writing, int64_t deadline, uint64_t paired_at, uint64_t expires_at)
{
    for (;;) {
        int timeout = remaining_ms(deadline, paired_at, expires_at);
        if (!timeout) return ZCL_ERR(-2, "connection deadline or grant interval expired or invalid");
        int ready = writing ? platform_socket_wait_writable(socket, timeout) :
                              platform_socket_wait_readable(socket, timeout);
        int error = platform_socket_last_error();
        if (ready < 0) {
            if (platform_socket_error_interrupted(error)) continue;
            return ZCL_ERR(error ? -error : -4, "device socket readiness wait failed (error=%d)", error);
        }
        if (!ready) return ZCL_ERR(-2, "device socket readiness deadline expired");
        if (!remaining_ms(deadline, paired_at, expires_at))
            return ZCL_ERR(-2, "connection deadline or grant interval expired after readiness");
        return ZCL_OK;
    }
}

static struct zcl_result transfer_until(platform_socket_t socket, uint8_t *bytes, size_t size,
    bool writing, int64_t deadline, uint64_t paired_at, uint64_t expires_at)
{
    if (!bytes || size > NOISE_MAX_MESSAGE)
        return ZCL_ERR(-1, "invalid bounded device transfer");
    size_t done = 0;
    while (done < size) {
        ZCL_CHECK(wait_for_transfer(socket, writing, deadline, paired_at, expires_at));
        int n = writing ? platform_socket_send(socket, bytes + done, size - done) :
                          platform_socket_receive(socket, bytes + done, size - done);
        int error = platform_socket_last_error();
        if (retry_socket_io(n, error)) continue;
        if (n < 0) return ZCL_ERR(error ? -error : -4, "device socket transfer failed (error=%d)", error);
        if (!n) return ZCL_ERR(-3, "device peer closed during bounded transfer");
        if (!remaining_ms(deadline, paired_at, expires_at))
            return ZCL_ERR(-2, "connection deadline or grant interval expired after transfer");
        done += (size_t)n;
    }
    return ZCL_OK;
}

struct zcl_result device_io_transfer(platform_socket_t socket, uint8_t *bytes, size_t size,
    bool writing, int64_t deadline_ns)
{
    return transfer_until(socket, bytes, size, writing, deadline_ns, 0, 0);
}

struct zcl_result device_io_record_granted(platform_socket_t socket,
    uint8_t wire[NOISE_MAX_MESSAGE], size_t *size, bool writing, int64_t deadline_ns,
    uint64_t paired_at, uint64_t expires_at)
{
    if (!wire || !size || (writing && (!*size || *size > NOISE_MAX_MESSAGE)))
        return ZCL_ERR(-1, "invalid framed device record");
    uint8_t prefix[2] = {0};
    if (writing) {
        prefix[0] = (uint8_t)(*size >> 8);
        prefix[1] = (uint8_t)*size;
    }
    ZCL_CHECK(transfer_until(socket, prefix, sizeof(prefix), writing, deadline_ns,
                            paired_at, expires_at));
    if (!writing) *size = ((size_t)prefix[0] << 8) | prefix[1];
    if (!*size || *size > NOISE_MAX_MESSAGE)
        return ZCL_ERR(-1, "device record exceeds protocol bound");
    return transfer_until(socket, wire, *size, writing, deadline_ns, paired_at, expires_at);
}

struct zcl_result device_io_record(platform_socket_t socket, uint8_t wire[NOISE_MAX_MESSAGE],
    size_t *size, bool writing, int64_t deadline_ns)
{
    return device_io_record_granted(socket, wire, size, writing, deadline_ns, 0, 0);
}

static struct zcl_result handshake_message(platform_socket_t socket,
    struct device_channel *channel, bool writing, int64_t deadline_ns)
{
    uint8_t wire[NOISE_MAX_MESSAGE];
    size_t size = 0;
    if (writing) {
        ZCL_CHECK(device_channel_handshake_write(channel, wire, &size));
        return device_io_record(socket, wire, &size, true, deadline_ns);
    }
    ZCL_CHECK(device_io_record(socket, wire, &size, false, deadline_ns));
    return device_channel_handshake_read(channel, wire, size);
}

struct zcl_result device_io_handshake(platform_socket_t socket, struct device_channel *channel,
    int64_t deadline_ns)
{
    if (!channel) return ZCL_ERR(-1, "missing device handshake channel");
    if (!platform_socket_set_nonblocking(socket, true)) {
        int error = platform_socket_last_error();
        return ZCL_ERR(error ? -error : -4, "cannot prepare nonblocking device handshake (error=%d)", error);
    }
    for (unsigned step = 0; step < 3; ++step) {
        bool writing = channel->initiator == (step != 1);
        struct zcl_result result = handshake_message(socket, channel, writing, deadline_ns);
        if (!result.ok) {
            device_channel_close(channel);
            LOG_ERROR("device_io", "hybrid handshake failed at message %u: %s", step + 1, result.message);
            return result;
        }
    }
    return ZCL_OK;
}
