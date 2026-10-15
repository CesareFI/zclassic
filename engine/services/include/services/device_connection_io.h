/* purpose: Define bounded framed socket IO under pairing interval and deadline checks. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_CONNECTION_IO_H
#define ZCL_SERVICES_DEVICE_CONNECTION_IO_H
#include "base/result.h"
#include "platform/socket_compat.h"
#include "services/device_channel.h"
/* Caller supplies a connected nonblocking socket and independent buffers.
 * One absolute monotonic deadline bounds all partial reads and writes.
 * Failures retain the original contextual result through framing/handshake:
 * invalid geometry, deadline/grant interval, peer EOF, or a saved socket
 * error. Socket error codes are negative; success is canonical code zero. */
struct zcl_result device_io_transfer(platform_socket_t socket, uint8_t *bytes, size_t size,
                         bool writing, int64_t deadline_ns);
struct zcl_result device_io_handshake(platform_socket_t socket, struct device_channel *channel,
                          int64_t deadline_ns);
struct zcl_result device_io_record(platform_socket_t socket, uint8_t wire[NOISE_MAX_MESSAGE],
                       size_t *size, bool writing, int64_t deadline_ns);
/* Zero/zero is unguarded traffic. A guarded interval requires nonzero
 * paired_at < expires_at; every readiness and partial-transfer boundary
 * rechecks that the current wall clock remains within that interval. */
struct zcl_result device_io_record_granted(platform_socket_t socket,
                               uint8_t wire[NOISE_MAX_MESSAGE], size_t *size,
                               bool writing, int64_t deadline_ns,
                               uint64_t paired_at, uint64_t expires_at);
#endif
