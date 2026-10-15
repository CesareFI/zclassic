/* purpose: Define supplied-identity authenticated device connection and status exchange. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_CONNECTION_H
#define ZCL_SERVICES_DEVICE_CONNECTION_H
#include "services/device_identity.h"
#include "platform/socket_compat.h"
#include "services/device_channel.h"

/* Connected nonblocking native sockets only. Neither function dials SSH,
 * executes commands, starts a daemon, or opens a canonical node datadir.
 * Network waits and partial traffic share an absolute monotonic deadline of
 * at most ten seconds. This does not bound filesystem operations or sampling.
 * Socket lifetime belongs to the caller; close it after any failure.
 * Server releases a sample only under a current status-read grant guard. */
struct zcl_result device_connection_probe(const struct device_identity *identity,
                                          const uint8_t peer[32],
                                          platform_socket_t socket,
                                          int64_t deadline_ns,
                                          struct device_disk_status *status);
struct zcl_result device_connection_respond(const struct device_identity *identity,
                                            platform_socket_t socket,
                                            int64_t deadline_ns,
                                            const char *root_path,
                                            const char *home_path);
#endif
