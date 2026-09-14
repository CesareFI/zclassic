/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: explicitly execute one exact installed resident app invocation. */
#include "command/native_command.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "services/package_resident.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static uint64_t npr_now(void)
{
    int64_t now = platform_time_monotonic_us();
    return now > 0 ? (uint64_t)now : 0;
}

static const char *npr_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static void npr_fail(struct zcl_command_reply *reply, const char *message)
{
    LOG_ERROR("app.invoke.package", "%s", message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, "RESIDENT_APP_REFUSED", "execute",
        false, false, message, "app.invoke.package");
}

static bool npr_input(const struct zcl_command_request *request,
    uint8_t root[32], uint8_t receipt[32], const char **datadir,
    const char **program, const char **digest, const char **text)
{
    const struct json_value *input = request ? request->input : NULL;
    const struct json_value *grant = input ? json_get(input, "accept_execution") : NULL;
    *datadir = npr_str(input, "datadir");
    *program = npr_str(input, "program");
    *digest = npr_str(input, "artifact_sha3");
    *text = npr_str(input, "input_text");
    const char *package_hex = npr_str(input, "package_root");
    const char *receipt_hex = npr_str(input, "receipt_id");
    uint8_t hash[32];
    return grant && grant->type == JSON_BOOL && json_get_bool(grant) &&
        *datadir && **datadir && *program && *digest && *text &&
        strlen(*text) <= 1024 && package_hex && receipt_hex &&
        zcl_hex_decode_lower(package_hex, root, 32) &&
        zcl_hex_decode_lower(receipt_hex, receipt, 32) &&
        zcl_hex_decode_lower(*digest, hash, 32);
}

static struct zcl_result npr_exchange(struct package_resident *app,
    const char *input, char output[4097])
{
#if defined(_WIN32)
    (void)app; (void)input; (void)output;
    return ZCL_ERR(-1, "resident app execution is unavailable on Windows");
#else
    struct resident_result_header header;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    int fd = (int)app->launch.ipc_native;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return ZCL_ERR(-1, "resident IPC nonblocking setup failed");
    if (!resident_result_read(&app->launch, &header, output, 4096, 2000, error, sizeof(error)) ||
        header.payload_len != 5 || memcmp(output, "READY", 5) != 0)
        return ZCL_ERR(-1, "resident READY refused: %s", error);
    struct { struct resident_result_header header; char text[1024]; } frame = {0};
    memcpy(frame.header.magic, "z23-res-run-v1", sizeof("z23-res-run-v1"));
    memcpy(frame.header.nonce, app->launch.nonce, sizeof(frame.header.nonce));
    frame.header.payload_len = (uint32_t)strlen(input);
    memcpy(frame.text, input, frame.header.payload_len);
    size_t bytes = sizeof(frame.header) + frame.header.payload_len;
    ssize_t sent = send(fd, &frame, bytes, MSG_NOSIGNAL);
    if (sent < 0 || (size_t)sent != bytes)
        return ZCL_ERR(-1, "resident input incomplete: candidate cancelled");
    if (!resident_result_read(&app->launch, &header, output, 4096, 2000, error, sizeof(error)))
        return ZCL_ERR(-1, "resident result refused: %s", error);
    for (uint32_t i = 0; i < header.payload_len; ++i) {
        unsigned char c = (unsigned char)output[i];
        if ((c < 32 && c != '\n' && c != '\t') || c > 126)
            return ZCL_ERR(-1, "resident result is not bounded display text");
    }
    output[header.payload_len] = 0;
    return ZCL_OK;
#endif
}

void zcl_native_handle_package_resident(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    uint64_t began = npr_now();
    uint8_t root[32], receipt_id[32];
    const char *datadir, *program, *digest, *input;
    if (!npr_input(request, root, receipt_id, &datadir, &program, &digest, &input)) {
        npr_fail(reply, "explicit execution acceptance requires exact package, receipt, artifact digest, program, input_text and datadir");
        return;
    }
    struct package_resident *app =
        zcl_calloc(1, sizeof(*app), "resident app owner");
    if (!app) { npr_fail(reply, "resident app allocation failed"); return; }
    package_resident_init(app);
    struct zcl_result result = package_resident_artifact_read(
        datadir, root, receipt_id, program, &app->artifact);
    if (result.ok && strcmp(app->artifact.accepted.image_sha3_hex, digest) != 0)
        result = ZCL_ERR(-1, "explicitly accepted artifact digest differs from installed receipt");
    uint64_t verified = npr_now();
    if (result.ok) result = package_resident_prepare(app, &app->artifact);
    if (result.ok) result = package_resident_start(app);
    char output[4097] = {0};
    if (result.ok) result = npr_exchange(app, input, output);
    uint64_t observed = npr_now();
    struct zcl_result closed = package_resident_close(app);
    if (!closed.ok) result = closed;
    if (result.ok) {
        json_set_object(&reply->data);
        bool rendered = json_push_kv_str(&reply->data, "artifact_sha3", digest) &&
            json_push_kv_str(&reply->data, "program", program) &&
            json_push_kv_str(&reply->data, "result", output) &&
            json_push_kv_str(&reply->data, "mapped_proof", app->receipt.mapped_proof) &&
            json_push_kv_str(&reply->data, "nonce", app->receipt.nonce) &&
            json_push_kv_int(&reply->data, "pid", (int64_t)app->receipt.pid) &&
            json_push_kv_int(&reply->data, "start_token", (int64_t)app->receipt.start_token) &&
            json_push_kv_int(&reply->data, "verification_us", (int64_t)(verified - began)) &&
            json_push_kv_int(&reply->data, "first_result_us", (int64_t)(observed - began)) &&
            json_push_kv_int(&reply->data, "completed_us", (int64_t)(npr_now() - began)) &&
            json_push_kv_bool(&reply->data, "child_reaped", true) &&
            json_push_kv_str(&reply->data, "next_action", "inspect result; explicitly invoke an accepted prior version to roll back");
        if (!rendered) result = ZCL_ERR(-1, "resident result allocation failed");
    }
    free(app);
    if (!result.ok) npr_fail(reply, result.message);
}
