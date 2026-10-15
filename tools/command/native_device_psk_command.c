/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: mint one HOST hash-PSK secret file and its public fingerprint. */
#include "command/native_command.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "support/cleanse.h"
#include "sha3/sha3.h"
#include "base/hex.h"
#include "util/log_macros.h"
#include <string.h>

/* Domain label, then a NUL, then the 32 key bytes. 64 bits of a hash over
 * a 256-bit uniform key give out-of-band comparison and leak no key bits
 * an attacker could use; the label keeps it unrelated to any other digest. */
static const char psk_fingerprint_domain[] = "z23.device.host.psk.fingerprint.v1";

void zcl_native_device_psk_fingerprint(const uint8_t key[32], char out[17])
{
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const unsigned char *)psk_fingerprint_domain, sizeof(psk_fingerprint_domain));
    sha3_256_write(&hash, key, 32);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, 8, out);
    memory_cleanse(&hash, sizeof(hash));
}

static void psk_refuse(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
    const char *code, bool mutated, const char *message)
{
    LOG_ERROR("native.device.psk", "%s", message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code, "psk_new", false, mutated,
        message, "absent key path inside an existing owner-private (0700) directory");
}

enum psk_write { PSK_WRITTEN, PSK_EXISTS, PSK_IO, PSK_UNCERTAIN, PSK_UNSUPPORTED };

/* Test-only failure injection after the file exists: bit 0 fails the write,
 * bit 1 fails the cleanup unlink. */
static unsigned psk_fault_for_test;
#if defined(ZCL_TESTING)
void zcl_native_device_psk_fault_for_test(unsigned mask) { psk_fault_for_test = mask; }
#endif

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* Exclusive create beneath the validated parent: O_EXCL refuses any existing
 * entry, O_NOFOLLOW refuses a planted symlink, and the parent descriptor is
 * the one whose ownership and 0700 mode were proven. */
static enum psk_write psk_write_new(uintptr_t parent_handle, const char *leaf, const uint8_t key[32])
{
#if !defined(_WIN32)
    int parent = (int)parent_handle;
    int fd = openat(parent, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC, 0600);
    if (fd < 0) return errno == EEXIST || errno == ELOOP ? PSK_EXISTS : PSK_IO;
    bool ok = !(psk_fault_for_test & 1u) && write(fd, key, 32) == 32 && fchmod(fd, 0600) == 0 && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    ok = ok && fsync(parent) == 0;
    if (ok) return PSK_WRITTEN;
    /* The file exists: only a confirmed unlink may claim "no key left". */
    bool removed = !(psk_fault_for_test & 2u) && unlinkat(parent, leaf, 0) == 0;
    return removed ? PSK_IO : PSK_UNCERTAIN;
#else
    (void)parent_handle; (void)leaf; (void)key;
    return PSK_UNSUPPORTED;
#endif
}

/* Resolve the requested path to a validated owner-private parent handle and
 * the new leaf name inside it. Refuses with a named code on any failure. */
static bool psk_destination(const struct zcl_command_request *request, struct zcl_command_reply *reply,
    char resolved[1200], uintptr_t *directory, const char **leaf)
{
    const struct json_value *value = request->input ? json_get(request->input, "key") : NULL;
    const char *path = value && value->type == JSON_STR ? json_get_str(value) : NULL;
    char parent[1200];
    if (!path || !path[0] || !platform_private_destination_resolve(path, resolved, 1200, parent, sizeof(parent))) {
        psk_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "PSK_KEY_PATH_REFUSED", false,
            "key must name a new file in an existing directory");
        return false;
    }
    *leaf = strrchr(resolved, '/');
    if (!*leaf || !(*leaf)[1] || !strcmp(*leaf, "/.") || !strcmp(*leaf, "/..")) {
        psk_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "PSK_KEY_PATH_REFUSED", false, "key must name a file");
        return false;
    }
    ++*leaf;
    if (!platform_private_directory_open_validated(parent, directory)) {
        psk_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "PSK_KEY_PARENT_NOT_PRIVATE", false,
            "key parent must be an owner-private 0700 directory, not a symlink");
        return false;
    }
    return true;
}

static bool psk_written(struct zcl_command_reply *reply, enum psk_write written)
{
    if (written == PSK_EXISTS)
        psk_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "PSK_KEY_EXISTS", false,
            "key path already exists (or is a symlink); it is never overwritten");
    else if (written == PSK_UNSUPPORTED)
        psk_refuse(reply, ZCL_COMMAND_EXIT_BLOCKED, "PSK_UNSUPPORTED", false,
            "durable private key creation is unsupported on Windows");
    else if (written == PSK_UNCERTAIN)
        psk_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "PSK_KEY_CLEANUP_UNCERTAIN", true,
            "key file was created but could not be made durable or removed; inspect and delete it before retry");
    else if (written != PSK_WRITTEN)
        psk_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "PSK_KEY_IO", false,
            "entropy or durable write failed; no key file was left behind");
    return written == PSK_WRITTEN;
}

void zcl_native_handle_ops_mesh_device_psk_new(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    char resolved[1200];
    uintptr_t directory;
    const char *leaf = NULL;
    if (!psk_destination(request, reply, resolved, &directory, &leaf)) return;
    uint8_t key[32];
    char fingerprint[17] = {0};
    enum psk_write written = rng_host_fill(key, sizeof(key)) ? psk_write_new(directory, leaf, key) : PSK_IO;
    if (written == PSK_WRITTEN) zcl_native_device_psk_fingerprint(key, fingerprint);
    memory_cleanse(key, sizeof(key));
    platform_private_directory_close(directory);
    if (!psk_written(reply, written)) return;
    json_set_object(&reply->data);
    reply->error.mutated = true;
    if (!json_push_kv_str(&reply->data, "schema", "zcl.device.psk.new.v1") ||
        !json_push_kv_int(&reply->data, "bytes", 32) ||
        !json_push_kv_str(&reply->data, "psk_fingerprint", fingerprint) ||
        !json_push_kv_str(&reply->data, "secret_publication", "durable"))
        psk_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "PSK_REPLY_FAILED", true,
            "key file is durable but the reply could not be built; inspect before retry");
}
