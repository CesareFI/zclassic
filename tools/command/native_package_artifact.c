/* purpose: Read bounded canonical package wire artifacts through retained digest-bound descriptors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "command/native_package_artifact.h"
#include "base/hex.h"
#include "platform/private_file.h"
#include "platform/positioned_file.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>

void zcl_native_package_artifact_digest(uint8_t digest[32], const uint8_t *bytes, size_t length)
{
    struct sha3_256_ctx context; sha3_256_init(&context);
    sha3_256_write(&context, bytes, length); sha3_256_finalize(&context, digest);
}

static const char *artifact_string(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}
bool zcl_native_package_artifact_absolute(const char *path, char *absolute, size_t capacity)
{
    char parent[4096];
    return path && platform_private_destination_resolve(path, absolute, capacity, parent, sizeof(parent));
}
static bool artifact_scalar_equal(const struct json_value *a, const struct json_value *b)
{
    if (a->type != b->type) return false;
    switch (a->type) {
    case JSON_STR: return a->val.s && b->val.s && strcmp(a->val.s, b->val.s) == 0;
    case JSON_INT: return a->val.i == b->val.i;
    case JSON_BOOL: return a->val.b == b->val.b;
    default: return false;
    }
}
bool zcl_native_package_artifact_fields_equal(const struct json_value *a, const struct json_value *b)
{
    if (!a || !b || a->type != JSON_OBJ || b->type != JSON_OBJ || a->num_children != b->num_children) return false;
    for (size_t i = 0; i < a->num_children; ++i) {
        if (!a->keys[i] || !b->keys[i] || strcmp(a->keys[i], b->keys[i]) ||
            !artifact_scalar_equal(&a->children[i], &b->children[i])) return false;
    }
    return true;
}
bool zcl_native_package_artifact_paths_absolute(const struct json_value *input)
{
    static const char *const keys[] = {"manifest_file", "recipe_file"}; char absolute[4096];
    for (size_t i = 0; i < 2; ++i) {
        if (!json_get(input, keys[i])) continue;
        const char *path = artifact_string(input, keys[i]);
        if (!zcl_native_package_artifact_absolute(path, absolute, sizeof(absolute)) || strcmp(path, absolute)) return false;
    }
    return true;
}
static bool artifact_hex(const char *hex, size_t maximum, uint8_t **bytes, size_t *length)
{
    size_t count = hex ? strlen(hex) : 0;
    if (!count || (count & 1u) || count / 2 > maximum) return false;
    uint8_t *copy = zcl_malloc(count / 2, "package.artifact.hex");
    if (!copy || !zcl_hex_decode_lower(hex, copy, count / 2)) { free(copy); return false; }
    *bytes = copy; *length = count / 2; return true;
}
static bool artifact_copy(const struct platform_positioned_file *file, uint8_t *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        int64_t count = platform_positioned_file_read(file, bytes + offset, length - offset, offset);
        if (count <= 0 || (uint64_t)count > length - offset) return false;
        offset += (size_t)count;
    }
    uint8_t extra;
    return platform_positioned_file_read(file, &extra, 1, length) == 0;
}
static bool artifact_pinned(const struct platform_positioned_file *file, const uint8_t expected[32],
    size_t maximum, uint8_t **bytes, size_t *length)
{
    struct platform_positioned_file_snapshot before, after; uint8_t actual[32];
    if (!platform_positioned_file_snapshot(file, &before) || !before.size ||
        before.size > maximum || before.size > SIZE_MAX) return false;
    uint8_t *copy = zcl_malloc((size_t)before.size, "package.artifact.file");
    if (!copy) return false;
    bool ok = artifact_copy(file, copy, (size_t)before.size) &&
        platform_positioned_file_snapshot(file, &after) && platform_positioned_file_snapshot_equal(&before, &after);
    if (ok) { zcl_native_package_artifact_digest(actual, copy, (size_t)before.size); ok = memcmp(actual, expected, 32) == 0; }
    if (!ok) { free(copy); return false; }
    *bytes = copy; *length = (size_t)before.size; return true;
}
static bool artifact_file(const char *path, const char *digest, size_t maximum,
    uint8_t **bytes, size_t *length)
{
    uint8_t expected[32]; char absolute[4096], parent[4096];
    if (!digest || !zcl_hex_decode_lower(digest, expected, 32) || !path ||
        !platform_private_destination_resolve(path, absolute, sizeof(absolute), parent, sizeof(parent))) return false;
    const char *leaf = strrchr(absolute, '/');
    if (!leaf || !leaf[1]) return false;
    struct platform_positioned_file file; platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open_beneath(&file, parent, leaf + 1) &&
        artifact_pinned(&file, expected, maximum, bytes, length);
    platform_positioned_file_close(&file); return ok;
}
bool zcl_native_package_artifact_read(const struct json_value *input,
    const char *hex_key, const char *file_key, const char *digest_key,
    size_t maximum, uint8_t **bytes, size_t *length)
{
    if (!bytes || !length) return false;
    *bytes = NULL; *length = 0;
    if (!input || !maximum) return false;
    bool has_hex = json_get(input, hex_key) != NULL;
    bool has_file = json_get(input, file_key) != NULL, has_digest = json_get(input, digest_key) != NULL;
    if (has_hex) return !has_file && !has_digest && artifact_hex(artifact_string(input, hex_key), maximum, bytes, length);
    return has_file && has_digest && artifact_file(artifact_string(input, file_key),
        artifact_string(input, digest_key), maximum, bytes, length);
}
