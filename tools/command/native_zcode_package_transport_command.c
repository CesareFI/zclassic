/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Explicit local admission of a fetched signed package carrier. */
#include "command/native_zcode_transport_leaves.h"
#include "vcs/package_transport.h"

static bool zpa_put_receipt(struct json_value *data,
                            const struct vcs_package_transport_import *receipt,
                            const char *transport_hex, const char *package_hex,
                            const char *recipe_hex, const char *release_hex)
{
    return json_push_kv_str(data, "transport_root", transport_hex) &&
           json_push_kv_str(data, "package_root", package_hex) &&
           json_push_kv_str(data, "recipe_root", recipe_hex) &&
           json_push_kv_str(data, "release_id", release_hex) &&
           json_push_kv_int(data, "source_bytes",
                            (int64_t)receipt->source_bytes) &&
           json_push_kv_int(data, "source_chunks",
                            receipt->source_chunks) &&
           json_push_kv_int(data, "cas_objects_reused",
                            receipt->cas_objects_reused) &&
           json_push_kv_bool(data, "reconstructed", true);
}

static bool zpa_receipt_roots_match(const struct json_value *data,
                                    const char *transport_hex,
                                    const char *package_hex,
                                    const char *recipe_hex,
                                    const char *release_hex)
{
    const char *transport = json_get_str(json_get(data, "transport_root"));
    const char *package = json_get_str(json_get(data, "package_root"));
    const char *recipe = json_get_str(json_get(data, "recipe_root"));
    const char *release = json_get_str(json_get(data, "release_id"));
    return transport && strcmp(transport, transport_hex) == 0 &&
           package && strcmp(package, package_hex) == 0 &&
           recipe && strcmp(recipe, recipe_hex) == 0 &&
           release && strcmp(release, release_hex) == 0;
}

static bool zpa_receipt_counts_match(
    const struct json_value *data,
    const struct vcs_package_transport_import *receipt)
{
    const struct json_value *bytes = json_get(data, "source_bytes");
    const struct json_value *chunks = json_get(data, "source_chunks");
    const struct json_value *reused = json_get(data, "cas_objects_reused");
    const struct json_value *reconstructed = json_get(data, "reconstructed");
    return bytes && bytes->type == JSON_INT &&
           json_get_int(bytes) == (int64_t)receipt->source_bytes &&
           chunks && chunks->type == JSON_INT &&
           json_get_int(chunks) == receipt->source_chunks &&
           reused && reused->type == JSON_INT &&
           json_get_int(reused) == receipt->cas_objects_reused &&
           reconstructed && reconstructed->type == JSON_BOOL &&
           json_get_bool(reconstructed);
}

void zcl_native_handle_zcode_package_admit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!ztl_zcode_dir(request, reply, "zcode.package.admit", zcode_dir))
        return;
    uint8_t transport_root[32];
    if (!ztl_hex32(request, reply, "zcode.package.admit",
                   "transport_root", "BAD_TRANSPORT_ROOT",
                   "the exact signed carrier root already fetched by this node",
                   transport_root))
        return;

    bool own_store = false;
    struct vcs_package_store *store = ztl_open_store(
        request, &own_store, "zcode.package.admit");
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the receiver package store could not open",
                               zcode_dir);
        return;
    }
    if (strcmp(vcs_package_store_root_dir(store), zcode_dir) != 0) {
        ztl_close_store(store, own_store);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_DENIED,
                               "STORE_SCOPE_MISMATCH", "authorize",
                               false, false,
                               "the active store belongs to another datadir",
                               zcode_dir);
        return;
    }
    struct vcs_package_store_status status;
    bool tracked = vcs_package_store_package_status(
        store, transport_root, &status);
    if (!tracked || !status.complete) {
        ztl_close_store(store, own_store);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            tracked ? "INCOMPLETE_CARRIER" : "CARRIER_NOT_TRACKED",
            "verify", false, false,
            tracked ? "the signed carrier still lacks verified CAS chunks; "
                      "resume its fetch before admission"
                    : "no complete carrier is tracked at this exact root; "
                      "fetch it before admission",
            "zcode.package.admit");
        return;
    }

    struct vcs_package_transport_import receipt;
    enum vcs_package_transport_result result =
        vcs_package_transport_import(store, transport_root, &receipt);
    ztl_close_store(store, own_store);
    if (result != VCS_PACKAGE_TRANSPORT_OK) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "IMPORT_REFUSED",
                               "verify", false, true,
                               "carrier or signed inner package refused; "
                               "inner manifest or recipe may have been admitted; "
                               "no absence-of-conflict claim is made",
                               vcs_package_transport_result_string(result));
        return;
    }

    char transport_hex[65], package_hex[65], recipe_hex[65], release_hex[65];
    zcl_hex_encode(receipt.transport_root, 32, transport_hex);
    zcl_hex_encode(receipt.package_root, 32, package_hex);
    zcl_hex_encode(receipt.recipe_root, 32, recipe_hex);
    zcl_hex_encode(receipt.release_id, 32, release_hex);
    /* json_push_kv_str may return true even if copying its value became
     * JSON_NULL under allocation failure. A partial exact-root receipt must
     * never be reported as a successful admission. */
    bool represented = zpa_put_receipt(&reply->data, &receipt,
                                       transport_hex, package_hex,
                                       recipe_hex, release_hex);
    represented = represented && zpa_receipt_roots_match(
        &reply->data, transport_hex, package_hex, recipe_hex, release_hex);
    represented = represented && zpa_receipt_counts_match(&reply->data,
                                                           &receipt);
    if (!represented) {
        json_free(&reply->data);
        json_set_object(&reply->data);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "RECEIPT_UNAVAILABLE", "respond", false, true,
            "package admitted, but the exact receipt could not be encoded",
            transport_hex);
    }
}
