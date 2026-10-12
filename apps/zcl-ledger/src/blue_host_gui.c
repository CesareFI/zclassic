/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_host_gui.h"

#include "blue_bagl_canvas.h"
#include "blue_install_params.h"
#include "blue_payment_fixture.h"
#include "blue_payment_screen.h"
#include "blue_payment_simulate.h"
#include "blue_wallet_protocol.h"
#include "zcl_address.h"
#include "zcl_tx_prevout.h"
#include "zcl_zip243_host.h"
#include "zripemd/zripemd.h"
#include "zsha256/zsha256.h"

#include <stdio.h>
#include <string.h>

static bool copy_text(char *dest, size_t size, const char *source) {
    if (!dest || !source || !source[0]) return false;
    size_t length = strlen(source);
    if (length >= size) return false;
    memcpy(dest, source, length + 1);
    return true;
}

static bool same_text(const char *left, const char *right) {
    return left && right && left[0] && strcmp(left, right) == 0;
}

bool blue_host_gui_facts_set(blue_host_gui_facts *facts,
    const char *connection, const char *app_name, const char *app_version,
    const char *receive, const char *recipient, const char *amount,
    const char *fee, const char *network, const char *memo,
    const char *approval, const uint8_t digest[BLUE_HOST_GUI_DIGEST_SIZE]) {
    if (!facts || !digest) return false;
    blue_host_gui_facts filled;
    memset(&filled, 0, sizeof filled);
    bool ok = copy_text(filled.connection, sizeof filled.connection,
                        connection) &&
        copy_text(filled.app_name, sizeof filled.app_name, app_name) &&
        copy_text(filled.app_version, sizeof filled.app_version,
                  app_version) &&
        copy_text(filled.receive, sizeof filled.receive, receive) &&
        copy_text(filled.recipient, sizeof filled.recipient, recipient) &&
        copy_text(filled.amount, sizeof filled.amount, amount) &&
        copy_text(filled.fee, sizeof filled.fee, fee) &&
        copy_text(filled.network, sizeof filled.network, network) &&
        copy_text(filled.memo, sizeof filled.memo, memo) &&
        copy_text(filled.approval, sizeof filled.approval, approval);
    if (!ok) return false;
    memcpy(filled.digest, digest, sizeof filled.digest);
    *facts = filled;
    return true;
}

static bool hash_sha256(const uint8_t *bytes, size_t length,
                        uint8_t digest[32]) {
    if ((!bytes && length) || !digest) return false;
    zsha256(bytes, length, digest);
    return true;
}

/* Public test vector used by the host simulator's secp256k1 stub.
 * It is not a device seed and it is not a valid curve point. */
static bool simulator_receive_hash(uint8_t hash160[20]) {
    uint8_t compressed[33], sha[32];
    compressed[0] = 0x02;
    memset(compressed + 1, 0x11, 32);
    zsha256(compressed, sizeof compressed, sha);
    zripemd160(sha, sizeof sha, hash160);
    return true;
}

static void format_branch(char text[BLUE_HOST_GUI_NETWORK_SIZE],
                          uint32_t branch) {
    static const char hex[] = "0123456789ABCDEF";
    memcpy(text, "BRANCH 0x", 9);
    for (unsigned i = 0; i < 8; ++i)
        text[9 + i] = hex[(branch >> (28u - 4u * i)) & 15u];
    text[17] = 0;
}

static bool transparent_suffix(const uint8_t *wire, size_t length) {
    if (!wire || length < 11) return false;
    for (size_t i = length - 11; i < length; ++i)
        if (wire[i] != 0) return false;
    return true;
}

static bool version_text(char text[BLUE_HOST_GUI_VERSION_SIZE]) {
    int wrote = snprintf(text, BLUE_HOST_GUI_VERSION_SIZE, "%u",
                         BLUE_WALLET_PROTOCOL_VERSION);
    return wrote > 0 && (size_t)wrote < BLUE_HOST_GUI_VERSION_SIZE;
}

bool blue_host_gui_load_representative(blue_host_gui_facts *facts) {
    if (!facts) return false;
    uint8_t hash160[20];
    blue_payment_fixture fixture;
    if (!simulator_receive_hash(hash160) ||
        !blue_payment_fixture_make(hash160, &fixture) ||
        !transparent_suffix(fixture.unsigned_wire, fixture.unsigned_length))
        return false;
    blue_payment_screen screens[BLUE_PAYMENT_REVIEW_MAX_OUTPUTS];
    uint32_t screen_count = 0;
    zcl_tx_previous_transaction previous = {
        .wire = fixture.previous, .length = fixture.previous_length};
    struct blake2b_ctx blake;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&blake);
    zcl_tx_transparent_facts parsed;
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    char receive[ZCL_ADDRESS_SIZE], version[BLUE_HOST_GUI_VERSION_SIZE];
    char network[BLUE_HOST_GUI_NETWORK_SIZE], fee[BLUE_HOST_GUI_AMOUNT_SIZE];
    if (!blue_payment_simulate(fixture.unsigned_wire,
            fixture.unsigned_length, BLUE_PAYMENT_FIXTURE_BRANCH,
            screens, &screen_count) || screen_count != 2 ||
        zcl_tx_transparent_bound_digests(fixture.unsigned_wire,
            fixture.unsigned_length, &previous, 1,
            BLUE_PAYMENT_FIXTURE_BRANCH, hash_sha256, &hasher,
            &parsed, digests, ZCL_TX_PREFLIGHT_MAX_INPUTS) != 0 ||
        parsed.transparent_outputs != 2 || parsed.fee_zat != 100000000 ||
        zcl_address_from_hash160(hash160, false, receive) < 0 ||
        strcmp(receive, screens[0].address) != 0 ||
        !version_text(version) ||
        !blue_payment_amount_text(parsed.fee_zat, fee))
        return false;
    format_branch(network, BLUE_PAYMENT_FIXTURE_BRANCH);
    return blue_host_gui_facts_set(facts, "Blue linked", "ZCL Wallet",
        version, receive, screens[1].address, screens[1].amount, fee,
        network, "NO MEMO", "SIGN ZCL", digests[0]);
}

static blue_host_gui_bind_status compare_field(
    blue_host_gui_bind_status id, const char *gui, const char *screen) {
    return same_text(gui, screen) ? BLUE_HOST_GUI_BIND_MATCH : id;
}

blue_host_gui_bind_status blue_host_gui_bind(
    const blue_host_gui_facts *gui, const blue_host_gui_facts *screen,
    const uint8_t *signed_bytes, size_t signed_length) {
    if (!gui || !screen) return BLUE_HOST_GUI_BIND_CONNECTION;
    blue_host_gui_bind_status fields[] = {
        compare_field(BLUE_HOST_GUI_BIND_CONNECTION, gui->connection,
                      screen->connection),
        compare_field(BLUE_HOST_GUI_BIND_APP_NAME, gui->app_name,
                      screen->app_name),
        compare_field(BLUE_HOST_GUI_BIND_APP_VERSION, gui->app_version,
                      screen->app_version),
        compare_field(BLUE_HOST_GUI_BIND_RECEIVE, gui->receive,
                      screen->receive),
        compare_field(BLUE_HOST_GUI_BIND_RECIPIENT, gui->recipient,
                      screen->recipient),
        compare_field(BLUE_HOST_GUI_BIND_AMOUNT, gui->amount, screen->amount),
        compare_field(BLUE_HOST_GUI_BIND_FEE, gui->fee, screen->fee),
        compare_field(BLUE_HOST_GUI_BIND_NETWORK, gui->network,
                      screen->network),
        compare_field(BLUE_HOST_GUI_BIND_MEMO, gui->memo, screen->memo),
        compare_field(BLUE_HOST_GUI_BIND_APPROVAL, gui->approval,
                      screen->approval)
    };
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; ++i)
        if (fields[i] != BLUE_HOST_GUI_BIND_MATCH) return fields[i];
    if (!signed_bytes || signed_length != BLUE_HOST_GUI_DIGEST_SIZE ||
        memcmp(gui->digest, signed_bytes, BLUE_HOST_GUI_DIGEST_SIZE) != 0 ||
        memcmp(screen->digest, signed_bytes, BLUE_HOST_GUI_DIGEST_SIZE) != 0)
        return BLUE_HOST_GUI_BIND_DIGEST;
    return BLUE_HOST_GUI_BIND_MATCH;
}

static void wipe(uint8_t *out, size_t capacity, size_t *out_length) {
    if (out && capacity) memset(out, 0, capacity);
    if (out_length) *out_length = 0;
}

bool blue_host_gui_release_signature(
    const blue_host_gui_facts *gui, const blue_host_gui_facts *screen,
    const uint8_t *signed_bytes, size_t signed_length, int authority,
    const uint8_t *device_signature, size_t device_signature_length,
    uint8_t *out, size_t out_capacity, size_t *out_length) {
    wipe(out, out_capacity, out_length);
    if (authority != BLUE_HOST_GUI_AUTHORITY_SIGN || !out || !out_length ||
        !device_signature || !device_signature_length ||
        device_signature_length > out_capacity ||
        blue_host_gui_bind(gui, screen, signed_bytes, signed_length) !=
            BLUE_HOST_GUI_BIND_MATCH)
        return false;
    memcpy(out, device_signature, device_signature_length);
    *out_length = device_signature_length;
    return true;
}

bool blue_host_gui_permit_install(int authority, const char *name,
                                  const char *version) {
    if (authority != BLUE_HOST_GUI_AUTHORITY_INSTALL) return false;
    return blue_install_image_allowed(name, version);
}

static bool draw_line(blue_bagl_canvas *image, const char *text, int x,
                      int y, int width, uint32_t foreground,
                      uint32_t background, blue_bagl_font font) {
    return blue_bagl_text(image, text, x, y, width, false, foreground,
                          background, font);
}

static bool draw_heading(blue_bagl_canvas *image, const char *label,
                         int *y, int step, uint32_t foreground,
                         uint32_t background, blue_bagl_font font) {
    if (!label || *y > 480 - step ||
        !draw_line(image, label, 16, *y, 288, foreground, background, font))
        return false;
    *y += step;
    return true;
}

static bool draw_address(blue_bagl_canvas *image, const char *address,
                         int *y, int step, uint32_t foreground,
                         uint32_t background, blue_bagl_font font) {
    if (!address || strlen(address) != 35) return false;
    char line[13];
    const size_t spans[] = {12, 12, 11};
    size_t offset = 0;
    for (size_t i = 0; i < 3; ++i) {
        memcpy(line, address + offset, spans[i]);
        line[spans[i]] = 0;
        offset += spans[i];
        if (*y > 480 - step ||
            !draw_line(image, line, 16, *y, 288, foreground, background,
                       font))
            return false;
        *y += step;
    }
    return true;
}

static bool draw_pair(blue_bagl_canvas *image, const char *label,
                      const char *value, int *y, int step,
                      uint32_t foreground, uint32_t background,
                      blue_bagl_font font) {
    char combined[96];
    if (!label || !value || *y > 480 - step) return false;
    int wrote = snprintf(combined, sizeof combined, "%s  %s", label, value);
    if (wrote > 0 && (size_t)wrote < sizeof combined &&
        draw_line(image, combined, 16, *y, 288, foreground, background,
                  font)) {
        *y += step;
        return true;
    }
    if (!draw_line(image, label, 16, *y, 288, foreground, background, font))
        return false;
    *y += step;
    if (*y > 480 - step ||
        !draw_line(image, value, 16, *y, 288, foreground, background, font))
        return false;
    *y += step;
    return true;
}

static bool facts_ready(const blue_host_gui_facts *facts) {
    return facts && facts->connection[0] && facts->app_name[0] &&
           facts->app_version[0] && facts->receive[0] &&
           facts->recipient[0] && facts->amount[0] && facts->fee[0] &&
           facts->network[0] && facts->memo[0] && facts->approval[0];
}

static void screen_colors(bool dark, uint32_t *body, uint32_t *text,
                          uint32_t *accent) {
    *body = dark ? 0x12161c : 0xf4f1ea;
    *text = dark ? 0xf4f7f5 : 0x1c2430;
    *accent = dark ? 0x41ccb4 : 0x0e6b4f;
}

static bool draw_identity(blue_bagl_canvas *image, const blue_host_gui_facts *facts,
                          int *y, int step, uint32_t text, uint32_t body,
                          blue_bagl_font font) {
    return draw_pair(image, "Link", facts->connection, y, step, text, body,
                     font) &&
           draw_pair(image, "App", facts->app_name, y, step, text, body,
                     font) &&
           draw_pair(image, "Identity", facts->app_version, y, step, text,
                     body, font);
}

static bool draw_payment(blue_bagl_canvas *image, const blue_host_gui_facts *facts,
                         int *y, int step, uint32_t text, uint32_t body,
                         uint32_t accent, blue_bagl_font font) {
    return draw_heading(image, "Receive", y, step, accent, body, font) &&
           draw_address(image, facts->receive, y, step, text, body, font) &&
           draw_heading(image, "Recipient", y, step, accent, body, font) &&
           draw_address(image, facts->recipient, y, step, text, body, font) &&
           draw_heading(image, "Amount", y, step, accent, body, font) &&
           draw_heading(image, facts->amount, y, step, text, body, font) &&
           draw_pair(image, "Fee", facts->fee, y, step, text, body, font) &&
           draw_pair(image, "Network", facts->network, y, step, text, body,
                     font) &&
           draw_pair(image, "Memo", facts->memo, y, step, text, body, font) &&
           draw_pair(image, "Approval", facts->approval, y, step, text, body,
                     font);
}

bool blue_host_gui_render_png(const char *path,
    const blue_host_gui_facts *facts, bool dark, bool large_text) {
    if (!path || !facts_ready(facts)) return false;
    uint32_t body, text, accent;
    screen_colors(dark, &body, &text, &accent);
    blue_bagl_font font = large_text ? BLUE_BAGL_TEXT_22 : BLUE_BAGL_TEXT_14;
    int step = blue_bagl_font_height(font) + (large_text ? 2 : 6);
    blue_bagl_canvas *image = blue_bagl_canvas_create(body);
    if (!image) return false;
    blue_bagl_rectangle(image, 0, 0, 320, 36, accent);
    int y = 40;
    bool drawn = draw_line(image, "Z23 laptop", 16, 8, 288, body, accent,
                           BLUE_BAGL_TEXT_14) &&
                 draw_identity(image, facts, &y, step, text, body, font) &&
                 draw_payment(image, facts, &y, step, text, body, accent,
                              font);
    bool wrote = drawn && blue_bagl_write_png(image, path);
    blue_bagl_canvas_destroy(image);
    return wrote;
}

static void digest_hex(const uint8_t digest[32], char text[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        text[2 * i] = hex[digest[i] >> 4];
        text[2 * i + 1] = hex[digest[i] & 15];
    }
    text[64] = 0;
}

bool blue_host_gui_write_log(FILE *out, const blue_host_gui_facts *facts,
                             blue_host_gui_bind_status status) {
    if (!out || !facts) return false;
    char digest[65];
    digest_hex(facts->digest, digest);
    int wrote = fprintf(out,
        "connection: %s\napp_name: %s\napp_version: %s\n"
        "receive: %s\nrecipient: %s\namount: %s\nfee: %s\n"
        "network: %s\nmemo: %s\napproval: %s\ndigest: %s\nbind: %s\n",
        facts->connection, facts->app_name, facts->app_version,
        facts->receive, facts->recipient, facts->amount, facts->fee,
        facts->network, facts->memo, facts->approval, digest,
        status == BLUE_HOST_GUI_BIND_MATCH ? "match" : "refused");
    return wrote > 0;
}
