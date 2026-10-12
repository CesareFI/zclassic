/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_host_gui.h"
#include "blue_install_params.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#undef NDEBUG
#include <assert.h>

static void corrupt(blue_host_gui_facts *facts, char *field) {
    assert(field[0]);
    field[0] = field[0] == 'A' ? 'B' : 'A';
    (void)facts;
}

static void assert_refuses(const blue_host_gui_facts *gui,
                           const blue_host_gui_facts *screen,
                           blue_host_gui_bind_status expected) {
    uint8_t out[64], signature[8];
    size_t out_length = 99;
    memset(signature, 0x5a, sizeof signature);
    memset(out, 0x11, sizeof out);
    assert(blue_host_gui_bind(gui, screen, screen->digest,
                              sizeof screen->digest) == expected);
    assert(!blue_host_gui_release_signature(gui, screen, screen->digest,
        sizeof screen->digest, BLUE_HOST_GUI_AUTHORITY_SIGN, signature,
        sizeof signature, out, sizeof out, &out_length));
    assert(out_length == 0);
    for (size_t i = 0; i < sizeof out; ++i) assert(out[i] == 0);
}

static void test_field_mismatch(const blue_host_gui_facts *original) {
    struct {
        size_t offset;
        blue_host_gui_bind_status status;
    } fields[] = {
        {offsetof(blue_host_gui_facts, connection),
         BLUE_HOST_GUI_BIND_CONNECTION},
        {offsetof(blue_host_gui_facts, app_name),
         BLUE_HOST_GUI_BIND_APP_NAME},
        {offsetof(blue_host_gui_facts, app_version),
         BLUE_HOST_GUI_BIND_APP_VERSION},
        {offsetof(blue_host_gui_facts, receive),
         BLUE_HOST_GUI_BIND_RECEIVE},
        {offsetof(blue_host_gui_facts, recipient),
         BLUE_HOST_GUI_BIND_RECIPIENT},
        {offsetof(blue_host_gui_facts, amount), BLUE_HOST_GUI_BIND_AMOUNT},
        {offsetof(blue_host_gui_facts, fee), BLUE_HOST_GUI_BIND_FEE},
        {offsetof(blue_host_gui_facts, network), BLUE_HOST_GUI_BIND_NETWORK},
        {offsetof(blue_host_gui_facts, memo), BLUE_HOST_GUI_BIND_MEMO},
        {offsetof(blue_host_gui_facts, approval),
         BLUE_HOST_GUI_BIND_APPROVAL}
    };
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; ++i) {
        blue_host_gui_facts changed = *original;
        corrupt(&changed, (char *)&changed + fields[i].offset);
        assert_refuses(&changed, original, fields[i].status);
    }
    blue_host_gui_facts changed = *original;
    changed.digest[0] ^= 0xff;
    assert_refuses(&changed, original, BLUE_HOST_GUI_BIND_DIGEST);
    uint8_t wrong[32];
    memcpy(wrong, original->digest, sizeof wrong);
    wrong[31] ^= 0xff;
    assert(blue_host_gui_bind(original, original, wrong, sizeof wrong) ==
           BLUE_HOST_GUI_BIND_DIGEST);
    assert(blue_host_gui_bind(original, original, original->digest, 31) ==
           BLUE_HOST_GUI_BIND_DIGEST);
}

static void test_authorities(const blue_host_gui_facts *facts) {
    uint8_t out[64], signature[8];
    size_t out_length = 7;
    memset(signature, 0xa5, sizeof signature);
    int readers[] = {
        BLUE_HOST_GUI_AUTHORITY_REVIEW,
        BLUE_HOST_GUI_AUTHORITY_KEYS,
        BLUE_HOST_GUI_AUTHORITY_INSTALL,
        0
    };
    for (size_t i = 0; i < sizeof readers / sizeof readers[0]; ++i) {
        memset(out, 0x22, sizeof out);
        out_length = 7;
        assert(!blue_host_gui_release_signature(facts, facts, facts->digest,
            sizeof facts->digest, readers[i], signature, sizeof signature,
            out, sizeof out, &out_length));
        assert(out_length == 0);
        for (size_t j = 0; j < sizeof out; ++j) assert(out[j] == 0);
    }
    assert(blue_host_gui_release_signature(facts, facts, facts->digest,
        sizeof facts->digest, BLUE_HOST_GUI_AUTHORITY_SIGN, signature,
        sizeof signature, out, sizeof out, &out_length));
    assert(out_length == sizeof signature &&
           memcmp(out, signature, sizeof signature) == 0);
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_REVIEW,
                                        "ZCL Probe", "0.1.0"));
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_KEYS,
                                        "ZCL Probe", "0.1.0"));
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_SIGN,
                                        "ZCL Probe", "0.1.0"));
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_INSTALL,
                                        "ZCL Wallet", "0.3.46"));
    assert(!blue_install_image_allowed("ZCL Wallet", "0.3.46"));
    assert(blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_INSTALL,
                                       "ZCL Probe", "0.1.0"));
}

static bool png_header(const char *path) {
    FILE *file = fopen(path, "rb");
    unsigned char magic[8];
    if (!file) return false;
    bool ok = fread(magic, 1, sizeof magic, file) == sizeof magic &&
        magic[0] == 0x89 && magic[1] == 'P' && magic[2] == 'N' &&
        magic[3] == 'G';
    fclose(file);
    return ok;
}

static void assert_modes_differ(char paths[4][256]) {
    for (size_t i = 1; i < 4; ++i) {
        FILE *left = fopen(paths[0], "rb");
        FILE *right = fopen(paths[i], "rb");
        assert(left && right);
        int different = 0;
        for (;;) {
            int a = fgetc(left), b = fgetc(right);
            if (a != b) different = 1;
            if (a == EOF || b == EOF) break;
        }
        fclose(left);
        fclose(right);
        assert(different);
    }
}

static void assert_log_records(const char *directory,
                               const blue_host_gui_facts *facts) {
    char log_path[256];
    assert(snprintf(log_path, sizeof log_path, "%s/log.txt", directory) > 0);
    FILE *log = fopen(log_path, "w");
    assert(log && blue_host_gui_write_log(log, facts,
                                          BLUE_HOST_GUI_BIND_MATCH));
    fclose(log);
    log = fopen(log_path, "r");
    char line[256];
    const char *required[] = {
        "connection: Blue linked", "app_name: ZCL Wallet",
        "app_version: 12", "memo: NO MEMO", "approval: SIGN ZCL",
        "bind: match"
    };
    char body[2048] = {0};
    size_t used = 0;
    while (fgets(line, sizeof line, log)) {
        size_t length = strlen(line);
        if (used + length < sizeof body) {
            memcpy(body + used, line, length);
            used += length;
        }
    }
    fclose(log);
    for (size_t i = 0; i < sizeof required / sizeof required[0]; ++i)
        assert(strstr(body, required[i]));
    assert(strstr(body, facts->receive) && strstr(body, facts->recipient));
    assert(strstr(body, facts->amount) && strstr(body, facts->fee) &&
           strstr(body, facts->network));
    assert(unlink(log_path) == 0);
}

static void test_render(const blue_host_gui_facts *facts) {
    char directory[] = "/tmp/zcl-blue-host-gui-XXXXXX";
    assert(mkdtemp(directory));
    const char *names[] = {"light.png", "dark.png", "large.png",
                           "large-dark.png"};
    const bool dark[] = {false, true, false, true};
    const bool large[] = {false, false, true, true};
    char paths[4][256];
    for (size_t i = 0; i < 4; ++i) {
        assert(snprintf(paths[i], sizeof paths[i], "%s/%s", directory,
                        names[i]) > 0);
        assert(blue_host_gui_render_png(paths[i], facts, dark[i], large[i]));
        assert(png_header(paths[i]));
    }
    assert_modes_differ(paths);
    blue_host_gui_facts blank = *facts;
    blank.memo[0] = 0;
    assert(!blue_host_gui_render_png(paths[0], &blank, false, true));
    assert_log_records(directory, facts);
    for (size_t i = 0; i < 4; ++i) assert(unlink(paths[i]) == 0);
    assert(rmdir(directory) == 0);
}

int main(void) {
    blue_host_gui_facts facts;
    assert(blue_host_gui_load_representative(&facts));
    assert(strcmp(facts.app_name, "ZCL Wallet") == 0);
    assert(strcmp(facts.app_version, "12") == 0);
    assert(strcmp(facts.memo, "NO MEMO") == 0);
    assert(strcmp(facts.approval, "SIGN ZCL") == 0);
    assert(strcmp(facts.network, "BRANCH 0x76B809BB") == 0);
    assert(facts.receive[0] == 't' && facts.recipient[0] == 't');
    assert(strcmp(facts.receive, facts.recipient) != 0);
    assert(blue_host_gui_bind(&facts, &facts, facts.digest,
                              sizeof facts.digest) ==
           BLUE_HOST_GUI_BIND_MATCH);
    test_field_mismatch(&facts);
    test_authorities(&facts);
    test_render(&facts);
    return 0;
}
