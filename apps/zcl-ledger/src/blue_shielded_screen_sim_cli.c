/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_review_render.h"
#include "blue_shielded_review_app.h"
#include "blue_shielded_review_client.h"
#include "zcl_zip243_host.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    blue_shielded_review_app app;
    struct blake2b_ctx blake;
    zcl_zip243_hasher hasher;
    const char *prefix;
    bool capture_ok;
} simulator;

static bool capture(const simulator *sim, const char *label) {
    char path[4096];
    int count = snprintf(path, sizeof path, "%s-%s.png",
        sim->prefix, label);
    if (count < 0 || (size_t)count >= sizeof path ||
        !blue_review_render_lines_png(path, sim->app.lines,
            "ZCL Shielded", "NEXT / REFRESH", sim->app.dark,
            sim->app.large_text ? sim->app.detail : -1)) return false;
    puts(path);
    return true;
}

static bool capture_pass(const simulator *sim, const char *stage) {
    char label[32];
    int count = snprintf(label, sizeof label, "pass-%u-%s",
        sim->app.transaction.replay.pass, stage);
    return count > 0 && (size_t)count < sizeof label &&
        capture(sim, label);
}

static bool exchange(void *context, const uint8_t *apdu,
    size_t apdu_length, uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    simulator *sim = context;
    if (capacity < 2 || apdu_length < 2) return false;
    size_t body_length = 0;
    uint16_t status = blue_shielded_review_app_command(&sim->app,
        apdu, apdu_length, reply, capacity - 2, &body_length,
        &sim->hasher);
    if (body_length > capacity - 2) return false;
    reply[body_length] = (uint8_t)(status >> 8);
    reply[body_length + 1] = (uint8_t)status;
    *reply_length = body_length + 2;
    if (status != 0x9000) return true;
    if (apdu[1] == 0x20 || apdu[1] == 0x22)
        sim->capture_ok = capture_pass(sim, "start");
    else if (apdu[1] == 0x21 &&
        sim->app.transaction.replay.wire.received ==
            sim->app.transaction.replay.expected)
        sim->capture_ok = capture_pass(sim, "complete");
    else if (apdu[1] == 0x23)
        sim->capture_ok = capture(sim, "summary");
    return sim->capture_ok;
}

static int hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool parse_branch(const char *text, uint32_t *branch) {
    if (strlen(text) != 10 || text[0] != '0' || text[1] != 'x')
        return false;
    uint32_t value = 0;
    for (unsigned i = 2; i < 10; ++i) {
        int nibble = hex_digit(text[i]);
        if (nibble < 0) return false;
        value = (value << 4) | (unsigned)nibble;
    }
    *branch = value;
    return true;
}

static bool read_exact(int fd, uint8_t *wire, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t received = read(fd, wire + offset, length - offset);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return false;
        offset += (size_t)received;
    }
    uint8_t extra;
    return read(fd, &extra, 1) == 0;
}

static bool read_wire(const char *path, uint8_t **wire, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat info;
    bool valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_size > 0 && info.st_size <= ZCL_TX_REVIEW_MAX_BYTES;
    size_t count = valid ? (size_t)info.st_size : 0;
    uint8_t *bytes = valid ? malloc(count) : NULL;
    if (!bytes) valid = false;
    if (valid) valid = read_exact(fd, bytes, count);
    if (close(fd) != 0) valid = false;
    if (!valid) { free(bytes); return false; }
    *wire = bytes;
    *length = count;
    return true;
}

static bool capture_large_lines(simulator *sim, const char *page,
    const char *theme) {
    for (unsigned detail = 0; detail < ZCL_BLUE_REVIEW_LINES; ++detail) {
        char label[48];
        int count = snprintf(label, sizeof label, "%s-large-%s-%u",
            page, theme, detail + 1);
        if (count < 0 || (size_t)count >= sizeof label ||
            !capture(sim, label)) return false;
        if (detail + 1 < ZCL_BLUE_REVIEW_LINES &&
            !blue_shielded_review_app_next(&sim->app)) return false;
    }
    return true;
}

static bool capture_normal_pages(simulator *sim) {
    if (!blue_shielded_review_app_next(&sim->app) ||
        !capture(sim, "digest") ||
        !blue_shielded_review_app_next(&sim->app) ||
        !capture(sim, "wire") ||
        !blue_shielded_review_app_next(&sim->app)) return false;
    blue_shielded_review_app_toggle_dark(&sim->app);
    if (!capture(sim, "summary-dark") ||
        !blue_shielded_review_app_next(&sim->app) ||
        !capture(sim, "digest-dark") ||
        !blue_shielded_review_app_next(&sim->app) ||
        !capture(sim, "wire-dark") ||
        !blue_shielded_review_app_next(&sim->app)) return false;
    return true;
}

static bool capture_accessibility(simulator *sim) {
    if (!capture_normal_pages(sim)) return false;
    blue_shielded_review_app_toggle_text(&sim->app);
    if (!capture_large_lines(sim, "summary", "dark") ||
        !blue_shielded_review_app_next(&sim->app) ||
        !capture_large_lines(sim, "digest", "dark") ||
        !blue_shielded_review_app_next(&sim->app) ||
        !capture_large_lines(sim, "wire", "dark")) return false;
    blue_shielded_review_app_toggle_dark(&sim->app);
    blue_shielded_review_app_toggle_text(&sim->app);
    blue_shielded_review_app_toggle_text(&sim->app);
    if (!capture_large_lines(sim, "wire", "light") ||
        !blue_shielded_review_app_next(&sim->app) ||
        !capture_large_lines(sim, "summary", "light") ||
        !blue_shielded_review_app_next(&sim->app) ||
        !capture_large_lines(sim, "digest", "light")) return false;
    return true;
}

int main(int argc, char **argv) {
    uint32_t branch;
    if (argc != 4 || !parse_branch(argv[2], &branch)) {
        fprintf(stderr, "Usage: %s TRANSACTION.bin 0xBRANCH "
            "OUTPUT_PREFIX\n", argv[0]);
        return 2;
    }
    uint8_t *wire = NULL;
    size_t length = 0;
    if (!read_wire(argv[1], &wire, &length)) {
        fputs("Expected a nonempty regular transaction file within 2 MiB.\n",
            stderr);
        return 1;
    }
    simulator *sim = calloc(1, sizeof *sim);
    if (!sim) { free(wire); return 1; }
    sim->prefix = argv[3];
    sim->capture_ok = true;
    sim->hasher = zcl_zip243_host_hasher(&sim->blake);
    blue_shielded_review_app_reset(&sim->app);
    zcl_tx_review review;
    uint8_t digest[32];
    bool ok = capture(sim, "ready") &&
        blue_shielded_review_client_run(wire, length, branch,
            exchange, sim, &review, digest) &&
        capture_accessibility(sim);
    if (!ok) fputs("Screen simulation failed; discard partial PNGs.\n",
        stderr);
    free(sim);
    free(wire);
    return ok ? 0 : 1;
}
