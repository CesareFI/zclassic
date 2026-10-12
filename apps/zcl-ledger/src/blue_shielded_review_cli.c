/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_shielded_review_app.h"
#include "blue_shielded_review_client.h"
#include "ledger_hid.h"
#include "zcl_zip243_host.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/hidraw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    bool simulate;
    int fd;
    blue_shielded_review_app app;
    struct blake2b_ctx blake;
    zcl_zip243_hasher hasher;
} review_connection;

static bool parse_branch(const char *text, uint32_t *branch) {
    if (strlen(text) != 10 || text[0] != '0' || text[1] != 'x')
        return false;
    uint32_t value = 0;
    for (unsigned i = 2; i < 10; ++i) {
        unsigned nibble;
        if (text[i] >= '0' && text[i] <= '9')
            nibble = (unsigned)(text[i] - '0');
        else if (text[i] >= 'a' && text[i] <= 'f')
            nibble = (unsigned)(text[i] - 'a' + 10);
        else if (text[i] >= 'A' && text[i] <= 'F')
            nibble = (unsigned)(text[i] - 'A' + 10);
        else return false;
        value = (value << 4) | nibble;
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

static int open_blue(const char *path) {
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct hidraw_devinfo info;
    if (ioctl(fd, HIDIOCGRAWINFO, &info) < 0 ||
        info.vendor != 0x2c97 || info.product != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool exchange(void *context, const uint8_t *apdu,
    size_t apdu_length, uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    review_connection *connection = context;
    if (!connection->simulate)
        return ledger_hid_exchange_timeout(connection->fd,
            apdu, apdu_length, reply, capacity, reply_length, 5000) == 0;
    if (capacity < 2) return false;
    size_t body_length = 0;
    uint16_t status = blue_shielded_review_app_command(&connection->app,
        apdu, apdu_length, reply, capacity - 2, &body_length,
        &connection->hasher);
    if (body_length > capacity - 2) return false;
    reply[body_length] = (uint8_t)(status >> 8);
    reply[body_length + 1] = (uint8_t)status;
    *reply_length = body_length + 2;
    return true;
}

static void print_digest(const uint8_t digest[32]) {
    fputs("ZIP-243 digest: ", stdout);
    for (unsigned i = 0; i < 32; ++i) printf("%02x", digest[i]);
    putchar('\n');
}

static void print_wire_commitment(const uint8_t commitment[32]) {
    fputs("Full-wire SHA-256: ", stdout);
    for (unsigned i = 0; i < 32; ++i)
        printf("%02x", commitment[i]);
    putchar('\n');
}

static void print_review(const blue_shielded_review_receipt *receipt,
    bool simulated) {
    const zcl_tx_review *review = &receipt->facts;
    printf("%s read-only review matched Z23's parser, ZIP-243 digest, and full wire.\n",
        simulated ? "Simulated Blue" : "Blue");
    printf("Transparent inputs/outputs: %" PRIu32 "/%" PRIu32 "\n",
        review->transparent_inputs, review->transparent_outputs);
    printf("Sapling spends/outputs: %" PRIu32 "/%" PRIu32 "\n",
        review->sapling_spends, review->sapling_outputs);
    printf("Sprout JoinSplits: %" PRIu32 "\n",
        review->sprout_joinsplits);
    printf("Public output total (zatoshis): %" PRIu64 "\n",
        review->transparent_output_zat);
    printf("Sapling value balance (zatoshis): %" PRId64 "\n",
        review->value_balance_zat);
    printf("Reviewed branch: 0x%08" PRIX32 "; wire bytes: %" PRIu32 "\n",
        receipt->branch_id, receipt->wire_length);
    print_digest(receipt->zip243_digest);
    print_wire_commitment(receipt->wire_sha256);
    puts("Fee, shielded recipients, amounts, memos, proofs, and ownership"
        " are not verified. No payment was authorized or signed.");
}

typedef struct {
    bool simulate;
    const char *device, *path;
    uint32_t branch;
} cli_args;

static bool parse_args(int argc, char **argv, cli_args *args) {
    if (argc == 4 && strcmp(argv[1], "--simulate") == 0) {
        args->simulate = true;
        args->device = NULL;
        args->path = argv[2];
        return parse_branch(argv[3], &args->branch);
    }
    if (argc == 5 && strcmp(argv[1], "--blue") == 0) {
        args->simulate = false;
        args->device = argv[2];
        args->path = argv[3];
        return parse_branch(argv[4], &args->branch);
    }
    return false;
}

static void initialize_connection(review_connection *connection,
    const cli_args *args) {
    connection->simulate = args->simulate;
    connection->fd = -1;
    if (args->simulate) {
        connection->hasher = zcl_zip243_host_hasher(&connection->blake);
        blue_shielded_review_app_reset(&connection->app);
        return;
    }
    connection->fd = open_blue(args->device);
    if (connection->fd < 0)
        fputs("Could not open a Ledger Blue HID device.\n", stderr);
}

int main(int argc, char **argv) {
    cli_args args;
    if (!parse_args(argc, argv, &args)) {
        fprintf(stderr, "Usage: %s (--simulate TRANSACTION.bin | "
            "--blue /dev/hidrawN TRANSACTION.bin) 0xBRANCH\n", argv[0]);
        return 2;
    }
    uint8_t *wire = NULL;
    size_t length = 0;
    if (!read_wire(args.path, &wire, &length)) {
        fputs("Expected a nonempty regular transaction file within 2 MiB.\n",
            stderr);
        return 1;
    }
    review_connection *connection = calloc(1, sizeof *connection);
    if (!connection) { free(wire); return 1; }
    initialize_connection(connection, &args);
    blue_shielded_review_receipt receipt;
    bool ok = (args.simulate || connection->fd >= 0) &&
        blue_shielded_review_client_run_receipt(wire, length, args.branch,
            exchange, connection, &receipt);
    if (ok) print_review(&receipt, args.simulate);
    else fputs("Blue read-only review failed; discard its result.\n",
        stderr);
    if (connection->fd >= 0) close(connection->fd);
    free(connection);
    free(wire);
    return ok ? 0 : 1;
}
