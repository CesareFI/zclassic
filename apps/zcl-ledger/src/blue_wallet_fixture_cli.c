/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_payment_fixture.h"
#include "blue_payment_host_assemble.h"
#include "blue_payment_host_sign.h"
#include "blue_payment_live.h"
#include "ledger_hid.h"
#include "zcl_address.h"
#include "zcl_host_crypto.h"
#include "zcl_tx_prevout.h"
#include "zcl_zip243_host.h"
#include "crypto/blake2b.h"
#include "zsha256/zsha256.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

typedef struct { int fd; uint32_t outputs; } fixture_device;

typedef struct {
    size_t length;
    uint8_t hash[32];
} fixture_result;

static void erase_bytes(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool hash_sha256(const uint8_t *bytes, size_t length,
    uint8_t digest[32]) {
    if ((!bytes && length) || !digest) return false;
    zsha256(bytes, length, digest);
    return true;
}

static int open_blue(const char *path) {
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct hidraw_devinfo info;
    if (fd < 0) return -1;
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
    fixture_device *device = context;
    if (ledger_hid_exchange_timeout(device->fd, apdu, apdu_length,
        reply, capacity, reply_length, 5000) >= 0) return true;
    fprintf(stderr, "Blue USB command %02x failed or timed out.\n",
        apdu_length >= 2 ? apdu[1] : 0);
    return false;
}

static int output_status(fixture_device *device, uint32_t index) {
    static const uint8_t request[5] = {0xa5, 0x25, 0, 0, 0};
    uint8_t reply[16];
    size_t length = 0;
    if (!exchange(device, request, sizeof request, reply,
        sizeof reply, &length)) return -1;
    return blue_payment_live_review_status(reply, length, index,
        device->outputs);
}

static bool continue_output(void *context, uint32_t index,
    const blue_payment_screen *screen) {
    fixture_device *device = context;
    printf("\n%s: %s\n%s\n", screen->title, screen->amount,
        screen->address);
    puts("Compare every address character on the Blue, then tap CONTINUE.");
    fflush(stdout);
    for (unsigned attempt = 0; attempt < 600; ++attempt) {
        int status = output_status(device, index);
        if (status != 0) return status > 0;
        struct timespec delay = {.tv_nsec = 500000000};
        while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
    }
    return false;
}

static bool approve_sign(void *context) {
    (void)context;
    char answer[16];
    puts("On the Blue, inspect CALCULATED FEE, tap TOTALS, inspect OUTPUT TOTALS,");
    puts("then tap NEXT and inspect FINAL PAYMENT CHECK.");
    puts("This is a synthetic test with no verified UTXO. Tap SIGN ZCL there,");
    puts("then type SIGN here and press Enter. Type anything else to cancel.");
    fflush(stdout);
    return fgets(answer, sizeof answer, stdin) &&
        strcmp(answer, "SIGN\n") == 0;
}

static bool read_public_key(fixture_device *device, uint8_t public_key[33]) {
    static const uint8_t request[5] = {0xa5, 0x02, 0, 0, 0};
    uint8_t reply[35];
    size_t length = 0;
    if (!exchange(device, request, sizeof request, reply,
        sizeof reply, &length) || length != sizeof reply ||
        reply[33] != 0x90 || reply[34] != 0) return false;
    bool valid = zcl_host_pubkey_valid(reply);
    if (valid) memcpy(public_key, reply, 33);
    return valid;
}

static bool read_signing_identity(fixture_device *device) {
    static const uint8_t request[5] = {0xa5, 0x01, 0, 0, 0};
    static const uint8_t expected[7] = {'Z', 'C', 'L', 12, 31, 0x90, 0};
    uint8_t reply[7];
    size_t length = 0;
    return exchange(device, request, sizeof request, reply,
        sizeof reply, &length) && length == sizeof expected &&
        memcmp(reply, expected, sizeof expected) == 0;
}

typedef struct {
    blue_payment_fixture fixture;
    blue_payment_live_plan plan;
    uint8_t hash160[20], digest[32];
    zcl_tx_transparent_facts facts;
} fixture_job;

static bool prepare(fixture_job *job, const uint8_t public_key[33]) {
    if (!zcl_host_hash160(public_key, job->hash160) ||
        !blue_payment_fixture_make(job->hash160, &job->fixture) ||
        !blue_payment_live_prepare(job->fixture.unsigned_wire,
            job->fixture.unsigned_length, BLUE_PAYMENT_FIXTURE_BRANCH,
            &job->plan)) return false;
    zcl_tx_previous_transaction previous = {
        .wire = job->fixture.previous,
        .length = job->fixture.previous_length};
    struct blake2b_ctx blake_context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&blake_context);
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    if (zcl_tx_transparent_bound_digests(job->fixture.unsigned_wire,
        job->fixture.unsigned_length, &previous, 1,
        BLUE_PAYMENT_FIXTURE_BRANCH, hash_sha256, &hasher,
        &job->facts, digests, ZCL_TX_PREFLIGHT_MAX_INPUTS) != 0 ||
        job->facts.transparent_inputs != 1 ||
        job->facts.fee_zat != 100000000) return false;
    memcpy(job->digest, digests[0], 32);
    return true;
}

static bool reviewed_wire_unchanged(const fixture_job *job) {
    uint8_t hash[32];
    zsha256(job->fixture.unsigned_wire,
        job->fixture.unsigned_length, hash);
    return memcmp(hash, job->plan.wire_hash, sizeof hash) == 0;
}

static bool review_and_sign(fixture_device *device, fixture_job *job,
    fixture_result *result) {
    zcl_tx_previous_transaction previous = {
        .wire = job->fixture.previous,
        .length = job->fixture.previous_length};
    device->outputs = job->plan.count;
    bool valid = blue_payment_live_run_bound(job->fixture.unsigned_wire,
        job->fixture.unsigned_length, &job->plan, &previous, 1,
        job->facts.fee_zat, (const uint8_t (*)[32])&job->digest,
        exchange, continue_output, device) &&
        reviewed_wire_unchanged(job);
    const uint8_t paths[1] = {BLUE_PAYMENT_INPUT_EXTERNAL};
    blue_payment_verified_signature verified[1] = {0};
    if (valid) valid = blue_payment_host_sign(1, paths,
        (const uint8_t (*)[20])&job->hash160,
        (const uint8_t (*)[32])&job->digest, exchange, approve_sign,
        device, zcl_host_hash160, zcl_host_verify_signature,
        NULL, verified);
    uint8_t signed_wire[512] = {0};
    size_t signed_length = 0;
    if (valid) valid = blue_payment_host_assemble_authenticated(
        job->fixture.unsigned_wire,
        job->fixture.unsigned_length, job->plan.wire_hash, verified,
        (const uint8_t (*)[32])&job->digest, paths,
        (const uint8_t (*)[20])&job->hash160, 1,
        zcl_host_hash160, zcl_host_verify_signature, NULL,
        signed_wire, sizeof signed_wire, &signed_length);
    if (valid) {
        zsha256(signed_wire, signed_length, result->hash);
        result->length = signed_length;
    }
    erase_bytes(signed_wire, sizeof signed_wire);
    erase_bytes(verified, sizeof verified);
    return valid;
}

static int hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool parse_hex_key(const char *text, uint8_t key[33]) {
    if (!text || strlen(text) != 66) return false;
    for (size_t i = 0; i < 33; ++i) {
        int high = hex_digit(text[2 * i]);
        int low = hex_digit(text[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        key[i] = (uint8_t)(high * 16 + low);
    }
    return zcl_host_pubkey_valid(key);
}

static bool report_fixture(const fixture_job *job,
    const uint8_t public_key[33]) {
    char address[ZCL_ADDRESS_SIZE];
    if (zcl_address_from_pubkey(public_key, address) < 0) return false;
    printf("SYNTHETIC TEST ONLY: %zu-byte previous wire; %zu-byte unsigned spend.\n",
        job->fixture.previous_length, job->fixture.unsigned_length);
    printf("Device path m/44'/147'/0'/0/0: %s\n", address);
    printf("Outputs: 1.00000000 ZCL to this key, 2.00000000 ZCL to fixed P2SH test address.\n");
    for (size_t i = 0; i < job->plan.count; ++i)
        printf("Output %zu: %s %s\n", i + 1,
            job->plan.screens[i].amount,
            job->plan.screens[i].address);
    printf("Calculated fee: %llu zatoshi. No chain UTXO verified; this tool has no broadcast path.\n",
        (unsigned long long)job->facts.fee_zat);
    return true;
}

static bool finish_live_fixture(fixture_device *device, bool signed_result) {
    bool cleared = blue_payment_live_abort(exchange, device);
    if (!cleared)
        fputs("Blue did not confirm review erasure; restart the app.\n",
            stderr);
    return signed_result && cleared;
}

static void report_signed_fixture(const fixture_result *result) {
    printf("Verified one Blue signature; assembled %zu synthetic bytes; SHA-256 ",
        result->length);
    for (size_t i = 0; i < sizeof result->hash; ++i)
        printf("%02x", result->hash[i]);
    puts(". No transaction was broadcast or saved. Tap EXIT on the Blue.");
}

static int run_fixture(bool offline, const char *argument) {
    fixture_device device = {.fd = -1};
    uint8_t public_key[33];
    if (offline) {
        if (!parse_hex_key(argument, public_key)) return 1;
    } else {
        device.fd = open_blue(argument);
        if (device.fd < 0 || !read_signing_identity(&device) ||
            !read_public_key(&device, public_key)) {
            fputs("Cannot identify an open ZCL Wallet on this Ledger Blue.\n",
                stderr);
            if (device.fd >= 0) close(device.fd);
            return 1;
        }
    }
    fixture_job job = {0};
    fixture_result result = {0};
    bool valid = prepare(&job, public_key) && report_fixture(&job, public_key);
    if (valid && !offline)
        valid = finish_live_fixture(&device,
            review_and_sign(&device, &job, &result));
    if (device.fd >= 0 && close(device.fd) != 0) valid = false;
    if (valid && !offline) report_signed_fixture(&result);
    erase_bytes(&result, sizeof result);
    erase_bytes(&job, sizeof job);
    return valid ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "--prepare") != 0 &&
                      strcmp(argv[1], "--device") != 0)) {
        fprintf(stderr, "Usage: %s --prepare COMPRESSED_PUBKEY_HEX | --device /dev/hidrawN\n",
            argv[0]);
        return 2;
    }
    return run_fixture(strcmp(argv[1], "--prepare") == 0, argv[2]);
}
