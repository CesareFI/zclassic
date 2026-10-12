/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_payment_live.h"
#include "blue_mainnet_branch.h"
#include "blue_chain_tip.h"
#include "blue_utxo.h"
#include "ledger_hid.h"
#include "zcl_tx_prevout.h"
#include "zcl_tx_review.h"
#include "zcl_zip243_host.h"
#include "crypto/blake2b.h"
#include "zsha256/zsha256.h"

#ifdef BLUE_WALLET_SIGN_CLI
#include "blue_payment_host_assemble.h"
#include "blue_payment_host_ownership.h"
#include "blue_payment_host_sign.h"
#include "blue_signed_output.h"
#include "zcl_address.h"
#include "zcl_host_crypto.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct { int fd; uint32_t outputs; } live_device;

static bool sha256_bytes(const uint8_t *bytes, size_t length,
    uint8_t digest[32]) {
    if ((!bytes && length) || !digest) return false;
    zsha256(bytes, length, digest);
    return true;
}

static void free_previous(uint8_t *bytes[ZCL_TX_PREFLIGHT_MAX_INPUTS],
    size_t count) {
    for (size_t i = 0; i < count; ++i) free(bytes[i]);
}

static bool read_exact(int fd, uint8_t *bytes, size_t length) {
    size_t position = 0;
    while (position < length) {
        ssize_t got = read(fd, bytes + position, length - position);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        position += (size_t)got;
    }
    uint8_t extra;
    return read(fd, &extra, 1) == 0;
}

static bool read_wire(const char *path, uint8_t **wire, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat info;
    bool valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_size > 0 && info.st_size <= ZCL_TX_STREAM_MAX_BYTES;
    uint8_t *bytes = valid ? malloc((size_t)info.st_size) : NULL;
    if (!bytes) valid = false;
    size_t expected = valid ? (size_t)info.st_size : 0;
    if (valid) valid = read_exact(fd, bytes, expected);
    if (close(fd) != 0) valid = false;
    if (!valid) { free(bytes); return false; }
    *wire = bytes;
    *length = expected;
    return true;
}

static bool load_previous(char *const paths[], size_t count,
    uint8_t *bytes[ZCL_TX_PREFLIGHT_MAX_INPUTS],
    zcl_tx_previous_transaction previous[ZCL_TX_PREFLIGHT_MAX_INPUTS]) {
    for (size_t i = 0; i < count; ++i) {
        if (!read_wire(paths[i], &bytes[i], &previous[i].length))
            return false;
        previous[i].wire = bytes[i];
    }
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

static bool live_exchange(void *context, const uint8_t *apdu,
    size_t apdu_length, uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    live_device *device = context;
    if (ledger_hid_exchange_timeout(device->fd, apdu, apdu_length,
            reply, capacity, reply_length, 5000) < 0) {
        fprintf(stderr, "Blue USB command %02x timed out or failed.\n",
            apdu_length >= 2 ? apdu[1] : 0);
        return false;
    }
    if (apdu_length >= 2 && *reply_length >= 2 &&
        (reply[*reply_length - 2] != 0x90 ||
         reply[*reply_length - 1] != 0 ||
         (apdu[1] != 0x21 && apdu[1] != 0x27 && apdu[1] != 0x25)))
        fprintf(stderr, "Blue USB command %02x replied %02x%02x.\n",
            apdu[1], reply[*reply_length - 2], reply[*reply_length - 1]);
    return true;
}

static int review_status(live_device *device, uint32_t index) {
    static const uint8_t command[] = {0xa5, 0x25, 0, 0, 0};
    uint8_t reply[16];
    size_t length = 0;
    if (!live_exchange(device, command, sizeof command, reply,
                       sizeof reply, &length)) return -1;
    return blue_payment_live_review_status(reply, length, index,
                                            device->outputs);
}

static bool wait_for_touch(void *context, uint32_t index,
    const blue_payment_screen *screen) {
    live_device *device = context;
    printf("\n%s  %s  %s\n%s\n",
        screen->title, screen->kind, screen->amount,
        screen->address);
    puts("Compare the full address on the Blue, then tap CONTINUE there.");
    fflush(stdout);
    for (unsigned attempt = 0; attempt < 600; ++attempt) {
        int status = review_status(device, index);
        if (status != 0) return status > 0;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 500000000};
        while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
    }
    return false;
}

static bool review_inputs_unchanged(bool reviewed, const char *rpc_binary,
                                   const blue_chain_tip *initial,
                                   const uint8_t *wire, size_t length,
                                   const zcl_tx_previous_transaction *previous,
                                   size_t previous_count) {
    if (!reviewed) return false;
    if (blue_utxo_recheck_at_tip(rpc_binary, initial, wire, length,
                                 previous, previous_count)) return true;
    fputs("Cannot confirm the local node tip and input UTXOs remained unchanged during Blue review; discard this result.\n",
          stderr);
    return false;
}

typedef struct {
    blue_chain_tip tip;
    uint32_t branch_id;
    uint8_t *wire;
    size_t length;
    blue_payment_live_plan *plan;
    size_t previous_count;
    uint8_t *previous_bytes[ZCL_TX_PREFLIGHT_MAX_INPUTS];
    zcl_tx_previous_transaction previous[ZCL_TX_PREFLIGHT_MAX_INPUTS];
    zcl_tx_transparent_facts facts;
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
} review_job;

static void free_job(review_job *job) {
    if (!job) return;
    free_previous(job->previous_bytes, job->previous_count);
    free(job->plan);
    free(job->wire);
    free(job);
}

static void report_unreviewable_wire(const uint8_t *wire, size_t length) {
    zcl_tx_review facts;
    if (zcl_tx_review_parse(wire, length, &facts) == 0 &&
        (facts.sapling_spends || facts.sapling_outputs ||
         facts.sprout_joinsplits || facts.value_balance_zat)) {
        fputs("Transactions with shielded fields cannot be reviewed by this Blue Wallet yet.\n",
              stderr);
        return;
    }
    fputs("The transaction cannot be reviewed by this Blue Wallet.\n", stderr);
}

static bool prepare_wire(review_job *job, const char *rpc_binary,
                         const char *path) {
    if (!blue_chain_tip_query(rpc_binary, &job->tip) ||
        !blue_mainnet_branch_for_height(job->tip.next_height,
                                         &job->branch_id)) {
        fputs("Cannot verify a synced ZCL mainnet tip at or after Sapling activation.\n",
              stderr);
        return false;
    }
    if (!read_wire(path, &job->wire, &job->length)) {
        fputs("Expected a nonempty regular unsigned transaction file within the Blue size limit.\n",
              stderr);
        return false;
    }
    job->plan = malloc(sizeof *job->plan);
    if (!job->plan) {
        fputs("Cannot allocate the Blue review plan.\n", stderr);
        return false;
    }
    if (!blue_payment_live_prepare(job->wire, job->length,
                                   job->branch_id, job->plan)) {
        report_unreviewable_wire(job->wire, job->length);
        return false;
    }
    return true;
}

static bool prepare_inputs(review_job *job, const char *rpc_binary,
                           char *const paths[]) {
    if (!load_previous(paths, job->previous_count,
                       job->previous_bytes, job->previous)) {
        fputs("Expected nonempty regular previous transaction files within the Blue size limit.\n",
              stderr);
        return false;
    }
    struct blake2b_ctx blake_context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&blake_context);
    if (zcl_tx_transparent_bound_digests(job->wire, job->length,
            job->previous, job->previous_count, job->branch_id,
            sha256_bytes, &hasher, &job->facts, job->digests,
            ZCL_TX_PREFLIGHT_MAX_INPUTS) < 0) {
        fputs("Input outpoints do not match previous transactions or digest calculation failed.\n",
              stderr);
        return false;
    }
    if (!blue_utxo_check_inputs(rpc_binary, job->wire, job->length,
                                job->previous, job->previous_count,
                                job->tip.next_height)) {
        fputs("A supplied input failed the local node's confirmation, UTXO, maturity, amount, or script check.\n",
              stderr);
        return false;
    }
    if (!blue_chain_tip_still_current(rpc_binary, &job->tip)) {
        fputs("Cannot confirm the local node tip remained unchanged during input checks; review stopped.\n",
              stderr);
        return false;
    }
    return true;
}

#ifndef BLUE_WALLET_SIGN_CLI
static bool run_device(review_job *job, const char *device_path,
                       const char *rpc_binary) {
    live_device device = {.fd = open_blue(device_path),
                          .outputs = job->plan->count};
    if (device.fd < 0) {
        fputs("The selected interface is not an accessible Ledger Blue.\n",
              stderr);
        return false;
    }
    printf("Read-only mainnet test review at node next height %u "
           "(branch %08x): %u hash-bound input(s), %u output(s), "
           "fee %llu zatoshi. Local UTXO status checked; independent peer sync and account ownership remain unverified.\n",
           job->tip.next_height, job->branch_id,
           job->facts.transparent_inputs, job->facts.transparent_outputs,
           (unsigned long long)job->facts.fee_zat);
    puts("This command never requests a payment signature.");
    puts("Z23 will clear the Blue review before checking the inputs again.");
    fflush(stdout);
    bool valid = blue_payment_live_run_bound(job->wire, job->length, job->plan,
        job->previous, job->previous_count, job->facts.fee_zat,
        (const uint8_t (*)[32])job->digests,
        live_exchange, wait_for_touch, &device);
    bool cleared = blue_payment_live_abort(live_exchange, &device);
    valid = review_inputs_unchanged(valid && cleared, rpc_binary, &job->tip,
        job->wire, job->length, job->previous, job->previous_count);
    close(device.fd);
    if (!cleared)
        fputs("The Blue did not confirm review erasure. Restart the app before another transaction.\n",
              stderr);
    if (!valid) {
        fputs("Blue review stopped; no payment was signed.\n", stderr);
        return false;
    }
    puts("Blue matched every input digest and displayed the fee.");
    puts("The review was cleared on the Blue; tap EXIT.");
    return true;
}
#else
static void erase_bytes(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static bool blue_external_hash(live_device *device, uint8_t hash[20]) {
    static const uint8_t request[5] = {0xa5, 0x02, 0, 0, 0};
    uint8_t reply[35];
    size_t length = 0;
    if (!live_exchange(device, request, sizeof request, reply,
            sizeof reply, &length) || length != sizeof reply ||
        reply[33] != 0x90 || reply[34] != 0 ||
        !zcl_host_pubkey_valid(reply) ||
        !zcl_host_hash160(reply, hash)) return false;
    char address[ZCL_ADDRESS_SIZE];
    if (zcl_address_from_pubkey(reply, address) < 0) return false;
    printf("Blue external receive key: %s\n", address);
    puts("Compare this address with the Blue before trusting this USB session.");
    return true;
}

static bool signing_approval(void *unused) {
    (void)unused;
    char answer[16];
    puts("On the Blue, inspect CALCULATED FEE, OUTPUT TOTALS, and FINAL PAYMENT CHECK.");
    puts("Confirm every destination and the fee. Tap SIGN ZCL on the Blue only if correct.");
    puts("Then type SIGN and Enter here. Any other input cancels.");
    fflush(stdout);
    return fgets(answer, sizeof answer, stdin) &&
        strcmp(answer, "SIGN\n") == 0;
}

static bool same_facts(const zcl_tx_transparent_facts *left,
    const zcl_tx_transparent_facts *right) {
    return left->transparent_inputs == right->transparent_inputs &&
        left->transparent_outputs == right->transparent_outputs &&
        left->input_zat == right->input_zat &&
        left->output_zat == right->output_zat &&
        left->fee_zat == right->fee_zat;
}

static bool sign_bound_job(review_job *job, live_device *device,
    const char *rpc_binary, blue_signed_output *stage,
    const blue_payment_host_ownership *owned, uint8_t saved_hash[32],
    size_t *saved_length) {
    blue_payment_verified_signature *signatures =
        calloc(job->previous_count, sizeof *signatures);
    uint8_t *signed_wire = malloc(ZCL_TX_REVIEW_MAX_BYTES);
    size_t signed_length = 0;
    bool valid = signatures && signed_wire &&
        blue_payment_live_run_bound(job->wire, job->length, job->plan,
            job->previous, job->previous_count, job->facts.fee_zat,
            (const uint8_t (*)[32])job->digests,
            live_exchange, wait_for_touch, device) &&
        review_inputs_unchanged(true, rpc_binary, &job->tip,
            job->wire, job->length, job->previous, job->previous_count) &&
        blue_payment_host_sign(job->previous_count, owned->paths,
            (const uint8_t (*)[20])owned->hashes,
            (const uint8_t (*)[32])job->digests, live_exchange,
            signing_approval, device, zcl_host_hash160,
            zcl_host_verify_signature, NULL, signatures) &&
        blue_payment_host_assemble_authenticated(job->wire, job->length,
            job->plan->wire_hash, signatures,
            (const uint8_t (*)[32])job->digests, owned->paths,
            (const uint8_t (*)[20])owned->hashes, job->previous_count,
            zcl_host_hash160, zcl_host_verify_signature, NULL,
            signed_wire, ZCL_TX_REVIEW_MAX_BYTES, &signed_length) &&
        review_inputs_unchanged(true, rpc_binary, &job->tip,
            job->wire, job->length, job->previous, job->previous_count);
    bool cleared = blue_payment_live_abort(live_exchange, device);
    if (!cleared)
        fputs("Blue did not confirm review erasure; restart the app.\n", stderr);
    if (valid && cleared) {
        valid = blue_signed_output_commit(stage, signed_wire, signed_length);
        if (valid) {
            zsha256(signed_wire, signed_length, saved_hash);
            *saved_length = signed_length;
        }
    }
    if (signed_wire) {
        erase_bytes(signed_wire, ZCL_TX_REVIEW_MAX_BYTES);
        free(signed_wire);
    }
    if (signatures) {
        erase_bytes(signatures,
            job->previous_count * sizeof *signatures);
        free(signatures);
    }
    return valid && cleared;
}

static bool execute_staged_sign(review_job *job, live_device *device,
    const char *rpc_binary, const char *output_path,
    const blue_payment_host_ownership *owned) {
    blue_signed_output stage = {.directory_fd = -1, .file_fd = -1};
    if (!blue_signed_output_begin(output_path, &stage)) return false;
    uint8_t saved_hash[32] = {0};
    size_t saved_length = 0;
    printf("Signing %u input(s), %u output(s), fee %llu zatoshi; node next height %u, branch %08x.\n",
        job->facts.transparent_inputs, job->facts.transparent_outputs,
        (unsigned long long)job->facts.fee_zat, job->tip.next_height,
        job->branch_id);
    puts("Inputs assigned to the internal path are provisional until the Blue verifies ownership.");
    fflush(stdout);
    bool valid = review_inputs_unchanged(true, rpc_binary, &job->tip,
        job->wire, job->length, job->previous, job->previous_count) &&
        sign_bound_job(job, device, rpc_binary, &stage, owned,
            saved_hash, &saved_length);
    blue_signed_output_discard(&stage);
    if (valid) {
        printf("Saved %zu verified signed bytes; SHA-256 ", saved_length);
        for (size_t i = 0; i < sizeof saved_hash; ++i)
            printf("%02x", saved_hash[i]);
        puts(". No transaction was broadcast.");
    }
    return valid;
}

static bool run_device(review_job *job, const char *device_path,
    const char *rpc_binary, const char *output_path) {
    live_device device = {.fd = open_blue(device_path),
                          .outputs = job->plan->count};
    if (device.fd < 0) {
        fputs("The selected interface is not an accessible Ledger Blue.\n",
            stderr);
        return false;
    }
    uint8_t external[20];
    blue_payment_host_ownership *owned = malloc(sizeof *owned);
    bool valid = owned && blue_external_hash(&device, external) &&
        blue_payment_host_propose_paths(job->wire, job->length,
            job->previous, job->previous_count, sha256_bytes,
            external, owned) &&
        same_facts(&owned->facts, &job->facts) &&
        execute_staged_sign(job, &device, rpc_binary, output_path, owned);
    if (!valid) (void)blue_payment_live_abort(live_exchange, &device);
    (void)close(device.fd);
    free(owned);
    if (!valid)
        fputs("Signing stopped. Check the output path before retrying; a complete signed file may remain after a publication error. Z23 did not broadcast.\n",
              stderr);
    return valid;
}
#endif

int main(int argc, char **argv) {
#ifdef BLUE_WALLET_SIGN_CLI
    if (argc < 7 || argc > 6 + ZCL_TX_PREFLIGHT_MAX_INPUTS ||
        strcmp(argv[1], "--sign-test") != 0) {
        fprintf(stderr, "Usage: %s --sign-test /dev/hidrawN /absolute/path/zcl-rpc UNSIGNED_TX.bin OUTPUT_TX.bin PREVIOUS_TX.bin...\n",
            argv[0]);
        return 2;
    }
#else
    if (argc < 6 || argc > 5 + ZCL_TX_PREFLIGHT_MAX_INPUTS ||
        strcmp(argv[1], "--test") != 0) {
        fprintf(stderr, "Usage: %s --test /dev/hidrawN /absolute/path/zcl-rpc UNSIGNED_TX.bin PREVIOUS_TX.bin...\n",
            argv[0]);
        return 2;
    }
#endif
    review_job *job = calloc(1, sizeof *job);
    if (!job) {
        fputs("Cannot allocate the Blue review job.\n", stderr);
        return 1;
    }
    job->previous_count = (size_t)argc -
#ifdef BLUE_WALLET_SIGN_CLI
        6;
    bool valid = prepare_wire(job, argv[3], argv[4]) &&
        prepare_inputs(job, argv[3], argv + 6) &&
        run_device(job, argv[2], argv[3], argv[5]);
#else
        5;
    bool valid = prepare_wire(job, argv[3], argv[4]) &&
        prepare_inputs(job, argv[3], argv + 5) &&
        run_device(job, argv[2], argv[3]);
#endif
    free_job(job);
    return valid ? 0 : 1;
}
