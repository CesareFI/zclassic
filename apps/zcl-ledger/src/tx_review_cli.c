/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_review_protocol.h"
#include "blue_review_simulate.h"
#include "ledger_hid.h"
#include "zcl_address.h"
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"
#include "zcl_zip243_host.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/hidraw.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_file(const char *path, uint8_t **bytes, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat info;
    if (fd < 0) return -1;
    if (fstat(fd, &info) < 0 || !S_ISREG(info.st_mode) ||
        info.st_size < 29 || info.st_size > ZCL_TX_REVIEW_MAX_BYTES) {
        close(fd);
        return -1;
    }
    size_t count = (size_t)info.st_size;
    uint8_t *buffer = malloc(count);
    if (!buffer) { close(fd); return -1; }
    size_t offset = 0;
    while (offset < count) {
        ssize_t got = read(fd, buffer + offset, count - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        offset += (size_t)got;
    }
    uint8_t extra;
    ssize_t trailing = offset == count ? read(fd, &extra, 1) : -1;
    close(fd);
    if (offset != count || trailing != 0) { free(buffer); return -1; }
    *bytes = buffer;
    *length = count;
    return 0;
}

static int send_expected(int fd, const uint8_t *apdu, size_t apdu_length,
                         const uint8_t *expected, size_t expected_length) {
    uint8_t reply[LEDGER_HID_MAX_RESPONSE];
    size_t length = 0;
    if (ledger_hid_exchange_timeout(fd, apdu, apdu_length, reply,
                                    sizeof reply, &length, 5000) < 0 ||
        length != expected_length + 2 ||
        (expected_length && memcmp(reply, expected, expected_length) != 0) ||
        reply[length - 2] != 0x90 || reply[length - 1] != 0) return -1;
    return 0;
}

static int send_transaction(int fd, const uint8_t *wire, size_t length) {
    uint8_t command[5 + 220] = {0xa5, 0x10, 0, 0, 2};
    command[5] = (uint8_t)length;
    command[6] = (uint8_t)(length >> 8);
    if (send_expected(fd, command, 7, NULL, 0) < 0) {
        fputs("Blue review begin failed.\n", stderr);
        return -1;
    }
    for (size_t offset = 0; offset < length; offset += 220) {
        size_t count = length - offset < 220 ? length - offset : 220;
        command[1] = 0x11;
        command[4] = (uint8_t)count;
        memcpy(command + 5, wire + offset, count);
        if (send_expected(fd, command, 5 + count, NULL, 0) < 0) {
            fprintf(stderr, "Blue review chunk at byte %zu failed.\n", offset);
            return -1;
        }
    }
    return 0;
}

static int open_blue_device(const char *device) {
    int fd = open(device, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct hidraw_devinfo info;
    if (fd < 0) return -1;
    if (ioctl(fd, HIDIOCGRAWINFO, &info) < 0 ||
        info.vendor != 0x2c97 || info.product != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int blue_review_exchange(int fd, const uint8_t *wire, size_t length,
                                bool has_branch, uint32_t branch_id,
                                const uint8_t zip_digest[32],
                                const uint8_t *summary, size_t summary_length) {
    static const uint8_t probe[] = {0xa5, 1, 0, 0, 0};
    static const uint8_t identity[] = {'Z', 'C', 'L', 6, 0x40};
    uint8_t final[] = {0xa5, 0x12, 0, 0, 0};
    uint8_t zip_command[9] = {0xa5, 0x14, 0, 0, 4};
    for (unsigned i = 0; i < 4; ++i)
        zip_command[5 + i] = (uint8_t)(branch_id >> (8 * i));
    int result = 0;
    if (send_expected(fd, probe, sizeof probe,
                      identity, sizeof identity) < 0) {
        fputs("Blue review identity failed.\n", stderr);
        result = -1;
    }
    if (result == 0 && send_transaction(fd, wire, length) < 0) result = -1;
    if (result == 0 && has_branch &&
        send_expected(fd, zip_command, sizeof zip_command,
                      zip_digest, 32) < 0) {
        fputs("Blue ZIP-243 digest request failed.\n", stderr);
        result = -1;
    }
    if (result == 0 && send_expected(fd, final, sizeof final,
                                     summary, summary_length) < 0) {
        fputs("Blue review summary failed.\n", stderr);
        result = -1;
    }
    return result;
}

static int blue_review(const char *device, const uint8_t *wire, size_t length,
                       const zcl_tx_review *review, bool has_branch,
                       uint32_t branch_id, const uint8_t zip_digest[32]) {
    if (length > ZCL_BLUE_REVIEW_MAX_BYTES) return -1;
    int fd = open_blue_device(device);
    if (fd < 0) return -1;
    uint8_t summary[76];
    blue_review_encode_summary(review, summary);
    if (!SHA256(wire, length, summary + 44)) {
        close(fd);
        return -1;
    }
    int result = blue_review_exchange(fd, wire, length, has_branch, branch_id,
                                      zip_digest, summary, sizeof summary);
    close(fd);
    return result;
}

static bool parse_branch(const char *text, uint32_t *branch) {
    if (strlen(text) != 10 || text[0] != '0' || text[1] != 'x') return false;
    uint32_t value = 0;
    for (size_t i = 2; i < 10; ++i) {
        char digit = text[i];
        unsigned nibble;
        if (digit >= '0' && digit <= '9') nibble = (unsigned)(digit - '0');
        else if (digit >= 'a' && digit <= 'f') nibble = (unsigned)(digit - 'a' + 10);
        else if (digit >= 'A' && digit <= 'F') nibble = (unsigned)(digit - 'A' + 10);
        else return false;
        value = (value << 4) | nibble;
    }
    *branch = value;
    return true;
}

static bool parse_args(int argc, char **argv, bool *json,
                       const char **device, bool *simulate_app,
                       bool *has_branch,
                       uint32_t *branch, const char **file) {
    int index = 1;
    *json = index < argc && strcmp(argv[index], "--json") == 0;
    if (*json) ++index;
    *device = NULL;
    *simulate_app = index < argc &&
        strcmp(argv[index], "--simulate-app") == 0;
    if (*simulate_app) ++index;
    if (index < argc && strcmp(argv[index], "--blue") == 0) {
        if (*simulate_app) return false;
        if (++index >= argc) return false;
        *device = argv[index++];
    }
    *has_branch = index < argc && strcmp(argv[index], "--branch-id") == 0;
    if (*has_branch) {
        if (++index >= argc || !parse_branch(argv[index++], branch)) return false;
    }
    if (index != argc - 1) return false;
    *file = argv[index];
    return true;
}

static int zip243_digest(const uint8_t *wire, size_t length,
                         uint32_t branch_id, uint8_t digest[32]) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    return zcl_zip243_shielded_digest(wire, length, branch_id,
                                      &hasher, digest);
}

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) printf("%02x", bytes[i]);
}

typedef struct {
    bool json;
    uint32_t shown;
} output_view;

static const char *output_type_name(zcl_tx_output_type type) {
    switch (type) {
    case ZCL_TX_OUTPUT_P2PKH: return "p2pkh";
    case ZCL_TX_OUTPUT_P2SH: return "p2sh";
    case ZCL_TX_OUTPUT_OP_RETURN: return "op_return";
    case ZCL_TX_OUTPUT_OTHER: return "other";
    }
    return "other";
}

static bool format_zcl_amount(uint64_t zat, char amount[32]) {
    int count = snprintf(amount, 32, "%" PRIu64 ".%08" PRIu64,
                         zat / 100000000, zat % 100000000);
    return count > 0 && count < 32;
}

static bool print_output(void *context, const zcl_tx_output *output) {
    output_view *view = context;
    if (output->index >= 32) return true;
    bool address_type = output->type == ZCL_TX_OUTPUT_P2PKH ||
                        output->type == ZCL_TX_OUTPUT_P2SH;
    char amount[32];
    if (!format_zcl_amount(output->value_zat, amount)) return false;
    char address[ZCL_ADDRESS_SIZE];
    if (address_type) {
        const uint8_t *hash = output->script +
            (output->type == ZCL_TX_OUTPUT_P2PKH ? 3 : 2);
        if (zcl_address_from_hash160(hash,
            output->type == ZCL_TX_OUTPUT_P2SH, address) < 0) return false;
    }
    uint8_t script_digest[SHA256_DIGEST_LENGTH];
    if (!address_type && !SHA256(output->script, output->script_length,
                                 script_digest)) return false;
    if (view->json) {
        printf("%s{\"index\":%" PRIu32 ",\"value_zat\":%" PRIu64
               ",\"amount_zcl\":\"%s\",\"type\":\"%s\"",
               view->shown ? "," : "", output->index, output->value_zat,
               amount, output_type_name(output->type));
        if (address_type) printf(",\"address\":\"%s\"", address);
        else {
            printf(",\"script_bytes\":%zu,\"script_sha256\":\"",
                   output->script_length);
            print_hex(script_digest, sizeof script_digest);
            putchar('"');
        }
        putchar('}');
    } else {
        printf("Output %" PRIu32 ": %s ZCL (%" PRIu64 " zatoshi), %s",
               output->index, amount, output->value_zat,
               output_type_name(output->type));
        if (address_type) printf(" -> %s\n", address);
        else {
            printf(" (%zu bytes, script SHA-256 ", output->script_length);
            print_hex(script_digest, sizeof script_digest);
            puts(")");
        }
    }
    ++view->shown;
    return true;
}

typedef struct {
    const zcl_tx_review *review;
    const zcl_tx_script_facts *scripts;
    const uint8_t *wire;
    size_t length;
    const uint8_t *transaction_hash;
    const uint8_t *zip_digest;
    bool has_branch;
    bool blue_parsed;
    bool app_simulated;
    uint32_t branch_id;
} review_report;

static bool print_json(const review_report *report) {
    const zcl_tx_review *review = report->review;
    const zcl_tx_script_facts *scripts = report->scripts;
    char public_amount[32];
    if (!format_zcl_amount(review->transparent_output_zat,
                           public_amount)) return false;
    printf("{\"ok\":true,\"format\":\"zcl-sapling-v4\","
           "\"transparent_inputs\":%" PRIu32 ","
           "\"transparent_outputs\":%" PRIu32 ","
           "\"sapling_spends\":%" PRIu32 ","
           "\"sapling_outputs\":%" PRIu32 ","
           "\"sprout_joinsplits\":%" PRIu32 ","
           "\"p2pkh_outputs\":%" PRIu32 ","
           "\"p2sh_outputs\":%" PRIu32 ","
           "\"op_return_outputs\":%" PRIu32 ","
           "\"other_outputs\":%" PRIu32 ","
           "\"zslp_marker\":%s,"
           "\"transparent_output_zat\":%" PRIu64 ","
           "\"transparent_output_zcl\":\"%s\","
           "\"value_balance_zat\":%" PRId64 ","
           "\"lock_time\":%" PRIu32 ","
           "\"expiry_height\":%" PRIu32 ","
           "\"shielded_details_verified\":false,"
           "\"signing_ready\":false,"
           "\"blue_parsed\":%s,\"app_simulated\":%s",
           review->transparent_inputs, review->transparent_outputs,
           review->sapling_spends, review->sapling_outputs,
           review->sprout_joinsplits, scripts->p2pkh_outputs,
           scripts->p2sh_outputs, scripts->op_return_outputs,
           scripts->other_outputs,
           scripts->zslp_marker ? "true" : "false",
           review->transparent_output_zat, public_amount,
           review->value_balance_zat, review->lock_time,
           review->expiry_height, report->blue_parsed ? "true" : "false",
           report->app_simulated ? "true" : "false");
    if (report->has_branch) {
        printf(",\"zip243_branch_id\":\"0x%08" PRIx32
               "\",\"zip243_shielded_digest\":\"", report->branch_id);
        print_hex(report->zip_digest, 32);
        printf("\",\"blue_zip243_matched\":%s",
               report->blue_parsed ? "true" : "false");
        printf(",\"simulated_zip243_matched\":%s",
               report->app_simulated ? "true" : "false");
    }
    fputs(",\"transaction_sha256\":\"", stdout);
    print_hex(report->transaction_hash, SHA256_DIGEST_LENGTH);
    fputs("\",\"outputs\":[", stdout);
    output_view view = {.json = true};
    if (zcl_tx_outputs_visit(report->wire, report->length,
                             print_output, &view) < 0) return false;
    printf("],\"output_details_truncated\":%s}\n",
           review->transparent_outputs > view.shown ? "true" : "false");
    return true;
}

static bool print_text(const review_report *report) {
    const zcl_tx_review *review = report->review;
    const zcl_tx_script_facts *scripts = report->scripts;
    char public_amount[32];
    if (!format_zcl_amount(review->transparent_output_zat,
                           public_amount)) return false;
    printf("ZCL Sapling v4: %" PRIu32 " transparent input(s), %" PRIu32
           " output(s), %" PRIu32 " Sapling spend(s), %" PRIu32
           " Sapling output(s), %" PRIu32 " Sprout JoinSplit(s).\n",
           review->transparent_inputs, review->transparent_outputs,
           review->sapling_spends, review->sapling_outputs,
           review->sprout_joinsplits);
    printf("Script outputs: %" PRIu32 " P2SH, %" PRIu32
           " OP_RETURN; first output has ZSLP marker: %s.\n",
           scripts->p2sh_outputs, scripts->op_return_outputs,
           scripts->zslp_marker ? "yes" : "no");
    output_view view = {0};
    if (zcl_tx_outputs_visit(report->wire, report->length,
                             print_output, &view) < 0) return false;
    if (review->transparent_outputs > view.shown)
        printf("%" PRIu32 " additional output(s) omitted.\n",
               review->transparent_outputs - view.shown);
    printf("Public output total: %s ZCL (%" PRIu64
           " zatoshi); value balance: %" PRId64 " zatoshi.\n",
           public_amount, review->transparent_output_zat,
           review->value_balance_zat);
    puts("Structural review only. Shielded recipients, amounts, fee, proofs, and signatures are unverified.");
    if (report->blue_parsed)
        puts("The Blue returned the same structural summary; no key operation occurred.");
    if (report->app_simulated)
        puts("C23 app simulation matched; no Ledger device was opened.");
    if (report->has_branch) {
        printf("ZIP-243 shielded digest for branch 0x%08" PRIx32 ": ",
               report->branch_id);
        print_hex(report->zip_digest, 32);
        putchar('\n');
        if (report->blue_parsed)
            puts("Blue and host ZIP-243 digests matched; no signing was requested.");
        if (report->app_simulated)
            puts("Simulated app and host ZIP-243 digests matched; no signing was requested.");
    }
    fputs("Transaction SHA-256: ", stdout);
    print_hex(report->transaction_hash, SHA256_DIGEST_LENGTH);
    putchar('\n');
    return true;
}

static int report_failure(bool json, const char *code,
                          const char *message, int exit_status) {
    if (json) printf("{\"ok\":false,\"error\":\"%s\"}\n", code);
    else fputs(message, stderr);
    return exit_status;
}

typedef struct {
    const uint8_t *wire;
    size_t length;
    zcl_tx_review review;
    zcl_tx_script_facts scripts;
    uint8_t transaction_hash[SHA256_DIGEST_LENGTH];
    uint8_t zip_digest[32];
    const char *device;
    uint32_t branch_id;
    bool has_branch;
    bool simulate_app;
} review_work;

static const char *check_review(review_work *work) {
    if (zcl_tx_review_parse(work->wire, work->length, &work->review) < 0)
        return "invalid_transaction";
    if (!SHA256(work->wire, work->length, work->transaction_hash))
        return "transaction_hash_failed";
    if (zcl_tx_script_facts_parse(work->wire, work->length,
                                   &work->scripts) < 0)
        return "script_review_failed";
    if (work->has_branch && zip243_digest(work->wire, work->length,
            work->branch_id, work->zip_digest) < 0)
        return "zip243_failed";
    if (work->device && blue_review(work->device, work->wire, work->length,
            &work->review, work->has_branch, work->branch_id,
            work->zip_digest) < 0)
        return "blue_review_failed";
    if (work->simulate_app &&
        !blue_review_simulate(work->wire, work->length, &work->review,
                              work->has_branch, work->branch_id,
                              work->zip_digest))
        return "app_simulation_failed";
    return NULL;
}

int main(int argc, char **argv) {
    bool json = argc > 1 && strcmp(argv[1], "--json") == 0;
    const char *device, *file;
    bool has_branch, simulate_app;
    uint32_t branch_id = 0;
    if (!parse_args(argc, argv, &json, &device, &simulate_app, &has_branch,
                    &branch_id, &file)) {
        if (json) return report_failure(true, "invalid_arguments", "", 2);
        fprintf(stderr, "Usage: %s [--json] [--simulate-app | --blue /dev/hidrawN] [--branch-id 0xXXXXXXXX] TRANSACTION.bin\n", argv[0]);
        return 2;
    }
    uint8_t *wire = NULL;
    size_t length = 0;
    if (read_file(file, &wire, &length) < 0) {
        return report_failure(json, "file_read_failed",
            "Cannot read a regular transaction file of 29 bytes to 2 MiB.\n", 1);
    }
    review_work work = {.wire = wire, .length = length, .device = device,
                        .branch_id = branch_id, .has_branch = has_branch,
                        .simulate_app = simulate_app};
    const char *error = check_review(&work);
    if (error) {
        free(wire);
        return report_failure(json, error,
            "Transaction review failed; no signing was requested.\n", 1);
    }
    review_report report = {
        .review = &work.review, .scripts = &work.scripts, .wire = wire,
        .length = length, .transaction_hash = work.transaction_hash,
        .zip_digest = work.zip_digest, .has_branch = has_branch,
        .blue_parsed = device != NULL, .app_simulated = simulate_app,
        .branch_id = branch_id
    };
    bool printed = json ? print_json(&report) : print_text(&report);
    if (!printed) {
        free(wire);
        return report_failure(json, "output_review_failed",
                              "Transaction output review failed.\n", 1);
    }
    free(wire);
    return 0;
}
