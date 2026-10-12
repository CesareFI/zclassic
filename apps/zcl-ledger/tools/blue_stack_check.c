/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue stack check requires ISO C23"
#endif

enum { FRAME_COUNT = 71, WALLET_FRAME_COUNT = 61,
       REVIEW_FRAME_COUNT = 10, REVIEW_REQUIRED_FRAME_COUNT = 64,
       STACK_MARGIN = 512,
       PATH_COUNT = 25 };

static const char *const frame_names[FRAME_COUNT] = {
    "answer_command", "blue_review_app_command", "blue_review_handle",
    "zcl_zip243_shielded_digest", "zcl_tx_review_parse", "io_event",
    "show_latest", "blue_review_app_next", "blue_review_screen_output",
    "zcl_tx_outputs_visit", "main", "blue_wallet_handle",
    "blue_wallet_receive_split", "zcl_base58_encode",
    "wallet_payment_command", "blue_payment_apdu_handle", "dispatch",
    "blue_payment_review_feed", "zcl_tx_replay_zip243_feed_review",
    "zcl_tx_stream_feed", "output_seen", "capture_output",
    "blue_payment_screen_format", "output_address",
    "blue_payment_review_finish", "zcl_tx_replay_zip243_finish",
    "final_digest", "continue_review",
    "blue_payment_apdu_touch_continue", "blue_payment_review_acknowledge",
    "wallet_payment_display", "blue_payment_review_next_pass",
    "zcl_tx_replay_zip243_next", "zcl_tx_previous_stream_begin",
    "zcl_tx_previous_stream_feed", "zcl_tx_previous_stream_finish",
    "previous_compact_done", "previous_output_done", "capture_input",
    "zcl_tx_replay_zip243_bound_digest", "show_totals", "show_fee",
    "blue_payment_amount_text", "blue_payment_account_classify",
    "blue_payment_screen_mark_account", "confirm_review",
    "blue_payment_apdu_touch_approve", "blue_payment_sign_next",
    "blue_wallet_sign_digest", "blue_payment_apdu_take_digest",
    "blue_ecdsa_der_low_s", "blue_wallet_public_hash160",
    "blue_payment_sign_command", "derive_public_key", "io_exchange",
    "cx_hash", "os_perso_derive_node_bip32",
    "cx_ecfp_generate_pair", "cx_hash_sha256",
    "cx_ecfp_init_private_key", "cx_ripemd160_init",
    "blue_review_abort", "blue_review_app_reset", "display_review",
    "erase_review_state", "reset_after_usb", "approve_sign",
    "sign_bound_digest", "sign_records_match", "hash_sha256",
    "overlaps_wallet_display"
};

typedef struct {
    unsigned bytes[FRAME_COUNT];
    bool present[FRAME_COUNT];
} stack_frames;

static bool read_stack_reserve(const char *path, unsigned *reserve) {
    FILE *file = fopen(path, "r");
    if (!file) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof line, file)) {
        unsigned value;
        if (sscanf(line, " STACK_SIZE = %u", &value) == 1) {
            if (found) { fclose(file); return false; }
            *reserve = value;
            found = true;
        }
    }
    bool valid = found && !ferror(file);
    if (fclose(file) != 0) valid = false;
    return valid;
}

static bool record_frame(char *line, stack_frames *frames) {
    char *tab = strchr(line, '\t');
    if (!tab) return false;
    *tab = 0;
    char *name = strrchr(line, ':');
    if (!name) return false;
    ++name;
    for (unsigned i = 0; i < FRAME_COUNT; ++i) {
        if (strcmp(name, frame_names[i]) != 0) continue;
        char *end;
        errno = 0;
        unsigned long bytes = strtoul(tab + 1, &end, 10);
        if (errno || end == tab + 1 || *end != '\t' ||
            bytes > UINT_MAX || frames->present[i]) return false;
        frames->bytes[i] = (unsigned)bytes;
        frames->present[i] = true;
    }
    return true;
}

static bool read_stack_usage(const char *path, stack_frames *frames) {
    FILE *file = fopen(path, "r");
    if (!file) return false;
    char line[512];
    bool valid = true;
    while (fgets(line, sizeof line, file)) {
        if (!strchr(line, '\n') || !record_frame(line, frames)) {
            valid = false;
            break;
        }
    }
    if (ferror(file)) valid = false;
    if (fclose(file) != 0) valid = false;
    return valid;
}

static unsigned sum_frames(const stack_frames *frames,
                           const unsigned *indices, size_t count) {
    unsigned sum = 0;
    for (size_t i = 0; i < count; ++i) sum += frames->bytes[indices[i]];
    return sum;
}

static unsigned largest_frame(const stack_frames *frames,
                              const unsigned *indices, size_t count) {
    unsigned largest = 0;
    for (size_t i = 0; i < count; ++i)
        if (frames->bytes[indices[i]] > largest)
            largest = frames->bytes[indices[i]];
    return largest;
}

static void report_signing_candidate(const stack_frames *frames,
                                     unsigned paths[PATH_COUNT]) {
    static const unsigned prefix[] = {10, 0, 14, 52, 47};
    const unsigned base = sum_frames(frames, prefix,
        sizeof prefix / sizeof *prefix);
    paths[18] = base + frames->bytes[67] + frames->bytes[48];
    paths[19] = base + frames->bytes[49];
    paths[20] = base + frames->bytes[50];
    paths[21] = base + frames->bytes[51];
    paths[23] = base + frames->bytes[67] + frames->bytes[68] +
        frames->bytes[69] + frames->bytes[58];
    printf("Signing paths: derive %u; digest %u; DER %u; public hash %u; record check %u; BOLOS frames excluded\n",
           paths[18], paths[19], paths[20], paths[21], paths[23]);
}

static bool frame_required(bool wallet, unsigned index) {
    if (wallet)
        return index == 0 || index == 5 || index == 66 || index >= 67 ||
            (index >= REVIEW_FRAME_COUNT && index < WALLET_FRAME_COUNT);
    return index < REVIEW_FRAME_COUNT ||
        (index >= WALLET_FRAME_COUNT &&
         index < REVIEW_REQUIRED_FRAME_COUNT);
}

static bool collect_frames(int argc, char **argv, int script_arg,
                           bool wallet, stack_frames *frames,
                           unsigned *reserve) {
    if (!read_stack_reserve(argv[script_arg], reserve)) {
        fputs("Cannot read Blue stack reserve.\n", stderr);
        return false;
    }
    if (*reserve > UINT_MAX / FRAME_COUNT) {
        fputs("Blue stack reserve exceeds path-sum limit.\n", stderr);
        return false;
    }
    for (int i = script_arg + 1; i < argc; ++i)
        if (!read_stack_usage(argv[i], frames)) {
            fprintf(stderr, "Cannot read stack usage: %s\n", argv[i]);
            return false;
    }
    for (unsigned i = 0; i < FRAME_COUNT; ++i) {
        if (frames->present[i] && frames->bytes[i] > *reserve) {
            fprintf(stderr, "Frame exceeds Blue stack reserve: %s\n",
                    frame_names[i]);
            return false;
        }
        if (frame_required(wallet, i) && !frames->present[i]) {
            fprintf(stderr, "Missing stack frame: %s\n", frame_names[i]);
            return false;
        }
    }
    return true;
}

static void report_paths(const stack_frames *frames, bool wallet,
                         unsigned reserve, unsigned paths[PATH_COUNT]) {
    static const unsigned apdu[] = {0, 1, 2, 3, 4};
    static const unsigned ui[] = {0, 5, 6, 7, 8, 9, 4};
    static const unsigned review_usb[] = {0, 5, 65, 64, 61, 62, 63};
    static const unsigned wallet_derive[] = {10, 53};
    static const unsigned derive_wrappers[] = {56, 57, 59};
    static const unsigned layout_helpers[] = {12, 13};
    static const unsigned wallet_apdu[] = {10, 0, 11};
    static const unsigned wallet_storage[] = {10, 0, 14, 70};
    static const unsigned wallet_event[] = {10, 0, 54, 5};
    static const unsigned wallet_upload[] = {10, 0, 14, 15, 16, 17, 18,
        19, 20, 21, 38};
    static const unsigned wallet_format[] = {10, 0, 14, 15, 16, 22, 23, 13};
    static const unsigned wallet_finish[] = {10, 0, 14, 15, 16, 24, 25, 26};
    static const unsigned wallet_next[] = {10, 0, 14, 15, 16, 31, 32};
    static const unsigned wallet_touch[] = {10, 0, 54, 5, 27, 28, 43, 29,
        30, 42};
    static const unsigned wallet_previous_begin[] = {10, 0, 14, 15, 16, 33};
    static const unsigned wallet_previous_feed[] = {10, 0, 14, 15, 16,
        34, 36, 37};
    static const unsigned wallet_previous_finish[] = {10, 0, 14, 15, 16, 35,
        39, 26};
    static const unsigned wallet_post_reply_fee[] = {10, 0, 30, 42};
    static const unsigned wallet_output_display[] = {10, 0, 30, 44, 43};
    static const unsigned wallet_totals_touch[] = {10, 0, 54, 5, 40, 30, 42};
    static const unsigned wallet_fee_touch[] = {10, 0, 54, 5, 41, 30, 42};
    static const unsigned wallet_confirm_touch[] = {10, 0, 54, 5, 45, 46,
        30, 42};
    static const unsigned wallet_approve_touch[] = {10, 0, 54, 5, 66, 46,
        30, 42};
    static const unsigned wallet_startup_hash[] = {10, 51};
    static const unsigned hash_wrappers[] = {55, 58, 60};
    memset(paths, 0, sizeof(unsigned) * PATH_COUNT);
    if (wallet) {
        paths[0] = sum_frames(frames, wallet_derive,
            sizeof wallet_derive / sizeof *wallet_derive) +
            largest_frame(frames, derive_wrappers,
                sizeof derive_wrappers / sizeof *derive_wrappers);
        paths[1] = frames->bytes[10] + largest_frame(frames,
            layout_helpers, sizeof layout_helpers / sizeof *layout_helpers);
        paths[2] = sum_frames(frames, wallet_apdu,
            sizeof wallet_apdu / sizeof *wallet_apdu);
        paths[3] = sum_frames(frames, wallet_event,
            sizeof wallet_event / sizeof *wallet_event);
        paths[24] = sum_frames(frames, wallet_storage,
            sizeof wallet_storage / sizeof *wallet_storage);
        paths[4] = sum_frames(frames, wallet_upload,
            sizeof wallet_upload / sizeof *wallet_upload);
        paths[5] = sum_frames(frames, wallet_format,
            sizeof wallet_format / sizeof *wallet_format);
        paths[6] = sum_frames(frames, wallet_finish,
            sizeof wallet_finish / sizeof *wallet_finish);
        paths[7] = sum_frames(frames, wallet_next,
            sizeof wallet_next / sizeof *wallet_next);
        paths[8] = sum_frames(frames, wallet_touch,
            sizeof wallet_touch / sizeof *wallet_touch);
        paths[9] = sum_frames(frames, wallet_previous_begin,
            sizeof wallet_previous_begin / sizeof *wallet_previous_begin);
        paths[10] = sum_frames(frames, wallet_previous_feed,
            sizeof wallet_previous_feed / sizeof *wallet_previous_feed);
        paths[11] = sum_frames(frames, wallet_previous_finish,
            sizeof wallet_previous_finish / sizeof *wallet_previous_finish);
        paths[12] = sum_frames(frames, wallet_post_reply_fee,
            sizeof wallet_post_reply_fee / sizeof *wallet_post_reply_fee);
        paths[13] = sum_frames(frames, wallet_output_display,
            sizeof wallet_output_display / sizeof *wallet_output_display);
        paths[14] = sum_frames(frames, wallet_totals_touch,
            sizeof wallet_totals_touch / sizeof *wallet_totals_touch);
        paths[15] = sum_frames(frames, wallet_fee_touch,
            sizeof wallet_fee_touch / sizeof *wallet_fee_touch);
        paths[16] = sum_frames(frames, wallet_confirm_touch,
            sizeof wallet_confirm_touch / sizeof *wallet_confirm_touch);
        paths[22] = sum_frames(frames, wallet_approve_touch,
            sizeof wallet_approve_touch / sizeof *wallet_approve_touch) +
            frames->bytes[69] + frames->bytes[58];
        paths[17] = sum_frames(frames, wallet_startup_hash,
            sizeof wallet_startup_hash / sizeof *wallet_startup_hash) +
            largest_frame(frames, hash_wrappers,
                sizeof hash_wrappers / sizeof *hash_wrappers);
        printf("Blue stack reserve %u; derive %u; layout %u; receive APDU %u; storage check %u; event %u; payment upload %u; format %u; finish %u; next %u; touch %u; previous begin %u; feed %u; finish %u; post-reply fee %u; output display %u; totals touch %u; fee touch %u; confirm touch %u; approve touch %u; startup hash %u; margin %u\n",
               reserve, paths[0], paths[1], paths[2], paths[24], paths[3], paths[4],
               paths[5], paths[6], paths[7], paths[8], paths[9], paths[10],
               paths[11], paths[12], paths[13], paths[14], paths[15],
               paths[16], paths[22], paths[17],
               STACK_MARGIN);
    } else {
        paths[0] = sum_frames(frames, apdu, sizeof apdu / sizeof *apdu);
        paths[1] = sum_frames(frames, ui, sizeof ui / sizeof *ui);
        paths[2] = sum_frames(frames, review_usb,
            sizeof review_usb / sizeof *review_usb);
        printf("Blue stack reserve %u; APDU path %u; screen path %u; USB reset %u; margin %u\n",
               reserve, paths[0], paths[1], paths[2], STACK_MARGIN);
    }
}

int main(int argc, char **argv) {
    bool wallet = argc > 1 && strcmp(argv[1], "--wallet") == 0;
    int script_arg = wallet ? 2 : 1;
    if (argc < script_arg + 2) {
        fprintf(stderr, "Usage: %s [--wallet] SDK_SCRIPT_LD FILE.su...\n",
                argv[0]);
        return 2;
    }
    unsigned reserve = 0, paths[PATH_COUNT];
    stack_frames frames = {0};
    if (!collect_frames(argc, argv, script_arg, wallet, &frames, &reserve))
        return 1;
    report_paths(&frames, wallet, reserve, paths);
    if (wallet) report_signing_candidate(&frames, paths);
    bool fits = reserve >= STACK_MARGIN;
    for (size_t i = 0; i < sizeof paths / sizeof *paths; ++i)
        if (fits && paths[i] > reserve - STACK_MARGIN) fits = false;
    if (!fits) {
        fputs("Blue stack budget exceeded; refusing image.\n", stderr);
        return 1;
    }
    return 0;
}
