/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue shielded stack check requires ISO C23"
#endif

enum { STACK_MARGIN = 512, FRAME_COUNT = 29 };

enum frame {
    ANSWER, EVENT, SHOW, APP_COMMAND, APP_NEXT, HANDLE, REPLAY_FEED,
    STREAM_FEED, OBSERVE, SHA_UPDATE, SHA_COMPRESS, REPLAY_FINISH,
    COMPLETE_PASS, SHA_FINAL, SCREEN_SUMMARY, SCREEN_FORMAT,
    SCREEN_PROGRESS, SCREEN_DIGEST, REPLAY_NEXT, STREAM_FINISH,
    REPLAY_BEGIN, STREAM_BEGIN, SHA_INIT, COMPACT_DONE,
    APP_RESET, ABORT, DISPLAY, ERASE, RESET
};

static const char *const names[FRAME_COUNT] = {
    "answer_command", "io_event", "show_latest",
    "blue_shielded_review_app_command", "blue_shielded_review_app_next",
    "blue_shielded_review_handle", "zcl_tx_shielded_replay_feed",
    "zcl_tx_shielded_stream_feed", "observe", "zsha256_update",
    "compress", "zcl_tx_shielded_replay_finish", "complete_pass",
    "zsha256_final", "blue_review_screen_zip243",
    "blue_review_screen_format", "blue_review_screen_progress",
    "blue_review_screen_zip243_digest", "zcl_tx_shielded_replay_next",
    "zcl_tx_shielded_stream_finish",
    "zcl_tx_shielded_replay_begin", "zcl_tx_shielded_stream_begin",
    "zsha256_init", "compact_done", "blue_shielded_review_app_reset",
    "blue_shielded_review_abort", "display_review",
    "erase_review_state", "reset_after_usb"
};

typedef struct {
    unsigned bytes[FRAME_COUNT];
    bool present[FRAME_COUNT];
} frames;

static bool stack_reserve(const char *path, unsigned *reserve) {
    FILE *file = fopen(path, "r");
    if (!file) return false;
    char line[512];
    unsigned found = 0;
    while (fgets(line, sizeof line, file)) {
        unsigned value;
        if (sscanf(line, " STACK_SIZE = %u", &value) == 1) {
            *reserve = value;
            ++found;
        }
    }
    bool valid = found == 1 && !ferror(file);
    if (fclose(file)) valid = false;
    return valid;
}

static bool record(char *line, frames *usage) {
    char *tab = strchr(line, '\t');
    if (!tab) return false;
    *tab = 0;
    char *name = strrchr(line, ':');
    if (!name) return false;
    ++name;
    for (unsigned i = 0; i < FRAME_COUNT; ++i) {
        if (strcmp(name, names[i])) continue;
        char *end;
        errno = 0;
        unsigned long value = strtoul(tab + 1, &end, 10);
        if (errno || end == tab + 1 || *end != '\t' ||
            value > UINT_MAX || usage->present[i]) return false;
        usage->bytes[i] = (unsigned)value;
        usage->present[i] = true;
    }
    return true;
}

static bool read_usage(const char *path, frames *usage) {
    FILE *file = fopen(path, "r");
    if (!file) return false;
    char line[512];
    bool valid = true;
    while (fgets(line, sizeof line, file)) {
        if (!strchr(line, '\n') || !record(line, usage)) {
            valid = false;
            break;
        }
    }
    if (ferror(file)) valid = false;
    if (fclose(file)) valid = false;
    return valid;
}

static unsigned path_bytes(const frames *usage,
    const enum frame *path, size_t length) {
    unsigned sum = 0;
    for (size_t i = 0; i < length; ++i) sum += usage->bytes[path[i]];
    return sum;
}

static bool check_paths(const frames *usage, unsigned reserve) {
    static const enum frame begin[] = {
        ANSWER, APP_COMMAND, HANDLE, REPLAY_BEGIN, STREAM_BEGIN, SHA_INIT
    };
    static const enum frame upload_parser[] = {
        ANSWER, APP_COMMAND, HANDLE, REPLAY_FEED, STREAM_FEED,
        COMPACT_DONE, OBSERVE
    };
    static const enum frame upload_hash[] = {
        ANSWER, APP_COMMAND, HANDLE, REPLAY_FEED, SHA_UPDATE, SHA_COMPRESS
    };
    static const enum frame advance[] = {
        ANSWER, APP_COMMAND, HANDLE, REPLAY_NEXT, COMPLETE_PASS,
        STREAM_FINISH, SHA_FINAL, SHA_COMPRESS
    };
    static const enum frame finish[] = {
        ANSWER, APP_COMMAND, HANDLE, REPLAY_FINISH, COMPLETE_PASS,
        STREAM_FINISH, SHA_FINAL, SHA_COMPRESS
    };
    static const enum frame progress[] = {
        ANSWER, APP_COMMAND, SCREEN_PROGRESS
    };
    static const enum frame summary[] = {
        ANSWER, APP_COMMAND, SCREEN_SUMMARY, SCREEN_FORMAT
    };
    static const enum frame digest_page[] = {
        EVENT, SHOW, APP_NEXT, SCREEN_DIGEST
    };
    static const enum frame usb_reset[] = {
        EVENT, RESET, ERASE, APP_RESET, ABORT, DISPLAY
    };
    static const struct {
        const char *name;
        const enum frame *path;
        size_t count;
    } paths[] = {
        {"begin", begin, sizeof begin / sizeof *begin},
        {"upload parser", upload_parser,
            sizeof upload_parser / sizeof *upload_parser},
        {"upload SHA-256", upload_hash,
            sizeof upload_hash / sizeof *upload_hash},
        {"advance", advance, sizeof advance / sizeof *advance},
        {"finish", finish, sizeof finish / sizeof *finish},
        {"progress", progress, sizeof progress / sizeof *progress},
        {"summary", summary, sizeof summary / sizeof *summary},
        {"digest page", digest_page,
            sizeof digest_page / sizeof *digest_page},
        {"USB reset", usb_reset,
            sizeof usb_reset / sizeof *usb_reset}
    };
    unsigned budget = reserve >= STACK_MARGIN ?
        reserve - STACK_MARGIN : 0;
    bool fits = reserve >= STACK_MARGIN;
    for (size_t i = 0; i < sizeof paths / sizeof *paths; ++i) {
        unsigned bytes = path_bytes(usage, paths[i].path, paths[i].count);
        printf("%s: %u/%u bytes\n", paths[i].name, bytes, budget);
        if (bytes > budget) fits = false;
    }
    return fits;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s SDK_SCRIPT_LD FILE.su...\n", argv[0]);
        return 2;
    }
    unsigned reserve = 0;
    if (!stack_reserve(argv[1], &reserve)) return 1;
    frames usage = {0};
    for (int i = 2; i < argc; ++i)
        if (!read_usage(argv[i], &usage)) return 1;
    for (unsigned i = 0; i < FRAME_COUNT; ++i)
        if ((i < ERASE && !usage.present[i]) ||
            (usage.present[i] && usage.bytes[i] > reserve)) {
            fprintf(stderr, "Missing or oversized stack frame: %s\n",
                names[i]);
            return 1;
        }
    if (!check_paths(&usage, reserve)) {
        fputs("Shielded Blue stack budget exceeded.\n", stderr);
        return 1;
    }
    return 0;
}
