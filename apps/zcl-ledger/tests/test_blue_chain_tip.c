/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_chain_tip.h"
#include "blue_utxo.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#undef NDEBUG
#include <assert.h>

static const char good[] =
    "{\"result\":{\"chain\":\"main\",\"blocks\":707001,"
    "\"headers\":707001,\"initialblockdownload\":false,\"bestblockhash\":"
    "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"},"
    "\"error\":null,\"id\":1}";
static const char txid[] =
    "0000000000000000000000000000000000000000000000000000000000000000";
static const uint8_t script[25] = {
    0x76, 0xa9, 0x14,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x88, 0xac
};
static const char live_script_hash[] =
    "e2f6c234985456932db846b2bf1a2fed2cb98b5b0f246f30711ea6148a76860e";
static const char utxo[] =
    "{\"result\":{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000000\","
    "\"coinbase\":false,\"height\":700000,\"num_outputs\":1,"
    "\"outputs\":[{\"n\":0,\"spent\":false,\"amount\":\"4.00000000\","
    "\"script_size\":25,\"script_sha256\":"
    "\"46402f61b3239cd80b93294e10b552d66a31b79c8fe7fdd92a832d00f832e82e\"}]},\"error\":null}";

static bool accepts(const char *reply) {
    blue_chain_tip tip;
    return blue_chain_tip_parse(reply, strlen(reply), &tip) &&
           tip.next_height == 707002;
}

static void replace_once(const char *source, const char *old,
                         const char *new_text, char changed[512]) {
    const char *at = strstr(source, old);
    assert(at);
    size_t prefix = (size_t)(at - source);
    size_t replacement = strlen(new_text);
    size_t suffix = strlen(at + strlen(old));
    assert(prefix + replacement + suffix < 512);
    memcpy(changed, source, prefix);
    memcpy(changed + prefix, new_text, replacement);
    memcpy(changed + prefix + replacement, at + strlen(old), suffix + 1);
}

static bool accepts_replacement(const char *old, const char *new_text) {
    char changed[512];
    replace_once(good, old, new_text, changed);
    return accepts(changed);
}

static bool utxo_replacement(const char *old, const char *new_text) {
    char changed[512];
    replace_once(utxo, old, new_text, changed);
    return blue_utxo_parse(changed, strlen(changed), txid, 0,
                           400000000, script, sizeof script, 707002);
}

static void fork_stdout_holder(const char *marker) {
    if (!marker) return;
    pid_t holder = fork();
    assert(holder >= 0);
    if (holder == 0) {
        struct timespec delay = {.tv_sec = 9};
        while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
        FILE *file = fopen(marker, "w");
        if (file) {
            (void)fputc('x', file);
            (void)fclose(file);
        }
        _exit(0);
    }
}

static void test_forked_holder(const char *rpc_binary) {
    char holder_marker[] = "/tmp/zcl-blue-holder-test-XXXXXX";
    int holder_fd = mkstemp(holder_marker);
    assert(holder_fd >= 0 && close(holder_fd) == 0);
    assert(setenv("BLUE_CHAIN_TIP_TEST_FORK_HOLDER", holder_marker, 1) == 0);
    blue_chain_tip tip;
    assert(!blue_chain_tip_query(rpc_binary, &tip));
    assert(unsetenv("BLUE_CHAIN_TIP_TEST_FORK_HOLDER") == 0);
    struct timespec delay = {.tv_sec = 3};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
    FILE *file = fopen(holder_marker, "r");
    assert(file);
    assert(fgetc(file) == EOF && fclose(file) == 0);
    assert(unlink(holder_marker) == 0);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "getblockchaininfo") == 0) {
        if (getenv("BLUE_CHAIN_TIP_TEST_STALL")) {
            struct timespec delay = {.tv_sec = 9};
            nanosleep(&delay, NULL);
        }
        const char *marker = getenv("BLUE_TIP_REORG_MARKER");
        if (marker) {
            FILE *file = fopen(marker, "r");
            if (file) {
                assert(fclose(file) == 0);
                char changed[sizeof good];
                memcpy(changed, good, sizeof good);
                char *hash = strstr(changed, "0123456789abcdef");
                assert(hash);
                hash[0] = '1';
                puts(changed);
                return 0;
            }
            file = fopen(marker, "w");
            assert(file && fclose(file) == 0);
        }
        fork_stdout_holder(getenv("BLUE_CHAIN_TIP_TEST_FORK_HOLDER"));
        puts(good);
        if (getenv("BLUE_CHAIN_TIP_TEST_CLOSE_STDOUT")) {
            assert(fflush(stdout) == 0);
            assert(close(STDOUT_FILENO) == 0);
            struct timespec delay = {.tv_sec = 9};
            nanosleep(&delay, NULL);
        }
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "gettxdetail") == 0) {
        const char *spent = getenv("BLUE_UTXO_TEST_SPENT") ? "true" : "false";
        const char *hash = getenv("BLUE_UTXO_TEST_BAD_SCRIPT")
            ? "12f6c234985456932db846b2bf1a2fed2cb98b5b0f246f30711ea6148a76860e"
            : live_script_hash;
        printf("{\"result\":{\"txid\":%s,\"coinbase\":false,"
               "\"height\":700000,\"num_outputs\":1,\"outputs\":["
               "{\"n\":0,\"spent\":%s,\"amount\":\"4.00000000\","
               "\"script_size\":25,\"script_sha256\":\"%s\"}]},"
               "\"error\":null,\"id\":1}\n",
               argv[2], spent, hash);
        return 0;
    }
    assert(argc == 1);
    assert(accepts(good));
    assert(!accepts_replacement("\"main\"", "\"test\""));
    assert(!accepts_replacement("\"blocks\":707001,",
                                "\"blocks\":707001,\"blocks\":707001,"));
    assert(!accepts_replacement("\"headers\":707001,",
                                "\"headers\":707002,"));
    assert(!accepts_replacement("\"initialblockdownload\":false,", ""));
    assert(!accepts_replacement("\"initialblockdownload\":false",
                                "\"initialblockdownload\":true"));
    assert(!accepts_replacement("\"initialblockdownload\":false",
                                "\"initialblockdownload\":null"));
    assert(!accepts_replacement("\"initialblockdownload\":false,",
                                "\"initialblockdownload\":false,"
                                "\"initialblockdownload\":false,"));
    assert(!accepts_replacement("\"error\":null", "\"error\":{}"));
    assert(!accepts_replacement("abcdef", "abcdeg"));
    assert(!accepts_replacement("\"chain\":\"main\",", ""));
    assert(blue_utxo_parse(utxo, strlen(utxo), txid, 0,
                           400000000, script, sizeof script, 707002));
    uint8_t wrong_script[sizeof script];
    memcpy(wrong_script, script, sizeof script);
    wrong_script[3] ^= 1;
    assert(!blue_utxo_parse(utxo, strlen(utxo), txid, 0,
                            400000000, wrong_script, sizeof wrong_script,
                            707002));
    assert(!utxo_replacement("\"spent\":false", "\"spent\":true"));
    assert(!utxo_replacement("4.00000000", "4.00000001"));
    assert(!utxo_replacement("\"height\":700000",
                             "\"height\":707002"));
    assert(!utxo_replacement("\"script_size\":25",
                             "\"script_size\":24"));
    assert(!utxo_replacement("\"script_sha256\":", "\"unused\":"));
    assert(!utxo_replacement("\"script_sha256\":",
                             "\"script_sha256\":\"46402f61b3239cd80b93294e10b552d66a31b79c8fe7fdd92a832d00f832e82e\",\"script_sha256\":"));
    assert(!utxo_replacement("46402f61b3239cd80b93294e10b552d66a31b79c8fe7fdd92a832d00f832e82e",
                             "16402f61b3239cd80b93294e10b552d66a31b79c8fe7fdd92a832d00f832e82e"));
    assert(!utxo_replacement("\"coinbase\":false,\"height\":700000",
                             "\"coinbase\":true,\"height\":706950"));
    assert(!utxo_replacement("\"n\":0,", "\"n\":0,\"n\":0,"));
    assert(!accepts("{\"result\":null,\"error\":null}"));
    assert(!accepts("{\"result\":{\"chain\":\"test\",\"blocks\":1,"
                    "\"headers\":1},\"error\":null}"));
    assert(!accepts("{\"result\":{\"chain\":\"main\",\"blocks\":1,"
                    "\"headers\":2,\"bestblockhash\":\"00\"},\"error\":null}"));
    assert(!accepts("{\"result\":{\"chain\":\"main\",\"blocks\":1,"
                    "\"headers\":1,\"bestblockhash\":\"00\"},\"error\":null}"));
    blue_chain_tip tip, same;
    assert(blue_chain_tip_query(argv[0], &tip));
    assert(tip.next_height == 707002);
    assert(blue_chain_tip_parse(good, strlen(good), &same));
    assert(blue_chain_tip_same(&tip, &same));
    assert(blue_chain_tip_still_current(argv[0], &tip));
    assert(!blue_chain_tip_still_current("/bin/false", &tip));
    assert(!blue_chain_tip_still_current(argv[0], NULL));
    char marker[] = "/tmp/zcl-blue-tip-test-XXXXXX";
    int marker_fd = mkstemp(marker);
    assert(marker_fd >= 0);
    assert(close(marker_fd) == 0);
    assert(unlink(marker) == 0);
    assert(setenv("BLUE_TIP_REORG_MARKER", marker, 1) == 0);
    assert(blue_chain_tip_still_current(argv[0], &tip));
    assert(!blue_chain_tip_still_current(argv[0], &tip));
    assert(unsetenv("BLUE_TIP_REORG_MARKER") == 0);
    assert(unlink(marker) == 0);
    assert(!blue_chain_tip_query("relative/path", &tip));
    assert(!blue_chain_tip_query("/bin/false", &tip));
    assert(setenv("BLUE_CHAIN_TIP_TEST_STALL", "1", 1) == 0);
    assert(!blue_chain_tip_query(argv[0], &tip));
    assert(unsetenv("BLUE_CHAIN_TIP_TEST_STALL") == 0);
    assert(setenv("BLUE_CHAIN_TIP_TEST_CLOSE_STDOUT", "1", 1) == 0);
    char response[512];
    memset(response, 0xa5, sizeof response);
    size_t response_length = SIZE_MAX;
    assert(!blue_rpc_capture(argv[0], "getblockchaininfo", NULL,
                             response, sizeof response, &response_length));
    assert(response_length == 0);
    for (size_t i = 0; i < strlen(good) + 1; ++i)
        assert(response[i] == 0);
    assert(unsetenv("BLUE_CHAIN_TIP_TEST_CLOSE_STDOUT") == 0);
    int status = 0;
    errno = 0;
    assert(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
    test_forked_holder(argv[0]);
    return 0;
}
