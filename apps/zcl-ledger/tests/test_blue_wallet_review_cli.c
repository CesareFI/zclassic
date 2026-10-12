/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "zsha256/zsha256.h"
#include "blue_utxo.h"
#include "zcl_tx_review.h"
#include "zcl_tx_stream.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#undef NDEBUG
#include <assert.h>

static int run_with_second(const char *program, const char *rpc_binary,
    const char *output, const char *spend, const char *previous,
    const char *second, char *error, size_t capacity,
    unsigned timeout_seconds) {
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        if (timeout_seconds) alarm(timeout_seconds);
        close(pipefd[0]);
        assert(dup2(pipefd[1], STDERR_FILENO) >= 0);
        close(pipefd[1]);
        if (output)
            execl(program, program, output, (char *)NULL);
        else if (second)
            execl(program, program, "--test", "/dev/hidraw999",
                  rpc_binary, spend, previous, second, (char *)NULL);
        else if (previous)
            execl(program, program, "--test", "/dev/hidraw999",
                  rpc_binary, spend, previous, (char *)NULL);
        else
            execl(program, program, "--test", "/dev/hidraw999",
                  rpc_binary, spend, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    size_t used = 0;
    while (used + 1 < capacity) {
        ssize_t count = read(pipefd[0], error + used, capacity - used - 1);
        if (count <= 0) break;
        used += (size_t)count;
    }
    error[used] = 0;
    close(pipefd[0]);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run(const char *program, const char *rpc_binary, const char *output,
    const char *spend, const char *previous, char *error, size_t capacity) {
    return run_with_second(program, rpc_binary, output, spend, previous,
                           NULL, error, capacity, 0);
}

static size_t read_file(const char *path, uint8_t bytes[256]) {
    FILE *file = fopen(path, "rb");
    assert(file);
    size_t length = fread(bytes, 1, 256, file);
    assert(!ferror(file) && length > 80 && length < 256);
    assert(fclose(file) == 0);
    return length;
}

static void write_file(const char *path, const uint8_t *bytes, size_t length) {
    FILE *file = fopen(path, "wb");
    assert(file);
    assert(fwrite(bytes, 1, length, file) == length);
    assert(fclose(file) == 0);
}

static size_t previous_version(const uint8_t *fixture, size_t length,
    unsigned version, uint8_t previous[256]) {
    assert(length > 80 && length < 256 && version >= 1 && version <= 4);
    for (size_t i = length - 11; i < length; ++i) assert(fixture[i] == 0);
    if (version == 4) {
        memcpy(previous, fixture, length);
        return length;
    }
    size_t body_length = length - 8 - (version == 3 ? 11 : 15);
    size_t header_length = version == 3 ? 8 : 4;
    uint32_t header = version == 3 ? 0x80000003u : version;
    for (unsigned i = 0; i < 4; ++i)
        previous[i] = (uint8_t)(header >> (8 * i));
    if (version == 3) {
        uint32_t group = 0x03c48270u;
        for (unsigned i = 0; i < 4; ++i)
            previous[4 + i] = (uint8_t)(group >> (8 * i));
    }
    memcpy(previous + header_length, fixture + 8, body_length);
    size_t result = header_length + body_length;
    if (version >= 2) previous[result++] = 0;
    return result;
}

static void check_shielded_rejection(const char *program,
    const char *rpc_binary, const char *path, const char *previous_path,
    const uint8_t *base, size_t length) {
    static const struct {
        size_t trim, count_from_end, body, trailing_counts, tail;
    } cases[] = {
        {2, 3, 384, 2, 64},
        {1, 2, 948, 1, 64},
        {0, 1, 1634, 0, 96}
    };
    uint8_t shielded[256 + 1634 + 96] = {0};
    char error[512];
    zcl_tx_review structural;
    for (unsigned kind = 0; kind < 3; ++kind) {
        memset(shielded, 0, sizeof shielded);
        size_t prefix = length - cases[kind].trim;
        size_t total = prefix + cases[kind].body +
            cases[kind].trailing_counts + cases[kind].tail;
        assert(total <= sizeof shielded);
        memcpy(shielded, base, prefix);
        shielded[length - cases[kind].count_from_end] = 1;
        assert(zcl_tx_review_parse(shielded, total, &structural) == 0);
        uint32_t counts[] = {structural.sapling_spends,
            structural.sapling_outputs, structural.sprout_joinsplits};
        assert(counts[kind] == 1);
        assert(counts[0] + counts[1] + counts[2] == 1);
        write_file(path, shielded, total);
        assert(run(program, rpc_binary, NULL, path, previous_path,
                   error, sizeof error) == 1);
        assert(strstr(error, "Transactions with shielded fields") != NULL);
        write_file(path, shielded, total - 1);
        assert(run(program, rpc_binary, NULL, path, previous_path,
                   error, sizeof error) == 1);
        assert(strstr(error, "transaction cannot be reviewed") != NULL);
    }
    uint8_t balance_only[256];
    memcpy(balance_only, base, length);
    balance_only[length - 11] = 1;
    assert(zcl_tx_review_parse(balance_only, length, &structural) == 0);
    assert(structural.value_balance_zat == 1);
    write_file(path, balance_only, length);
    assert(run(program, rpc_binary, NULL, path, previous_path,
               error, sizeof error) == 1);
    assert(strstr(error, "Transactions with shielded fields") != NULL);
}

typedef struct {
    const char *reviewer, *signer, *rpc, *fixture, *spend, *previous;
    const char *shielded, *marker, *missing, *fifo, *link;
    const char *oversize, *empty, *signed_path;
    char error[512];
} cli_case;

static void check_signer_without_device(const cli_case *test) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        execl(test->signer, test->signer, "--sign-test", "/dev/hidraw999",
            test->rpc, test->spend, test->signed_path, test->previous,
            (char *)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 1);
    assert(access(test->signed_path, F_OK) != 0);
}

static void check_v4_file_inputs(cli_case *test) {
    assert(unlink(test->link) == 0);
    assert(symlink(test->previous, test->link) == 0);
    assert(run(test->reviewer, test->rpc, NULL, test->spend, test->link,
               test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "regular previous transaction files") != NULL);
    assert(run_with_second(test->reviewer, test->rpc, NULL, test->spend,
                           test->fifo, NULL, test->error, sizeof test->error,
                           10) == 1);
    assert(strstr(test->error, "regular previous transaction files") != NULL);
    assert(run(test->reviewer, test->rpc, NULL, test->spend, test->oversize,
               test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "Blue size limit") != NULL);
    assert(run(test->reviewer, test->rpc, NULL, test->spend, test->empty,
               test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "nonempty regular previous") != NULL);
    assert(run_with_second(test->reviewer, test->rpc, NULL, test->spend,
                           test->previous, test->missing, test->error,
                           sizeof test->error, 0) == 1);
    assert(strstr(test->error, "regular previous transaction files") != NULL);
}

static void check_v4_rpc(cli_case *test, const uint8_t *spend,
    size_t spend_length, const uint8_t *previous, size_t previous_length) {
    blue_chain_tip tip;
    zcl_tx_previous_transaction bound_previous = {
        .wire = previous, .length = previous_length
    };
    assert(blue_chain_tip_query(test->rpc, &tip));
    assert(blue_utxo_recheck_at_tip(test->rpc, &tip, spend, spend_length,
                                    &bound_previous, 1));
    assert(!blue_utxo_recheck_at_tip(test->rpc, NULL, spend, spend_length,
                                     &bound_previous, 1));
    assert(run(test->reviewer, test->rpc, NULL, test->spend, NULL,
               test->error, sizeof test->error) == 2);
    assert(strstr(test->error, "PREVIOUS_TX.bin") != NULL);
    assert(run(test->reviewer, test->rpc, NULL, test->spend, test->fixture,
               test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "outpoints do not match") != NULL);
    assert(setenv("BLUE_UTXO_TEST_SPENT", "1", 1) == 0);
    assert(!blue_utxo_recheck_at_tip(test->rpc, &tip, spend, spend_length,
                                     &bound_previous, 1));
    assert(run(test->reviewer, test->rpc, NULL, test->spend, test->previous,
               test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "UTXO, maturity, amount, or script") != NULL);
    assert(unsetenv("BLUE_UTXO_TEST_SPENT") == 0);
    assert(setenv("BLUE_UTXO_TEST_BAD_SCRIPT", "1", 1) == 0);
    assert(!blue_utxo_recheck_at_tip(test->rpc, &tip, spend, spend_length,
                                     &bound_previous, 1));
    assert(run(test->reviewer, test->rpc, NULL, test->spend, test->previous,
               test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "UTXO, maturity, amount, or script") != NULL);
    assert(unsetenv("BLUE_UTXO_TEST_BAD_SCRIPT") == 0);
    assert(setenv("BLUE_TIP_REORG_MARKER", test->marker, 1) == 0);
    assert(!blue_utxo_recheck_at_tip(test->rpc, &tip, spend, spend_length,
                                     &bound_previous, 1));
    assert(unlink(test->marker) == 0);
    assert(run(test->reviewer, test->rpc, NULL, test->spend, test->previous,
               test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "Cannot confirm the local node tip") != NULL);
    assert(unsetenv("BLUE_TIP_REORG_MARKER") == 0);
    assert(unlink(test->marker) == 0);
}

static void check_unsigned_files(cli_case *test, const uint8_t *base,
                                 size_t length) {
    check_shielded_rejection(test->reviewer, test->rpc, test->shielded,
                             test->previous, base, length);
    assert(mkfifo(test->fifo, 0600) == 0);
    assert(run_with_second(test->reviewer, test->rpc, NULL, test->fifo,
                           test->previous, NULL, test->error,
                           sizeof test->error, 10) == 1);
    assert(strstr(test->error, "regular unsigned transaction file") != NULL);
    int oversized = open(test->oversize, O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(oversized >= 0);
    assert(ftruncate(oversized, ZCL_TX_STREAM_MAX_BYTES + 1) == 0);
    assert(close(oversized) == 0);
    assert(run(test->reviewer, test->rpc, NULL, test->oversize,
               test->previous, test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "Blue size limit") != NULL);
    int empty = open(test->empty, O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(empty >= 0 && close(empty) == 0);
    assert(run(test->reviewer, test->rpc, NULL, test->empty,
               test->previous, test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "nonempty regular unsigned") != NULL);
    assert(symlink(test->fixture, test->link) == 0);
    assert(run(test->reviewer, test->rpc, NULL, test->link,
               test->previous, test->error, sizeof test->error) == 1);
    assert(strstr(test->error, "regular unsigned transaction file") != NULL);
}

static void check_previous_versions(cli_case *test, const uint8_t *base,
                                    size_t length) {
    uint8_t previous[256], spend[256], first[32], txid[32];
    for (unsigned version = 1; version <= 4; ++version) {
        size_t previous_length = previous_version(base, length,
                                                  version, previous);
        uint64_t amount = 400000000;
        size_t amount_offset = version >= 3 ? 51 : 47;
        for (unsigned i = 0; i < 8; ++i)
            previous[amount_offset + i] = (uint8_t)(amount >> (i * 8));
        zsha256(previous, previous_length, first);
        zsha256(first, sizeof first, txid);
        memcpy(spend, base, length);
        memcpy(spend + 9, txid, sizeof txid);
        write_file(test->spend, spend, length);
        write_file(test->previous, previous, previous_length);
        if (version == 4) {
            check_v4_file_inputs(test);
            check_v4_rpc(test, spend, length, previous, previous_length);
        }
        assert(run(test->reviewer, test->rpc, NULL, test->spend,
                   test->previous, test->error, sizeof test->error) == 1);
        assert(strstr(test->error, "not an accessible Ledger Blue") != NULL);
        check_signer_without_device(test);
    }
}

static void cleanup_files(const cli_case *test, const char *directory) {
    assert(unlink(test->fixture) == 0);
    assert(unlink(test->spend) == 0);
    assert(unlink(test->previous) == 0);
    assert(unlink(test->shielded) == 0);
    assert(unlink(test->fifo) == 0);
    assert(unlink(test->link) == 0);
    assert(unlink(test->oversize) == 0);
    assert(unlink(test->empty) == 0);
    assert(rmdir(directory) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 5);
    char directory[] = "/tmp/zcl-wallet-review-cli-XXXXXX";
    assert(mkdtemp(directory));
    char fixture[256], spend_path[256], previous_path[256];
    char shielded_path[256];
    char marker_path[256], missing_path[256], fifo_path[256], link_path[256];
    char oversize_path[256], empty_path[256], signed_path[256];
    assert(snprintf(fixture, sizeof fixture, "%s/fixture.bin", directory) > 0);
    assert(snprintf(spend_path, sizeof spend_path, "%s/spend.bin", directory) > 0);
    assert(snprintf(previous_path, sizeof previous_path,
                    "%s/previous.bin", directory) > 0);
    assert(snprintf(shielded_path, sizeof shielded_path,
                    "%s/shielded.bin", directory) > 0);
    assert(snprintf(marker_path, sizeof marker_path,
                    "%s/reorg.marker", directory) > 0);
    assert(snprintf(missing_path, sizeof missing_path,
                    "%s/missing.bin", directory) > 0);
    assert(snprintf(fifo_path, sizeof fifo_path,
                    "%s/blocked.fifo", directory) > 0);
    assert(snprintf(link_path, sizeof link_path,
                    "%s/linked.bin", directory) > 0);
    assert(snprintf(oversize_path, sizeof oversize_path,
                    "%s/oversize.bin", directory) > 0);
    assert(snprintf(empty_path, sizeof empty_path,
                    "%s/empty.bin", directory) > 0);
    assert(snprintf(signed_path, sizeof signed_path,
                    "%s/signed.bin", directory) > 0);
    cli_case test = {.reviewer = argv[2], .signer = argv[3], .rpc = argv[4],
        .fixture = fixture, .spend = spend_path, .previous = previous_path,
        .shielded = shielded_path, .marker = marker_path,
        .missing = missing_path, .fifo = fifo_path, .link = link_path,
        .oversize = oversize_path, .empty = empty_path,
        .signed_path = signed_path};
    assert(run(argv[1], test.rpc, test.fixture, NULL, NULL,
               test.error, sizeof test.error) == 0);
    uint8_t base[256];
    size_t length = read_file(test.fixture, base);
    assert(length >= 3);
    check_unsigned_files(&test, base, length);
    check_previous_versions(&test, base, length);
    cleanup_files(&test, directory);
    return 0;
}
