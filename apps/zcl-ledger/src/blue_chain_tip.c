/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_chain_tip.h"
#include "json/json.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const struct json_value *unique_field(const struct json_value *object,
                                             const char *name) {
    if (!object || object->type != JSON_OBJ) return NULL;
    const struct json_value *found = NULL;
    for (size_t i = 0; i < object->num_children; ++i) {
        if (strcmp(object->keys[i], name) != 0) continue;
        if (found) return NULL;
        found = &object->children[i];
    }
    return found;
}

static bool hex_hash(const char *text) {
    if (!text || strlen(text) != 64) return false;
    for (size_t i = 0; i < 64; ++i) {
        char digit = text[i];
        if ((digit < '0' || digit > '9') &&
            (digit < 'a' || digit > 'f') &&
            (digit < 'A' || digit > 'F')) return false;
    }
    return true;
}

static void copy_hash_lowercase(char dest[65], const char source[65]) {
    for (size_t i = 0; i < 64; ++i)
        dest[i] = (source[i] >= 'A' && source[i] <= 'F')
            ? (char)(source[i] - 'A' + 'a') : source[i];
    dest[64] = 0;
}

static bool mainnet_identity(const struct json_value *result) {
    const struct json_value *chain = unique_field(result, "chain");
    const struct json_value *hash = unique_field(result, "bestblockhash");
    const struct json_value *ibd = unique_field(result, "initialblockdownload");
    return chain && chain->type == JSON_STR &&
        strcmp(chain->val.s, "main") == 0 && hash &&
        hash->type == JSON_STR && hex_hash(hash->val.s) &&
        ibd && ibd->type == JSON_BOOL && !ibd->val.b;
}

static bool synced_next_height(const struct json_value *result,
                               uint32_t *next_height) {
    const struct json_value *blocks = unique_field(result, "blocks");
    const struct json_value *headers = unique_field(result, "headers");
    if (!blocks || blocks->type != JSON_INT || blocks->val.i < 0 ||
        blocks->val.i >= INT_MAX || !headers || headers->type != JSON_INT ||
        headers->val.i != blocks->val.i) return false;
    *next_height = (uint32_t)(blocks->val.i + 1);
    return true;
}

bool blue_chain_tip_parse(const char *reply, size_t length,
                          blue_chain_tip *tip) {
    if (!reply || !tip || !length || length > 65535) return false;
    struct json_value root = {0};
    bool valid = json_read(&root, reply, length);
    const struct json_value *result = valid ? unique_field(&root, "result") : NULL;
    const struct json_value *error = valid ? unique_field(&root, "error") : NULL;
    uint32_t next_height = 0;
    valid = result && result->type == JSON_OBJ && error &&
        error->type == JSON_NULL && mainnet_identity(result) &&
        synced_next_height(result, &next_height);
    if (valid) {
        const char *hash = unique_field(result, "bestblockhash")->val.s;
        tip->next_height = next_height;
        copy_hash_lowercase(tip->block_hash, hash);
    }
    json_free(&root);
    return valid;
}

bool blue_chain_tip_same(const blue_chain_tip *first,
                         const blue_chain_tip *second) {
    return first && second && first->next_height == second->next_height &&
        strcmp(first->block_hash, second->block_hash) == 0;
}

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool read_reply(int fd, char *reply, size_t capacity, size_t *used,
                       int64_t deadline) {
    *used = 0;
    while (*used < capacity) {
        int64_t now = monotonic_ms();
        if (now < 0) return false;
        int64_t remaining = deadline - now;
        if (remaining <= 0 || remaining > INT_MAX) return false;
        struct pollfd entry = {.fd = fd, .events = POLLIN};
        int ready = poll(&entry, 1, (int)remaining);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;
        ssize_t count = read(fd, reply + *used, capacity - *used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return false;
        if (count == 0) return true;
        *used += (size_t)count;
    }
    return false;
}

static bool finish_child(pid_t child, bool complete, int64_t deadline) {
    int status = 0;
    pid_t waited;
    while (complete) {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (waited < 0 && errno != EINTR) return false;
        int64_t now = monotonic_ms();
        if (now < 0 || now >= deadline) break;
        struct timespec pause = {.tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    return false;
}

static bool capture_request_valid(const char *rpc_binary,
                                  const char *method, const char *reply,
                                  size_t capacity, const size_t *length) {
    return rpc_binary && rpc_binary[0] == '/' && method && reply &&
           capacity && length;
}

bool blue_rpc_capture(const char *rpc_binary, const char *method,
                      const char *argument, char *reply, size_t capacity,
                      size_t *length) {
    if (!capture_request_valid(rpc_binary, method, reply, capacity, length))
        return false;
    *length = 0;
    int64_t start = monotonic_ms();
    if (start < 0 || start > INT64_MAX - 7000) return false;
    int64_t deadline = start + 7000;
    int pipefd[2];
    if (pipe(pipefd) != 0) return false;
    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return false;
    }
    if (child == 0) {
        if (setpgid(0, 0) != 0) _exit(127);
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            setenv("ZCL_RPC_MAX_TIME_SECS", "5", 1) != 0)
            _exit(127);
        close(pipefd[1]);
        if (argument)
            execl(rpc_binary, rpc_binary, method, argument, (char *)NULL);
        else
            execl(rpc_binary, rpc_binary, method, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    bool complete = read_reply(pipefd[0], reply, capacity, length, deadline);
    close(pipefd[0]);
    bool finished = finish_child(child, complete, deadline);
    if (!finished) {
        memset(reply, 0, *length);
        *length = 0;
    }
    return finished;
}

bool blue_chain_tip_query(const char *rpc_binary, blue_chain_tip *tip) {
    if (!tip) return false;
    char reply[65536];
    size_t length = 0;
    return blue_rpc_capture(rpc_binary, "getblockchaininfo", NULL,
                            reply, sizeof reply, &length) &&
        blue_chain_tip_parse(reply, length, tip);
}

bool blue_chain_tip_still_current(const char *rpc_binary,
                                  const blue_chain_tip *initial) {
    blue_chain_tip current;
    return initial && blue_chain_tip_query(rpc_binary, &current) &&
        blue_chain_tip_same(initial, &current);
}
