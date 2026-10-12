/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "zsha256/zsha256.h"

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

static const uint8_t wallet_0346_text_sha256[32] = {
    0xd0, 0x05, 0xd4, 0xfa, 0x9d, 0x4a, 0x77, 0xcf,
    0x17, 0x81, 0xc6, 0xcf, 0x56, 0x6d, 0x79, 0x32,
    0xe2, 0x46, 0x8d, 0x32, 0xd0, 0xb8, 0xf6, 0xf1,
    0x1a, 0xcb, 0x60, 0x11, 0x0f, 0xfe, 0x28, 0xfb
};

static void hash_file(const char *path, uint8_t digest[32]) {
    struct stat info;
    assert(stat(path, &info) == 0 && S_ISREG(info.st_mode));
    assert(info.st_size >= 1024 && info.st_size <= 65536 &&
           info.st_size % 64 == 0);
    uint8_t *bytes = malloc((size_t)info.st_size);
    assert(bytes);
    int fd = open(path, O_RDONLY);
    assert(fd >= 0);
    size_t got = 0;
    while (got < (size_t)info.st_size) {
        ssize_t count = read(fd, bytes + got, (size_t)info.st_size - got);
        assert(count > 0);
        got += (size_t)count;
    }
    assert(close(fd) == 0);
    zsha256(bytes, got, digest);
    free(bytes);
}

static int run_installer(const char *program, bool image_check,
                         const char *image, char output[1024]) {
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        alarm(5);
        close(pipefd[0]);
        assert(dup2(pipefd[1], STDOUT_FILENO) >= 0);
        assert(dup2(pipefd[1], STDERR_FILENO) >= 0);
        close(pipefd[1]);
        if (image_check)
            execl(program, program, "--image-check", image, (char *)NULL);
        else
            execl(program, program, "/dev/hidraw999", image, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    size_t used = 0;
    while (used + 1 < 1024) {
        ssize_t count = read(pipefd[0], output + used, 1023 - used);
        if (count <= 0) break;
        used += (size_t)count;
    }
    output[used] = 0;
    close(pipefd[0]);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(int argc, char **argv) {
    assert(argc == 3);
    uint8_t digest[32];
    hash_file(argv[2], digest);
    assert(memcmp(digest, wallet_0346_text_sha256, sizeof digest) == 0);
    char output[1024];
    assert(run_installer(argv[1], true, argv[2], output) == 0);
    assert(strstr(output, "Reviewed image: ZCL Wallet 0.3.46;"));
    assert(strstr(output, "signing path declared;"));
    assert(strstr(output, "installation blocked pending physical validation"));
    assert(!strstr(output, "installation permitted"));
    assert(!strstr(output, "selected interface"));
    assert(run_installer(argv[1], false, argv[2], output) == 1);
    assert(strstr(output, "App image is not approved for installation."));
    assert(strstr(output,
                  "Expected a regular ZCL app binary"));
    assert(!strstr(output, "selected interface"));
    assert(!strstr(output, "The selected interface"));
    return 0;
}
