/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
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

static int run_install(const char *program, const char *image,
    bool verify, bool offline, char error[512]) {
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        alarm(5);
        close(pipefd[0]);
        assert(dup2(pipefd[1], STDERR_FILENO) >= 0);
        close(pipefd[1]);
        if (offline)
            execl(program, program, "--image-check", image,
                  (char *)NULL);
        else if (verify)
            execl(program, program, "/dev/hidraw999", "--ca-verify",
                  "/missing/key.pem", image, (char *)NULL);
        else execl(program, program, "/dev/hidraw999", image,
                   (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    size_t used = 0;
    while (used + 1 < 512) {
        ssize_t count = read(pipefd[0], error + used, 511 - used);
        if (count <= 0) break;
        used += (size_t)count;
    }
    error[used] = 0;
    close(pipefd[0]);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void write_unknown_image(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    uint8_t bytes[1024] = {0};
    assert(write(fd, bytes, sizeof bytes) == (ssize_t)sizeof bytes);
    assert(close(fd) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char directory[] = "/tmp/zcl-blue-install-image-XXXXXX";
    assert(mkdtemp(directory));
    char image[256], link[256], fifo[256], oversize[256], error[512];
    assert(snprintf(image, sizeof image, "%s/unknown.bin", directory) > 0);
    assert(snprintf(link, sizeof link, "%s/linked.bin", directory) > 0);
    assert(snprintf(fifo, sizeof fifo, "%s/blocked.fifo", directory) > 0);
    assert(snprintf(oversize, sizeof oversize,
                    "%s/oversize.bin", directory) > 0);
    write_unknown_image(image);
    assert(run_install(argv[1], image, false, false, error) == 1);
    assert(strstr(error, "SHA-256 does not match a reviewed build") &&
           !strstr(error, "selected interface"));
    assert(run_install(argv[1], image, true, false, error) == 1);
    assert(strstr(error, "SHA-256 does not match a reviewed build") &&
           !strstr(error, "Cannot load owner-only"));
    assert(run_install(argv[1], image, false, true, error) == 1);
    assert(strstr(error, "SHA-256 does not match a reviewed build") &&
           !strstr(error, "selected interface"));
    assert(symlink(image, link) == 0);
    assert(run_install(argv[1], link, false, false, error) == 1);
    assert(strstr(error, "Expected a regular ZCL app binary") &&
           !strstr(error, "SHA-256 does not match"));
    assert(run_install(argv[1], link, false, true, error) == 1);
    assert(strstr(error, "Expected a regular ZCL app binary") &&
           !strstr(error, "SHA-256 does not match"));
    assert(mkfifo(fifo, 0600) == 0);
    assert(run_install(argv[1], fifo, false, false, error) == 1);
    assert(strstr(error, "Expected a regular ZCL app binary") &&
           !strstr(error, "selected interface"));
    int fd = open(oversize, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && ftruncate(fd, 65536 + 64) == 0 && close(fd) == 0);
    assert(run_install(argv[1], oversize, false, false, error) == 1);
    assert(strstr(error, "Expected a regular ZCL app binary") &&
           !strstr(error, "selected interface"));
    assert(unlink(image) == 0 && unlink(link) == 0 &&
           unlink(fifo) == 0 && unlink(oversize) == 0 &&
           rmdir(directory) == 0);
    return 0;
}
