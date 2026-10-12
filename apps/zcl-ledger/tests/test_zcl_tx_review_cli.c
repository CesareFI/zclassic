/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L

#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static void write_fixture(const char *source, int destination) {
    FILE *file = fopen(source, "r");
    assert(file);
    char line[512];
    do { assert(fgets(line, sizeof line, file)); } while (line[0] == '#');
    assert(strcspn(line, "\r\n") == 490);
    uint8_t wire[245];
    for (size_t i = 0; i < sizeof wire; ++i) {
        int high = digit(line[2 * i]), low = digit(line[2 * i + 1]);
        assert(high >= 0 && low >= 0);
        wire[i] = (uint8_t)((high << 4) | low);
    }
    assert(fclose(file) == 0);
    assert(write(destination, wire, sizeof wire) == (ssize_t)sizeof wire);
    assert(close(destination) == 0);
}

static int capture(char *const argv[], char output[4096]) {
    int fds[2];
    assert(pipe(fds) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(dup2(fds[1], STDOUT_FILENO) >= 0);
        close(fds[0]);
        close(fds[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    assert(close(fds[1]) == 0);
    size_t used = 0;
    for (;;) {
        ssize_t count = read(fds[0], output + used, 4095 - used);
        assert(count >= 0);
        if (!count) break;
        used += (size_t)count;
        assert(used < 4095);
    }
    output[used] = 0;
    assert(close(fds[0]) == 0);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status));
    return WEXITSTATUS(status);
}

static void check_png(const char *path) {
    FILE *png = fopen(path, "rb");
    assert(png);
    uint8_t header[24];
    assert(fread(header, 1, sizeof header, png) == sizeof header);
    assert(memcmp(header, "\x89PNG\r\n\x1a\n", 8) == 0);
    assert(header[16] == 0 && header[17] == 0 &&
           header[18] == 1 && header[19] == 64);
    assert(header[20] == 0 && header[21] == 0 &&
           header[22] == 1 && header[23] == 224);
    assert(fclose(png) == 0 && unlink(path) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 4);
    char path[] = "/tmp/zcl-review-cli-XXXXXX";
    int file = mkstemp(path);
    assert(file >= 0);
    write_fixture(argv[2], file);
    char output[4096];
    char *const success[] = {argv[1], "--json", "--simulate-app",
        "--branch-id", "0x76b809bb", path, NULL};
    assert(capture(success, output) == 0);
    assert(strstr(output, "\"ok\":true"));
    assert(strstr(output, "\"blue_parsed\":false,\"app_simulated\":true"));
    assert(strstr(output, "\"simulated_zip243_matched\":true"));
    assert(strstr(output, "\"signing_ready\":false"));
    char prefix[] = "/tmp/zcl-screen-cli-XXXXXX";
    int directory = mkstemp(prefix);
    assert(directory >= 0 && close(directory) == 0 && unlink(prefix) == 0);
    char *const screenshot[] = {argv[3], path, prefix, NULL};
    assert(capture(screenshot, output) == 0);
    for (unsigned page = 0; page < 4; ++page) {
        char png_path[128];
        assert(snprintf(png_path, sizeof png_path, "%s-%02u.png", prefix,
                        page) > 0);
        check_png(png_path);
    }
    char final_page[128];
    assert(snprintf(final_page, sizeof final_page, "%s-04.png", prefix) > 0);
    check_png(final_page);
    char *const accessible[] = {argv[3], path, prefix,
        "--large-text", "--dark", NULL};
    assert(capture(accessible, output) == 0);
    unsigned images = 0;
    char *save = NULL;
    for (char *name = strtok_r(output, "\n", &save); name;
         name = strtok_r(NULL, "\n", &save)) {
        check_png(name);
        ++images;
    }
    assert(images == 29);
    char *const invalid[] = {argv[1], "--json", "--simulate-app",
        "--blue", "/dev/hidraw1", path, NULL};
    assert(capture(invalid, output) == 2);
    assert(strcmp(output, "{\"ok\":false,\"error\":\"invalid_arguments\"}\n") == 0);
    char *const missing[] = {argv[1], "--json", "--simulate-app",
        "/no/such/transaction", NULL};
    assert(capture(missing, output) == 1);
    assert(strcmp(output, "{\"ok\":false,\"error\":\"file_read_failed\"}\n") == 0);
    assert(unlink(path) == 0);
    return 0;
}
