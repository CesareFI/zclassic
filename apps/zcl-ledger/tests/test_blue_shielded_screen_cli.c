/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "zsha256/zsha256.h"

#undef NDEBUG
#include <assert.h>
#include <png.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int hex_digit(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

static void write_vector(const char *source, const char *target,
    size_t expected_length) {
    FILE *input = fopen(source, "r");
    FILE *output = fopen(target, "wb");
    assert(input && output);
    int ch;
    do {
        ch = fgetc(input);
        if (ch == '#')
            while (ch != '\n' && ch != EOF) ch = fgetc(input);
    } while (ch == '\n');
    size_t length = 0;
    while (ch != '\n' && ch != EOF) {
        int high = hex_digit(ch);
        int low = hex_digit(fgetc(input));
        assert(high >= 0 && low >= 0);
        assert(fputc((high << 4) | low, output) != EOF);
        ++length;
        ch = fgetc(input);
    }
    assert(length == expected_length);
    assert(!ferror(input) && fclose(input) == 0);
    assert(fclose(output) == 0);
}

static void run_simulator(const char *program, const char *wire,
    const char *branch, const char *prefix) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        FILE *sink = freopen("/dev/null", "w", stdout);
        if (!sink) _exit(126);
        execl(program, program, wire, branch, prefix,
            (char *)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static const char *expected_pixels(const char *suffix) {
    if (strcmp(suffix, "summary") == 0)
        return "16135e256da8af13db033defa4c19611685cc7eb47bbfe9eade634c227005385";
    if (strcmp(suffix, "summary-dark") == 0)
        return "73c75e24ef515e732744d045bef9d9605566834db6c6bba9dc3becee56af980a";
    if (strcmp(suffix, "summary-large-light-3") == 0)
        return "9faaf6574bbbd724c2e72d98a42e35d31ba1f4f9455ded8c29df634a2787b1f5";
    if (strcmp(suffix, "digest") == 0)
        return "39a73bf57e30ffa833289e24a8726e586de864175f5d622578ce081b66245f29";
    if (strcmp(suffix, "digest-dark") == 0)
        return "f551ef8c2fbb6b87ea920a87ab8a872a1f5070b0455c06ef504f4ce3f55ace8a";
    if (strcmp(suffix, "digest-large-light-1") == 0)
        return "6b41bf2b5370876da0657f1099c6a9f4d3ce6060398f97d1bbd0baa41d360691";
    if (strcmp(suffix, "digest-large-dark-1") == 0)
        return "d8c8a951786a40601d7483ac511a431ae811e5e2362a91db3eae25df949ab53a";
    return NULL;
}

static void check_pixels(const char *path, const char *expected) {
    png_image png = { .version = PNG_IMAGE_VERSION };
    assert(png_image_begin_read_from_file(&png, path));
    assert(png.width == 320 && png.height == 480);
    png.format = PNG_FORMAT_RGB;
    size_t length = PNG_IMAGE_SIZE(png);
    uint8_t *rgb = malloc(length);
    assert(rgb && png_image_finish_read(&png, NULL, rgb, 0, NULL));
    uint8_t digest[32];
    char hex[65];
    zsha256(rgb, length, digest);
    for (size_t i = 0; i < sizeof digest; ++i)
        assert(snprintf(hex + 2 * i, 3, "%02x", digest[i]) == 2);
    if (strcmp(hex, expected) != 0)
        fprintf(stderr, "%s: expected %s, got %s\n", path, expected, hex);
    assert(strcmp(hex, expected) == 0);
    free(rgb);
    png_image_free(&png);
}

static void check_png(const char *prefix, const char *suffix,
    bool consensus_fixture) {
    char path[4096];
    int count = snprintf(path, sizeof path, "%s-%s.png", prefix, suffix);
    assert(count > 0 && (size_t)count < sizeof path);
    FILE *file = fopen(path, "rb");
    assert(file);
    uint8_t header[24];
    assert(fread(header, 1, sizeof header, file) == sizeof header);
    static const uint8_t expected[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 13, 'I', 'H', 'D', 'R',
        0, 0, 1, 64, 0, 0, 1, 224
    };
    assert(memcmp(header, expected, sizeof expected) == 0);
    assert(fclose(file) == 0);
    const char *pixel_hash = consensus_fixture ?
        expected_pixels(suffix) : NULL;
    if (pixel_hash) check_pixels(path, pixel_hash);
    assert(unlink(path) == 0);
}

static void check_pages(const char *prefix, bool consensus_fixture) {
    check_png(prefix, "ready", consensus_fixture);
    for (unsigned pass = 1; pass <= 6; ++pass) {
        char label[32];
        assert(snprintf(label, sizeof label, "pass-%u-start", pass) > 0);
        check_png(prefix, label, consensus_fixture);
        assert(snprintf(label, sizeof label, "pass-%u-complete", pass) > 0);
        check_png(prefix, label, consensus_fixture);
    }
    check_png(prefix, "summary", consensus_fixture);
    check_png(prefix, "digest", consensus_fixture);
    check_png(prefix, "wire", consensus_fixture);
    check_png(prefix, "summary-dark", consensus_fixture);
    check_png(prefix, "digest-dark", consensus_fixture);
    check_png(prefix, "wire-dark", consensus_fixture);
    for (unsigned detail = 1; detail <= 6; ++detail) {
        for (unsigned page = 0; page < 3; ++page) {
            for (unsigned dark = 0; dark < 2; ++dark) {
                char label[48];
                assert(snprintf(label, sizeof label, "%s-large-%s-%u",
                    page == 0 ? "summary" :
                        page == 1 ? "digest" : "wire",
                    dark ? "dark" : "light", detail) > 0);
                check_png(prefix, label, consensus_fixture);
            }
        }
    }
}

int main(int argc, char **argv) {
    assert(argc == 4);
    char directory[] = "/tmp/zcl-blue-screen-XXXXXX";
    assert(mkdtemp(directory));
    char wire[256], prefix[256];
    assert(snprintf(wire, sizeof wire, "%s/fixture.bin", directory) > 0);
    assert(snprintf(prefix, sizeof prefix, "%s/screen", directory) > 0);
    write_vector(argv[1], wire, 4118);
    run_simulator(argv[2], wire, "0x76b809bb", prefix);
    check_pages(prefix, false);
    write_vector(argv[3], wire, 1425);
    run_simulator(argv[2], wire, "0x76b809bb", prefix);
    check_pages(prefix, true);
    run_simulator(argv[2], wire, "0x930b540d", prefix);
    check_pages(prefix, false);
    assert(unlink(wire) == 0 && rmdir(directory) == 0);
    puts("Blue shielded screen PNG sequences: 165 valid 320x480 images");
    return 0;
}
