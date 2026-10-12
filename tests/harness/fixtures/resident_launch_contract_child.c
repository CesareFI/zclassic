/* Copyright 2026 Rhett Creighton - Apache 2.0
 *
 * Reference child fixture for test_resident_launch_contract.c (built by the
 * Makefile into build/fixtures/, never linked into any product binary).
 *
 * A script cannot be the resident image: the pinned descriptor is O_CLOEXEC,
 * and fexecve of a shebang script re-opens /dev/fd/N for the interpreter
 * AFTER exec closed it (ENOENT on Linux). Only a real ELF can be launched
 * through resident_launch_spawn, so the reference child is one.
 *
 * The child speaks EXACTLY the wire of the landed consumer
 * (tools/command/native_package_resident_command.c) and its shipped app
 * (contexts/commons/packages/ztasks/app/main.c): the launch nonce arrives as
 * argv[2] (`<image> --resident <nonce>`, empty environment), the child
 * answers one READY frame, reads one z23-res-run-v1 frame, and echoes its
 * payload back in one z23-res-run-v1 frame — all on fd 3
 * (RESIDENT_LAUNCH_CHILD_FD).
 *
 * Three build/run variants:
 *   (default)          READY, one frame round-trip, exit 0.
 *   argv[3] "park"     READY, then park forever (the cancel/reap target).
 *   RLC_FIXTURE_BROKEN exits 1 without framing: the failed candidate the
 *                      READY gate must refuse.
 * The header layout is the REAL struct resident_result_header, so the wire
 * bytes cannot drift from the parent side.
 */
#include "platform/resident_launch.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if !defined(RLC_FIXTURE_BROKEN)
static bool rlc_child_io(void *buffer, size_t size, bool sending)
{
    unsigned char *bytes = buffer;
    for (size_t done = 0; done < size;) {
        ssize_t n = sending
            ? write(RESIDENT_LAUNCH_CHILD_FD, bytes + done, size - done)
            : read(RESIDENT_LAUNCH_CHILD_FD, bytes + done, size - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t)n;
    }
    return true;
}

static bool rlc_child_reply(const char *nonce, const char *payload,
                            uint32_t len)
{
    struct resident_result_header header;
    memset(&header, 0, sizeof(header));
    (void)snprintf(header.magic, sizeof(header.magic), "%s", "z23-res-run-v1");
    (void)snprintf(header.nonce, sizeof(header.nonce), "%s", nonce);
    header.payload_len = len;
    return rlc_child_io(&header, sizeof(header), true) &&
           rlc_child_io((void *)payload, len, true);
}
#endif

int main(int argc, char **argv)
{
#if defined(RLC_FIXTURE_BROKEN)
    (void)argc;
    (void)argv;
    return 1;
#else
    if (argc < 3 || strcmp(argv[1], "--resident") != 0)
        return 2;
    const char *nonce = argv[2];
    if (strlen(nonce) != RESIDENT_LAUNCH_NONCE_HEX)
        return 2;
    if (!rlc_child_reply(nonce, "READY", 5))
        return 3;
    if (argc > 3 && strcmp(argv[3], "park") == 0) {
        for (;;)
            pause();
    }
    struct resident_result_header input;
    memset(&input, 0, sizeof(input));
    char payload[1024];
    if (!rlc_child_io(&input, sizeof(input), false) ||
        memcmp(input.magic, "z23-res-run-v1", sizeof("z23-res-run-v1")) != 0 ||
        memcmp(input.nonce, nonce, sizeof(input.nonce)) != 0 ||
        input.payload_len == 0 || input.payload_len > sizeof(payload) ||
        !rlc_child_io(payload, input.payload_len, false))
        return 4;
    if (!rlc_child_reply(nonce, payload, input.payload_len))
        return 5;
    return 0;
#endif
}
