/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: z23-fixed-result-seccomp: emits the exact compiler-child filter
 *          bytes root installs at /etc/z23verify/fixed_result.seccomp.bpf,
 *          prints their SHA3-256 (the seccomp_filter_sha3 pin) and the
 *          allowlist, and verifies an installed file byte for byte. */
#include "fixed_result_seccomp.h"

#include "base/hex.h"
#include "sha3/sha3.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int frs_refuse(const char *why)
{
    fprintf(stderr, "fixed_result_seccomp_refuse=%s\n", why);
    return 2;
}

static int frs_emit_bytes(void)
{
    uint8_t prog[ZCL_FRS_MAX_BYTES];
    size_t len = 0;
    const char *why = NULL;
    if (!zcl_frs_build(prog, &len, &why)) return frs_refuse(why);
    if (isatty(STDOUT_FILENO)) return frs_refuse("stdout_is_terminal");
    return fwrite(prog, 1, len, stdout) == len && fflush(stdout) == 0
               ? 0 : frs_refuse("write_failed");
}

static int frs_print(void)
{
    uint8_t digest[32];
    size_t insns = 0;
    const char *why = NULL;
    char hex[65];
    if (!zcl_frs_sha3(digest, &insns, &why)) return frs_refuse(why);
    zcl_hex_encode(digest, 32u, hex);
    for (size_t i = 0; i < zcl_frs_allowed_count(); i++) {
        int nr = 0;
        const char *name = NULL, *rule = NULL;
        zcl_frs_allowed(i, &nr, &name, &rule);
        printf("allow nr=%d name=%s rule=%s\n", nr, name, rule);
    }
    printf("default=errno_eperm foreign_arch=kill_process x32=kill_process\n");
    printf("pin seccomp_filter_sha3=%s\n", hex);
    printf("fixed_result_seccomp insns=%zu bytes=%zu sha3=%s "
           "attest_eligible=0\n", insns, insns * ZCL_FRS_INSN_BYTES, hex);
    return 0;
}

static int frs_verify(const char *path)
{
    uint8_t want[ZCL_FRS_MAX_BYTES], got[ZCL_FRS_MAX_BYTES + 1];
    size_t len = 0;
    const char *why = NULL;
    if (!zcl_frs_build(want, &len, &why)) return frs_refuse(why);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return frs_refuse("filter_missing");
    ssize_t n = read(fd, got, sizeof(got));
    close(fd);
    if (n != (ssize_t)len || memcmp(want, got, len) != 0)
        return frs_refuse("filter_mismatch");
    printf("fixed_result_seccomp_verified=1 bytes=%zu attest_eligible=0\n", len);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "emit") == 0) return frs_emit_bytes();
    if (argc == 2 && strcmp(argv[1], "print") == 0) return frs_print();
    if (argc == 3 && strcmp(argv[1], "verify") == 0) return frs_verify(argv[2]);
    fprintf(stderr, "usage: z23-fixed-result-seccomp emit > FILE | print | "
                    "verify FILE\n");
    return 2;
}
