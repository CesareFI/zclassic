/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: z23-fixed-result-signer, run as z23verify (UID 60092).
 *
 *   pubkey    print the installed seed's public key for root to pin
 *   seal-fds  seal the launch handed over as descriptors 3..7: launch.bin,
 *             object.o, deps.d, stderr.bin, preprocessed.i (a failure
 *             receipt leaves 4 and 5 closed)
 *   seal-fail-fds  seal a failure handed over as 3 launch.bin, 4 stderr.bin,
 *             5 preprocessed.i
 *
 * It executes nothing and takes no path, UID or key from its arguments or
 * environment; all trust comes from root-owned /etc/z23verify. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "verify/fixed_result_signer.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int refuse(const char *why)
{
    fprintf(stderr, "fixed_result_signer_refuse=%s\n",
            why ? why : ZCL_FRS_WHY_ARGUMENTS);
    return 2;
}

static int pubkey_main(void)
{
    char hex[65];
    const char *why = zcl_frs_pubkey_production(hex);
    if (why) return refuse(why);
    printf("%s\n", hex);
    return fflush(stdout) == 0 ? 0 : refuse("signer_output_failed");
}

static int seal_main(const int fds[ZCL_FRS_INPUTS])
{
    struct zcl_frs_result r;
    zcl_frs_seal_production(fds, &r);
    if (r.reason) return refuse(r.reason);
    printf("fixed_result_signer_sealed=1 verdict=%s exit_code=%d "
           "store_key=%s record_sha3=%s\n",
           r.failure ? "fail" : "pass", (int)r.exit_code, r.store_key,
           r.record_sha3);
    return fflush(stdout) == 0 ? 0 : refuse("signer_output_failed");
}

static int open_fd(int fd)
{
    return fcntl(fd, F_GETFD) >= 0 ? fd : -1;
}

/* seal-fds: 3..7 in slot order, a closed descriptor being absent. */
static int seal_fds_main(void)
{
    int fds[ZCL_FRS_INPUTS];
    for (int i = 0; i < ZCL_FRS_INPUTS; i++) fds[i] = open_fd(3 + i);
    return seal_main(fds);
}

/* seal-fail-fds: 3 launch.bin, 4 stderr.bin, 5 preprocessed.i, the dense
 * layout a service manager's OpenFile= list produces for a failure. */
static int seal_fail_fds_main(void)
{
    int fds[ZCL_FRS_INPUTS] = {-1, -1, -1, -1, -1};
    fds[ZCL_FRS_IN_RECEIPT] = open_fd(3);
    fds[ZCL_FRS_IN_STDERR] = open_fd(4);
    fds[ZCL_FRS_IN_PP] = open_fd(5);
    if (open_fd(6) >= 0 || open_fd(7) >= 0) return refuse(ZCL_FRS_WHY_INPUTS);
    return seal_main(fds);
}

int main(int argc, char **argv)
{
    umask(0077);
    if (argc == 2 && strcmp(argv[1], "pubkey") == 0) return pubkey_main();
    if (argc == 2 && strcmp(argv[1], "seal-fds") == 0) return seal_fds_main();
    if (argc == 2 && strcmp(argv[1], "seal-fail-fds") == 0)
        return seal_fail_fds_main();
    return refuse("request_shape_unsupported");
}
