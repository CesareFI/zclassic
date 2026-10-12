/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: z23-fixed-result-publisher, run as root.
 *
 *   publish <record-sha3>  re-verify /var/lib/z23verify/staging/<record-sha3>
 *                          and add it no-clobber to the observation store
 *
 * It takes no path, UID or key from its environment; all trust comes from
 * root-owned /etc/z23verify. It never removes store history. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "verify/fixed_result_publisher.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    umask(0077);
    if (argc != 3 || strcmp(argv[1], "publish") != 0) {
        fprintf(stderr, "fixed_result_publisher_refuse=request_shape_unsupported\n");
        return 2;
    }
    struct zcl_frp_result r;
    zcl_frp_publish_production(argv[2], &r);
    if (r.reason) {
        fprintf(stderr, "fixed_result_publisher_refuse=%s conflict_recorded=%d\n",
                r.reason, r.conflict_recorded ? 1 : 0);
        return 2;
    }
    printf("fixed_result_publisher_published=1 verdict=%s conflict=%s "
           "conflict_recorded=%d store_key=%s record_sha3=%s\n",
           r.failure ? "fail" : "pass", r.conflict ? r.conflict : "none",
           r.conflict_recorded ? 1 : 0, r.store_key, r.record_sha3);
    return fflush(stdout) == 0 ? 0 : 2;
}
