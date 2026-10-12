/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The real fixed-result worker (tools/verify/fixed_result_worker.c)
 *          linked into the test harness, so the verify_signer dress
 *          rehearsal runs its unmodified `qualify` path in a forked child.
 *          Only `main` is renamed; every check and compiler argument is the
 *          worker's own. */
#if defined(__linux__)
#undef _GNU_SOURCE
int zcl_test_fixed_result_worker_main(int argc, char **argv);
#define main zcl_test_fixed_result_worker_main
#include "verify/fixed_result_worker.c"
#undef main
#else
typedef int zcl_test_fixed_result_worker_linux_only;
#endif
