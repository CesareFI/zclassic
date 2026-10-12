/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zssh — harness group for the zssh module (contexts/commons/modules/zssh/).
 *
 * Runs ONLY the module end-to-end suite, tests/test_zssh.c, which pumps a
 * real client and server engine against each other over in-memory FIFOs and
 * links the real layers. Its main is renamed for this translation unit, and
 * the group reports 0 when the suite exits 0 and 1 otherwise. The four layer
 * tests (auth, channel, kex, packet) stay standalone module tests and are not
 * registered here.
 */

#define main zssh_e2e_suite_main
#include "../../../contexts/commons/modules/zssh/tests/test_zssh.c"
#undef main

int test_zssh(void)
{
    return zssh_e2e_suite_main() == 0 ? 0 : 1;
}
