/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: package-local proof that rvuser refuses a truncated ELF with a
 * typed setup stop. The full loader and syscall proofs live in the
 * repository suite. */
#include "rvuser/rvuser.h"

#include <stdint.h>
#include <string.h>

int main(void)
{
    static const uint8_t junk[4] = {0x7f, 'E', 'L', 'F'};
    struct rvuser_io io;
    memset(&io, 0, sizeof(io));
    struct rvuser_limits lim = {1000, 16, (size_t)1 << 20, 0};
    struct rvuser_result out;
    if (rvuser_run(junk, sizeof(junk), NULL, NULL, &io, &lim, &out) != 0)
        return 1;
    if (out.stop != RVUSER_STOP_SETUP || out.error != RVUSER_ERR_TRUNCATED)
        return 2;
    if (strcmp(rvuser_error_name(out.error), "") == 0 ||
        strcmp(rvuser_stop_name(out.stop), "") == 0)
        return 3;
    return 0;
}
