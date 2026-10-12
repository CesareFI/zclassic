/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "mlkem/mlkem.h"

#include <stdio.h>
#include <string.h>

static bool urandom_bytes(void *context, uint8_t *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    (void)context;
    if (!f)
        return false;
    const bool ok = fread(out, 1, len, f) == len;
    fclose(f);
    return ok;
}

int main(void)
{
    uint8_t ek[ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE];
    uint8_t dk[ZCL_MLKEM768_DECAPSULATION_KEY_SIZE];
    uint8_t ct[ZCL_MLKEM768_CIPHERTEXT_SIZE];
    uint8_t sender[ZCL_MLKEM768_SHARED_SECRET_SIZE];
    uint8_t receiver[ZCL_MLKEM768_SHARED_SECRET_SIZE];

    if (zcl_mlkem768_keygen(urandom_bytes, NULL, ek, dk) != ZCL_MLKEM_OK ||
        zcl_mlkem768_encaps(urandom_bytes, NULL, ek, sizeof(ek), ct, sender) !=
            ZCL_MLKEM_OK ||
        zcl_mlkem768_decaps(dk, sizeof(dk), ct, sizeof(ct), receiver) !=
            ZCL_MLKEM_OK)
        return 1;
    return memcmp(sender, receiver, sizeof(sender)) == 0 ? 0 : 1;
}
