/* purpose: Validate canonical SSH composite public-key bytes and derive representation roots. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/device_host_key.h"
#include "models/device_pairing.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include <string.h>

struct zcl_result device_host_key_root(uint32_t backend_profile, const uint8_t *blob,
    size_t length, uint8_t root[32])
{
    static const uint8_t algorithm[] = "ssh-mldsa44-ed25519";
    static const uint8_t domain[] = "Z23HOSTSSHKEY1";
    if (!blob || !root || length != DEVICE_HOST_KEY_BLOB_SIZE)
        LOG_RETURN(ZCL_ERR(-1, "missing output or noncanonical composite public-key length"), "device_host_key", "missing output or noncanonical composite public-key length");
    if (backend_profile != DEVICE_PAIRING_HOST_OPENSSH_MLKEM768X25519_MLDSA44ED25519)
        LOG_RETURN(ZCL_ERR(-1, "unsupported host backend profile"), "device_host_key", "unsupported host backend profile");
    if (zcl_read_u32_be(blob) != sizeof(algorithm) - 1 ||
        memcmp(blob + 4, algorithm, sizeof(algorithm) - 1) ||
        zcl_read_u32_be(blob + 4 + sizeof(algorithm) - 1) != 1344)
        LOG_RETURN(ZCL_ERR(-1, "noncanonical plain composite SSH public key"), "device_host_key", "noncanonical plain composite SSH public key");
    uint8_t framing[8];
    zcl_write_u32_le(framing, backend_profile);
    zcl_write_u32_be(framing + 4, (uint32_t)length);
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, framing, sizeof(framing));
    sha3_256_write(&hash, blob, length);
    sha3_256_finalize(&hash, root);
    return ZCL_OK;
}
