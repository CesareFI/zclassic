/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_app_catalog.h"
#include "blue_ca.h"
#include "blue_secure.h"
#include "blue_install_params.h"
#include "ledger_hid.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

enum { TARGET_ID = 0x31010004, MAX_CODE = 65536, CHUNK = 208 };
typedef struct {
    const char *name;
    const char *version;
    uint8_t hash[32];
    bool zcl_sign_path;
} app_profile;

static const app_profile profiles[] = {
    {
        "ZCL Probe", "0.1.0",
        {0xb3, 0x87, 0x04, 0xd3, 0x47, 0x6a, 0xc9, 0x91,
         0x4d, 0xde, 0x5d, 0x81, 0x6d, 0xe8, 0x89, 0x30,
         0xed, 0x70, 0x5b, 0xdd, 0x53, 0x24, 0x69, 0x03,
         0x41, 0x9c, 0x1c, 0xb9, 0x62, 0x11, 0xeb, 0x33}, false
    },
    {
        "ZCL Fixture", "0.1.0",
        {0xf1, 0x0b, 0xc3, 0x66, 0xc6, 0xea, 0xcb, 0xeb,
         0x58, 0xc6, 0x36, 0x2d, 0xca, 0x39, 0x15, 0x19,
         0x3d, 0x4b, 0x76, 0x47, 0x7c, 0x89, 0x86, 0x30,
         0xe7, 0x9e, 0x09, 0x6a, 0xe9, 0x9a, 0xe4, 0xc6}, false
    },
    {
        "ZCL Review", "0.2.0",
        {0x9d, 0xe4, 0x44, 0xa3, 0x17, 0x95, 0x20, 0xd7,
         0xed, 0xf6, 0xa6, 0x0e, 0x67, 0x41, 0x7e, 0xf5,
         0xe5, 0x79, 0x42, 0xeb, 0x3d, 0x04, 0xd5, 0x3e,
         0x73, 0xfa, 0x1a, 0x7f, 0x69, 0xad, 0x75, 0x28}, false
    },
    {
        "ZCL Review", "0.3.0",
        {0xae, 0x57, 0x55, 0x69, 0x0d, 0x83, 0x17, 0xfd,
         0xa9, 0xfa, 0x4c, 0x82, 0x7a, 0x8c, 0x5c, 0xdc,
         0x60, 0x49, 0x7b, 0x0c, 0xd9, 0x2a, 0x19, 0x6f,
         0xe4, 0xe2, 0x8e, 0x69, 0xb6, 0x2f, 0x9e, 0xaf}, false
    },
    {
        "ZCL Review", "0.3.1",
        {0xda, 0x4f, 0x66, 0x71, 0xea, 0xa4, 0x1b, 0x3a,
         0x1c, 0x94, 0xec, 0x5f, 0x37, 0x93, 0x6f, 0xc7,
         0x8f, 0x48, 0x45, 0xec, 0x96, 0xac, 0x8d, 0x84,
         0xc0, 0xf9, 0x4a, 0xa3, 0x7b, 0x86, 0x2d, 0x08}, false
    },
    {
        "ZCL Shielded Review", "0.5.0",
        {0x42, 0xfc, 0x4f, 0xe0, 0xc7, 0xe9, 0xac, 0x38,
         0x64, 0xed, 0x49, 0x77, 0xb0, 0xac, 0x60, 0x1b,
         0x74, 0x2c, 0x95, 0x86, 0x87, 0x98, 0xfa, 0x80,
         0x80, 0x70, 0x34, 0xb8, 0x3f, 0xd0, 0xee, 0xc2}, false
    },
    {
        "ZCL Shielded Review", "0.5.1",
        {0x87, 0x7b, 0x78, 0x74, 0x7b, 0x4f, 0x57, 0x36,
         0x42, 0x92, 0xaa, 0x4d, 0x70, 0xbf, 0x7a, 0xf5,
         0x6a, 0x0a, 0xc9, 0x42, 0x4d, 0x4a, 0x28, 0xf5,
         0x67, 0x70, 0xe6, 0x4e, 0xb4, 0xe6, 0x01, 0x97}, false
    },
    {
        "ZCL Shielded Review", "0.5.2",
        {0x8d, 0x37, 0xf0, 0xde, 0x33, 0x40, 0x8c, 0xe3,
         0xd6, 0xe7, 0x20, 0x12, 0x16, 0x36, 0x46, 0x90,
         0x8b, 0x89, 0x78, 0xe3, 0xfd, 0x88, 0xe1, 0x9d,
         0x7a, 0xa9, 0x2d, 0x08, 0x46, 0x0f, 0x08, 0x5b}, false
    },
    {
        "ZCL Shielded Review", "0.5.8",
        {0x64, 0x66, 0x83, 0x7f, 0x12, 0x1c, 0xfb, 0x3b,
         0xc8, 0x74, 0xad, 0xc5, 0x99, 0xff, 0x41, 0x51,
         0x83, 0x67, 0x73, 0x4a, 0xf4, 0x3c, 0x65, 0x8c,
         0x8c, 0xfe, 0xd4, 0x82, 0xa8, 0xe8, 0xcd, 0x42}, false
    },
    {
        "ZCL Shielded Review", "0.5.9",
        {0xc2, 0x47, 0x1f, 0x69, 0x6f, 0x92, 0xcb, 0xc5,
         0x08, 0x53, 0xd0, 0xef, 0xdb, 0xff, 0x41, 0x25,
         0x3a, 0x11, 0x00, 0x90, 0x22, 0x7b, 0x73, 0x4d,
         0x1f, 0x33, 0xe0, 0x4c, 0xed, 0x42, 0x24, 0x5a}, false
    },
    {
        "ZCL Shielded Review", "0.5.10",
        {0x08, 0x28, 0x4d, 0xd4, 0xfd, 0xd7, 0xf2, 0x2f,
         0xe3, 0x48, 0x3c, 0x76, 0x0a, 0xc8, 0x0d, 0xee,
         0x9e, 0x3c, 0x69, 0x0a, 0xc3, 0xe1, 0xf1, 0xb4,
         0x3b, 0x2f, 0x00, 0x08, 0x86, 0x64, 0x56, 0xd3}, false
    },
    {
        "ZCL Shielded Review", "0.5.11",
        {0x67, 0x1d, 0x32, 0x3a, 0x0d, 0x97, 0x20, 0xbd,
         0xd7, 0x9a, 0xf3, 0xcb, 0xb5, 0x31, 0x66, 0x48,
         0x1d, 0xa0, 0x49, 0x52, 0xd7, 0x10, 0x19, 0x17,
         0xce, 0xd5, 0x19, 0x2d, 0xba, 0x1f, 0xa4, 0xff}, false
    },
    {
        "ZCL Sign Test", "0.1.0",
        {0x0f, 0xc3, 0x89, 0x31, 0xf3, 0x34, 0x47, 0x15,
         0x09, 0x09, 0x53, 0x53, 0x84, 0x95, 0xc9, 0x64,
         0x8b, 0x3e, 0x47, 0x56, 0x21, 0x85, 0x3a, 0xc4,
         0xc2, 0xdc, 0x7e, 0x56, 0x88, 0x74, 0x59, 0x0b}, true
    },
    {
        "ZCL Wallet", "0.3.4",
        {0xe6, 0xc1, 0x58, 0x62, 0x1a, 0x68, 0xbb, 0xf3,
         0x0a, 0xe9, 0x2a, 0x72, 0x23, 0xfe, 0x15, 0x1a,
         0xa9, 0xd5, 0x7f, 0xd1, 0x84, 0x46, 0x6b, 0x0c,
         0x65, 0x37, 0xc0, 0xcf, 0x39, 0xc5, 0xbf, 0x6a}, true
    },
    {
        "ZCL Wallet", "0.3.44",
        {0xd5, 0x28, 0x8c, 0x8c, 0xbc, 0x2e, 0x1e, 0x5f,
         0xc2, 0xf4, 0x7d, 0x6d, 0x11, 0xd1, 0x47, 0x96,
         0x74, 0x4e, 0xdf, 0x33, 0x46, 0xef, 0xfd, 0x5f,
         0x7e, 0xb9, 0x37, 0xd6, 0x5e, 0x44, 0x61, 0xa8}, true
    },
    {
        "ZCL Wallet", "0.3.45",
        {0x5b, 0x7b, 0xb5, 0xa2, 0x05, 0xca, 0x4c, 0xc2,
         0x81, 0xe6, 0xbb, 0xdc, 0x45, 0x82, 0xb1, 0xf5,
         0x58, 0xba, 0xbd, 0x87, 0x1c, 0x05, 0x8e, 0xd6,
         0xed, 0xe7, 0xec, 0x0a, 0x2b, 0xa5, 0x9b, 0x93}, true
    },
    {
        "ZCL Wallet", "0.3.46",
        {0xd0, 0x05, 0xd4, 0xfa, 0x9d, 0x4a, 0x77, 0xcf,
         0x17, 0x81, 0xc6, 0xcf, 0x56, 0x6d, 0x79, 0x32,
         0xe2, 0x46, 0x8d, 0x32, 0xd0, 0xb8, 0xf6, 0xf1,
         0x1a, 0xcb, 0x60, 0x11, 0x0f, 0xfe, 0x28, 0xfb}, true
    }
};

static const app_profile *profile_named(const char *name) {
    for (size_t i = 0; i < sizeof profiles / sizeof profiles[0]; ++i)
        if (strcmp(profiles[i].name, name) == 0) return &profiles[i];
    return NULL;
}

typedef struct {
    int fd;
    bool secure;
    blue_secure_channel channel;
    uint8_t version[31];
    size_t version_length;
} installer;

static void put_be32(uint8_t *output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static int exchange_body(installer *device, uint8_t ins,
                         const uint8_t *response, size_t response_length,
                         uint8_t *body, size_t body_capacity, size_t *body_length) {
    if (device->secure) {
        if (blue_secure_unwrap(&device->channel, response, response_length,
                               body, body_capacity, body_length) < 0) {
            fprintf(stderr, "Invalid secure-channel reply to command %02x.\n", ins);
            return -1;
        }
    } else {
        if (response_length > body_capacity) return -1;
        memcpy(body, response, response_length);
        *body_length = response_length;
    }
    return 0;
}

static int exchange_send(installer *device, const uint8_t *data, size_t length,
                         uint8_t *apdu, size_t apdu_capacity,
                         size_t *wire_length) {
    *wire_length = length;
    if (device->secure) {
        if (blue_secure_wrap(&device->channel, data, length, apdu + 5,
                             apdu_capacity - 5, wire_length) < 0) return -1;
    } else if (length) memcpy(apdu + 5, data, length);
    apdu[4] = (uint8_t)*wire_length;
    return 0;
}

static int exchange_check_status(uint8_t ins, const uint8_t *data, size_t length,
                                 const uint8_t *response, size_t response_length) {
    uint16_t status = (uint16_t)(((uint16_t)response[response_length - 2] << 8) |
                                  response[response_length - 1]);
    if (status != 0x9000) {
        fprintf(stderr, "Selected device rejected command %02x with status %04x.\n",
                ins, status);
        if (status == 0x6985 && ins == 0 && length > 0 &&
            (data[0] == 0x12 || data[0] == 0x13))
            fputs("Custom CA changes require Blue Recovery mode.\n", stderr);
        return -1;
    }
    return 0;
}

static int exchange(installer *device, uint8_t ins, uint8_t p1,
                    const uint8_t *data, size_t length,
                    uint8_t *body, size_t body_capacity, size_t *body_length) {
    if (!device || length > 225 || (length && !data) || !body || !body_length)
        return -1;
    uint8_t apdu[256] = {0xe0, ins, p1, 0, 0};
    size_t wire_length = 0;
    if (exchange_send(device, data, length, apdu, sizeof apdu,
                      &wire_length) < 0)
        return -1;
    uint8_t response[LEDGER_HID_MAX_RESPONSE];
    size_t response_length = 0;
    if (ledger_hid_exchange_timeout(device->fd, apdu, 5 + wire_length,
                                    response, sizeof response,
                                    &response_length, 60000) < 0 ||
        response_length < 2) {
        fprintf(stderr, "No HID reply to command %02x.\n", ins);
        return -1;
    }
    if (exchange_check_status(ins, data, length, response, response_length) < 0)
        return -1;
    response_length -= 2;
    return exchange_body(device, ins, response, response_length,
                         body, body_capacity, body_length);
}

static int no_reply(installer *device, uint8_t ins, uint8_t p1,
                    const uint8_t *data, size_t length) {
    uint8_t body[256];
    size_t body_length = 0;
    return exchange(device, ins, p1, data, length,
                    body, sizeof body, &body_length) == 0 &&
        body_length == 0 ? 0 : -1;
}

static int send_certificate(installer *device, EVP_PKEY *signer,
                            EVP_PKEY *subject, uint8_t p1,
                            const uint8_t *prefix, size_t prefix_length) {
    uint8_t public_key[65], message[82], cert[140];
    if (blue_key_public(subject, public_key) < 0 ||
        prefix_length > sizeof message - sizeof public_key) return -1;
    memcpy(message, prefix, prefix_length);
    memcpy(message + prefix_length, public_key, sizeof public_key);
    size_t signature_length = sizeof cert - 67;
    cert[0] = sizeof public_key;
    memcpy(cert + 1, public_key, sizeof public_key);
    if (blue_sign(signer, message, prefix_length + sizeof public_key,
                  cert + 67, &signature_length) < 0 || signature_length > 73)
        return -1;
    cert[66] = (uint8_t)signature_length;
    return no_reply(device, 0x51, p1, cert, 67 + signature_length);
}

static int parse_device_certificate(const uint8_t *cert, size_t length,
                                    uint8_t public_key[65],
                                    const uint8_t **signature,
                                    size_t *signature_length) {
    if (!cert || length < 4 || !public_key || !signature || !signature_length)
        return -1;
    size_t pos = 0, header_length = cert[pos++];
    if (header_length > length - pos) return -1;
    pos += header_length;
    if (pos >= length || cert[pos++] != 65 || length - pos < 65) return -1;
    memcpy(public_key, cert + pos, 65);
    if (public_key[0] != 4) return -1;
    pos += 65;
    if (pos >= length) return -1;
    size_t signature_size = cert[pos++];
    if (signature_size == 0 || signature_size != length - pos) return -1;
    *signature = cert + pos;
    *signature_length = signature_size;
    return 0;
}

/* Reads the device issuer and ephemeral certificates, verifies the issuer's
 * signature over both nonces and the device ephemeral key, and acknowledges.
 * On success peer holds the device ephemeral public key. */
static int verify_device_certificates(installer *device, const uint8_t nonce[8],
                                      const uint8_t device_nonce[8],
                                      uint8_t peer[65]) {
    uint8_t first[256], second[256], issuer[65], message[82];
    size_t first_length = 0, second_length = 0, signature_length = 0;
    const uint8_t *signature = NULL;
    if (exchange(device, 0x52, 0, NULL, 0, first, sizeof first,
                 &first_length) < 0 ||
        exchange(device, 0x52, 0x80, NULL, 0, second, sizeof second,
                 &second_length) < 0 ||
        parse_device_certificate(first, first_length, issuer,
                                 &signature, &signature_length) < 0 ||
        parse_device_certificate(second, second_length, peer,
                                 &signature, &signature_length) < 0)
        return -1;
    message[0] = 0x12;
    memcpy(message + 1, device_nonce, 8);
    memcpy(message + 9, nonce, 8);
    memcpy(message + 17, peer, 65);
    if (blue_verify(issuer, message, sizeof message,
                    signature, signature_length) < 0 ||
        no_reply(device, 0x53, 0, NULL, 0) < 0) return -1;
    return 0;
}

static int establish_channel(installer *device, EVP_PKEY *ca_key) {
    uint8_t target[4], nonce[8], reply[256], device_nonce[8];
    size_t length = 0;
    put_be32(target, TARGET_ID);
    if (exchange(device, 0x04, 0, target, sizeof target,
                 reply, sizeof reply, &length) < 0 ||
        RAND_bytes(nonce, sizeof nonce) != 1 ||
        exchange(device, 0x50, 0, nonce, sizeof nonce,
                 reply, sizeof reply, &length) < 0 || length < 12) return -1;
    memcpy(device_nonce, reply + 4, sizeof device_nonce);
    EVP_PKEY *root = ca_key ? ca_key : blue_key_generate();
    EVP_PKEY *ephemeral = blue_key_generate();
    uint8_t root_prefix = 0x01, ephemeral_prefix[17] = {0x11};
    memcpy(ephemeral_prefix + 1, nonce, 8);
    memcpy(ephemeral_prefix + 9, device_nonce, 8);
    int result = -1;
    if (!root || !ephemeral ||
        send_certificate(device, root, root, 0, &root_prefix, 1) < 0 ||
        send_certificate(device, root, ephemeral, 0x80,
                         ephemeral_prefix, sizeof ephemeral_prefix) < 0)
        goto done;
    uint8_t peer[65];
    if (verify_device_certificates(device, nonce, device_nonce, peer) < 0)
        goto done;
    uint8_t secret[32];
    if (blue_ecdh(ephemeral, peer, secret) == 0 &&
        blue_secure_init(&device->channel, secret) == 0) {
        device->secure = true;
        result = 0;
    }
    OPENSSL_cleanse(secret, sizeof secret);
done:
    EVP_PKEY_free(ephemeral);
    if (!ca_key) EVP_PKEY_free(root);
    return result;
}

static int verify_secure_version(installer *device) {
    uint8_t command = 0x10, response[256];
    size_t length = 0;
    if (exchange(device, 0, 0, &command, 1, response, sizeof response,
                 &length) < 0 || length < 6 || response[4] == 0 ||
        response[4] > sizeof device->version ||
        length < 5 + (size_t)response[4] ||
        response[0] != (uint8_t)(TARGET_ID >> 24) ||
        response[1] != (uint8_t)(TARGET_ID >> 16) ||
        response[2] != (uint8_t)(TARGET_ID >> 8) ||
        response[3] != (uint8_t)TARGET_ID) return -1;
    for (size_t i = 0; i < response[4]; ++i)
        if (response[5 + i] < 0x20 || response[5 + i] > 0x7e) return -1;
    device->version_length = response[4];
    memcpy(device->version, response + 5, device->version_length);
    printf("Development channel reports target %02x%02x%02x%02x; device identity is unverified.\n",
           response[0], response[1], response[2], response[3]);
    return 0;
}

static uint16_t crc16(const uint8_t *data, size_t length) {
    uint16_t crc = 0xffff;
    for (size_t i = 0; i < length; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (uint16_t)((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0));
    }
    return crc;
}

static int load_segment(installer *device, uint32_t address,
                        const uint8_t *data, size_t length) {
    if (length > MAX_CODE) return -1;
    uint8_t command[1 + 4 + CHUNK];
    command[0] = 0x05;
    put_be32(command + 1, address);
    if (no_reply(device, 0, 0, command, 5) < 0) return -1;
    for (size_t offset = 0; offset < length; offset += CHUNK) {
        size_t count = length - offset < CHUNK ? length - offset : CHUNK;
        command[0] = 0x06;
        command[1] = (uint8_t)(offset >> 8);
        command[2] = (uint8_t)offset;
        memcpy(command + 3, data + offset, count);
        if (no_reply(device, 0, 0, command, 3 + count) < 0) return -1;
    }
    command[0] = 0x07;
    if (no_reply(device, 0, 0, command, 1) < 0) return -1;
    uint16_t crc = crc16(data, length);
    command[0] = 0x08;
    command[1] = command[2] = 0;
    put_be32(command + 3, (uint32_t)length);
    command[7] = (uint8_t)(crc >> 8);
    command[8] = (uint8_t)crc;
    return no_reply(device, 0, 0, command, 9);
}

static bool prepare_image(size_t code_length, const app_profile *profile,
                          uint8_t create[21],
                          uint8_t params[ZCL_BLUE_INSTALL_PARAMS_MAX],
                          size_t *params_length) {
    if (code_length < 1024 || code_length > MAX_CODE || code_length % 64)
        return false;
    *params_length = blue_install_params(profile->name, profile->version,
                                         profile->zcl_sign_path, params);
    if (!*params_length) return false;
    memset(create, 0, 21);
    create[0] = 0x0b;
    put_be32(create + 1, (uint32_t)code_length);
    put_be32(create + 9, (uint32_t)*params_length);
    put_be32(create + 17, 1);
    return true;
}

static int install(installer *device, const uint8_t *code,
                   size_t code_length, const app_profile *profile,
                   EVP_PKEY *ca_key) {
    uint8_t params[ZCL_BLUE_INSTALL_PARAMS_MAX], create[21];
    size_t params_length = 0;
    if (!prepare_image(code_length, profile, create, params,
                       &params_length)) return -1;
    uint8_t commit[1 + 1 + 73] = {0x09};
    size_t commit_length = 1;
    if (ca_key) {
        uint8_t digest[32];
        size_t signature_length = 0;
        if (blue_ca_app_hash(TARGET_ID, device->version,
                             device->version_length, create, code, code_length,
                             params, params_length, digest) < 0 ||
            blue_ca_sign_digest(ca_key, digest, commit + 2,
                                &signature_length) < 0) return -1;
        OPENSSL_cleanse(digest, sizeof digest);
        commit[1] = (uint8_t)signature_length;
        commit_length = 2 + signature_length;
    }
    printf("Creating the %s app slot.\n", profile->name);
    if (no_reply(device, 0, 0, create, sizeof create) < 0) return -1;
    printf("Loading the %s code.\n", profile->name);
    if (load_segment(device, 0, code, code_length) < 0) return -1;
    printf("Loading the %s name and version.\n", profile->name);
    if (load_segment(device, (uint32_t)code_length,
                     params, params_length) < 0) return -1;
    printf("Committing the %s app.\n", profile->name);
    return no_reply(device, 0, 0, commit, commit_length);
}

static bool read_image_exact(int fd, uint8_t *bytes, size_t length) {
    for (size_t used = 0; used < length;) {
        ssize_t got = read(fd, bytes + used, length - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        used += (size_t)got;
    }
    uint8_t extra;
    return read(fd, &extra, 1) == 0;
}

static bool load_image_regular(const char *path, uint8_t **data,
                               size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat info;
    bool valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_size >= 1024 && info.st_size <= MAX_CODE &&
        info.st_size % 64 == 0;
    size_t count = valid ? (size_t)info.st_size : 0;
    uint8_t *bytes = valid ? malloc(count) : NULL;
    if (!bytes) valid = false;
    if (valid) valid = read_image_exact(fd, bytes, count);
    if (close(fd) != 0) valid = false;
    if (!valid) { free(bytes); return false; }
    *data = bytes;
    *length = count;
    return true;
}

static int read_binary(const char *path, uint8_t **data, size_t *length,
                       const app_profile **profile, bool installing) {
    uint8_t *bytes = NULL;
    size_t count = 0;
    if (!load_image_regular(path, &bytes, &count)) return -1;
    int result = -1;
    uint8_t hash[32];
    bool blocked = false;
    if (SHA256(bytes, count, hash)) {
        for (size_t i = 0; i < sizeof profiles / sizeof profiles[0]; ++i) {
            if (CRYPTO_memcmp(hash, profiles[i].hash, sizeof hash) == 0) {
                if (installing &&
                    !blue_install_image_allowed(profiles[i].name,
                                                profiles[i].version)) {
                    blocked = true;
                    break;
                }
                *profile = &profiles[i];
                result = 0;
                break;
            }
        }
    }
    if (result < 0)
        fputs(blocked ? "App image is not approved for installation.\n" :
              "App image SHA-256 does not match a reviewed build.\n", stderr);
    if (result < 0) free(bytes);
    else { *data = bytes; *length = count; }
    return result;
}

static int open_blue(const char *path) {
    int fd = open(path, O_RDWR | O_CLOEXEC);
    struct hidraw_devinfo info;
    if (fd < 0 || ioctl(fd, HIDIOCGRAWINFO, &info) < 0 ||
        info.vendor != 0x2c97 || info.product != 0) {
        fputs("The selected interface does not report Ledger Blue USB IDs.\n",
              stderr);
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static int enroll_ca(installer *device, EVP_PKEY *ca_key) {
    static const char name[] = "Z23";
    uint8_t command[1 + 1 + sizeof name - 1 + 1 + 65] = {
        0x12, sizeof name - 1, 'Z', '2', '3', 65
    };
    if (blue_key_public(ca_key, command + sizeof command - 65) < 0)
        return -1;
    return no_reply(device, 0, 0, command, sizeof command);
}

static int list_apps(installer *device, const char *name,
                     const uint8_t expected[32]) {
    blue_app_entry entries[64];
    size_t count = 0;
    for (size_t page = 0; page < 32; ++page) {
        uint8_t command = page ? 0x0f : 0x0e;
        uint8_t reply[LEDGER_HID_MAX_RESPONSE];
        size_t length = 0, page_count = 0;
        if (exchange(device, 0, 0, &command, 1, reply, sizeof reply,
                     &length) < 0 ||
            blue_app_catalog_parse(reply, length, entries + count,
                                   64 - count, &page_count) < 0)
            return -1;
        if (!page_count) {
            if (expected) {
                if (!blue_app_catalog_unique_hash(entries, count,
                                                   name, expected)) return -1;
                printf("%s catalog hash matches the reviewed installation payload.\n",
                       name);
                return 0;
            }
            for (size_t i = 0; i < count; ++i) {
                printf("%s app hash ", entries[i].name);
                for (size_t j = 0; j < sizeof entries[i].hash; ++j)
                    printf("%02x", entries[i].hash[j]);
                putchar('\n');
            }
            printf("%zu application(s) listed by the selected device.\n", count);
            return 0;
        }
        count += page_count;
    }
    return -1;
}

static int verify_catalog(installer *device, const uint8_t *code,
                          size_t code_length, const app_profile *profile) {
    uint8_t params[ZCL_BLUE_INSTALL_PARAMS_MAX], create[21], digest[32];
    size_t params_length = 0;
    if (!prepare_image(code_length, profile, create, params,
                       &params_length) ||
        blue_ca_app_hash(TARGET_ID, device->version,
            device->version_length, create, code, code_length,
            params, params_length, digest) < 0) return -1;
    int result = list_apps(device, profile->name, digest);
    OPENSSL_cleanse(digest, sizeof digest);
    return result;
}

static int run_installer(installer *device, bool delete_app, bool channel_only,
                         const app_profile *profile,
                         const uint8_t *code, size_t code_length,
                         EVP_PKEY *ca_key, bool enroll, bool reset,
                         bool list, bool verify) {
    int result = establish_channel(device, enroll || reset ? NULL : ca_key);
    if (result == 0) result = verify_secure_version(device);
    if (result != 0) return result;
    if (verify) return verify_catalog(device, code, code_length, profile);
    if (list) return list_apps(device, NULL, NULL);
    if (enroll) return enroll_ca(device, ca_key);
    if (reset) {
        const uint8_t command = 0x13;
        return no_reply(device, 0, 0, &command, 1);
    }
    if (delete_app) {
        uint8_t delete_command[2 + 32] = {0x0c};
        size_t name_length = strlen(profile->name);
        delete_command[1] = (uint8_t)name_length;
        memcpy(delete_command + 2, profile->name, name_length);
        return no_reply(device, 0, 0, delete_command, 2 + name_length);
    }
    if (!channel_only) {
        printf("Development channel established; device identity unverified; loading %s.\n",
               profile->name);
        return install(device, code, code_length, profile, ca_key);
    }
    return 0;
}

static void report_result(int result, bool delete_app, bool channel_only,
                          bool enroll, bool reset, bool list, bool verify,
                          const app_profile *profile) {
    if (result == 0 && enroll)
        puts("Selected device accepted the Z23 custom CA enrollment command.");
    else if (result == 0 && reset)
        puts("Selected device accepted the custom CA reset command.");
    else if (result == 0 && delete_app)
        printf("%s delete command accepted by the selected device.\n",
               profile->name);
    else if (result == 0 && (list || verify)) return;
    else if (result == 0 && channel_only)
        puts("Development channel established; device identity unverified.");
    else if (result == 0)
        printf("%s install command accepted by the selected device.\n",
               profile->name);
    else if (verify)
        fputs("Selected device catalog image check failed.\n", stderr);
    else fputs("Installation failed. Check the selected device's screen.\n",
               stderr);
}

typedef struct {
    const char *image_path;
    const char *ca_path;
    const app_profile *profile;
    bool channel_only, delete_app, enroll, reset, list, verify;
} install_args;

static bool parse_ca_read_args(int argc, char **argv,
                               install_args *args) {
    if (argc != 4) return false;
    if (strcmp(argv[2], "--ca-enroll") == 0) {
        args->ca_path = argv[3];
        args->enroll = true;
    } else if (strcmp(argv[2], "--ca-channel-only") == 0) {
        args->ca_path = argv[3];
        args->channel_only = true;
    } else if (strcmp(argv[2], "--ca-list") == 0) {
        args->ca_path = argv[3];
        args->list = true;
    } else return false;
    return true;
}

static bool parse_ca_delete_args(int argc, char **argv,
                                install_args *args) {
    if (argc != 4) return false;
    const char *name = NULL;
    if (strcmp(argv[2], "--ca-delete-fixture") == 0)
        name = "ZCL Fixture";
    else if (strcmp(argv[2], "--ca-delete-review") == 0)
        name = "ZCL Review";
    else if (strcmp(argv[2], "--ca-delete-shielded-review") == 0)
        name = "ZCL Shielded Review";
    else if (strcmp(argv[2], "--ca-delete-sign-test") == 0)
        name = "ZCL Sign Test";
    else if (strcmp(argv[2], "--ca-delete-wallet") == 0)
        name = "ZCL Wallet";
    if (!name) return false;
    args->ca_path = argv[3];
    args->delete_app = true;
    args->profile = profile_named(name);
    return args->profile != NULL;
}

static bool parse_ca_args(int argc, char **argv, install_args *args) {
    if (parse_ca_read_args(argc, argv, args) ||
        parse_ca_delete_args(argc, argv, args)) return true;
    if (argc == 5 && strcmp(argv[2], "--ca-install") == 0) {
        args->ca_path = argv[3];
        args->image_path = argv[4];
    } else if (argc == 5 && strcmp(argv[2], "--ca-verify") == 0) {
        args->ca_path = argv[3];
        args->image_path = argv[4];
        args->verify = true;
    } else return false;
    return true;
}

static const app_profile *plain_delete_profile(const char *option) {
    if (strcmp(option, "--delete") == 0) return profile_named("ZCL Probe");
    if (strcmp(option, "--delete-fixture") == 0)
        return profile_named("ZCL Fixture");
    if (strcmp(option, "--delete-review") == 0)
        return profile_named("ZCL Review");
    if (strcmp(option, "--delete-shielded-review") == 0)
        return profile_named("ZCL Shielded Review");
    if (strcmp(option, "--delete-sign-test") == 0)
        return profile_named("ZCL Sign Test");
    if (strcmp(option, "--delete-wallet") == 0)
        return profile_named("ZCL Wallet");
    return NULL;
}

static bool parse_plain_args(int argc, char **argv, install_args *args) {
    if (argc != 3) return false;
    if (strcmp(argv[2], "--ca-reset") == 0)
        args->reset = true;
    else if (strcmp(argv[2], "--channel-only") == 0)
        args->channel_only = true;
    else if ((args->profile = plain_delete_profile(argv[2])) != NULL)
        args->delete_app = true;
    else args->image_path = argv[2];
    return true;
}

static int parse_args(int argc, char **argv, install_args *args) {
    *args = (install_args){0};
    return parse_ca_args(argc, argv, args) ||
           parse_plain_args(argc, argv, args) ? 0 : -1;
}

static int offline_image_check(const char *path) {
    uint8_t *code = NULL;
    size_t length = 0;
    const app_profile *profile = NULL;
    if (read_binary(path, &code, &length, &profile, false) < 0) {
        fputs("Expected a regular ZCL app binary, 64-byte-aligned and matched to a reviewed image.\n",
              stderr);
        return 1;
    }
    printf("Reviewed image: %s %s; signing path %s; installation %s.\n",
        profile->name, profile->version,
        profile->zcl_sign_path ? "declared" : "absent",
        blue_install_image_allowed(profile->name, profile->version) ?
            "permitted" : "blocked pending physical validation");
    free(code);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--image-check") == 0)
        return offline_image_check(argv[2]);
    install_args args;
    if (parse_args(argc, argv, &args) < 0) {
        fprintf(stderr, "Usage: %s --image-check app.bin\n"
                        "       %s /dev/hidrawN app.bin|--channel-only|--delete|--delete-fixture|--delete-review|--delete-shielded-review|--delete-sign-test|--delete-wallet|--ca-reset\n"
                        "       %s /dev/hidrawN --ca-enroll PRIVATE_KEY_FILE\n"
                        "       %s /dev/hidrawN --ca-channel-only PRIVATE_KEY_FILE\n"
                        "       %s /dev/hidrawN --ca-list PRIVATE_KEY_FILE\n"
                        "       %s /dev/hidrawN --ca-delete-fixture PRIVATE_KEY_FILE\n"
                        "       %s /dev/hidrawN --ca-delete-review PRIVATE_KEY_FILE\n"
                        "       %s /dev/hidrawN --ca-delete-shielded-review PRIVATE_KEY_FILE\n"
                        "       %s /dev/hidrawN --ca-delete-sign-test PRIVATE_KEY_FILE\n"
                        "       %s /dev/hidrawN --ca-delete-wallet PRIVATE_KEY_FILE\n"
                        "       %s /dev/hidrawN --ca-install PRIVATE_KEY_FILE app.bin\n"
                        "       %s /dev/hidrawN --ca-verify PRIVATE_KEY_FILE app.bin\n",
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0],
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }
    uint8_t *code = NULL;
    size_t code_length = 0;
    if (args.image_path &&
        read_binary(args.image_path, &code, &code_length, &args.profile,
                    !args.verify) < 0) {
        fputs("Expected a regular ZCL app binary, 64-byte-aligned and matched to a reviewed image.\n",
              stderr);
        return 1;
    }
    EVP_PKEY *ca_key = args.ca_path ? blue_ca_load(args.ca_path) : NULL;
    if (args.ca_path && !ca_key) {
        fputs("Cannot load owner-only secp256k1 CA key file.\n", stderr);
        free(code);
        return 1;
    }
    int fd = open_blue(argv[1]);
    if (fd < 0) {
        EVP_PKEY_free(ca_key);
        free(code);
        return 1;
    }
    installer device = {.fd = fd};
    int result = run_installer(&device, args.delete_app, args.channel_only,
                               args.profile, code, code_length, ca_key,
                               args.enroll, args.reset, args.list,
                               args.verify);
    report_result(result, args.delete_app, args.channel_only,
                  args.enroll, args.reset, args.list, args.verify,
                  args.profile);
    OPENSSL_cleanse(&device.channel, sizeof device.channel);
    close(fd);
    EVP_PKEY_free(ca_key);
    free(code);
    return result == 0 ? 0 : 1;
}
