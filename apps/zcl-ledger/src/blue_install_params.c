/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_install_params.h"

#include <string.h>

static bool valid_version(const char *version, size_t length) {
    if (length < 5 || length > 7) return false;
    unsigned dots = 0, digits = 0;
    for (size_t i = 0; i < length; ++i) {
        if (version[i] == '.') {
            if (!digits || dots == 2) return false;
            ++dots;
            digits = 0;
        } else if (version[i] >= '0' && version[i] <= '9') {
            ++digits;
        } else return false;
    }
    return dots == 2 && digits != 0;
}

size_t blue_install_params(const char *name, const char *version,
                           bool zcl_sign_path,
                           uint8_t output[ZCL_BLUE_INSTALL_PARAMS_MAX]) {
    if (!name || !version || !output) return 0;
    size_t name_length = strlen(name);
    size_t version_length = strlen(version);
    if (name_length == 0 || name_length > 32 ||
        !valid_version(version, version_length)) return 0;
    static const uint8_t zcl_path[] = {
        0x01, 5,
        0x80, 0, 0, 0x2c,
        0x80, 0, 0, 0x93,
        0x80, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    if (2 + name_length + 2 + version_length + 2 +
        (zcl_sign_path ? sizeof zcl_path : 1) >
        ZCL_BLUE_INSTALL_PARAMS_MAX) return 0;
    size_t length = 0;
    output[length++] = 0x01;
    output[length++] = (uint8_t)name_length;
    memcpy(output + length, name, name_length);
    length += name_length;
    output[length++] = 0x02;
    output[length++] = (uint8_t)version_length;
    memcpy(output + length, version, version_length);
    length += version_length;
    output[length++] = 0x04;
    output[length++] = zcl_sign_path ? sizeof zcl_path : 1;
    if (zcl_sign_path) {
        memcpy(output + length, zcl_path, sizeof zcl_path);
        length += sizeof zcl_path;
    } else output[length++] = 0;
    return length;
}

bool blue_install_image_allowed(const char *name, const char *version) {
    if (!name || !version) return false;
    return (strcmp(name, "ZCL Probe") == 0 &&
            strcmp(version, "0.1.0") == 0) ||
           (strcmp(name, "ZCL Fixture") == 0 &&
            strcmp(version, "0.1.0") == 0) ||
           (strcmp(name, "ZCL Sign Test") == 0 &&
            strcmp(version, "0.1.0") == 0);
}
