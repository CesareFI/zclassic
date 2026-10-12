/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_install_params.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    uint8_t output[ZCL_BLUE_INSTALL_PARAMS_MAX];
    static const uint8_t expected[] = {
        0x01, 13, 'Z','C','L',' ','S','i','g','n',' ','T','e','s','t',
        0x02, 5, '0','.','1','.','0',
        0x04, 22, 0x01, 5,
        0x80, 0, 0, 0x2c,
        0x80, 0, 0, 0x93,
        0x80, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    size_t length = blue_install_params("ZCL Sign Test", "0.1.0", true,
                                        output);
    assert(length == sizeof expected && memcmp(output, expected, length) == 0);
    static const uint8_t review[] = {
        0x01, 10, 'Z','C','L',' ','R','e','v','i','e','w',
        0x02, 5, '0','.','3','.','0', 0x04, 1, 0
    };
    length = blue_install_params("ZCL Review", "0.3.0", false, output);
    assert(length == sizeof review && memcmp(output, review, length) == 0);
    length = blue_install_params("ZCL Wallet", "0.1.0", true, output);
    assert(length == sizeof expected - 3);
    assert(output[0] == 1 && output[1] == 10);
    assert(memcmp(output + 2, "ZCL Wallet", 10) == 0);
    assert(output[19] == 0x04 && output[20] == 22);
    static const uint8_t wallet_45[] = {
        0x01, 10, 'Z','C','L',' ','W','a','l','l','e','t',
        0x02, 6, '0','.','3','.','4','5',
        0x04, 22, 0x01, 5,
        0x80, 0, 0, 0x2c,
        0x80, 0, 0, 0x93,
        0x80, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    length = blue_install_params("ZCL Wallet", "0.3.45", true, output);
    assert(length == sizeof wallet_45 &&
        memcmp(output, wallet_45, length) == 0);
    char max_name[33];
    memset(max_name, 'A', 32);
    max_name[32] = 0;
    length = blue_install_params(max_name, "0.3.100", true, output);
    assert(length == ZCL_BLUE_INSTALL_PARAMS_MAX &&
        output[1] == 32 && output[34] == 0x02 &&
        output[35] == 7 && output[43] == 0x04);
    assert(blue_install_params("", "0.1.0", true, output) == 0);
    assert(blue_install_params("ZCL", "0.1", true, output) == 0);
    assert(blue_install_params("ZCL", "0..45", true, output) == 0);
    assert(blue_install_params("ZCL", "0.3.45x", true, output) == 0);
    assert(blue_install_params("ZCL", "0.3.1000", true, output) == 0);
    assert(blue_install_params(NULL, "0.1.0", true, output) == 0);
    assert(!blue_install_image_allowed("ZCL Wallet", "0.3.4"));
    assert(!blue_install_image_allowed("ZCL Wallet", "0.3.7"));
    assert(!blue_install_image_allowed("ZCL Wallet", "0.3.46"));
    assert(!blue_install_image_allowed("ZCL Review", "0.2.0"));
    assert(!blue_install_image_allowed("ZCL Review", "0.3.1"));
    assert(!blue_install_image_allowed("ZCL Shielded Review", "0.5.2"));
    assert(!blue_install_image_allowed("ZCL Shielded Review", "0.5.8"));
    assert(!blue_install_image_allowed("ZCL Shielded Review", "0.5.9"));
    assert(!blue_install_image_allowed("ZCL Shielded Review", "0.5.10"));
    assert(!blue_install_image_allowed("ZCL Shielded Review", "0.5.11"));
    assert(blue_install_image_allowed("ZCL Probe", "0.1.0"));
    assert(blue_install_image_allowed("ZCL Fixture", "0.1.0"));
    assert(blue_install_image_allowed("ZCL Sign Test", "0.1.0"));
    assert(!blue_install_image_allowed(NULL, "0.3.4"));
    return 0;
}
