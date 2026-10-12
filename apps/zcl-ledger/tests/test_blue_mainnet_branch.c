/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_mainnet_branch.h"

#undef NDEBUG
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

int main(void) {
    static const struct {
        uint32_t height;
        bool valid;
        uint32_t branch;
    } cases[] = {
        {0, false, 0},
        {476968, false, 0},
        {476969, true, 0x76b809bb},
        {585317, true, 0x76b809bb},
        {585318, true, 0x821a451c},
        {585321, true, 0x821a451c},
        {585322, true, 0x930b540d},
        {706999, true, 0x930b540d},
        {707000, true, 0x930b540d},
        {INT32_MAX, true, 0x930b540d},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        uint32_t branch = UINT32_MAX;
        assert(blue_mainnet_branch_for_height(cases[i].height,
                                              &branch) == cases[i].valid);
        if (cases[i].valid) assert(branch == cases[i].branch);
    }
    assert(!blue_mainnet_branch_for_height(476969, NULL));
    assert(blue_mainnet_branch_is_known(0x76b809bb));
    assert(blue_mainnet_branch_is_known(0x821a451c));
    assert(blue_mainnet_branch_is_known(0x930b540d));
    assert(!blue_mainnet_branch_is_known(0));
    assert(!blue_mainnet_branch_is_known(0xffffffff));
    return 0;
}
