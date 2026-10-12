/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_mainnet_branch.h"

enum {
    BLUE_BRANCH_SAPLING = 0x76b809bb,
    BLUE_BRANCH_BUBBLES = 0x821a451c,
    BLUE_BRANCH_BUBBLY = 0x930b540d
};

/* Mainnet heights: core/chainparams/src/chainparams.c.
 * Branch IDs: core/params/src/upgrades.c. */
bool blue_mainnet_branch_for_height(uint32_t height, uint32_t *branch) {
    if (!branch || height < 476969) return false;
    if (height < 585318) *branch = BLUE_BRANCH_SAPLING;
    else if (height < 585322) *branch = BLUE_BRANCH_BUBBLES;
    else *branch = BLUE_BRANCH_BUBBLY;
    return true;
}

bool blue_mainnet_branch_is_known(uint32_t branch) {
    return branch == BLUE_BRANCH_SAPLING || branch == BLUE_BRANCH_BUBBLES ||
        branch == BLUE_BRANCH_BUBBLY;
}
