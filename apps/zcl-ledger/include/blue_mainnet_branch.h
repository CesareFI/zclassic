/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef BLUE_MAINNET_BRANCH_H
#define BLUE_MAINNET_BRANCH_H

#include <stdbool.h>
#include <stdint.h>

bool blue_mainnet_branch_for_height(uint32_t height, uint32_t *branch);
bool blue_mainnet_branch_is_known(uint32_t branch);

#endif
