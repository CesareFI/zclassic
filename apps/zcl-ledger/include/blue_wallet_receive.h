/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_WALLET_RECEIVE_H
#define ZCL_BLUE_WALLET_RECEIVE_H

#include <stdbool.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue receive layout requires ISO C23"
#endif

enum { ZCL_WALLET_ADDRESS_CHARS = 35, ZCL_WALLET_ADDRESS_LINES = 3,
       ZCL_WALLET_ADDRESS_LINE_SIZE = 13 };

bool blue_wallet_receive_split(
    const char address[ZCL_WALLET_ADDRESS_CHARS + 1],
    char lines[ZCL_WALLET_ADDRESS_LINES][ZCL_WALLET_ADDRESS_LINE_SIZE]);

#endif
