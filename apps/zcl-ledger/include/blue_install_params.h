/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_INSTALL_PARAMS_H
#define ZCL_BLUE_INSTALL_PARAMS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue installer requires ISO C23"
#endif

enum { ZCL_BLUE_INSTALL_PARAMS_MAX = 67 };

size_t blue_install_params(const char *name, const char *version,
                           bool zcl_sign_path,
                           uint8_t output[ZCL_BLUE_INSTALL_PARAMS_MAX]);
bool blue_install_image_allowed(const char *name, const char *version);

#endif
