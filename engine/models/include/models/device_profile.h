/* purpose: Define owner-private local device identity profile publication and validation. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_MODELS_DEVICE_PROFILE_H
#define ZCL_MODELS_DEVICE_PROFILE_H
#include <stdbool.h>
#include <stdint.h>
#define DEVICE_PROFILE_PENDING "owner-device.pending"
/* Trusted owner-private profile only; no hostile ancestor/path qualification.
 * Publish creates exclusively; read validates stable, nonzero public bytes.
 * Neither function establishes operator consent or peer possession. */
bool db_device_profile_publish(const char *directory, const uint8_t public_key[32]);
bool db_device_profile_read(const char *directory, uint8_t public_key[32]);
#endif
