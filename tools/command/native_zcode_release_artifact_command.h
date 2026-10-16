/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_NATIVE_ZCODE_RELEASE_ARTIFACT_COMMAND_H
#define ZCL_NATIVE_ZCODE_RELEASE_ARTIFACT_COMMAND_H
#include "command/native_command.h"
void zcl_native_handle_zcode_release_artifact_prepare(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_zcode_release_artifact_admit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
#endif
