/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Standalone foreground optional program. No node startup or shell. */
#include "services/device_host_runtime_entry.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    bool role = argc == 3 && (!strcmp(argv[1], "client") || !strcmp(argv[1], "receiver"));
    if (!role || strncmp(argv[2], "--input=", 8)) {
        fprintf(stderr, "error=HOST_RUNTIME_INPUT_REFUSED usage=tunnel_client_or_receiver_one_bounded_input\n");
        return DEVICE_HOST_ENTRY_INVALID;
    }
    bool receiver = !strcmp(argv[1], "receiver");
    struct json_value input = {0};
    bool valid = device_host_runtime_entry_parse(&input, argv[2] + 8, strnlen(argv[2] + 8, 4097), receiver).ok;
    int result = DEVICE_HOST_ENTRY_INVALID;
    if (valid) {
        enum device_host_runtime_entry_exit status = DEVICE_HOST_ENTRY_INVALID;
        struct zcl_result ran = device_host_runtime_entry_run(&input, receiver, &status);
        result = (int)status;
        if (!ran.ok && result == DEVICE_HOST_ENTRY_OK) result = DEVICE_HOST_ENTRY_FAILED;
    }
    else fprintf(stderr, "error=HOST_RUNTIME_INPUT_REFUSED\n");
    json_free(&input); return result;
}
