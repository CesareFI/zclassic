/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: expandable guest data disks under <home>/.z23/guests/<name>/data.img
 * for dev.app.machine.data and the data_disk input of dev.app.machine.boot. */
#ifndef ZCL_NATIVE_MACHINE_DATA_H
#define ZCL_NATIVE_MACHINE_DATA_H
#include "command/native_command.h"
#include "json/json.h"
#include "platform/private_file.h"
#include "rvmachine/rvmachine.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MD_PATH "dev.app.machine.data"
#define MD_NAME_MAX 32u
#define MD_SIZE_MIB_MAX ((int64_t)(RVMACHINE_DISK_BYTES_MAX >> 20))

/* True for [a-z0-9][a-z0-9-]{0,31}. */
bool zcl_mb_data_name_valid(const char *name);

/* Backend callbacks over a locked private file; ctx is a struct zcl_mb_data_file. */
struct zcl_mb_data_file {
    struct platform_private_file file;
    uint64_t bytes;
};
bool zcl_mb_data_read_cb(void *ctx, uint64_t off, void *buf, size_t n);
bool zcl_mb_data_write_cb(void *ctx, uint64_t off, const void *buf, size_t n);
bool zcl_mb_data_flush_cb(void *ctx);

/* Opens an existing data disk exclusively. False when the file is absent or
 * locked, with the matching refusal written to reply. */
struct zcl_mb_data_file *zcl_mb_data_open(const char *home, const char *name,
                                          struct zcl_command_reply *reply);
uint64_t zcl_mb_data_file_bytes(const struct zcl_mb_data_file *file);
void zcl_mb_data_close(struct zcl_mb_data_file *file);

/* Boot hooks. owner identifies the run; a run without data_disk does nothing. */
bool zcl_mb_data_parse(const void *owner, const struct json_value *in,
                       struct zcl_command_reply *reply);
bool zcl_mb_data_attach(const void *owner, struct rvmachine_disk **out,
                        struct zcl_command_reply *reply);
void zcl_mb_data_emit(const void *owner, struct json_value *data);
void zcl_mb_data_release(const void *owner);

void zcl_native_handle_dev_machine_data(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply);
#endif
