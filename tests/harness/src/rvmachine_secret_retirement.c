/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Source-inclusion retirement witness observing bytes before release. */
#include "test/test_core.h"
#include "../../../platform/modules/rvmachine/src/rvmachine_priv.h"
#include "base/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct retirement_span { void *ptr; size_t size; unsigned frees; bool zero; };
static struct retirement_span retirement_spans[4];
static bool retirement_observing;
static bool retirement_capture_create;
static bool retirement_fail_ram;
static bool retirement_capture_block;
static void *retirement_malloc(size_t size, const char *tag)
{
    void *ptr = zcl_malloc(size, tag);
    if (retirement_capture_block && ptr != NULL && strcmp(tag, "rvmachine_disk_block") == 0)
        retirement_spans[0] = (struct retirement_span){.ptr = ptr, .size = size};
    return ptr;
}
static void *retirement_calloc(size_t n, size_t size, const char *tag)
{
    if (retirement_fail_ram && strcmp(tag, "rvmachine_ram") == 0) return NULL;
    void *ptr = zcl_calloc(n, size, tag);
    if (retirement_capture_create && ptr != NULL && strcmp(tag, "rvmachine") == 0)
        retirement_spans[0] = (struct retirement_span){.ptr = ptr, .size = n * size};
    return ptr;
}
static void retirement_free(void *ptr)
{
    if (retirement_observing && ptr != NULL)
        for (unsigned i = 0; i < 4u; i++)
            if (retirement_spans[i].ptr == ptr) {
                struct retirement_span *s = &retirement_spans[i];
                if (s->frees != 0u) {
                    s->frees++;
                    s->zero = false;
                    return; /* fail the witness without reading/releasing freed bytes */
                }
                s->frees++;
                s->zero = true;
                const uint8_t *p = ptr;
                for (size_t j = 0; j < s->size; j++) s->zero &= p[j] == 0;
            }
    free(ptr);
}

typeof(rvmachine_config_resources_validate) retirement_rvmachine_config_resources_validate;
typeof(rvmachine_create) retirement_rvmachine_create;
typeof(rvmachine_destroy) retirement_rvmachine_destroy;
typeof(rvmachine_dtb) retirement_rvmachine_dtb;
typeof(rvmachine_console_put) retirement_rvmachine_console_put;
typeof(rvmachine_input_pump) retirement_rvmachine_input_pump;
typeof(rvmachine_console_input) retirement_rvmachine_console_input;
typeof(rvmachine_entropy_ready) retirement_rvmachine_entropy_ready;
typeof(rvmachine_request_stop) retirement_rvmachine_request_stop;
typeof(rvmachine_set_trace) retirement_rvmachine_set_trace;
typeof(rvmachine_retired) retirement_rvmachine_retired;
typeof(rvmachine_time) retirement_rvmachine_time;
typeof(rvmachine_stop_name) retirement_rvmachine_stop_name;
typeof(rvmachine_status_name) retirement_rvmachine_status_name;
typeof(rvmachine_sbi_getchar) retirement_rvmachine_sbi_getchar;
typeof(rvmachine_disk_open) retirement_rvmachine_disk_open;
typeof(rvmachine_disk_open_backend) retirement_rvmachine_disk_open_backend;
typeof(rvmachine_disk_flush) retirement_rvmachine_disk_flush;
typeof(rvmachine_disk_close) retirement_rvmachine_disk_close;
typeof(rvmachine_disk_size) retirement_rvmachine_disk_size;
typeof(rvmachine_disk_read) retirement_rvmachine_disk_read;
typeof(rvmachine_disk_write) retirement_rvmachine_disk_write;
typeof(rvmachine_disk_overlay_blocks) retirement_rvmachine_disk_overlay_blocks;
typeof(rvmachine_disk_cleanse) retirement_rvmachine_disk_cleanse;
#define rvmachine_config_resources_validate retirement_rvmachine_config_resources_validate
#define rvmachine_create retirement_rvmachine_create
#define rvmachine_destroy retirement_rvmachine_destroy
#define rvmachine_dtb retirement_rvmachine_dtb
#define rvmachine_console_put retirement_rvmachine_console_put
#define rvmachine_input_pump retirement_rvmachine_input_pump
#define rvmachine_console_input retirement_rvmachine_console_input
#define rvmachine_entropy_ready retirement_rvmachine_entropy_ready
#define rvmachine_request_stop retirement_rvmachine_request_stop
#define rvmachine_set_trace retirement_rvmachine_set_trace
#define rvmachine_retired retirement_rvmachine_retired
#define rvmachine_time retirement_rvmachine_time
#define rvmachine_stop_name retirement_rvmachine_stop_name
#define rvmachine_status_name retirement_rvmachine_status_name
#define rvmachine_sbi_getchar retirement_rvmachine_sbi_getchar
#define rvmachine_disk_open retirement_rvmachine_disk_open
#define rvmachine_disk_open_backend retirement_rvmachine_disk_open_backend
#define rvmachine_disk_flush retirement_rvmachine_disk_flush
#define rvmachine_disk_close retirement_rvmachine_disk_close
#define rvmachine_disk_size retirement_rvmachine_disk_size
#define rvmachine_disk_read retirement_rvmachine_disk_read
#define rvmachine_disk_write retirement_rvmachine_disk_write
#define rvmachine_disk_overlay_blocks retirement_rvmachine_disk_overlay_blocks
#define rvmachine_disk_cleanse retirement_rvmachine_disk_cleanse

#define free retirement_free
#undef zcl_calloc
#define zcl_calloc retirement_calloc
#undef zcl_malloc
#define zcl_malloc retirement_malloc
#include "../../../platform/modules/rvmachine/src/rvmachine_disk.c"
#include "../../../platform/modules/rvmachine/src/rvmachine.c"
#undef free
#undef zcl_calloc
#undef zcl_malloc
#undef rvmachine_config_resources_validate
#undef rvmachine_create
#undef rvmachine_destroy
#undef rvmachine_dtb
#undef rvmachine_console_put
#undef rvmachine_input_pump
#undef rvmachine_console_input
#undef rvmachine_entropy_ready
#undef rvmachine_request_stop
#undef rvmachine_set_trace
#undef rvmachine_retired
#undef rvmachine_time
#undef rvmachine_stop_name
#undef rvmachine_status_name
#undef rvmachine_sbi_getchar
#undef rvmachine_disk_open
#undef rvmachine_disk_open_backend
#undef rvmachine_disk_flush
#undef rvmachine_disk_close
#undef rvmachine_disk_size
#undef rvmachine_disk_read
#undef rvmachine_disk_write
#undef rvmachine_disk_overlay_blocks
#undef rvmachine_disk_cleanse

static bool retirement_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    const uint8_t *image = ctx;
    if (off > 3u * RVMACHINE_DISK_BLOCK || n > 3u * RVMACHINE_DISK_BLOCK - off)
        return false;
    memcpy(buf, image + off, n);
    return true;
}

static bool retirement_case(bool enabled)
{
    static uint8_t image[3u * RVMACHINE_DISK_BLOCK];
    static uint8_t secret[RVMACHINE_DISK_BLOCK];
    memset(image, 0x7b, sizeof image);
    memset(secret, 0xa5, sizeof secret);
    struct rvmachine_disk *d = NULL;
    if (retirement_rvmachine_disk_open(&d, sizeof image, retirement_read, image) != RVMACHINE_OK)
        return false;
    struct rvmachine *m = NULL;
    struct rvmachine_config c = {.ram_bytes = RVMACHINE_RAM_MIN, .disk = d,
                                  .cleanse_on_destroy = enabled};
    if (retirement_rvmachine_create(&m, &c) != RVMACHINE_OK) {
        retirement_rvmachine_disk_close(d);
        return false;
    }
    if (!retirement_rvmachine_disk_write(d, 0, secret, sizeof secret) ||
        !retirement_rvmachine_disk_write(d, 2u * RVMACHINE_DISK_BLOCK, secret, sizeof secret)) {
        retirement_rvmachine_destroy(m);
        return false;
    }
    uint8_t *ram = m->mem.bytes;
    size_t size = m->mem.size;
    memset(ram, 0xa5, size);
    memset(m, 0xa5, sizeof *m);
    m->mem.bytes = ram;
    m->mem.size = size;
    m->disk = d;
    m->data_disk = NULL;
    m->cleanse_on_destroy = enabled;
    memset(retirement_spans, 0, sizeof retirement_spans);
    retirement_spans[0] = (struct retirement_span){.ptr = ram, .size = size};
    retirement_spans[1] = (struct retirement_span){.ptr = m, .size = sizeof *m};
    retirement_spans[2] = (struct retirement_span){.ptr = d->overlay[0], .size = RVMACHINE_DISK_BLOCK};
    retirement_spans[3] = (struct retirement_span){.ptr = d->overlay[1], .size = RVMACHINE_DISK_BLOCK};
    retirement_observing = true;
    retirement_rvmachine_destroy(m);
    retirement_observing = false;
    bool ok = true;
    for (unsigned i = 0; i < 4u; i++)
        ok &= retirement_spans[i].frees == 1u && retirement_spans[i].zero == enabled;
    for (size_t i = 0; i < sizeof image; i++) ok &= image[i] == 0x7b;
    return ok;
}

static bool retirement_read_partial(void *ctx, uint64_t off, void *buf, size_t n)
{
    (void)ctx;
    (void)off;
    memset(buf, 0xa5, n);
    return false;
}

static bool retirement_failed_copy(void)
{
    struct rvmachine_disk *disk = NULL;
    if (retirement_rvmachine_disk_open(&disk, RVMACHINE_DISK_BLOCK,
                                      retirement_read_partial, NULL) != RVMACHINE_OK)
        return false;
    memset(retirement_spans, 0, sizeof retirement_spans);
    retirement_capture_block = true;
    retirement_observing = true;
    uint8_t byte = 1;
    bool wrote = retirement_rvmachine_disk_write(disk, 0, &byte, 1);
    retirement_observing = false;
    retirement_capture_block = false;
    bool ok = !wrote && retirement_spans[0].frees == 1u && retirement_spans[0].zero &&
        retirement_rvmachine_disk_overlay_blocks(disk) == 0u;
    retirement_rvmachine_disk_close(disk);
    return ok;
}

static bool retirement_failed_create(bool allocation_failure)
{
    static uint8_t image[3u * RVMACHINE_DISK_BLOCK];
    memset(retirement_spans, 0, sizeof retirement_spans);
    struct rvmachine_disk *disk = NULL;
    if (retirement_rvmachine_disk_open(&disk, sizeof image, retirement_read, image) != RVMACHINE_OK)
        return false;
    retirement_spans[1] = (struct retirement_span){.ptr = disk, .size = sizeof *disk};
    retirement_capture_create = true;
    retirement_fail_ram = allocation_failure;
    retirement_observing = true;
    struct rvmachine_config c = {.ram_bytes = allocation_failure ? RVMACHINE_RAM_MIN : 1u,
                                  .disk = disk,
                                  .cleanse_on_destroy = true};
    struct rvmachine *m = NULL;
    enum rvmachine_status status = retirement_rvmachine_create(&m, &c);
    retirement_observing = false;
    retirement_capture_create = false;
    retirement_fail_ram = false;
    bool ok = status == (allocation_failure ? RVMACHINE_ERR_NOMEM : RVMACHINE_ERR_ARG) &&
        m == NULL && retirement_spans[0].frees == 1u && retirement_spans[0].zero &&
        retirement_spans[1].frees == 0u;
    /* Observe caller release only if failed create retained the disk. */
    if (retirement_spans[1].frees == 0u) {
        retirement_observing = true;
        retirement_rvmachine_disk_close(disk);
        retirement_observing = false;
        ok &= retirement_spans[1].frees == 1u;
    }
    return ok;
}

int rvmachine_secret_retirement_cases(void);
int rvmachine_secret_retirement_cases(void)
{
    retirement_rvmachine_destroy(NULL);
    bool on = retirement_case(true);
    bool off = retirement_case(false);
    bool partial = retirement_failed_create(false) && retirement_failed_create(true) &&
        retirement_failed_copy();
    printf("rvmachine secret retirement before-free observation: opt-in=%s opt-out=%s failures=%s\n",
           on ? "OK" : "FAIL", off ? "OK" : "FAIL", partial ? "OK" : "FAIL");
    return on && off && partial ? 0 : 1;
}
