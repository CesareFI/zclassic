/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Bind an owned private volume handle to checked guest disk callbacks. */
#include "config/mesh_guest_private_volume.h"
#include "base/log_macros.h"
#include <string.h>

static bool volume_refuse(struct zcl_machine_private_volume *v, const char *phase)
{
    if (v != NULL) v->failed = true;
    LOG_WARN("machine.volume", "retained private volume refused during %s", phase);
    return false;
}

static bool volume_check(struct zcl_machine_private_volume *v)
{
    struct platform_positioned_file_snapshot now;
    if (v == NULL || v->failed || v->file == NULL || !v->file->locked)
        return volume_refuse(v, "lifetime");
    /* Metadata-only borrowed view of the same native descriptor. Never close
     * this view: the private-file owner alone releases the handle. */
    struct platform_positioned_file borrowed = {.native = v->file->native};
    if (!platform_positioned_file_snapshot(&borrowed, &now) ||
        !platform_positioned_file_is_private(&borrowed) ||
        !platform_positioned_file_is_current_user_only(&borrowed) ||
        now.size != v->initial.size || now.volume != v->initial.volume ||
        now.file_low != v->initial.file_low || now.file_high != v->initial.file_high)
        return volume_refuse(v, "descriptor identity, size or private ownership");
    return true;
}

static bool volume_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct zcl_machine_private_volume *v = ctx;
    if (!volume_check(v)) return false;
    if (!platform_private_file_read_at(v->file, buf, n, off))
        return volume_refuse(v, "read");
    return volume_check(v);
}

static bool volume_write(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct zcl_machine_private_volume *v = ctx;
    if (!volume_check(v)) return false;
    if (v->sequence == UINT64_MAX) return volume_refuse(v, "write ordering overflow");
    if (!platform_private_file_write_at(v->file, buf, n, off))
        return volume_refuse(v, "write");
    if (!volume_check(v)) return false;
    v->write_sequence = ++v->sequence;
    return true;
}

static bool volume_flush(void *ctx)
{
    struct zcl_machine_private_volume *v = ctx;
    if (!volume_check(v)) return false;
    if (v->sequence == UINT64_MAX) return volume_refuse(v, "flush ordering overflow");
    if (!platform_private_file_authority_flush(v->file))
        return volume_refuse(v, "durability barrier");
    if (!volume_check(v)) return false;
    v->flush_sequence = ++v->sequence;
    return true;
}

bool zcl_machine_private_volume_bind(struct zcl_machine_private_volume *v,
    struct platform_private_file *file, struct rvmachine_disk **disk)
{
    if (disk == NULL) return volume_refuse(v, "missing disk output");
    *disk = NULL;
    if (v == NULL || file == NULL || !file->locked)
        return volume_refuse(v, "missing locked owner");
    memset(v, 0, sizeof *v);
    v->file = file;
    struct platform_positioned_file borrowed = {.native = file->native};
    if (!platform_positioned_file_snapshot(&borrowed, &v->initial) ||
        !platform_positioned_file_is_private(&borrowed) ||
        !platform_positioned_file_is_current_user_only(&borrowed) ||
        v->initial.size == 0 || v->initial.size > RVMACHINE_DISK_BYTES_MAX)
        return volume_refuse(v, "private regular volume admission");
    if (rvmachine_disk_open_backend(disk, v->initial.size, volume_read,
                                   volume_write, volume_flush, v) != RVMACHINE_OK)
        return volume_refuse(v, "backend allocation");
    return true;
}
