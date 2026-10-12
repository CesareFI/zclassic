/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Explicit host adapter for an already-owned private development volume. */
#ifndef ZCL_MESH_GUEST_PRIVATE_VOLUME_H
#define ZCL_MESH_GUEST_PRIVATE_VOLUME_H
#include "platform/private_file.h"
#include "platform/positioned_file.h"
#include "rvmachine/rvmachine.h"

struct zcl_machine_private_volume {
    struct platform_private_file *file;
    struct platform_positioned_file_snapshot initial;
    /* Successful callback ordering for this binding only. A flush after the
     * latest write observes a host durability barrier, not guest FS/key health. */
    uint64_t sequence, write_sequence, flush_sequence;
    bool failed;
};
/* The caller retains an exclusively locked handle and this context until
 * disk close, serializes callbacks, and quiesces execution before releasing
 * either. Bind never opens a path, closes the handle or creates a file.
 * Existing descriptor-bound regular-file/private-owner validation applies.
 * This adapter does not encrypt bytes; secret-bearing launches require a
 * separately qualified encryption and credential layer. */
bool zcl_machine_private_volume_bind(struct zcl_machine_private_volume *volume,
    struct platform_private_file *file, struct rvmachine_disk **disk);
#endif
