/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: replace a symbolic link in one step so a reader sees either the
 * old target or the new target and never a missing link. */
#ifndef ZCL_PLATFORM_ATOMIC_LINK_H
#define ZCL_PLATFORM_ATOMIC_LINK_H

/* Point link_path at target. The new link is created beside link_path under
 * a process-unique temporary name (a leftover from an interrupted earlier
 * call is removed first) and renamed over link_path, which is atomic on
 * POSIX. Returns 0 on success. On failure returns -1 with errno set, leaves
 * link_path exactly as it was, and removes the temporary link. A host without
 * symbolic links reports ENOTSUP. */
int platform_atomic_symlink(const char *target, const char *link_path);

#endif
