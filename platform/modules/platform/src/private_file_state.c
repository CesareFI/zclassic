/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: stat metadata of a private path or held private file; POSIX
 * stats, Windows refuses so callers take their full authority path. */
#include "platform/private_file_state.h"

#ifndef _WIN32
#include <sys/stat.h>

static void pfs_state(const struct stat *st,
                      struct platform_private_path_state *state) {
  *state = (struct platform_private_path_state){
      .volume = (uint64_t)st->st_dev,
      .file = (uint64_t)st->st_ino,
      .size = (uint64_t)st->st_size,
      .mode = (uint64_t)st->st_mode,
      .owner = (uint64_t)st->st_uid,
      .links = (uint64_t)st->st_nlink,
#if defined(__APPLE__)
      .modified_ns = (int64_t)st->st_mtimespec.tv_sec * 1000000000 +
                     st->st_mtimespec.tv_nsec,
      .changed_ns = (int64_t)st->st_ctimespec.tv_sec * 1000000000 +
                    st->st_ctimespec.tv_nsec,
#else
      .modified_ns = (int64_t)st->st_mtim.tv_sec * 1000000000 +
                     st->st_mtim.tv_nsec,
      .changed_ns = (int64_t)st->st_ctim.tv_sec * 1000000000 +
                    st->st_ctim.tv_nsec,
#endif
  };
}
#endif

bool platform_private_path_state(const char *path,
                                 struct platform_private_path_state *state) {
#ifdef _WIN32
  (void)path;
  (void)state;
  return false;
#else
  struct stat st;
  if (!path || !state || lstat(path, &st) != 0)
    return false;
  pfs_state(&st, state);
  return true;
#endif
}

bool platform_private_file_state(struct platform_private_file *file,
                                 struct platform_private_path_state *state) {
#ifdef _WIN32
  (void)file;
  (void)state;
  return false;
#else
  struct stat st;
  if (!file || !state || (int)file->native < 0 ||
      fstat((int)file->native, &st) != 0)
    return false;
  pfs_state(&st, state);
  return true;
#endif
}
