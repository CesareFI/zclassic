/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_STORAGE_SQLITE_PINNED_READER_H
#define ZCL_STORAGE_SQLITE_PINNED_READER_H
#include <stdbool.h>
#include "platform/positioned_file.h"
typedef struct sqlite3 sqlite3;
struct sqlite_pinned_reader;
/* Borrow a finalized, standalone, offline file. Its handle and bytes must
 * remain unchanged until checked close succeeds. No producer provenance or
 * digest is established here. The caller must admit the finalized standalone
 * input, including absence of required WAL or hot rollback journal; this
 * handle-only adapter cannot inspect sidecars or prove capture provenance.
 * Header format 1 is a conservative requirement, not a capture proof.
 * One owner operates the returned connection. Ordinary failures leave *out
 * NULL. Exceptional failed-open cleanup can return false with non-NULL *out:
 * this is a cleanup-only owner, and the file must remain retained until its
 * checked close succeeds. It never exposes a usable connection. */
bool sqlite_pinned_reader_open(
    const struct platform_positioned_file *file,
    const struct platform_positioned_file_snapshot *expected,
    struct sqlite_pinned_reader **out);
/* Borrowed connection (NULL for a cleanup-only owner): never sqlite3_close it directly. Do not close or
 * reuse the retained file before successful wrapper close. */
sqlite3 *sqlite_pinned_reader_db(struct sqlite_pinned_reader *reader);
/* SQLITE_BUSY preserves the reader for statement cleanup and another close.
 * On success consumes *reader, leaving the caller's file open. */
bool sqlite_pinned_reader_close(struct sqlite_pinned_reader **reader);
#endif
