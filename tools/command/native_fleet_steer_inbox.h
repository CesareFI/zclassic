/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the quarantine inbox behind fleet.steer.deliver. Bounded,
 * private, inert transfer staging: bytes are stored and hash-checked, never
 * compiled, executed, dispatched or accepted.
 *
 * Layout under <state root>/steer/inbox:
 *   .lock                       global quota/creation lock
 *   <binding>/<upload_id>/      0700, one directory per upload
 *       payload                 0600 bytes received so far
 *       manifest                0600 durable cursor (see fsi_meta)
 *       lock                    per-upload lock
 * Every object below the retained inbox handle is opened descriptor
 * relative with O_NOFOLLOW and checked for type, owner, mode and link
 * count. POSIX only; elsewhere every call refuses UNSUPPORTED. */
#ifndef ZCL_NATIVE_FLEET_STEER_INBOX_H
#define ZCL_NATIVE_FLEET_STEER_INBOX_H

#include <stdbool.h>
#include <stddef.h>

#define FSI_CHUNK 16384u
#define FSI_SIZE_MAX 262144u
#define FSI_PER_GRANT 8u
#define FSI_TOTAL 64u
#define FSI_BYTES_GRANT (2u * 1024u * 1024u)
#define FSI_BYTES_TOTAL (16u * 1024u * 1024u)
#define FSI_REQ_PER_MIN 60u
#define FSI_BYTES_PER_HOUR (16LL * 1024 * 1024)
#define FSI_OUTSTANDING 32u
#define FSI_PARTIAL_TTL_S (24LL * 60 * 60)
#define FSI_FAILED_TTL_S (60LL * 60)
#define FSI_ID_HEX 32
#define FSI_SHA_HEX 128

/* Frozen at creation except offset, state and updated. */
struct fsi_meta {
    char ref[65];
    char name[65];
    char digest[FSI_SHA_HEX + 1];
    char state[12]; /* receiving | quarantined | failed */
    long long size;
    long long offset;
    long long created;
    long long updated;
};

/* Re-checks the credential; NULL admits, otherwise the typed refusal. */
typedef const char *(*fsi_recheck_fn)(void *ctx);

struct fsi_upload {
    int bind_fd;
    int dir_fd;
    int lock_fd;
    int payload_fd;
    int global_fd;
    char binding[33];
    char id[FSI_ID_HEX + 1];
    struct fsi_meta meta;
    fsi_recheck_fn recheck;
    void *recheck_ctx;
    size_t charge; /* bytes this call adds to the grant's hourly ledger */
};

#ifdef ZCL_TESTING
/* Fault points for crash tests; absent from production builds. */
enum fsi_fault {
    FSI_FAULT_NONE = 0,
    FSI_FAULT_AFTER_PAYLOAD,
    FSI_FAULT_AFTER_MANIFEST_RENAME,
    FSI_FAULT_BEFORE_FINAL_COMMIT,
    FSI_FAULT_SHORT_PAYLOAD,
    FSI_FAULT_SHORT_MANIFEST,
    FSI_FAULT_RENAME_FAIL,
    FSI_FAULT_BINDING_VANISH,
};
void fsi_test_fault(enum fsi_fault point);
#endif

/* Open the inbox root under the state root (created when `create`). On
 * success *root is a retained directory descriptor. Typed suffix on failure. */
const char *fsi_root_open(bool create, int *root);
void fsi_root_close(int root);
bool fsi_root_path(char *out, size_t cap);

/* Find or create the upload and take its lock. `want` carries the frozen
 * fields; `first` is true when offset is zero (the only creating call).
 * Returns the typed suffix (BUSY, QUOTA, CONFLICT, NOT_FOUND, ...). */
const char *fsi_begin(struct fsi_upload *u, int root, const char *binding,
                      const char *id, const struct fsi_meta *want, bool first,
                      size_t charge);

/* Owner cleanup: remove one retained upload unless it is being written. */
const char *fsi_drop(int root, const char *binding, const char *id);

/* Accept one chunk at `offset`. *dup is set for a byte-identical retry. */
const char *fsi_append(struct fsi_upload *u, long long offset,
                       const unsigned char *data, size_t n, bool *dup);

/* Verify the whole payload and commit quarantined or failed. */
const char *fsi_finish(struct fsi_upload *u);

void fsi_end(struct fsi_upload *u);

/* Read-only listing support (no locks, no mutation). */
struct fsi_row {
    char binding[33];
    char id[FSI_ID_HEX + 1];
    struct fsi_meta meta;
};
typedef bool (*fsi_row_fn)(const struct fsi_row *row, void *ctx);
/* Rows include unreadable manifests as state "damaged"; *skipped counts
 * entries whose names are not identifiers. */
const char *fsi_each(int root, fsi_row_fn fn, void *ctx, unsigned *skipped);

#endif
