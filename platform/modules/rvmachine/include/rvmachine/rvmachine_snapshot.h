/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: save and restore of a booted machine. A snapshot is a versioned,
 * field-by-field little-endian file: header bindings, the hart, the interrupt
 * controller, timer, serial port, firmware state, the console input queues,
 * a per-slot device table, the sparse non-zero 4 KiB pages of RAM, the disk
 * overlay blocks and a SHA-256 trailer over everything before it.
 *
 * Excluded by design: the boot seed scratch buffer and every host entropy
 * source (only its declared mode and a caller-supplied position are kept),
 * host callbacks and pointers, the engine's derived caches, and the device
 * scratch buffers. A restore leaves every derived cache invalid.
 *
 * Restore verifies the format version, the trailer and every binding (RAM
 * size, device tree placement, boot arguments, slot layout, kernel and disk
 * identity) before it touches a machine, and returns either a complete
 * machine or a named refusal and nothing else. */
#ifndef ZCL_RVMACHINE_SNAPSHOT_H
#define ZCL_RVMACHINE_SNAPSHOT_H

#include "rvmachine/rvmachine.h"

#define RVMACHINE_SNAPSHOT_VERSION 2u
/* The largest file restore reads into memory. */
#define RVMACHINE_SNAPSHOT_FILE_MAX (UINT64_C(2) << 30)
#define RVMACHINE_SNAPSHOT_PAGE 4096u
#define RVMACHINE_SNAPSHOT_DIGEST 32u
#define RVMACHINE_SNAPSHOT_SOURCE_STATE_MAX 64u

/* How the machine's entropy was supplied. A snapshot is taken only from a
 * machine that declares one of the last three. */
enum rvmachine_snapshot_entropy {
    RVMACHINE_SNAPSHOT_ENTROPY_UNDECLARED = 0,
    RVMACHINE_SNAPSHOT_ENTROPY_NONE,        /* no entropy device and no boot seed */
    RVMACHINE_SNAPSHOT_ENTROPY_TEST_STREAM, /* repeatable, public, not secure */
    RVMACHINE_SNAPSHOT_ENTROPY_HOST         /* bytes from the host's provider */
};

/* REPLAY continues bit for bit: the guest's random pool equals the
 * snapshot's, so the result is NOT FOR USE WITH SECRETS; it is refused for a
 * snapshot that used host entropy, which cannot repeat. FRESH needs such a
 * snapshot and a host entropy source in the configuration: the guest then
 * draws new host bytes through its entropy device, and folds them into its
 * random pool only after some guest time (the caller runs the guest through
 * that interval before use). */
enum rvmachine_snapshot_mode {
    RVMACHINE_SNAPSHOT_REPLAY = 1,
    RVMACHINE_SNAPSHOT_FRESH
};

enum rvmachine_snapshot_status {
    RVMACHINE_SNAPSHOT_OK = 0,
    RVMACHINE_SNAPSHOT_ERR_ARG,
    RVMACHINE_SNAPSHOT_ERR_IO,           /* a sink or source call failed */
    RVMACHINE_SNAPSHOT_ERR_NOMEM,
    RVMACHINE_SNAPSHOT_ERR_NOT_RUNNABLE, /* save: not loaded, halted or faulted */
    RVMACHINE_SNAPSHOT_ERR_PRIVATE,      /* save: private (cleansed or keyfile) machine */
    RVMACHINE_SNAPSHOT_ERR_BYTE_PORTS,   /* save: named byte ports are not captured */
    RVMACHINE_SNAPSHOT_ERR_DISK_RETAINED, /* save: a retained writable disk backend */
    RVMACHINE_SNAPSHOT_ERR_SEED_LIVE,    /* save: the boot seed is still in guest RAM */
    RVMACHINE_SNAPSHOT_ERR_ENTROPY_UNDECLARED, /* save: mode missing or inconsistent */
    RVMACHINE_SNAPSHOT_ERR_BAD_MAGIC,
    RVMACHINE_SNAPSHOT_ERR_VERSION,
    RVMACHINE_SNAPSHOT_ERR_TRUNCATED,
    RVMACHINE_SNAPSHOT_ERR_TRAILER,      /* the SHA-256 trailer does not match */
    RVMACHINE_SNAPSHOT_ERR_FORMAT,       /* a field or section is malformed */
    RVMACHINE_SNAPSHOT_ERR_RAM_SIZE,
    RVMACHINE_SNAPSHOT_ERR_CONFIG,       /* boot arguments, wait mode, tree or timebase */
    RVMACHINE_SNAPSHOT_ERR_SLOT_UNKNOWN, /* a slot kind this version does not know */
    RVMACHINE_SNAPSHOT_ERR_SLOT_MISMATCH, /* slot layout differs from the configuration */
    RVMACHINE_SNAPSHOT_ERR_KERNEL_HASH,
    RVMACHINE_SNAPSHOT_ERR_DISK_BINDING, /* disk size or hash differs */
    RVMACHINE_SNAPSHOT_ERR_DISK_NOT_FRESH, /* restore: the disk already holds overlay blocks */
    RVMACHINE_SNAPSHOT_ERR_ENTROPY_MODE, /* restore: declared mode differs from the file's */
    RVMACHINE_SNAPSHOT_ERR_FRESH_UNAVAILABLE, /* restore: fresh needs a host-entropy snapshot and source */
    RVMACHINE_SNAPSHOT_ERR_MODEL,        /* restore: the machine model version differs */
    RVMACHINE_SNAPSHOT_ERR_TOO_LARGE     /* restore: the file exceeds RVMACHINE_SNAPSHOT_FILE_MAX */
};

const char *rvmachine_snapshot_status_name(enum rvmachine_snapshot_status status);

/* The caller's SHA-256 (this module links no hash). begin starts a stream,
 * write feeds it, finish ends it and writes 32 bytes. */
struct rvmachine_snapshot_hash {
    void *ctx;
    void (*begin)(void *ctx);
    void (*write)(void *ctx, const uint8_t *data, size_t n);
    void (*finish)(void *ctx, uint8_t out[RVMACHINE_SNAPSHOT_DIGEST]);
};

/* Sequential output; false on failure. */
struct rvmachine_snapshot_sink {
    void *ctx;
    bool (*write)(void *ctx, const void *buf, size_t n);
};

/* Random-access input of exactly size bytes; false on failure. */
struct rvmachine_snapshot_source {
    void *ctx;
    uint64_t size;
    bool (*read)(void *ctx, uint64_t off, void *buf, size_t n);
};

struct rvmachine_snapshot_params {
    struct rvmachine_snapshot_hash hash;
    uint8_t kernel_sha256[RVMACHINE_SNAPSHOT_DIGEST];
    uint8_t disk_sha256[RVMACHINE_SNAPSHOT_DIGEST];
    /* restore: false compares only the disk size, not its hash */
    bool disk_hash_known;
    enum rvmachine_snapshot_entropy entropy;
    /* save: kept verbatim, only for TEST_STREAM, so a replay can continue the
     * stream; restore: when nonzero, the declared mode that must match */
    uint8_t source_state[RVMACHINE_SNAPSHOT_SOURCE_STATE_MAX];
    uint32_t source_state_len;
};

struct rvmachine_snapshot_info {
    uint8_t digest[RVMACHINE_SNAPSHOT_DIGEST]; /* the trailer */
    uint64_t file_size;
    uint64_t retired;
    uint64_t guest_time;
    uint64_t pages;          /* non-zero RAM pages stored */
    uint64_t overlay_blocks; /* disk overlay blocks stored */
    enum rvmachine_snapshot_entropy entropy;
    uint8_t source_state[RVMACHINE_SNAPSHOT_SOURCE_STATE_MAX];
    uint32_t source_state_len;
    bool disk_hash_checked;
    enum rvmachine_snapshot_mode mode; /* restore only */
};

/* Writes the machine to sink. The machine is not changed. */
enum rvmachine_snapshot_status rvmachine_snapshot_save(
    const struct rvmachine *m, const struct rvmachine_snapshot_params *params,
    const struct rvmachine_snapshot_sink *sink, struct rvmachine_snapshot_info *info);

/* Builds a machine from the source into a new machine made from config (the
 * same RAM size, boot arguments, wait mode, disk, entropy and console as the
 * saved one; the disk is a fresh handle with no overlay blocks). On success
 * the machine owns config->disk; on any refusal *out is NULL and the disk is
 * still the caller's. The kernel is not loaded again; it is in the pages. */
enum rvmachine_snapshot_status rvmachine_snapshot_restore(
    struct rvmachine **out, const struct rvmachine_config *config,
    const struct rvmachine_snapshot_params *params, enum rvmachine_snapshot_mode mode,
    const struct rvmachine_snapshot_source *source, struct rvmachine_snapshot_info *info);

/* What a snapshot says about the machine it holds, read after its version,
 * size and trailer were verified. A caller builds the matching configuration
 * from it. */
struct rvmachine_snapshot_inspection {
    uint8_t digest[RVMACHINE_SNAPSHOT_DIGEST];
    uint8_t kernel_sha256[RVMACHINE_SNAPSHOT_DIGEST];
    uint8_t disk_sha256[RVMACHINE_SNAPSHOT_DIGEST];
    uint8_t source_state[RVMACHINE_SNAPSHOT_SOURCE_STATE_MAX];
    char bootargs[RVMACHINE_BOOTARGS_MAX];
    uint64_t ram_bytes, retired, guest_time, file_size, pages, overlay_blocks, disk_size;
    uint32_t source_state_len;
    enum rvmachine_snapshot_entropy entropy;
    bool wait_stops, disk_present;
    bool entropy_device; /* slot 1 holds an entropy device */
};

enum rvmachine_snapshot_status rvmachine_snapshot_inspect(
    const struct rvmachine_snapshot_source *source, const struct rvmachine_snapshot_hash *hash,
    struct rvmachine_snapshot_inspection *out);

#endif
