/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Private state and callbacks shared by the native boot leaf and its PUBLIC owner. */
#ifndef ZCL_NATIVE_MACHINE_BOOT_INTERNAL_H
#define ZCL_NATIVE_MACHINE_BOOT_INTERNAL_H
#include "command/native_command.h"
#include "config/mesh_guest_service.h"
#include "crypto/sha256.h"
#include "platform/positioned_file.h"
#include "services/package_lifecycle.h"
#include "services/guest_image_admission.h"
#define MB_PATH "dev.app.machine.boot"
#define MB_TAIL 256u
#define MB_BUF 4096u
struct mb_file {
    const char *path; /* NULL when not given */
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before; /* through the open handle */
    bool changed;
};

#define MB_PORT_BYTES 65536u
struct mb_port {
    const char *name;
    const char *after;
    struct mb_file input, expect;
    uint8_t input_bytes[MB_PORT_BYTES], expected_bytes[MB_PORT_BYTES];
    size_t accepted, received;
    uint32_t epoch;
    uint32_t ready_epoch;
    bool started;
    bool ready;
};

struct mb_public_identity {
    uint8_t wire[51], fingerprint[32];
};
struct mb_pc_counts {
    uint32_t hit[9], total;
};
struct mb_pc_privileges {
    uint16_t hit[4]; /* U/S/M/unknown returned-slice locations, not work. */
    bool unavailable;
};
struct mb_newfs_geometry {
    uint32_t groups, blocks, inodes;
};
struct mb_p7_bracket {
    uint64_t lower, upper;
    bool seen, valid;
    uint64_t dispatch, dispatch_instance;
    const struct rvmachine *dispatch_machine;
    uint32_t dispatch_host_epoch, dispatch_device_epoch;
    bool dispatch_seen, dispatch_valid;
};
struct mb_v3_dispatch {
    uint64_t work, instance;
    const struct rvmachine *machine;
    uint32_t host_epoch, device_epoch;
    bool seen, valid;
};
struct mb_p7_privilege_history {
    struct mb_v3_dispatch sample, dispatch, completed;
    struct mb_pc_privileges counts;
    uint8_t kernel[32], root[32];
    uint32_t total;
    bool seen, unavailable;
};
struct mb_command_observation {
    uint64_t instance;
    uint32_t host_epoch, device_epoch;
    unsigned phase;
    bool active, rc_seen, next_seen, done_seen;
};
struct mb_state {
    struct {
        bool enabled, recover, admitted, retained, attempted, delivered, failed, mutated;
        const char *volume_path, *record_path, *credential_path;
        char *owned_volume_path, *owned_record_path, *owned_credential_path;
        uint8_t authorized_kernel[32];
        uint32_t profile_revision;
        struct mb_protected_owner *protected;
        struct mb_public_identity identity;
        struct mb_command_observation command;
        bool public_key_seen, fingerprint_seen;
        bool identity_ready;
        bool prepared20k_seen;
        bool v3_newfs_done;
        bool phase7_dd_done, phase7_newfs_done;
        struct mb_pc_counts pc_counts;
        struct mb_pc_privileges pc_privileges;
        struct mb_p7_privilege_history p7_privilege_history;
        bool pc_unqualified;
        struct mb_newfs_geometry geometry;
        bool geometry_seen, geometry_unqualified;
        struct mb_p7_bracket p7_bracket;
        struct mb_v3_dispatch v3_dispatch;
        struct mb_v3_dispatch transition_actual, phase_dispatch[17];
        uint32_t phase_dispatch_attempted;
        bool last_result_valid;
        uint64_t started_ms, enrollment_generation;
        struct platform_private_file volume, record, credential;
        struct platform_positioned_file_snapshot credential_snapshot;
        struct mesh_guest_service_manager *manager;
        uint64_t instance, health_instance;
        uint64_t last_retired, last_fw_calls, last_device_work;
        uint32_t line_epoch, ready_epoch, line_device_epoch, ready_device_epoch;
        uint32_t health_epoch, health_device_epoch;
        uint64_t line_instance;
        bool ready, health, child, done, line_failed, command_pending;
        uint8_t line[256];
        size_t line_length;
        size_t command_step;
    } owner;
    struct {
        const char *datadir, *output, *root_hex;
        uint8_t root[32];
        uint64_t capacity, verification;
        struct package_lifecycle_declared_output *reader;
        struct guest_image_admission *public_reader;
        bool public_observation;
        bool protected_observation;
        uint8_t *image;
        size_t length;
        char image_sha256[65];
        bool changed;
    } accepted;
    struct mb_port ports[2];
    unsigned port_count;
    bool port_failed;
    bool private_export_failed;
    uint8_t port_line[256];
    size_t port_line_len;

    struct mb_file kernel;
    struct mb_file disk;
    const char *bootargs;
    const char *transcript;
    uint64_t ram_bytes;
    uint64_t max_work;
    struct rvmachine_script script;
    struct rvmachine *m;
    struct rvmachine_result res;
    bool ran;
    int out_fd;
    bool out_failed;
    bool console_full; /* the console limit was reached */
    uint8_t buf[MB_BUF];
    size_t buf_len;
    struct sha256_ctx sha;
    char sha_hex[2 * SHA256_OUTPUT_SIZE + 1];
    char tail[MB_TAIL + 1u];
    size_t tail_len;
    /* The test entropy source, when a seed was given. */
    bool seeded;
    bool host_entropy;
    bool entropy_failed;
    uint64_t seed;
    uint64_t ent_block;                   /* number of the next block */
    uint8_t ent_bytes[SHA256_OUTPUT_SIZE]; /* the current block */
    size_t ent_used;                      /* bytes of it already handed out */
    uint64_t ent_given;                   /* bytes handed to the machine */
    /* The boot seed from the same test seed, when early_seed asked for it. */
    bool early;
    uint64_t early_given; /* bytes handed to the machine */
};
bool zcl_mb_boot_fail(struct zcl_command_reply *, enum zcl_command_exit,
    const char *, const char *, const char *, const char *);
bool zcl_mb_boot_bad_input(struct zcl_command_reply *, const char *);
bool zcl_mb_boot_opt_str(const struct json_value *, const char **);
bool zcl_mb_boot_opt_int(const struct json_value *, int64_t, int64_t, int64_t, int64_t *);
size_t zcl_mb_boot_host_entropy(void *, uint8_t *, size_t);
bool zcl_mb_boot_host_boot_seed(void *, uint8_t *, size_t, size_t *);
bool zcl_mb_boot_accepted_read(struct mb_state *, struct zcl_command_reply *);
bool zcl_mb_owner_image_grant(void *, const uint8_t[32],
    const struct vcs_guest_image_observation *);
bool zcl_mb_owner_parse(const struct json_value *, struct mb_state *, struct zcl_command_reply *);
bool zcl_mb_owner_called(struct mb_state *, struct zcl_command_reply *);
/* False means the complete state remains reachable; caller must not free it. */
bool zcl_mb_owner_dispose(struct mb_state *);
#endif
