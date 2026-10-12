/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bounded receiver-owned guest launch and byte-channel lifecycle APIs. */
#ifndef ZCL_CONFIG_MESH_GUEST_SERVICE_H
#define ZCL_CONFIG_MESH_GUEST_SERVICE_H
#include "platform/guest_service_runner.h"
#include "platform/guest_chan.h"
#include "platform/private_file.h"
#include "platform/positioned_file.h"
enum mesh_guest_enrollment_mode {
    MESH_GUEST_ENROLLMENT_OFF = 0,
    MESH_GUEST_ENROLLMENT_INITIAL,
    MESH_GUEST_ENROLLMENT_RECOVER
};
/* Public owner-local binding. Root identifies the accepted PUBLIC boot image,
 * never the private encrypted volume. Serialize fields with codec/cursor. */
struct mesh_guest_enrollment_record {
    uint8_t guest_id[32], ssh_fingerprint[32];
    uint8_t kernel[32], root[32], helper[32], profile[32], owner_grant[32];
    uint64_t volume_device, volume_file, volume_bytes, generation;
};
struct mesh_guest_enrollment_admission {
    enum mesh_guest_enrollment_mode mode;
    struct mesh_guest_enrollment_record expected;
    struct platform_private_file *record, *volume, *credential;
    const char *initial_destination;
};
/* Helpers owned by configured launch admission, not mesh object grants.
 * Handles remain locked and caller-owned through successful manager destroy.
 * No credential contents are read. Account protection is not host isolation. */
bool mesh_guest_enrollment_handles(const struct mesh_guest_enrollment_admission *,
    struct platform_positioned_file_snapshot *);
bool mesh_guest_enrollment_read(struct platform_private_file *,
    struct mesh_guest_enrollment_record *);
bool mesh_guest_enrollment_equal(const struct mesh_guest_enrollment_record *,
    const struct mesh_guest_enrollment_record *);
bool mesh_guest_enrollment_admit(const struct mesh_guest_enrollment_admission *,
    struct mesh_guest_enrollment_record *, struct platform_positioned_file_snapshot *);
bool mesh_guest_enrollment_publish(const char *, const struct mesh_guest_enrollment_record *,
    struct platform_private_file *);
struct mesh_guest_service;
/* Receiver-owned control admission, requiring the actual instance/slot/key
 * exchange and guest binding ACK before success. No default handler exists.
 * Runs in the adapter callback: no machine access, I/O, reentry or blocking.
 * slot is 0..1; role is 0 (T transport) or 1 (P payload). */
typedef bool (*mesh_guest_service_binding_fn)(void *, const uint8_t peer[32],
    const uint8_t *, size_t, uint8_t *, size_t, size_t *, uint32_t *slot,
    uint32_t *role);
struct mesh_guest_service_config {
    struct rvmachine_config machine;
    const uint8_t *kernel;
    size_t kernel_length;
    struct guest_limits limits;
    mesh_guest_service_binding_fn binding;
    void *binding_context;
};
enum rvmachine_status mesh_guest_service_create(struct mesh_guest_service **,
    const struct mesh_guest_service_config *, bool *disk_consumed);
/* No activation during creation. Absent actual binding handler refuses. */
bool mesh_guest_service_attach(struct mesh_guest_service *);
bool mesh_guest_service_enable(struct mesh_guest_service *, bool);
/* Single owner, after every returned slice. Adapter callbacks may concurrently
 * enqueue bounded work, but only this owner accesses the machine. */
void mesh_guest_service_pump(struct mesh_guest_service *, int64_t now_unix);
enum rvmachine_status mesh_guest_service_slice(struct mesh_guest_service *,
    uint64_t now_ms, uint64_t previous_us, bool startup,
    struct guest_gov_decision *, struct rvmachine_result *);
bool mesh_guest_service_stop(struct mesh_guest_service *);
bool mesh_guest_service_destroy(struct mesh_guest_service *);
bool mesh_guest_service_snapshot(const struct mesh_guest_service *,
    struct guest_service_runner_snapshot *);
/* Explicit configured owner. Image/read source and callback contexts remain
 * immutable and alive through destruction. Creation allocates only the owner;
 * default disabled, no guest, stream registration, disk or execution. */
struct mesh_guest_service_manager;
enum mesh_guest_launch_policy {
    MESH_GUEST_LAUNCH_UNSPECIFIED = 0,
    MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE,
    MESH_GUEST_LAUNCH_SECRET_REQUIRED
};
enum mesh_guest_disk_mode {
    MESH_GUEST_DISK_UNSPECIFIED = 0,
    MESH_GUEST_DISK_NONE,
    MESH_GUEST_DISK_EPHEMERAL_OVERLAY,
    MESH_GUEST_DISK_RETAINED_BACKEND
};
/* First called-owner fixture only. This mode never admits arbitrary keyfile
 * material or an arbitrary accepted image. Artifact currentness and explicit
 * local authorization are separate prerequisites. */
enum mesh_guest_unlock_policy {
    MESH_GUEST_UNLOCK_OFF = 0,
    MESH_GUEST_UNLOCK_PUBLIC_KEYFILE_FIXTURE,
    MESH_GUEST_UNLOCK_PROTECTED_HOST
};
enum mesh_guest_unlock_purpose {
    MESH_GUEST_UNLOCK_PURPOSE_NONE = 0,
    MESH_GUEST_UNLOCK_PUBLIC_GELI_KEYFILE,
    MESH_GUEST_UNLOCK_PROTECTED_GELI_KEYFILE
};
struct mesh_guest_unlock_admission {
    enum mesh_guest_unlock_policy policy;
    enum mesh_guest_unlock_purpose purpose;
    uint32_t receiver_revision;
    uint8_t authorized_kernel[32];
    bool (*accepted_current)(void *, const uint8_t kernel[32]);
    bool (*public_keyfile_current)(void *, const struct platform_private_file *);
    bool (*receiver_current)(void *, const struct rvmachine *, uint64_t instance,
        uint32_t private_epoch);
    /* Fixed PUBLIC matcher only. Snapshot fields may be observed during this
     * callback; no machine/manager API reentry or public transcript export. */
    void (*receiver_console)(void *, const struct rvmachine *, uint64_t instance,
        const uint8_t *, size_t);
    void *owner_context;
};
/* These selections enforce local prerequisites, not artifact acceptance or
 * encryption. Only the accepted-launch owner may authorize product start.
 * Backend callbacks are bounded and nonblocking; their caller-owned context
 * remains valid until successful machine destruction. Close does not flush
 * or release it. Retained storage grants no encryption guarantee.
 * Opted-in enrollment requires SECRET_REQUIRED and RETAINED_BACKEND, with
 * disk_bytes matching enrollment.volume and no caller disk callbacks/context.
 * The manager binds the locked enrolled descriptor directly and preserves
 * backend failures across retries. Its owner must retain that handle until
 * successful destruction. Backend failures stop at manager drive boundaries;
 * this does not establish guest mount or credential-delivery authority. */
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Separate protected enrollment framing; a record is not a grant. */
#define MESH_GUEST_PROTECTED_ENROLLMENT_WIRE_BYTES 328u
enum mesh_guest_protected_enrollment_phase {
    MESH_GUEST_PROTECTED_INITIAL_ATTEMPTED = 1,
    MESH_GUEST_PROTECTED_READY = 2
};
struct mesh_guest_protected_enrollment_extension {
    struct mesh_guest_enrollment_record enrollment;
    enum mesh_guest_protected_enrollment_phase phase;
    uint64_t highest_reserved;
    uint64_t revoked_through;
};
bool mesh_guest_protected_enrollment_encode(
    const struct mesh_guest_protected_enrollment_extension *,
    uint8_t *, size_t);
bool mesh_guest_protected_enrollment_decode(const uint8_t *, size_t,
    struct mesh_guest_protected_enrollment_extension *);
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Protected enrollment operations under the existing manager owner. */
struct mesh_guest_protected_enrollment_operation {
    struct platform_private_file *volume; /* borrowed, stable exclusive lock */
    struct mesh_guest_enrollment_record expected;
    bool unknown;
};
bool mesh_guest_protected_enrollment_initial(struct mesh_guest_protected_enrollment_operation *,
    const char *, const char *, struct platform_private_file *);
bool mesh_guest_protected_enrollment_reserve(struct mesh_guest_protected_enrollment_operation *,
    const char *, const char *, struct platform_private_file *, uint64_t *);
bool mesh_guest_protected_enrollment_ready(struct mesh_guest_protected_enrollment_operation *,
    const char *, const char *, const uint8_t[32], struct platform_private_file *);
bool mesh_guest_protected_enrollment_revoke(struct mesh_guest_protected_enrollment_operation *,
    const char *, const char *, uint64_t, struct platform_private_file *);
bool mesh_guest_protected_enrollment_read_current(struct mesh_guest_protected_enrollment_operation *,
    const char *, struct platform_private_file *, struct mesh_guest_protected_enrollment_extension *);
struct mesh_guest_protected_enrollment_owner {
    const char *extension_path, *fresh_stage_path, *fresh_ready_stage_path;
    /* Cached owner grant metadata only; bounded/no key read/no I/O/reentry.
     * Current exact accepted image is independently checked by unlock admission. */
    bool (*grant_current)(void *, const struct mesh_guest_enrollment_record *, uint64_t);
    void *context;
};
/* Add owner above to launch_config only for coherent PROTECTED_HOST policy.
 * Manager owns extension readback, operation, reservation + attempted flags.
 * No cached key bytes are placed in manager config. */
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Bounded protected-provider callback contract. */

struct mesh_guest_protected_tuple {
    struct mesh_guest_enrollment_record enrollment; /* full image/root/helper/profile/grant/volume tuple */
    struct platform_positioned_file_snapshot credential;
    uint64_t instance_id;
    uint64_t provider_generation; /* nonzero, monotonic; never reused */
    /* Explicit immutable owner policy: admission < delivery <= authority.
     * Delivery expiry never extends service authority or reopens delivery. */
    uint64_t admitted_ms, delivery_deadline_ms, authority_expires_ms;
    uint32_t host_epoch, device_epoch; /* both nonzero, dedicated receiver */
};
enum mesh_guest_provider_result {
    MESH_GUEST_PROVIDER_CURRENT,
    MESH_GUEST_PROVIDER_REFUSED,
    MESH_GUEST_PROVIDER_UNKNOWN
};
/* Token belongs to one manager lifetime and exact tuple; owner never retries
 * after an admitted attempt, including read/delivery failure. Not a grant. */
struct mesh_guest_provider_lease { uint64_t id, generation; };
struct mesh_guest_secret_provider {
    void *context;
    struct platform_private_file *credential; /* borrowed, exclusively locked */
    enum mesh_guest_provider_result (*current)(void *,
        const struct mesh_guest_protected_tuple *, uint64_t decision_ms);
    enum mesh_guest_provider_result (*begin)(void *,
        const struct mesh_guest_protected_tuple *, uint64_t decision_ms, struct mesh_guest_provider_lease *);
    /* Exact capacity32, writes32 only on success; caller zeroes before and
     * cleanses on ALL exits, including partial failing callback writes. */
    bool (*read_key)(void *, const struct mesh_guest_protected_tuple *,
        const struct mesh_guest_provider_lease *, uint8_t *, size_t capacity);
    /* Must succeed immediately before commit; false invalidates this attempt.
     * It does not itself deliver or authenticate a receiver. */
    enum mesh_guest_provider_result (*commit_current)(void *,
        const struct mesh_guest_protected_tuple *, uint64_t decision_ms, const struct mesh_guest_provider_lease *);
    /* delivered is true only after the actual atomic receiver queue commit.
     * Always wipes plaintext; false terminates authority, true retains only
     * consumed-generation metadata until authority expiry or revocation. */
    void (*end)(void *, const struct mesh_guest_provider_lease *, bool delivered);
};
/* Serialized manager entry binds exact enrollment/provider generations and
 * both receiver epochs; callbacks must not reenter the manager. */
bool mesh_guest_service_manager_unlock_protected(
    struct mesh_guest_service_manager *, uint64_t instance_id,
    uint64_t enrollment_generation, uint32_t host_epoch, uint32_t device_epoch,
    uint64_t provider_generation, uint64_t now_ms);
bool mesh_guest_service_manager_protected_tuple(
    struct mesh_guest_service_manager *, uint64_t instance_id,
    uint32_t host_epoch, uint32_t device_epoch,
    struct mesh_guest_protected_tuple *);

/* Each decision time comes from trusted owner monotonic clock, never guest
 * or wall time. current uses decision_ms < authority_expires_ms; equality
 * refuses. decision_ms must be >= admitted_ms and >= last accepted decision.
 * Refresh trusted time immediately before commit_current; missing/backward
 * clock refuses. begin and commit additionally require decision_ms strictly
 * below delivery_deadline_ms. After successful end, current remains testable
 * against authority_expires_ms, but begin/read never repeat. No callback clock
 * reads, derived duration, or silent deadline extension; both deadlines bind
 * the exact immutable tuple and generation. */
/* Sole owner calls callbacks outside instance/stream lane mutexes with manager
 * driving guard held. All callbacks bounded/nonblocking/nonreentrant; current
 * uses cached immutable metadata, never filesystem/network reload. Context,
 * provider and credential stay live until manager successfully destroys and
 * every lease ends; refused join retains them. Cross-thread manager use is
 * unsupported. External revocation posts monotonic generation invalidation;
 * it must not call manager APIs or free provider state concurrently.
 *
 * begin/commit_current/end serialize against revocation in provider. Delivery
 * is a sole-owner atomic receiver queue commit between commit_current and end.
 * Revocation becomes ACKNOWLEDGED only after owner seals receiver suffix,
 * stops/quiesces guest and ends outstanding leases. A revoke request can deny
 * future commit but cannot undo already consumed bytes; no stronger claim.
 * If a request races after commit_current, lease drain defines commit-before-
 * revoke ordering. Implementation must enforce this lease protocol, not infer
 * it from two unlocked boolean checks. No key hashes/transcript exports. */
struct mesh_guest_service_launch_config {
    struct mesh_guest_enrollment_admission enrollment;
    struct mesh_guest_unlock_admission unlock;
    struct mesh_guest_protected_enrollment_owner protected_enrollment;
    struct mesh_guest_secret_provider protected_provider;
    void (*protected_invalidate)(void *); /* serialized terminalize/wipe; no I/O */
    uint64_t protected_admitted_ms, protected_delivery_deadline_ms, protected_authority_expires_ms;
    enum mesh_guest_launch_policy policy;
    enum mesh_guest_disk_mode disk_mode;
    struct mesh_guest_service_config service;
    uint64_t disk_bytes;
    rvmachine_disk_read_fn disk_read;
    rvmachine_disk_write_fn disk_write;
    rvmachine_disk_flush_fn disk_flush;
    void *disk_context;
};
bool mesh_guest_service_manager_create(struct mesh_guest_service_manager **,
    const struct mesh_guest_service_launch_config *);
bool mesh_guest_service_manager_event(struct mesh_guest_service_manager *,
    const struct guest_event *, uint64_t now_ms, struct guest_action *);
/* Generic events cannot manufacture peer/slot/port/join/readiness facts.
 * The secure readiness owner checks actual entropy/startup/injection evidence
 * for this exact returned instance handle before calling ready. This API
 * supplies no marker parser, key handler or verification substitute. */
uint64_t mesh_guest_service_manager_instance(const struct mesh_guest_service_manager *);
/* Same-instance retained-volume observation between drives. Requires a real
 * successful backend flush later than its latest write; creation/metadata and
 * a guest console marker do not qualify. No guest mount/key/authentication claim. */
bool mesh_guest_service_manager_storage_synced(struct mesh_guest_service_manager *,
    uint64_t instance_id);
/* PUBLIC fixed material only; the called owner supplies source-bound raw and
 * initialized-guest health evidence for the exact instance/epoch. One admitted
 * attempt per manager lifetime, including failure; no secret-use authority.
 * Null, stale instance/epoch and out-of-phase entries are outside admission
 * and leave active authority unchanged. Current-epoch refusal is sticky. */
bool mesh_guest_service_manager_unlock_public(struct mesh_guest_service_manager *,
    uint64_t instance_id, uint32_t private_epoch, uint64_t now_ms);
/* Trusted existing readiness owner reports actual mount/identity observation.
 * The generation is the persisted enrollment generation, NOT a private-port
 * epoch. Secret delivery requires a later dedicated receiver epoch boundary.
 * No console marker, metadata match or supplied digest proves key possession. */
bool mesh_guest_service_manager_identity_finish(struct mesh_guest_service_manager *,
    uint64_t instance_id, uint64_t enrollment_generation,
    const uint8_t fingerprint[32], bool mounted);
/* Handles never repeat within this process, across manager replacements.
 * They are local readiness selection only, not S7 wire or key identities. */
bool mesh_guest_service_manager_ready(struct mesh_guest_service_manager *,
    uint64_t instance_id, uint64_t now_ms, struct guest_action *);
enum rvmachine_status mesh_guest_service_manager_drive(
    struct mesh_guest_service_manager *, uint64_t now_ms, int64_t now_unix,
    struct guest_gov_decision *, struct rvmachine_result *);
/* The manager measures real invocation host time with the monotonic clock,
 * rounds a zero-resolution interval up to one microsecond, retains failed-work
 * charges, and settles the final charge before destruction/join. A bad clock
 * retains the instance and pending obligation; no cost is invented. */
bool mesh_guest_service_manager_snapshot(const struct mesh_guest_service_manager *,
    uint64_t now_ms, struct guest_service_snapshot *);
bool mesh_guest_service_manager_destroy(struct mesh_guest_service_manager *,
    uint64_t now_ms);
#ifdef ZCL_TESTING
/* Borrowed real machine only between slices, with the owning drive quiescent.
 * No fabricated observation or alternate device/transport implementation. */
struct rvmachine *mesh_guest_service_test_machine(struct mesh_guest_service *);
#endif
#endif
