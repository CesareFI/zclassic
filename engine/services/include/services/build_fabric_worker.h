/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One confined, content-addressed ZBuild V1 worker dispatch. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_WORKER_H
#define ZCL_SERVICES_BUILD_FABRIC_WORKER_H

#include "base/result.h"
#include "models/build_fabric.h"
#include "services/build_fabric_worker_feedback.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What the executing host itself observed for one action. `host_*` fields
 * come from this process: its own launch counter and the kernel's wait4()
 * and /proc accounting of the confined child (see util/spawn.h). The
 * `child_reported_*_unverified` fields are the sandboxed child's own stdout
 * claims about processes it started; they are kept for diagnosis only and
 * must never support a claim that work was avoided or performed.
 * Not a receipt, proof, or acceptance authority. */
struct build_fabric_host_accounting {
    bool measured;                    /* the confined executor was launched */
    bool reaped;                      /* wait4() returned its usage */
    bool io_observed;                 /* /proc/<pid>/io read before reap */
    int io_error;                     /* errno when it was not */
    uint64_t host_processes_launched; /* every launch this worker thread made
                                         for the action, through publication */
    uint64_t host_executor_launches;  /* the confined executor itself: 0 or 1 */
    int64_t host_wall_us;
    int64_t host_cpu_user_us;         /* executor plus descendants it reaped */
    int64_t host_cpu_system_us;
    int64_t host_max_rss_kib;
    int64_t host_in_blocks;
    int64_t host_out_blocks;
    uint64_t host_read_bytes;
    uint64_t host_write_bytes;
    uint64_t host_storage_read_bytes;
    uint64_t host_storage_write_bytes;
    uint64_t child_reported_processes_unverified;
    uint64_t child_reported_compiler_processes_unverified;
    uint64_t child_reported_test_processes_unverified;
};

/* Execute one already-claimed action. The caller owns lease acquisition;
 * this path rechecks it at start, verification, and signed publication.
 * `out_accounting` may be NULL; when present it is zeroed on entry and holds
 * the host's own accounting as far as the action got, including a refusal
 * after the executor ran. */
struct zcl_result build_fabric_worker_execute(
    struct node_db *ndb, const char *workspace_root, const char *datadir,
    const char *action_id,
    const char *lease_id, const uint8_t signer_secret[32],
    const uint8_t signer_pubkey[32], struct db_build_receipt *out_receipt,
    struct build_fabric_worker_feedback *out_feedback,
    struct build_fabric_host_accounting *out_accounting);

/* Load or atomically create the operator-owned local worker key. The returned
 * row is suitable for explicit -buildworker self-approval. A host that
 * cannot capture a gcc toolchain capsule (vcs_toolchain_capsule_v1_capture,
 * ELF/glibc-specific) cannot execute c23.compile/.test/.fuzz/.package and
 * this returns a named error instead of an approvable row that would
 * advertise capability it cannot honor. */
struct zcl_result build_fabric_worker_identity_load(
    const char *datadir, struct db_build_worker *worker,
    uint8_t signer_secret[32], uint8_t signer_pubkey[32]);

/* Startup recovery needs the original Ed25519 seed to reconstruct the
 * issuer log. The caller must erase seed_out after replay. */
struct zcl_result build_fabric_worker_identity_load_with_seed(
    const char *datadir, struct db_build_worker *worker,
    uint8_t signer_secret[32], uint8_t signer_pubkey[32],
    uint8_t seed_out[32]);

#ifdef ZCL_TESTING
/* Test seam: the honest capabilities-or-refusal decision, driven by a
 * caller-supplied outcome rather than the real toolchain probe, so tests
 * can exercise the refusal path on a host (e.g. this repo's own Linux CI)
 * where vcs_toolchain_capsule_v1_capture() always succeeds. Mirrors
 * the "force the outcome, run the real decision code" shape of
 * os_proc_mem_set_override() / platform_clock_set_source(). */
struct zcl_result build_fabric_worker_capabilities_for_test(
    bool have_toolchain, char *out, size_t out_len);

/* Resolve a fixed verifier as if `running_executable` were the node image.
 * This keeps the production/dev sibling selection observable without a test
 * needing to rename its own harness process. */
struct zcl_result build_fabric_worker_verifier_path_for_test(
    const char *running_executable, const char *workspace, char *out,
    size_t cap);
#endif

#endif /* ZCL_SERVICES_BUILD_FABRIC_WORKER_H */
