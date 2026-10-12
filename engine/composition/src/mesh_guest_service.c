/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Composes governed guests, bounded byte channels and retained stop accounting. */
#include "config/mesh_guest_service.h"
#include "config/mesh_guest_chan.h"
#include "config/mesh_guest_private_volume.h"
#include "base/safe_alloc.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "util/sync.h"
#include "platform/time_compat.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SGS_QUEUE 16384u
#define SGS_CHUNK 512u
struct sgs_port {
    struct guest_chan_port token;
    bool live, ending, resume, guest_open;
    uint8_t rx[SGS_QUEUE], tx[SGS_QUEUE];
    size_t rx_length, tx_length;
    uint32_t machine_generation;
    size_t consumed_seen;
};
struct mesh_guest_service {
    zcl_mutex_t lock;
    struct guest_service_runner *runner;
    const struct mesh_guest_unlock_admission *public_owner;
    struct rvmachine *public_device;
    uint64_t public_instance;
    mesh_guest_service_binding_fn binding;
    void *binding_context;
    const struct guest_chan_host_ops *host_ops;
    void *host;
    bool attached, stopping;
    bool bound[2], retired[2];
    uint8_t peers[2][32];
    struct sgs_port ports[4];
};
static _Atomic uint64_t sgs_generation;
static uint32_t sgs_next_generation(void)
{
    uint64_t current = atomic_load(&sgs_generation);
    while (current < UINT32_MAX) {
        if (atomic_compare_exchange_weak(&sgs_generation, &current, current + 1))
            return (uint32_t)(current + 1);
    }
    return 0;
}
static bool sgs_fail(const char *message)
{
    fprintf(stderr, "mesh guest service: %s\n", message);
    return false;
}
static struct sgs_port *sgs_live(struct mesh_guest_service *s, struct guest_chan_port t)
{
    if (t.index >= 4 || !t.generation) return NULL;
    struct sgs_port *p = &s->ports[t.index];
    return p->live && p->token.generation == t.generation ? p : NULL;
}
static bool sgs_legacy_accept(void *context, struct guest_chan_port *out)
{
    (void)context;
    (void)out;
    return false;
}
/* Caller holds the device lock for admission and generation assignment. */
static bool sgs_admit_slot(struct mesh_guest_service *s, const uint8_t peer[32],
    uint32_t slot, uint32_t role, struct guest_chan_port *token)
{
    struct sgs_port *p = &s->ports[slot * 2 + role];
    bool ok = !s->retired[slot] && !p->live && !p->ending && p->guest_open &&
        (!s->bound[slot] || memcmp(s->peers[slot], peer, 32) == 0);
    for (size_t i = 0; i < 2 && ok; i++)
        if (i != slot && s->bound[i] && !memcmp(s->peers[i], peer, 32)) ok = false;
    if (ok) {
        uint32_t generation = sgs_next_generation();
        ok = generation != 0;
        if (ok) {
            s->bound[slot] = true;
            memcpy(s->peers[slot], peer, 32);
            p->token = (struct guest_chan_port){ slot * 2 + role, generation };
            p->live = true;
            p->resume = true;
            *token = p->token;
        }
    }
    return ok;
}
static bool sgs_accept(void *context, const uint8_t peer[32],
    const uint8_t *payload, size_t length, uint8_t *reply, size_t capacity,
    size_t *produced, struct guest_chan_port *token)
{
    struct mesh_guest_service *s = context;
    uint32_t slot = UINT32_MAX, role = UINT32_MAX;
    zcl_mutex_lock(&s->lock);
    bool ok = !s->stopping && s->binding && s->binding(s->binding_context,
        peer, payload, length, reply, capacity, produced, &slot, &role);
    ok = ok && slot < 2 && role < 2 && *produced <= capacity;
    if (ok) ok = sgs_admit_slot(s, peer, slot, role, token);
    zcl_mutex_unlock(&s->lock);
    return ok;
}
static size_t sgs_write(void *context, struct guest_chan_port token,
    const uint8_t *bytes, size_t length)
{
    struct mesh_guest_service *s = context;
    zcl_mutex_lock(&s->lock);
    struct sgs_port *p = sgs_live(s, token);
    size_t n = p && !s->stopping ? SGS_QUEUE - p->rx_length : 0;
    if (n > length) n = length;
    if (n) { memcpy(p->rx + p->rx_length, bytes, n); p->rx_length += n; }
    zcl_mutex_unlock(&s->lock);
    return n;
}
static void sgs_resume(void *context, struct guest_chan_port token)
{
    struct mesh_guest_service *s = context;
    zcl_mutex_lock(&s->lock);
    struct sgs_port *p = sgs_live(s, token);
    if (p) p->resume = true;
    zcl_mutex_unlock(&s->lock);
}
static void sgs_end(void *context, struct guest_chan_port token, enum guest_chan_end reason)
{
    struct mesh_guest_service *s = context;
    zcl_mutex_lock(&s->lock);
    struct sgs_port *p = sgs_live(s, token);
    if (p) {
        p->live = false;
        p->ending = true;
        p->rx_length = p->tx_length = 0;
        if (reason == GUEST_CHAN_END_REVOKED) s->retired[token.index / 2] = true;
    }
    zcl_mutex_unlock(&s->lock);
}
static size_t sgs_sink(void *context, unsigned index, const uint8_t *bytes, size_t length)
{
    struct mesh_guest_service *s = context;
    if (index >= 4) return 0;
    zcl_mutex_lock(&s->lock);
    struct sgs_port *p = &s->ports[index];
    size_t n = p->live && !s->stopping ? SGS_QUEUE - p->tx_length : 0;
    if (n > length) n = length;
    if (n) { memcpy(p->tx + p->tx_length, bytes, n); p->tx_length += n; }
    zcl_mutex_unlock(&s->lock);
    return n;
}
static const struct guest_chan_device_ops sgs_ops = {
    .accept = sgs_legacy_accept, .write = sgs_write, .resume = sgs_resume, .end = sgs_end
};
static void sgs_public_console(void *context, uint8_t byte)
{
    struct mesh_guest_service *s = context;
    if (s->public_device && s->public_instance)
        s->public_owner->receiver_console(s->public_owner->owner_context,
            s->public_device, s->public_instance, &byte, 1);
}
static enum rvmachine_status sgs_create(struct mesh_guest_service **out,
    const struct mesh_guest_service_config *config, bool *disk_consumed,
    const struct mesh_guest_unlock_admission *bootstrap)
{
    if (out) *out = NULL;
    if (disk_consumed) *disk_consumed = false;
    if (!out || !config || config->machine.conport_count ||
        config->machine.private_keyfile_port_plus_one) {
        (void)sgs_fail("invalid factory configuration");
        return RVMACHINE_ERR_ARG;
    }
    struct mesh_guest_service *s = zcl_calloc(1, sizeof(*s), "mesh guest service");
    if (!s) { (void)sgs_fail("allocation failed"); return RVMACHINE_ERR_NOMEM; }
    zcl_mutex_init(&s->lock);
    s->binding = config->binding;
    s->binding_context = config->binding_context;
    struct rvmachine_config machine = config->machine;
    machine.conport_count = 4;
    const char *names[] = { "z23.l0.t", "z23.l0.p", "z23.l1.t", "z23.l1.p" };
    for (size_t i = 0; i < 4; i++) machine.conport_names[i] = names[i];
    if (bootstrap) {
        s->public_owner = bootstrap;
        machine.conport_count = 5;
        machine.conport_names[4] = bootstrap->policy == MESH_GUEST_UNLOCK_PROTECTED_HOST ?
            "z23.protected.bootstrap.v1" : "z23.bootstrap.keyfile";
        machine.private_keyfile_port_plus_one = 5;
        machine.console = sgs_public_console;
        machine.console_ctx = s;
    }
    machine.conport_sink = sgs_sink;
    machine.conport_ctx = s;
    enum rvmachine_status status = guest_service_runner_create(&s->runner,
        &machine, config->kernel, config->kernel_length, &config->limits, disk_consumed);
    if (status != RVMACHINE_OK) { zcl_mutex_destroy(&s->lock); free(s); return status; }
    if (bootstrap) s->public_device = guest_service_runner_device(s->runner);
    *out = s;
    return RVMACHINE_OK;
}
enum rvmachine_status mesh_guest_service_create(struct mesh_guest_service **out,
    const struct mesh_guest_service_config *config, bool *disk_consumed)
{
    return sgs_create(out, config, disk_consumed, NULL);
}
bool mesh_guest_service_attach(struct mesh_guest_service *s)
{
    if (!s || !s->binding || s->attached || s->stopping)
        return sgs_fail("attachment requires an actual binding handler and idle instance");
    if (!mesh_guest_chan_attach_peer_v2(&sgs_ops, sgs_accept, s, NULL,
        &s->host_ops, &s->host)) return false;
    s->attached = true;
    return true;
}
bool mesh_guest_service_enable(struct mesh_guest_service *s, bool on)
{
    if (!s || !s->attached || (on && s->stopping))
        return sgs_fail("activation before attachment or after stop");
    return mesh_guest_chan_set_enabled(on);
}
/* Called under the device lock, after the owning machine run has returned. */
static size_t sgs_pump_input(struct sgs_port *p, struct rvmachine *machine,
    unsigned index, uint8_t *bytes, size_t n, bool ending, bool resume,
    bool *live, bool *epoch_lost)
{
    (void)rvmachine_conport_input(machine, index, NULL, 0);
    uint32_t epoch = rvmachine_conport_generation(machine, index);
    *epoch_lost = *live && epoch != p->machine_generation;
    if (*epoch_lost) {
        p->live = false;
        p->rx_length = p->tx_length = 0;
        ending = true;
        n = 0;
        *live = false;
    }
    if (ending) {
        (void)rvmachine_conport_close(machine, index);
        (void)rvmachine_conport_discard(machine, index);
        (void)rvmachine_conport_consumed(machine, index);
    }
    size_t taken = *live && n ? rvmachine_conport_input(machine, index, bytes, n) : 0;
    if (*live && resume) rvmachine_conport_resume(machine, index);
    return taken;
}
static void sgs_pump_sent(struct mesh_guest_service *s, struct sgs_port *p,
    struct rvmachine *machine, unsigned index, struct guest_chan_port token,
    size_t n, size_t sent)
{
    zcl_mutex_lock(&s->lock);
    bool same = p->live && p->token.generation == token.generation;
    if (same && sent <= n && sent) {
        memmove(p->tx, p->tx + sent, p->tx_length - sent);
        p->tx_length -= sent;
        rvmachine_conport_resume(machine, index);
    }
    zcl_mutex_unlock(&s->lock);
}
static size_t sgs_copy_chunk(uint8_t bytes[SGS_CHUNK], const uint8_t *queue, size_t n)
{
    if (n > SGS_CHUNK) n = SGS_CHUNK;
    if (n) memcpy(bytes, queue, n);
    return n;
}
static void sgs_pump_port(struct mesh_guest_service *s, struct rvmachine *machine,
    unsigned index)
{
    uint8_t bytes[SGS_CHUNK];
    zcl_mutex_lock(&s->lock);
    struct sgs_port *p = &s->ports[index];
    struct guest_chan_port token = p->token;
    bool ending = p->ending, resume = p->resume, live = p->live;
    p->ending = p->resume = false;
    size_t n = sgs_copy_chunk(bytes, p->rx, live ? p->rx_length : 0);
    /* These bounded queue APIs do not invoke the sink. The owning drive has
     * returned from run, so holding the device lock serializes end/admission
     * with machine queue changes without a machine-to-device lock cycle. */
    bool epoch_lost;
    size_t taken = sgs_pump_input(p, machine, index, bytes, n, ending, resume,
        &live, &epoch_lost);
    size_t total_consumed = rvmachine_conport_consumed(machine, index);
    size_t consumed = live && total_consumed >= p->consumed_seen
        ? total_consumed - p->consumed_seen : 0;
    p->consumed_seen = total_consumed;
    p->machine_generation = rvmachine_conport_generation(machine, index);
    bool guest_open = rvmachine_conport_guest_open(machine, index);
    p->guest_open = guest_open;
    bool same = p->live && p->token.generation == token.generation;
    if (same && taken) {
        memmove(p->rx, p->rx + taken, p->rx_length - taken);
        p->rx_length -= taken;
    }
    n = sgs_copy_chunk(bytes, p->tx, same ? p->tx_length : 0);
    zcl_mutex_unlock(&s->lock);
    if (epoch_lost && s->attached) s->host_ops->closed(s->host, token);
    if (!s->attached || !same) return;
    if (consumed) s->host_ops->drained(s->host, token, consumed);
    if (taken) s->host_ops->writable(s->host, token);
    size_t sent = n ? s->host_ops->from_guest(s->host, token, bytes, n) : 0;
    sgs_pump_sent(s, p, machine, index, token, n, sent);
}
void mesh_guest_service_pump(struct mesh_guest_service *s, int64_t now)
{
    if (!s) { (void)sgs_fail("null pump"); return; }
    struct rvmachine *machine = guest_service_runner_device(s->runner);
    if (!machine) { (void)sgs_fail("pump before run returned"); return; }
    for (unsigned i = 0; i < 4; i++) sgs_pump_port(s, machine, i);
    if (s->attached) mesh_guest_chan_pump(now);
}
enum rvmachine_status mesh_guest_service_slice(struct mesh_guest_service *s,
    uint64_t now, uint64_t previous_us, bool startup,
    struct guest_gov_decision *decision, struct rvmachine_result *result)
{
    if (!s) { (void)sgs_fail("null slice"); return RVMACHINE_ERR_ARG; }
    return guest_service_runner_slice(s->runner, now, previous_us, startup, decision, result);
}
bool mesh_guest_service_stop(struct mesh_guest_service *s)
{
    if (!s) return true;
    struct guest_service_runner_snapshot snapshot;
    if (!guest_service_runner_snapshot(s->runner, &snapshot) || snapshot.in_slice)
        return sgs_fail("stop requires owning drive after run return");
    zcl_mutex_lock(&s->lock);
    s->stopping = true;
    zcl_mutex_unlock(&s->lock);
    guest_service_runner_request_stop(s->runner);
    if (s->attached) {
        if (!mesh_guest_chan_set_enabled(false)) return false;
        mesh_guest_service_pump(s, 0);
        mesh_guest_chan_detach();
        s->attached = false;
        s->host_ops = NULL;
        s->host = NULL;
    }
    return true;
}
bool mesh_guest_service_destroy(struct mesh_guest_service *s)
{
    if (!s) return true;
    if (!mesh_guest_service_stop(s) || !guest_service_runner_destroy(s->runner)) return false;
    zcl_mutex_destroy(&s->lock);
    free(s);
    return true;
}
bool mesh_guest_service_snapshot(const struct mesh_guest_service *s,
    struct guest_service_runner_snapshot *out)
{
    if (!s) return sgs_fail("null snapshot");
    return guest_service_runner_snapshot(s->runner, out);
}
#ifdef ZCL_TESTING
struct rvmachine *mesh_guest_service_test_machine(struct mesh_guest_service *s)
{
    return s ? guest_service_runner_device(s->runner) : NULL;
}
#endif

struct mesh_guest_service_manager {
    struct mesh_guest_enrollment_record enrollment;
    struct platform_positioned_file_snapshot credential;
    struct platform_private_file owned_record;
    struct platform_private_file owned_extension;
    struct mesh_guest_protected_enrollment_operation protected_operation;
    struct mesh_guest_protected_tuple protected_tuple;
    bool protected_attempted;
    uint64_t protected_generation;
    uint64_t protected_last_grant_ms;
    struct zcl_machine_private_volume volume;
    bool enrollment_failed, enrollment_verified, initial_attempted;
    bool unlock_attempted, unlock_delivered;
    struct guest_service lifecycle;
    struct mesh_guest_service_launch_config config;
    struct mesh_guest_service *instance;
    bool driving;
    uint64_t instance_id;
    uint64_t pending_us;
    bool pending_measured;
    bool seen_bound[2], seen_retired[2], seen_ports[4];
};
static _Atomic uint64_t sgm_generation;
static uint64_t sgm_next_generation(void)
{
    uint64_t current = atomic_load(&sgm_generation);
    while (current < UINT64_MAX) {
        if (atomic_compare_exchange_weak(&sgm_generation, &current, current + 1))
            return current + 1;
    }
    return 0;
}
static enum rvmachine_status sgm_measured_slice(struct mesh_guest_service_manager *m,
    uint64_t now, bool startup, struct guest_gov_decision *decision,
    struct rvmachine_result *result)
{
    struct guest_service_runner_snapshot before, after;
    if (!mesh_guest_service_snapshot(m->instance, &before) ||
        (before.accounting_pending && !m->pending_measured)) {
        (void)sgs_fail("pending invocation has no valid clock measurement");
        return RVMACHINE_ERR_STATE;
    }
    int64_t started = platform_time_monotonic_us();
    if (started < 0) { (void)sgs_fail("monotonic clock refused"); return RVMACHINE_ERR_STATE; }
    enum rvmachine_status status = mesh_guest_service_slice(m->instance, now,
        before.accounting_pending ? m->pending_us : 0, startup, decision, result);
    int64_t ended = platform_time_monotonic_us();
    if (!mesh_guest_service_snapshot(m->instance, &after)) return RVMACHINE_ERR_STATE;
    if (!after.accounting_pending) { m->pending_us = 0; m->pending_measured = false; }
    else if (after.slices != before.slices) {
        m->pending_measured = ended >= started;
        if (!m->pending_measured) {
            (void)sgs_fail("invocation clock reversed; retaining pending resources");
            return RVMACHINE_ERR_STATE;
        }
        m->pending_us = ended == started ? 1 : (uint64_t)(ended - started);
    }
    return status;
}
static bool sgm_apply(struct mesh_guest_service_manager *, struct guest_action *, uint64_t);
/* The second PUBLIC fixture has its own complete fixed enrollment tuple. */
static bool sgm_public_label(const uint8_t actual[32], const char *label)
{
    uint8_t expected[32]; struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, (const uint8_t *)label, strlen(label));
    sha256_finalize(&hash, expected);
    return memcmp(actual, expected, 32) == 0;
}
static bool sgm_public_hash(const uint8_t actual[32], const char *hex)
{
    uint8_t expected[32];
    return zcl_hex_decode_lower(hex, expected, 32) && !memcmp(actual, expected, 32);
}
static bool sgm_unlock_v2_tuple(const struct mesh_guest_service_launch_config *config)
{
    const struct mesh_guest_enrollment_record *r=&config->enrollment.expected;
    return config->service.kernel_length == UINT64_C(43407928) &&
        config->disk_bytes == (UINT64_C(16) << 20) && r->volume_bytes == config->disk_bytes &&
        r->generation != 0 &&
        sgm_public_hash(r->root,"66298db371101e5085cd88abfaf4b5835208ae75b441d4fdd3a325fa72741ae9") &&
        sgm_public_hash(r->helper,"274880bbfd8a46a278d78c5e765a76c4299d107ced67f583e676993b826c8e5f") &&
        sgm_public_label(r->guest_id,"z23.PUBLIC.geli.owner.guest.v2") &&
        sgm_public_label(r->profile,"z23.PUBLIC.geli.owner.profile.v2") &&
        sgm_public_label(r->owner_grant,"local.operator.PUBLIC.geli.keyfile.v2");
}

static bool sgm_unlock_v3_tuple(const struct mesh_guest_service_launch_config *config)
{
    const struct mesh_guest_enrollment_record *r=&config->enrollment.expected;
    return config->service.kernel_length == UINT64_C(43407928) &&
        config->disk_bytes == (UINT64_C(16) << 20) && r->volume_bytes == config->disk_bytes &&
        r->generation != 0 &&
        sgm_public_hash(r->root,"ae126a37ac11db4203992f905c5a4a14ceb2668bb67fd3b861f704cdcde0e7a8") &&
        sgm_public_hash(r->helper,"716e739adbd37ca284765790267cc1e973f82686359a6cbe7993d060ac91e9f4") &&
        sgm_public_label(r->guest_id,"z23.PUBLIC.geli.owner.guest.v3") &&
        sgm_public_label(r->profile,"z23.PUBLIC.geli.owner.profile.v3") &&
        sgm_public_label(r->owner_grant,"local.operator.PUBLIC.geli.keyfile.v3");
}

static bool sgm_unlock_derived_tuple(const struct mesh_guest_service_launch_config *config,
    unsigned revision)
{
    static const struct {
        uint64_t bytes;
        const char *guest, *profile, *grant;
    } rows[] = {
        {UINT64_C(43408024), "z23.PUBLIC.geli.owner.guest.v4",
         "z23.PUBLIC.geli.owner.profile.v4", "local.operator.PUBLIC.geli.keyfile.v4"},
        {UINT64_C(43406744), "z23.PUBLIC.geli.owner.guest.v5",
         "z23.PUBLIC.geli.owner.profile.v5", "local.operator.PUBLIC.geli.keyfile.v5"},
        {UINT64_C(43412608), "z23.PUBLIC.geli.owner.guest.v6",
         "z23.PUBLIC.geli.owner.profile.v6", "local.operator.PUBLIC.geli.keyfile.v6"},
        {UINT64_C(43412608), "z23.PUBLIC.geli.owner.guest.v7",
         "z23.PUBLIC.geli.owner.profile.v7", "local.operator.PUBLIC.geli.keyfile.v7"}
    };
    if (revision < 4 || revision > 7) return false;
    size_t index = revision - 4;
    const struct mesh_guest_enrollment_record *r=&config->enrollment.expected;
    const char *root = revision == 7 ?
        "9541a135ed646af120c182fb19b7586a8f3ead63b1edd1cc880d8f584c674cac" :
        "ae126a37ac11db4203992f905c5a4a14ceb2668bb67fd3b861f704cdcde0e7a8";
    return config->service.kernel_length == rows[index].bytes &&
        config->disk_bytes == (UINT64_C(16) << 20) && r->volume_bytes == config->disk_bytes &&
        r->generation != 0 &&
        sgm_public_hash(r->root,root) &&
        sgm_public_hash(r->helper,"716e739adbd37ca284765790267cc1e973f82686359a6cbe7993d060ac91e9f4") &&
        sgm_public_label(r->guest_id,rows[index].guest) &&
        sgm_public_label(r->profile,rows[index].profile) &&
        sgm_public_label(r->owner_grant,rows[index].grant);
}

static bool sgm_unlock_combined_image(const struct mesh_guest_service_launch_config *config,
    uint8_t selected[32])
{
    static const char *const kernels[] = {
        "82d6598d9669339eb9890d9c8b5152597beac22cbfc5c86200a23f1dc2cd3562",
        "f7e7379fb08fd0035cf67bd98d5896376e103ab80851363d2c1f1a16a53e675d"
    };
    for (unsigned i = 0; i < 2; ++i) {
        if (!zcl_hex_decode_lower(kernels[i], selected, 32)) return false;
        if (!memcmp(config->unlock.authorized_kernel, selected, 32))
            return sgm_unlock_derived_tuple(config, i + 6);
    }
    return false;
}

static const uint8_t *sgm_unlock_image(const struct mesh_guest_service_launch_config *config,
    const uint8_t legacy[32], uint8_t selected[32])
{
    if (!memcmp(config->unlock.authorized_kernel, legacy, 32)) return legacy;
    if (!zcl_hex_decode_lower("db2440c0ce534decbac8aac94fade789c8978e5d145f1795fa216603a7404af5", selected, 32)) return NULL;
    if (!memcmp(config->unlock.authorized_kernel, selected, 32))
        return sgm_unlock_v2_tuple(config) ? selected : NULL;
    if (!zcl_hex_decode_lower("fca910590d9b3171712883285fb30743b30f7715a4b8fb41c17a51bfdcca6a6e", selected, 32)) return NULL;
    if (!memcmp(config->unlock.authorized_kernel, selected, 32))
        return sgm_unlock_derived_tuple(config,4) ? selected : NULL;
    if (!zcl_hex_decode_lower("c7df418c75c63125a6ea77edba7b654486c5912bc1fd60c53fcc39778dbb1bf7", selected, 32)) return NULL;
    if (!memcmp(config->unlock.authorized_kernel, selected, 32))
        return sgm_unlock_derived_tuple(config,5) ? selected : NULL;
    if (sgm_unlock_combined_image(config, selected)) return selected;
    if (!zcl_hex_decode_lower("ac1dd2f5260aa64d2ba9cf30c13927709ff7f427709571dd65521051cf44b57c", selected, 32) ||
        memcmp(config->unlock.authorized_kernel, selected, 32) || !sgm_unlock_v3_tuple(config)) return NULL;
    return selected;
}
static bool sgm_unlock_admit(const struct mesh_guest_service_launch_config *);
static bool sgm_protected_reserve_before_factory(struct mesh_guest_service_manager *, uint64_t);
static bool sgm_protected_grant_current(struct mesh_guest_service_manager *);
static bool sgm_protected_ready_after_identity(struct mesh_guest_service_manager *, const uint8_t[32], uint64_t);
static bool sgm_step(struct mesh_guest_service_manager *m, struct guest_event event,
    uint64_t now, struct guest_action *action)
{
    return guest_service_step(&m->lifecycle, &event, now, action) && sgm_apply(m, action, now);
}
static bool sgm_release(struct mesh_guest_service_manager *m, uint64_t now)
{
    if (!m->instance) return sgs_fail("stop action without an actual instance");
    struct guest_service_runner_snapshot actual;
    if (!mesh_guest_service_snapshot(m->instance, &actual) || actual.in_slice)
        return sgs_fail("release before the owning drive returned");
    if (!mesh_guest_service_stop(m->instance)) return false;
    if (!actual.slices) return sgs_fail("never-run instance requires start-refusal cleanup");
    if (actual.accounting_pending) {
        struct guest_gov_decision decision;
        struct rvmachine_result result;
        (void)sgm_measured_slice(m, now, false, &decision, &result);
        if (!mesh_guest_service_snapshot(m->instance, &actual) || actual.accounting_pending)
            return sgs_fail("final invocation charge remains pending");
    }
    if (!mesh_guest_service_destroy(m->instance)) return false;
    m->instance = NULL;
    struct guest_action joined;
    return guest_service_step(&m->lifecycle,
        &(struct guest_event){ .kind = GUEST_EV_GUEST_STOPPED }, now, &joined);
}
static enum rvmachine_status sgm_open_disk(struct mesh_guest_service_manager *m,
    struct mesh_guest_service_config *config)
{
    if (!m->config.disk_bytes) return RVMACHINE_OK;
    if (m->config.enrollment.mode != MESH_GUEST_ENROLLMENT_OFF) {
        if (m->enrollment_failed || m->volume.failed) return RVMACHINE_ERR_STATE;
        return zcl_machine_private_volume_bind(&m->volume,
            m->config.enrollment.volume, &config->machine.disk)
            ? RVMACHINE_OK : RVMACHINE_ERR_DISK;
    }
    if (m->config.disk_mode == MESH_GUEST_DISK_RETAINED_BACKEND)
        return rvmachine_disk_open_backend(&config->machine.disk, m->config.disk_bytes,
            m->config.disk_read, m->config.disk_write, m->config.disk_flush,
            m->config.disk_context);
    return rvmachine_disk_open(&config->machine.disk, m->config.disk_bytes,
        m->config.disk_read, m->config.disk_context);
}
static bool sgm_result_continues(const struct rvmachine_result *result)
{
    return result->stop == RVMACHINE_STOP_BUDGET || result->stop == RVMACHINE_STOP_WAIT ||
        result->stop == RVMACHINE_STOP_IDLE;
}
static bool sgm_enrollment_current(struct mesh_guest_service_manager *);
static bool sgm_enrollment_fail(struct mesh_guest_service_manager *);
static bool sgm_enrollment_start(struct mesh_guest_service_manager *m)
{
    if (m->config.enrollment.mode == MESH_GUEST_ENROLLMENT_OFF) return true;
    if (!sgm_enrollment_current(m)) return false;
    if (m->config.enrollment.mode == MESH_GUEST_ENROLLMENT_INITIAL &&
        m->initial_attempted && !m->owned_record.locked)
        return sgm_enrollment_fail(m);
    return !m->enrollment_failed;
}
static enum rvmachine_status sgm_factory(struct mesh_guest_service_manager *m,
    struct mesh_guest_service_config *config)
{
    enum rvmachine_status status = sgm_open_disk(m, config);
    if (status != RVMACHINE_OK) return status;
    if (m->config.enrollment.mode == MESH_GUEST_ENROLLMENT_INITIAL)
        m->initial_attempted = true;
    bool consumed = false;
    status = m->config.unlock.policy != MESH_GUEST_UNLOCK_OFF ?
        sgs_create(&m->instance, config, &consumed, &m->config.unlock) :
        mesh_guest_service_create(&m->instance, config, &consumed);
    if (!consumed && config->machine.disk) rvmachine_disk_close(config->machine.disk);
    return status;
}
static bool sgm_public_initial_epoch(struct mesh_guest_service_manager *m, uint64_t now)
{
    if (m->config.unlock.policy == MESH_GUEST_UNLOCK_OFF) return true;
    m->instance->public_instance = m->instance_id;
    /* Kernel load opens every configured port; never reopen the receiver. */
    struct rvmachine *device = m->instance->public_device;
    if (!device || !device->con.ports[4].host_open ||
        !rvmachine_conport_generation(device, 4) ||
        device->conports[4].seen_generation != device->con.ports[4].generation) {
        if (m->config.unlock.policy == MESH_GUEST_UNLOCK_PROTECTED_HOST) {
            /* No measured slice exists yet: release cannot settle it. */
            if (!mesh_guest_service_destroy(m->instance))
                return sgs_fail("protected never-run receiver destroy refused");
            m->instance=NULL;
        } else (void)sgm_release(m, now);
        return sgs_fail("PUBLIC receiver host-open refused before first slice");
    }
    return true;
}
static bool sgm_start_admission(struct mesh_guest_service_manager *m)
{
    if (m->config.unlock.policy != MESH_GUEST_UNLOCK_OFF && !sgm_unlock_admit(&m->config)) {
        (void)sgm_enrollment_fail(m);
        return false;
    }
    if (m->config.unlock.policy == MESH_GUEST_UNLOCK_PUBLIC_KEYFILE_FIXTURE && m->unlock_attempted)
        return false;
    return sgm_enrollment_start(m);
}
static bool sgm_start_first_slice(struct mesh_guest_service_manager *m,uint64_t now,
    struct guest_action *action)
{
    memset(m->seen_bound, 0, sizeof(m->seen_bound));
    memset(m->seen_retired, 0, sizeof(m->seen_retired));
    memset(m->seen_ports, 0, sizeof(m->seen_ports));
    /* Start is explicit execution admission. The initial governed run makes
     * the later stopped event refer to a real returned run, not a stub. */
    struct guest_gov_decision decision;
    struct rvmachine_result result;
    if (m->config.unlock.policy == MESH_GUEST_UNLOCK_PROTECTED_HOST &&
        !sgm_protected_grant_current(m)) {
        if (!mesh_guest_service_destroy(m->instance))
            return sgm_step(m,(struct guest_event){.kind=GUEST_EV_BOOT_FAILED,
                .reason=GUEST_REASON_BOOT_FAILED},now,action);
        m->instance=NULL;
        goto refused;
    }
    enum rvmachine_status status=sgm_measured_slice(m, now, true, &decision, &result);
    struct guest_service_runner_snapshot actual;
    if (!mesh_guest_service_snapshot(m->instance, &actual)) return false;
    if (!actual.slices) {
        if (!mesh_guest_service_destroy(m->instance)) {
            struct guest_action failed = {0};
            (void)sgm_step(m, (struct guest_event){ .kind = GUEST_EV_BOOT_FAILED,
                .reason = GUEST_REASON_BOOT_FAILED }, now, &failed);
            *action = failed;
            return false;
        }
        m->instance = NULL;
        goto refused;
    }
    if (status == RVMACHINE_OK && decision.kind == GUEST_GOV_RUN_SLICE &&
        sgm_result_continues(&result) && mesh_guest_service_attach(m->instance))
        return true;
    return sgm_step(m, (struct guest_event){ .kind = GUEST_EV_BOOT_FAILED,
        .reason = GUEST_REASON_BOOT_FAILED }, now, action);
refused:
    /* No run was invoked and actual factory allocations are released. */
    return sgm_step(m, (struct guest_event){ .kind = GUEST_EV_START_REFUSED,
        .reason = GUEST_REASON_BOOT_FAILED }, now, action);
}
static bool sgm_start(struct mesh_guest_service_manager *m,uint64_t now,
    struct guest_action *action)
{
    if(m->instance)return sgs_fail("start while an instance is retained");
    if(!sgm_start_admission(m))
        return sgm_step(m,(struct guest_event){.kind=GUEST_EV_START_REFUSED,
            .reason=GUEST_REASON_INJECT_FAILED},now,action);
    m->enrollment_verified=false;
    struct mesh_guest_service_config config=m->config.service;
    uint64_t instance_id=sgm_next_generation();
    if(!config.binding||!instance_id)goto refused;
    if(m->config.unlock.policy==MESH_GUEST_UNLOCK_PROTECTED_HOST&&
        !sgm_protected_reserve_before_factory(m,now))goto refused;
    if(sgm_factory(m,&config)!=RVMACHINE_OK)goto refused;
    m->instance_id=instance_id;
    if(!sgm_public_initial_epoch(m,now)){
        if(m->config.unlock.policy!=MESH_GUEST_UNLOCK_PROTECTED_HOST)return false;
        if(!m->instance)goto refused;
        return sgm_step(m,(struct guest_event){.kind=GUEST_EV_BOOT_FAILED,
            .reason=GUEST_REASON_BOOT_FAILED},now,action);
    }
    return sgm_start_first_slice(m,now,action);
refused:
    return sgm_step(m,(struct guest_event){.kind=GUEST_EV_START_REFUSED,
        .reason=GUEST_REASON_BOOT_FAILED},now,action);
}
static bool sgm_apply(struct mesh_guest_service_manager *m,
    struct guest_action *action, uint64_t now)
{
    if (action->kind == GUEST_ACTION_START_GUEST) return sgm_start(m, now, action);
    if (action->kind == GUEST_ACTION_STOP_GUEST) return sgm_release(m, now);
    return true;
}
static bool sgm_secret_policy_ok(const struct mesh_guest_service_launch_config *c)
{
    return c->policy != MESH_GUEST_LAUNCH_SECRET_REQUIRED ||
        (c->service.machine.entropy_fail_closed && c->service.machine.cleanse_on_destroy &&
         c->service.machine.entropy && c->service.machine.boot_seed && c->service.binding);
}
static bool sgm_enrolled_disk_policy(const struct mesh_guest_service_launch_config *c)
{
    return c->disk_mode == MESH_GUEST_DISK_RETAINED_BACKEND &&
        c->policy == MESH_GUEST_LAUNCH_SECRET_REQUIRED && c->disk_bytes &&
        c->disk_bytes == c->enrollment.expected.volume_bytes &&
        !c->disk_read && !c->disk_write && !c->disk_flush && !c->disk_context;
}
static bool sgm_public_disk_policy(const struct mesh_guest_service_launch_config *c)
{
    switch (c->disk_mode) {
    case MESH_GUEST_DISK_NONE:
        return !c->disk_bytes && !c->disk_read && !c->disk_write && !c->disk_flush &&
            !c->disk_context;
    case MESH_GUEST_DISK_EPHEMERAL_OVERLAY:
        return c->disk_bytes && c->disk_read && !c->disk_write && !c->disk_flush;
    case MESH_GUEST_DISK_RETAINED_BACKEND:
        return c->policy == MESH_GUEST_LAUNCH_SECRET_REQUIRED && c->disk_bytes &&
            c->disk_read && c->disk_write && c->disk_flush;
    default:
        return false;
    }
}
static bool sgm_disk_policy_ok(const struct mesh_guest_service_launch_config *c)
{
    if (c->enrollment.mode != MESH_GUEST_ENROLLMENT_OFF)
        return sgm_enrolled_disk_policy(c);
    return sgm_public_disk_policy(c);
}
static bool sgm_launch_policy_ok(const struct mesh_guest_service_launch_config *c)
{
    if (c->policy != MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE &&
        c->policy != MESH_GUEST_LAUNCH_SECRET_REQUIRED) return false;
    if (!sgm_secret_policy_ok(c)) return false;
    return sgm_disk_policy_ok(c);
}
static bool sgm_unlock_local(const struct mesh_guest_unlock_admission *admission,
    const uint8_t allowed[32])
{
    return admission->policy == MESH_GUEST_UNLOCK_PUBLIC_KEYFILE_FIXTURE &&
        admission->purpose == MESH_GUEST_UNLOCK_PUBLIC_GELI_KEYFILE &&
        admission->receiver_revision == 1 && admission->accepted_current &&
        admission->public_keyfile_current && admission->receiver_current &&
        admission->receiver_console && admission->owner_context &&
        memcmp(admission->authorized_kernel, allowed, 32) == 0;
}
static bool sgm_unlock_config(const struct mesh_guest_service_launch_config *config)
{
    return config->policy == MESH_GUEST_LAUNCH_SECRET_REQUIRED &&
        config->disk_mode == MESH_GUEST_DISK_RETAINED_BACKEND &&
        config->enrollment.mode != MESH_GUEST_ENROLLMENT_OFF &&
        config->service.machine.entropy && config->service.machine.entropy_fail_closed &&
        config->service.machine.boot_seed && config->service.machine.cleanse_on_destroy &&
        !config->service.machine.conport_count && !config->service.machine.private_keyfile_port_plus_one;
}
static bool sgm_protected_callbacks(const struct mesh_guest_service_launch_config *c)
{
    const struct mesh_guest_secret_provider *p=&c->protected_provider;
    return c->unlock.purpose==MESH_GUEST_UNLOCK_PROTECTED_GELI_KEYFILE &&
        c->unlock.receiver_revision==1 && c->unlock.accepted_current &&
        c->unlock.receiver_current && c->unlock.receiver_console && c->unlock.owner_context &&
        p->context && p->credential==c->enrollment.credential && p->current &&
        p->begin && p->read_key && p->commit_current && p->end && c->protected_invalidate;
}
static bool sgm_protected_image(const struct mesh_guest_service_launch_config *c)
{
    uint8_t expected[32],actual[32];
    if(c->service.kernel_length!=UINT64_C(43412608) ||
        !zcl_hex_decode_lower("a5080bb076351c5b5e058a81e5bf6ad3a0f748e97423d2214af5602a5f90097c",expected,32))return false;
    struct sha256_ctx h;sha256_init(&h);sha256_write(&h,c->service.kernel,c->service.kernel_length);sha256_finalize(&h,actual);
    return !memcmp(actual,expected,32) && !memcmp(c->unlock.authorized_kernel,expected,32) &&
        !memcmp(c->enrollment.expected.kernel,expected,32) &&
        c->unlock.accepted_current(c->unlock.owner_context,expected);
}
static bool sgm_protected_tuple(const struct mesh_guest_service_launch_config *c)
{
    const struct mesh_guest_enrollment_record *r=&c->enrollment.expected;
    return c->disk_bytes==(UINT64_C(16)<<20) && r->volume_bytes==c->disk_bytes && r->generation &&
        sgm_public_hash(r->root,"f4201650db84c2c831e53b1914316c9cd738f8a61ee1b6f6b52bddb4688fd7f3") &&
        sgm_public_hash(r->helper,"194bd9c2977dcab3c340472d10f8291c266bdc6fff463d0223f130886c396c4e") &&
        sgm_public_label(r->guest_id,"z23.PROTECTED.geli.owner.guest.v1") &&
        sgm_public_label(r->profile,"z23.PROTECTED.geli.owner.profile.v1") &&
        sgm_public_label(r->owner_grant,"local.operator.PROTECTED.geli.keyfile.v1");
}
static bool sgm_protected_admit(const struct mesh_guest_service_launch_config *c)
{
    const struct mesh_guest_protected_enrollment_owner *o=&c->protected_enrollment;
    if(!sgm_unlock_config(c) || !sgm_protected_callbacks(c) || !sgm_protected_tuple(c) ||
        !o->extension_path || !o->fresh_stage_path || !o->fresh_ready_stage_path ||
        !o->grant_current || !o->context || !c->protected_admitted_ms ||
        c->protected_delivery_deadline_ms<=c->protected_admitted_ms ||
        c->protected_authority_expires_ms<c->protected_delivery_deadline_ms)
        return sgs_fail("protected image owner/provider configuration refused");
    if(!sgm_protected_image(c))return sgs_fail("protected exact accepted image refused");
    return true;
}
static bool sgm_unlock_admit(const struct mesh_guest_service_launch_config *config)
{
#if defined(SGM_PUBLIC_SOURCE_TWIN)
#if !defined(ZCL_TESTING)
#error "PUBLIC consumer substitution is confined to the registered source twin"
#endif
    const uint8_t *allowed = SGM_PUBLIC_SOURCE_TWIN;
#else
    static const uint8_t allowed[32] = {
        0x24,0x45,0xa0,0xca,0x74,0x7b,0xb2,0x8e,0xac,0x52,0xc8,0xc2,0xbb,0x86,0x1e,0xe9,
        0xbe,0x06,0xf3,0xc7,0x35,0x35,0x87,0xd8,0x8e,0x3c,0x3f,0xcb,0xb8,0x32,0xb2,0xf4
    };
#endif
    const struct mesh_guest_unlock_admission *admission = &config->unlock;
    if (admission->policy == MESH_GUEST_UNLOCK_OFF) return true;
    if (admission->policy == MESH_GUEST_UNLOCK_PROTECTED_HOST)
        return sgm_protected_admit(config);
    uint8_t v2[32];
    const uint8_t *chosen = sgm_unlock_image(config, allowed, v2);
    if (!chosen) return sgs_fail("PUBLIC unlock fixed image or enrollment tuple refused");
    if (!sgm_unlock_local(admission, chosen))
        return sgs_fail("PUBLIC unlock local policy or fixed consumer refused");
    if (!sgm_unlock_config(config))
        return sgs_fail("PUBLIC unlock protected launch configuration refused");
    uint8_t actual[32];
    struct sha256_ctx hash;
    sha256_init(&hash);
    sha256_write(&hash, config->service.kernel, config->service.kernel_length);
    sha256_finalize(&hash, actual);
    if (memcmp(actual, chosen, sizeof(actual)) != 0 ||
        memcmp(config->enrollment.expected.kernel, chosen, sizeof(actual)) != 0 ||
        !admission->accepted_current(admission->owner_context, actual) ||
        !admission->public_keyfile_current(admission->owner_context, config->enrollment.credential))
        return sgs_fail("PUBLIC unlock current consumer or keyfile owner refused");
    return true;
}

bool mesh_guest_service_manager_create(struct mesh_guest_service_manager **out,
    const struct mesh_guest_service_launch_config *config)
{
    if (out) *out = NULL;
    if (!out || !config || !config->service.kernel || !config->service.kernel_length ||
        config->service.machine.disk || !config->service.machine.wait_stops ||
        !guest_limits_ok(&config->service.limits) ||
        rvmachine_config_resources_validate(&config->service.machine) != RVMACHINE_OK ||
        !sgm_launch_policy_ok(config)) return sgs_fail("invalid launch input");
    if (!sgm_unlock_admit(config)) return false;
    struct mesh_guest_enrollment_record enrollment = {0};
    struct platform_positioned_file_snapshot credential = {0};
    if (!mesh_guest_enrollment_admit(&config->enrollment, &enrollment, &credential))
        return sgs_fail("enrollment admission refused before factory");
    struct mesh_guest_service_manager *m = zcl_calloc(1, sizeof(*m), "mesh guest manager");
    if (!m) return sgs_fail("manager allocation failed");
    m->config = *config;
    m->enrollment = enrollment;
    m->credential = credential;
    platform_private_file_init(&m->owned_record);
    platform_private_file_init(&m->owned_extension);
    guest_service_init(&m->lifecycle);
    *out = m;
    return true;
}
bool mesh_guest_service_manager_event(struct mesh_guest_service_manager *m,
    const struct guest_event *event, uint64_t now, struct guest_action *action)
{
    if (!m || !event || !action || m->driving || event->kind == GUEST_EV_GUEST_STOPPED ||
        event->kind == GUEST_EV_PORT_OPENED || event->kind == GUEST_EV_PORT_CLOSED ||
        event->kind == GUEST_EV_SLOT_BOUND || event->kind == GUEST_EV_START_REFUSED ||
        event->kind == GUEST_EV_REVOKED_PEER || event->kind == GUEST_EV_PEER_OPEN ||
        event->kind == GUEST_EV_BOOT_READY)
        return sgs_fail("invalid or fabricated lifecycle event");
    m->driving = true;
    bool ok = sgm_step(m, *event, now, action);
    m->driving = false;
    return ok;
}
uint64_t mesh_guest_service_manager_instance(const struct mesh_guest_service_manager *m)
{
    return m && !m->driving && m->instance ? m->instance_id : 0;
}
static bool sgm_enrollment_fail(struct mesh_guest_service_manager *m)
{
    if(m->config.unlock.policy==MESH_GUEST_UNLOCK_PROTECTED_HOST){
        m->config.protected_invalidate(m->config.protected_provider.context);
        if(m->instance && m->instance->public_device)
            (void)rvmachine_keyfile_deliver(m->instance->public_device,4,
                m->instance->public_device->conports[4].generation,NULL,0);
    }
    m->enrollment_failed = true;
    m->enrollment_verified = false;
    return sgs_fail("owner enrollment failed; reconciliation required");
}
static bool sgm_enrollment_current(struct mesh_guest_service_manager *m)
{
    if (m->volume.failed) return sgm_enrollment_fail(m);
    struct platform_positioned_file_snapshot credential;
    if (m->enrollment_failed ||
        !mesh_guest_enrollment_handles(&m->config.enrollment, &credential) ||
        !platform_positioned_file_snapshot_equal(&credential, &m->credential))
        return sgm_enrollment_fail(m);
    struct platform_private_file *file = m->config.enrollment.record;
    if (m->owned_record.locked) file = &m->owned_record;
    if (file) {
        struct mesh_guest_enrollment_record current;
        if (!mesh_guest_enrollment_read(file, &current) ||
            !mesh_guest_enrollment_equal(&current, &m->enrollment))
            return sgm_enrollment_fail(m);
    }
    return true;
}
bool mesh_guest_service_manager_storage_synced(struct mesh_guest_service_manager *m,
    uint64_t instance_id)
{
    if (!m || m->driving || !m->instance || !instance_id ||
        instance_id != m->instance_id ||
        m->config.enrollment.mode == MESH_GUEST_ENROLLMENT_OFF)
        return sgs_fail("storage barrier without current retained guest owner");
    if (!sgm_enrollment_current(m)) return false;
    if (!m->volume.flush_sequence || m->volume.flush_sequence <= m->volume.write_sequence)
        return sgs_fail("storage barrier does not follow the latest guest write");
    return true;
}
static bool sgm_public_keyfile_read(struct mesh_guest_service_manager *m, uint8_t bytes[32])
{
    struct platform_positioned_file view = {.native = m->config.enrollment.credential->native};
    size_t offset = 0;
    while (offset < 32) {
        int64_t n = platform_positioned_file_read(&view, bytes + offset, 32 - offset, offset);
        if (n <= 0 || (uint64_t)n > 32 - offset) return sgs_fail("PUBLIC keyfile read refused");
        offset += (size_t)n;
    }
    uint8_t extra = 0;
    int64_t extra_n = platform_positioned_file_read(&view, &extra, 1, 32);
    memory_cleanse(&extra, sizeof(extra));
    if (extra_n != 0)
        return sgs_fail("PUBLIC keyfile exact length refused");
    for (size_t i = 0; i < 32; i++)
        if (bytes[i] != (uint8_t)(i + 1)) return sgs_fail("non-PUBLIC material refused");
    return sgm_enrollment_current(m) &&
        m->config.unlock.public_keyfile_current(m->config.unlock.owner_context,
            m->config.enrollment.credential);
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Durable protected generation admission precedes factory creation and any
 * provider key callback; retained records do not replace current owner grant. */
static bool sgm_protected_reserve_before_factory(struct mesh_guest_service_manager *m,
    uint64_t now)
{
    const struct mesh_guest_protected_enrollment_owner *o=&m->config.protected_enrollment;
    if(m->protected_attempted || !o->grant_current || !o->context ||
        !o->grant_current(o->context,&m->enrollment,now))
        return sgs_fail("protected generation grant or repeat refused");
    /* Admission/image/enrollment must already pass; no provider key callback. */
    m->protected_attempted=true;
    m->protected_operation=(struct mesh_guest_protected_enrollment_operation){
        .volume=m->config.enrollment.volume,.expected=m->enrollment};
    bool ok;
    if(m->config.enrollment.mode==MESH_GUEST_ENROLLMENT_INITIAL){
        ok=mesh_guest_protected_enrollment_initial(&m->protected_operation,
            o->extension_path,o->fresh_stage_path,&m->owned_extension);
        if(ok)m->protected_generation=1;
    }else if(m->config.enrollment.mode==MESH_GUEST_ENROLLMENT_RECOVER){
        ok=mesh_guest_protected_enrollment_reserve(&m->protected_operation,
            o->extension_path,o->fresh_stage_path,&m->owned_extension,&m->protected_generation);
    }else ok=false;
    if(!ok)return sgm_enrollment_fail(m);
    return true;
}
/* After existing identity_finish has verified actual instance/generation/mount,
 * published initial identity record, checked fingerprint and enrollment_current.
 * READY failure never reports identity verified or permits retry/init. */
static bool sgm_protected_ready_after_identity(struct mesh_guest_service_manager *m,
    const uint8_t fingerprint[32],uint64_t fresh_now)
{
    (void)fresh_now;
    if(m->config.enrollment.mode==MESH_GUEST_ENROLLMENT_RECOVER)return true;
    const struct mesh_guest_protected_enrollment_owner *o=&m->config.protected_enrollment;
    if(!sgm_protected_grant_current(m))
        return sgm_enrollment_fail(m);
    platform_private_file_close(&m->owned_extension);
    if(!mesh_guest_protected_enrollment_ready(&m->protected_operation,
        o->extension_path,o->fresh_ready_stage_path,fingerprint,&m->owned_extension))
        return sgm_enrollment_fail(m);
    return true;
}
/* Fresh cached grant decision after potentially slow durable publication or
 * factory work. Clock and callback are bounded; no provider/key I/O here. */
static bool sgm_protected_grant_current(struct mesh_guest_service_manager *m)
{
    const struct mesh_guest_protected_enrollment_owner *o=&m->config.protected_enrollment;
    int64_t now=platform_time_monotonic_ms();
    if(now<=0 || (uint64_t)now<m->config.protected_admitted_ms ||
        (uint64_t)now<m->protected_last_grant_ms ||
        (uint64_t)now>=m->config.protected_authority_expires_ms || !o->grant_current || !o->context)
        return false;
    if(!o->grant_current(o->context,&m->enrollment,(uint64_t)now))return false;
    m->protected_last_grant_ms=(uint64_t)now;return true;
}
static bool sgm_unlock_entry(const struct mesh_guest_service_manager *m,
    uint64_t instance_id, uint32_t epoch)
{
    return m && !m->driving && m->instance && instance_id &&
        instance_id == m->instance_id && epoch && m->lifecycle.state == GUEST_STATE_STARTING &&
        m->config.unlock.policy == MESH_GUEST_UNLOCK_PUBLIC_KEYFILE_FIXTURE;
}
static bool sgm_unlock_receiver(struct mesh_guest_service_manager *m,
    struct rvmachine *machine, uint64_t instance_id, uint32_t epoch)
{
    return machine && !machine->entropy_fault && rvmachine_boot_seed_cleared(machine) &&
        rvmachine_conport_generation(machine, 4) == epoch &&
        rvmachine_conport_guest_open(machine, 4) && machine->con.ports[4].host_open &&
        rvmachine_conport_queued(machine, 4) == 0 &&
        m->config.unlock.receiver_current(m->config.unlock.owner_context, machine, instance_id, epoch);
}
bool mesh_guest_service_manager_unlock_public(struct mesh_guest_service_manager *m,
    uint64_t instance_id, uint32_t epoch, uint64_t now)
{
    if (!sgm_unlock_entry(m, instance_id, epoch))
        return sgs_fail("invalid PUBLIC unlock entry");
    struct rvmachine *machine = guest_service_runner_device(m->instance->runner);
    if (!machine || rvmachine_conport_generation(machine, 4) != epoch ||
        machine->conports[4].seen_generation != machine->con.ports[4].generation)
        return sgs_fail("PUBLIC unlock names a stale receiver epoch");
    bool repeated = m->unlock_attempted;
    m->unlock_attempted = true;
    m->driving = true;
    uint8_t bytes[32] = {0};
    bool ok = !repeated && sgm_unlock_admit(&m->config) && sgm_enrollment_current(m) &&
        sgm_unlock_receiver(m, machine, instance_id, epoch) &&
        sgm_public_keyfile_read(m, bytes) && rvmachine_keyfile_deliver(machine, 4, epoch, bytes, sizeof(bytes));
    memory_cleanse(bytes, sizeof(bytes));
    m->driving = false;
    if (ok) { m->unlock_delivered = true; return true; }
    /* Admitted owner failure seals and clears any queued host suffix even
     * when measured stop accounting prevents immediate destruction. */
    if (machine) (void)rvmachine_keyfile_deliver(machine, 4, epoch, NULL, 0);
    (void)sgm_enrollment_fail(m);
    (void)sgm_release(m, now);
    return sgs_fail("PUBLIC unlock refused; no second delivery");
}
static bool sgm_protected_receiver(struct mesh_guest_service_manager *m,
    uint64_t instance,uint32_t host,uint32_t device)
{
    struct rvmachine *v=m->instance->public_device;
    return v && instance==m->instance_id && host && device && !v->entropy_fault &&
        rvmachine_boot_seed_cleared(v) && v->conports[4].private_keyfile &&
        !v->conports[4].private_failed && !v->conports[4].retired && !v->conport_fault &&
        v->conports[4].generation==host && v->con.ports[4].generation==device &&
        v->conports[4].seen_generation==device &&
        (v->con.dev.status&RVVIRTIO_STATUS_DRIVER_OK)!=0 &&
        (v->con.dev.status&(RVVIRTIO_STATUS_FAILED|RVVIRTIO_STATUS_NEEDS_RESET))==0;
}
static bool sgm_protected_receiver_ready(struct mesh_guest_service_manager *m,
    uint64_t instance,uint32_t host,uint32_t device)
{
    struct rvmachine *v=m->instance->public_device;
    return sgm_protected_receiver(m,instance,host,device) &&
        v->con.ports[4].host_open && v->con.ports[4].guest_open &&
        !v->conports[4].private_sealed && v->conports[4].count==0 &&
        !strcmp(v->conport_names[4],"z23.protected.bootstrap.v1") &&
        m->config.unlock.receiver_current(m->config.unlock.owner_context,v,instance,host);
}
static bool sgm_protected_delivered_tuple(struct mesh_guest_service_manager *m,
    uint64_t instance,uint32_t host,uint32_t device,struct mesh_guest_protected_tuple *out)
{
    if(instance!=m->protected_tuple.instance_id||host!=m->protected_tuple.host_epoch||
        device!=m->protected_tuple.device_epoch||!sgm_protected_receiver(m,instance,host,device))
        return sgs_fail("protected retained tuple stale");
    int64_t fresh=platform_time_monotonic_ms();
    if(fresh<=0||m->config.protected_provider.current(m->config.protected_provider.context,
        &m->protected_tuple,(uint64_t)fresh)!=MESH_GUEST_PROVIDER_CURRENT)
        return sgs_fail("protected consumed generation no longer current");
    *out=m->protected_tuple;return true;
}
bool mesh_guest_service_manager_protected_tuple(struct mesh_guest_service_manager *m,
    uint64_t instance,uint32_t host,uint32_t device,struct mesh_guest_protected_tuple *out)
{
    if(out)memset(out,0,sizeof(*out));
    if(!m || !out || m->driving || !m->instance ||
        m->config.unlock.policy!=MESH_GUEST_UNLOCK_PROTECTED_HOST ||
        !sgm_protected_grant_current(m) || !sgm_enrollment_current(m))
        return sgs_fail("protected tuple owner refused");
    if(m->unlock_delivered)return sgm_protected_delivered_tuple(m,instance,host,device,out);
    if(!m->protected_generation || !sgm_protected_receiver_ready(m,instance,host,device))
        return sgs_fail("protected tuple receiver refused");
    *out=(struct mesh_guest_protected_tuple){.enrollment=m->enrollment,.credential=m->credential,
        .instance_id=instance,.provider_generation=m->protected_generation,.host_epoch=host,.device_epoch=device,
        .admitted_ms=m->config.protected_admitted_ms,.delivery_deadline_ms=m->config.protected_delivery_deadline_ms,
        .authority_expires_ms=m->config.protected_authority_expires_ms};
    return true;
}
static bool sgm_protected_current(struct mesh_guest_service_manager *m)
{
    if(!sgm_protected_grant_current(m) || !sgm_enrollment_current(m))return false;
    if(!m->unlock_attempted)return true; /* early slices require metadata grant, no configured key yet */
    if(!m->unlock_delivered || !sgm_protected_receiver(m,m->protected_tuple.instance_id,
        m->protected_tuple.host_epoch,m->protected_tuple.device_epoch))return false;
    int64_t fresh=platform_time_monotonic_ms();
    return fresh>0 && m->config.protected_provider.current(m->config.protected_provider.context,
        &m->protected_tuple,(uint64_t)fresh)==MESH_GUEST_PROVIDER_CURRENT;
}
static bool sgm_protected_commit(struct mesh_guest_service_manager *m,
    const struct mesh_guest_provider_lease *lease,uint8_t bytes[32])
{
    const struct mesh_guest_secret_provider *p=&m->config.protected_provider;
    const struct mesh_guest_protected_tuple *t=&m->protected_tuple;
    if(!sgm_protected_grant_current(m) ||
        !sgm_protected_receiver_ready(m,t->instance_id,t->host_epoch,t->device_epoch))return false;
    int64_t fresh=platform_time_monotonic_ms();
    if(fresh<=0 || p->commit_current(p->context,t,(uint64_t)fresh,lease)!=MESH_GUEST_PROVIDER_CURRENT)return false;
    return rvmachine_keyfile_deliver(m->instance->public_device,4,t->host_epoch,bytes,32);
}
bool mesh_guest_service_manager_unlock_protected(struct mesh_guest_service_manager *m,
    uint64_t instance,uint64_t enrollment_generation,uint32_t host,uint32_t device,
    uint64_t provider_generation,uint64_t now)
{
    struct mesh_guest_protected_tuple t;
    if(!m || m->lifecycle.state!=GUEST_STATE_STARTING || m->unlock_attempted ||
        enrollment_generation!=m->enrollment.generation || provider_generation!=m->protected_generation ||
        !mesh_guest_service_manager_protected_tuple(m,instance,host,device,&t))
        return sgs_fail("protected delivery entry refused");
    m->unlock_attempted=true;m->driving=true;m->protected_tuple=t;
    const struct mesh_guest_secret_provider *p=&m->config.protected_provider;
    struct mesh_guest_provider_lease lease={0};uint8_t bytes[32]={0};
    int64_t fresh=platform_time_monotonic_ms();
    bool leased=fresh>0 && p->begin(p->context,&t,(uint64_t)fresh,&lease)==MESH_GUEST_PROVIDER_CURRENT;
    bool ok=leased && lease.id && lease.generation==provider_generation &&
        p->read_key(p->context,&t,&lease,bytes,sizeof bytes) && sgm_protected_commit(m,&lease,bytes);
    memory_cleanse(bytes,sizeof bytes);
    if(leased)p->end(p->context,&lease,ok);
    m->driving=false;
    if(ok){m->unlock_delivered=true;return true;}
    m->config.protected_invalidate(p->context);
    (void)rvmachine_keyfile_deliver(m->instance->public_device,4,host,NULL,0);
    (void)sgm_enrollment_fail(m);(void)sgm_release(m,now);
    return sgs_fail("protected delivery failed; no retry");
}
static bool sgm_identity_pending(struct mesh_guest_service_manager *m,
    uint64_t instance_id, uint64_t generation, bool mounted)
{
    return m->instance && instance_id && instance_id == m->instance_id &&
        mounted && generation == m->enrollment.generation && sgm_enrollment_current(m);
}
static bool sgm_identity_record(struct mesh_guest_service_manager *m,const uint8_t fingerprint[32])
{
    if(m->config.enrollment.mode==MESH_GUEST_ENROLLMENT_INITIAL&&!m->owned_record.locked){
        memcpy(m->enrollment.ssh_fingerprint,fingerprint,32);
        if(!mesh_guest_enrollment_publish(m->config.enrollment.initial_destination,
            &m->enrollment,&m->owned_record))return sgm_enrollment_fail(m);
    }else if(memcmp(m->enrollment.ssh_fingerprint,fingerprint,32)){
        return sgm_enrollment_fail(m);
    }
    return true;
}
bool mesh_guest_service_manager_identity_finish(struct mesh_guest_service_manager *m,
    uint64_t instance_id, uint64_t generation, const uint8_t fingerprint[32], bool mounted)
{
    if (!m || m->driving || !fingerprint ||
        m->config.enrollment.mode == MESH_GUEST_ENROLLMENT_OFF)
        return sgs_fail("identity finish without admitted owner");
    if (m->lifecycle.state != GUEST_STATE_STARTING || m->enrollment_verified)
        return sgs_fail("identity finish outside pending owner verification");
    if (!sgm_identity_pending(m, instance_id, generation, mounted))
        return sgm_enrollment_fail(m);
    if(m->config.unlock.policy==MESH_GUEST_UNLOCK_PROTECTED_HOST &&
        !sgm_protected_grant_current(m))return sgm_enrollment_fail(m);
    if(!sgm_identity_record(m,fingerprint))return false;
    if (!sgm_enrollment_current(m)) return false;
    if(m->config.unlock.policy==MESH_GUEST_UNLOCK_PROTECTED_HOST){
        int64_t fresh=platform_time_monotonic_ms();
        if(fresh<=0 || !sgm_protected_ready_after_identity(m,fingerprint,(uint64_t)fresh))
            return sgm_enrollment_fail(m);
    }
    m->enrollment_verified = true;
    return true;
}
static bool sgm_ready_state(const struct mesh_guest_service_manager *m,
    uint64_t instance_id, enum guest_state state)
{
    return m->instance && m->instance_id == instance_id && m->lifecycle.state == state;
}
static bool sgm_ready_tick(struct mesh_guest_service_manager *m,
    uint64_t instance_id, uint64_t now, struct guest_action *action)
{
    return sgm_step(m, (struct guest_event){.kind = GUEST_EV_TICK}, now, action) &&
        sgm_ready_state(m, instance_id, GUEST_STATE_STARTING);
}
static bool sgm_ready_owner(struct mesh_guest_service_manager *m)
{
    if (m->config.enrollment.mode != MESH_GUEST_ENROLLMENT_OFF &&
        (!m->enrollment_verified || !sgm_enrollment_current(m)))
        return sgs_fail("readiness before owner enrollment identity verification");
    if (m->config.unlock.policy != MESH_GUEST_UNLOCK_OFF &&
        !m->unlock_delivered)
        return sgs_fail("readiness before admitted PUBLIC keyfile delivery");
    return true;
}
static bool sgm_protected_ready_tick(struct mesh_guest_service_manager *m,
    uint64_t instance_id,uint64_t *now,struct guest_action *action)
{
    int64_t fresh=platform_time_monotonic_ms();
    if(fresh<=0||(uint64_t)fresh<*now||(uint64_t)fresh<m->protected_last_grant_ms)
        return sgs_fail("protected readiness clock missing or moved backwards");
    *now=(uint64_t)fresh;
    return sgm_ready_tick(m,instance_id,*now,action);
}
static bool sgm_ready_resource_current(struct mesh_guest_service_manager *m,
    uint64_t instance_id,uint64_t *now,struct guest_action *action)
{
    if(m->config.unlock.policy!=MESH_GUEST_UNLOCK_PROTECTED_HOST)return true;
    if(sgm_protected_ready_tick(m,instance_id,now,action))return true;
    (void)sgm_enrollment_fail(m);
    if(m->instance)(void)sgm_release(m,*now);
    return false;
}
static bool sgm_ready_authority_current(struct mesh_guest_service_manager *m,
    uint64_t now)
{
    if(m->config.unlock.policy!=MESH_GUEST_UNLOCK_PROTECTED_HOST)return true;
    if(sgm_protected_current(m))return true;
    m->config.protected_invalidate(m->config.protected_provider.context);
    (void)sgm_enrollment_fail(m);
    (void)sgm_release(m,now);
    return sgs_fail("protected readiness authority no longer current");
}
bool mesh_guest_service_manager_ready(struct mesh_guest_service_manager *m,
    uint64_t instance_id, uint64_t now, struct guest_action *action)
{
    if (!m || !action || m->driving || !instance_id ||
        !sgm_ready_state(m, instance_id, GUEST_STATE_STARTING))
        return sgs_fail("readiness for a stale or absent guest instance");
    if (!sgm_ready_owner(m)) return false;
    m->driving = true;
    /* Apply an overdue startup before enabling any guest channel. A handled
     * stop event is not successful readiness. */
    if (!sgm_ready_tick(m, instance_id, now, action)) {
        m->driving = false;
        return sgs_fail("readiness after startup expiry or guest stop");
    }
    if(!sgm_ready_authority_current(m,now)){
        m->driving=false;
        return false;
    }
    /* Currentness may read retained metadata. Reapply the unchanged startup
     * deadline with actual owner time immediately before enabling transport. */
    if(!sgm_ready_resource_current(m,instance_id,&now,action)){
        m->driving=false;
        return sgs_fail("protected readiness after fresh startup deadline refusal");
    }
    bool enabled = mesh_guest_service_enable(m->instance, true);
    bool ok = sgm_step(m, (struct guest_event){ .kind = enabled
        ? GUEST_EV_BOOT_READY : GUEST_EV_BOOT_FAILED,
        .reason = enabled ? GUEST_REASON_NONE : GUEST_REASON_INJECT_FAILED }, now, action);
    m->driving = false;
    if (!ok || !enabled || !sgm_ready_state(m, instance_id, GUEST_STATE_READY))
        return sgs_fail("guest did not enter readiness");
    return true;
}
static bool sgm_reconcile_slots(struct mesh_guest_service_manager *m, uint64_t now,
    const bool bound[2], const bool retired[2])
{
    struct guest_action action;
    for (uint32_t slot = 0; slot < 2 && m->instance; slot++) {
        if (bound[slot] && !m->seen_bound[slot]) {
            if (!sgm_step(m, (struct guest_event){ .kind = GUEST_EV_SLOT_BOUND,
                .slot = slot, .peer = slot + 1 }, now, &action)) return false;
            m->seen_bound[slot] = true;
        }
        if (retired[slot] && !m->seen_retired[slot]) {
            if (!sgm_step(m, (struct guest_event){ .kind = GUEST_EV_REVOKED_PEER,
                .peer = slot + 1 }, now, &action)) return false;
            m->seen_retired[slot] = true;
        }
    }
    return true;
}
static bool sgm_reconcile(struct mesh_guest_service_manager *m, uint64_t now)
{
    if (!m->instance || m->lifecycle.state == GUEST_STATE_STARTING) return true;
    bool bound[2], retired[2], live[4];
    zcl_mutex_lock(&m->instance->lock);
    memcpy(bound, m->instance->bound, sizeof(bound));
    memcpy(retired, m->instance->retired, sizeof(retired));
    for (size_t i = 0; i < 4; i++) live[i] = m->instance->ports[i].live;
    zcl_mutex_unlock(&m->instance->lock);
    struct guest_action action;
    if (!sgm_reconcile_slots(m, now, bound, retired)) return false;
    for (uint32_t index = 0; index < 4 && m->instance; index++) {
        if (live[index] == m->seen_ports[index]) continue;
        if (!sgm_step(m, (struct guest_event){ .kind = live[index]
            ? GUEST_EV_PORT_OPENED : GUEST_EV_PORT_CLOSED,
            .peer = index / 2 + 1 }, now, &action)) return false;
        m->seen_ports[index] = live[index];
    }
    return true;
}
static bool sgm_startup_bound(const struct rvmachine_result *result)
{
    uint64_t remaining = UINT64_C(600000000);
    if (result->retired > remaining) return false;
    remaining -= result->retired;
    if (result->fw_calls > remaining) return false;
    remaining -= result->fw_calls;
    return result->device_work <= remaining;
}
static bool sgm_state_runnable(enum guest_state state)
{
    return state == GUEST_STATE_STARTING || state == GUEST_STATE_READY ||
        state == GUEST_STATE_SERVING || state == GUEST_STATE_IDLE;
}
static bool sgm_slice_stopped(enum rvmachine_status status,
    const struct guest_gov_decision *decision, const struct rvmachine_result *result)
{
    bool stopped = status != RVMACHINE_OK && status != RVMACHINE_ERR_WAITING;
    return stopped || (status == RVMACHINE_OK && decision->kind == GUEST_GOV_RUN_SLICE &&
        !sgm_result_continues(result));
}
static enum rvmachine_status sgm_after_slice(struct mesh_guest_service_manager *m,
    uint64_t now, enum rvmachine_status status,
    const struct guest_gov_decision *decision, const struct rvmachine_result *result)
{
    bool stopped = sgm_slice_stopped(status, decision, result);
    bool over_work = m->lifecycle.state == GUEST_STATE_STARTING &&
        status == RVMACHINE_OK && decision->kind == GUEST_GOV_RUN_SLICE && !sgm_startup_bound(result);
    if (stopped || over_work) {
        if (m->lifecycle.state == GUEST_STATE_STARTING) {
            struct guest_action action;
            if (!sgm_step(m, (struct guest_event){ .kind = GUEST_EV_BOOT_FAILED,
                .reason = GUEST_REASON_BOOT_FAILED }, now, &action)) status = RVMACHINE_ERR_STATE;
        } else {
            if (!sgm_release(m, now)) return RVMACHINE_ERR_STATE;
        }
    } else if (!sgm_reconcile(m, now)) status = RVMACHINE_ERR_STATE;
    return status;
}
static bool sgm_retry_stopping(struct mesh_guest_service_manager *m, uint64_t now)
{
    if (!m->instance || m->lifecycle.state != GUEST_STATE_STOPPING) return true;
    return sgm_release(m, now);
}
static bool sgm_backend_guard(struct mesh_guest_service_manager *m, uint64_t now)
{
    if (m->config.enrollment.mode == MESH_GUEST_ENROLLMENT_OFF ||
        (!m->enrollment_failed && !m->volume.failed)) return true;
    (void)sgm_enrollment_fail(m);
    if (m->instance) (void)sgm_release(m, now);
    return false;
}
static enum rvmachine_status sgm_drive_absent(const struct mesh_guest_service_manager *m,
    struct guest_gov_decision *decision)
{
    if(m->lifecycle.state!=GUEST_STATE_ABSENT)return RVMACHINE_ERR_STATE;
    *decision=(struct guest_gov_decision){.kind=GUEST_GOV_SLEEP,
        .sleep_ms=GUEST_GOV_MAX_SLEEP_MS,.reason=GUEST_SLEEP_IDLE_UNTIL_INPUT};
    return RVMACHINE_OK;
}
static bool sgm_drive_protected_current(struct mesh_guest_service_manager *m,uint64_t now)
{
    if(m->config.unlock.policy!=MESH_GUEST_UNLOCK_PROTECTED_HOST||sgm_protected_current(m))return true;
    m->config.protected_invalidate(m->config.protected_provider.context);
    (void)sgm_enrollment_fail(m);
    (void)sgm_release(m,now);
    return false;
}
enum rvmachine_status mesh_guest_service_manager_drive(struct mesh_guest_service_manager *m,
    uint64_t now, int64_t wall,
    struct guest_gov_decision *decision, struct rvmachine_result *result)
{
    if (decision) memset(decision, 0, sizeof(*decision));
    if (result) memset(result, 0, sizeof(*result));
    if (!m || !decision || !result || m->driving) {
        (void)sgs_fail("invalid or reentrant manager drive");
        return RVMACHINE_ERR_ARG;
    }
    m->driving = true;
    struct guest_action action;
    enum rvmachine_status status = RVMACHINE_ERR_STATE;
    if (!sgm_backend_guard(m, now)) { status = RVMACHINE_ERR_DISK; goto done; }
    if (!sgm_step(m, (struct guest_event){ .kind = GUEST_EV_TICK }, now, &action)) goto done;
    if (!sgm_retry_stopping(m, now)) goto done;
    if (!m->instance) {
        status=sgm_drive_absent(m,decision);
        goto done;
    }
    if (!sgm_state_runnable(m->lifecycle.state)) goto done;
    if(!sgm_drive_protected_current(m,now))goto done;
    status = sgm_measured_slice(m, now,
        m->lifecycle.state == GUEST_STATE_STARTING, decision, result);
    if (!sgm_backend_guard(m, now)) { status = RVMACHINE_ERR_DISK; goto done; }
    mesh_guest_service_pump(m->instance, wall);
    status = sgm_after_slice(m, now, status, decision, result);
done:
    m->driving = false;
    if (status == RVMACHINE_ERR_STATE) (void)sgs_fail("manager drive has no runnable instance");
    return status;
}
bool mesh_guest_service_manager_snapshot(const struct mesh_guest_service_manager *m,
    uint64_t now, struct guest_service_snapshot *out)
{
    if (!m || !out || m->driving) return sgs_fail("invalid or active manager snapshot");
    return guest_service_snapshot(&m->lifecycle, now, out);
}
bool mesh_guest_service_manager_destroy(struct mesh_guest_service_manager *m, uint64_t now)
{
    if (!m) return true;
    if (m->driving) return sgs_fail("manager destruction during drive");
    if(m->config.unlock.policy==MESH_GUEST_UNLOCK_PROTECTED_HOST)
        m->config.protected_invalidate(m->config.protected_provider.context);
    struct guest_action action;
    if (!mesh_guest_service_manager_event(m,
        &(struct guest_event){ .kind = GUEST_EV_ENABLE, .enable = false }, now, &action)) return false;
    if (m->instance && !sgm_release(m, now)) return false;
    platform_private_file_close(&m->owned_record);
    platform_private_file_close(&m->owned_extension);
    free(m);
    return true;
}
