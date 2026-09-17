/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_bundle_fetch_peer_seeds — feed the file-service endpoints our PEERS
 * already told us about into the instant-on bundle-fetch seed set, with ZERO
 * operator input and ZERO compiled host list.
 *
 * THE GAP THIS CLOSES IS CONSUMPTION, NOT ADVERTISEMENT. Every part of the
 * advertisement already existed and already works on live nodes:
 *
 *   SEND    core/modules/net/src/msg_version.c — after a ZCL23 handshake a node pushes
 *           "zfileaddr" carrying its own file-service PORT.
 *   HANDLE  core/modules/net/src/msgprocessor.c handle_zfileaddr — reads the 2-byte
 *           port, pairs it with the peer's IP from the live connection.
 *   STORE   engine/composition/src/boot_msg_callbacks.c boot_save_file_service ->
 *           db_file_service_save(), table file_services
 *           (ip[16], port, p2p_port, last_seen, is_zcl23).
 *   READ    db_file_service_recent() (engine/models/include/models/file_service.h)
 *           — whose header already says "for download scheduling", describing
 *           a consumer that did not exist.
 *
 * A production node's journal shows both halves live: it registers and serves
 * a 513 MB consensus bundle, and it has saved peers advertising a file service
 * on port 18034 AND on port 18035. Nobody ever read that table back. The
 * bundle fetch therefore assembled seeds from operator flags only, found none
 * on a plain run, logged `bootstrap.no_state_source fetch=seeds_empty`, and
 * fell back to a from-genesis IBD. This module is the missing reader.
 *
 * NOTE THE TWO PORTS. That is why the advertisement is a MESSAGE carrying a
 * port and not a service bit, and why nothing here ever substitutes FS_PORT:
 * the peer's own advertised port is used verbatim, or the peer is not offered.
 *
 * WHY A ONE-SHOT SNAPSHOT AND NOT A LIVE QUERY. bbf_assemble_seeds (and
 * therefore boot_bundle_fetch_seed_count, which the no_state_source blocker
 * calls) is documented pure and IO-free. The single SELECT happens here, in
 * boot_bundle_fetch_arm_peer_seeds(), and the registered provider is a pure
 * copy-out of the resulting static table.
 *
 * TRUST — the line this module must not cross. What is offered here is an
 * ADDRESS. It is handed to bbf_assemble_seeds as the LOWEST-precedence source
 * and from there travels the identical path an -fileservice= seed travels:
 * per-chunk transport MAC, per-chunk SHA3 against the committed manifest,
 * whole-file SHA3 before the atomic rename (net/rom_fetch.h), then the
 * installer's CHECKPOINT_ROM / CHECKPOINT_CONTENT authority binding the result
 * to the COMPILED checkpoint. A peer that advertises and then serves garbage
 * wastes one bounded fetch and is dropped. Nothing in this file relaxes any
 * check, and nothing in this file may ever be allowed to.
 *
 * First-ever startup has no saved endpoints. For that case boot selection arms
 * one deferred retry. After P2P persists an eligible advertisement, a bounded
 * automatic respawn returns to the existing single-threaded fetch/import/
 * install seam. No download or install races the live reducer.
 */

#include "config/boot_bundle_fetch.h"
#include "config/boot.h"
#include "config/consensus_state_install_runtime.h"

#include "models/database.h"
#include "models/file_service.h"
#include "net/netaddr.h"
#include "services/chain_tip_watchdog.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BBFPS_SUBSYS "boot_bundle_fetch"

/* How many cached endpoints we snapshot. The seed array the assembler fills is
 * ROM_FETCH_MAX_WORKERS (8) wide and earlier, operator-named sources take
 * slots first, so a handful of the most-recently-seen peers is the useful
 * range; the SELECT is `ORDER BY last_seen DESC LIMIT ?`. Static — never sized
 * from a database value. */
#define BBFPS_MAX 8

static struct boot_bundle_peer_seed g_armed[BBFPS_MAX];
static size_t g_armed_count = 0;

static _Atomic(const struct app_context *) g_retry_ctx;
static _Atomic(const struct app_context *) g_retry_pending;
#define BBFPS_RETRY_KEY "bbf.peer_discovery_retry_used"
#ifdef ZCL_TESTING
static bool g_suppress_shutdown;
void boot_bundle_fetch_suppress_shutdown_for_test(bool suppress)
{
    g_suppress_shutdown = suppress;
}
#endif

static bool bbfps_host(const uint8_t ip[16], char host[64])
{
    if (!ip)
        return false; /* raw-return-ok: address eligibility predicate */
    struct net_addr a;
    net_addr_init(&a);
    memcpy(a.ip, ip, sizeof(a.ip));
    return net_addr_is_valid(&a) && !net_addr_is_tor(&a) &&
           net_addr_to_string(&a, host, 64) > 0 && host[0];
}

void boot_bundle_fetch_defer_peer_retry(const struct app_context *ctx)
{
    atomic_store(&g_retry_ctx, NULL);
    atomic_store(&g_retry_pending, NULL);
    if (!ctx || !boot_bundle_fetch_should_run(ctx->datadir, ctx) ||
        boot_bundle_fetch_seed_count(ctx) != 0)
        return;

    sqlite3 *pdb = progress_store_db();
    unsigned char used = 0;
    bool found = false;
    size_t len = 0;
    progress_store_tx_lock();
    bool ok = pdb && progress_meta_get(pdb, BBFPS_RETRY_KEY, &used,
                                       sizeof(used), &len, &found);
    progress_store_tx_unlock();
    if (!ok || found) {
        LOG_WARN(BBFPS_SUBSYS, "delayed bootstrap retry unavailable: %s; "
                 "falling back to P2P IBD",
                 !ok ? "retry budget unreadable" : "retry budget exhausted");
        return;
    }
    atomic_store(&g_retry_ctx, ctx);
    LOG_INFO(BBFPS_SUBSYS, "fast-sync source absent at fresh startup; awaiting "
             "P2P file-service discovery for one automatic bootstrap retry");
}

void boot_bundle_fetch_peer_saved(const char *datadir, const uint8_t ip[16],
                                  uint16_t port)
{
    const struct app_context *ctx = atomic_load(&g_retry_ctx);
    char host[64] = {0};
    if (!ctx || !datadir || strcmp(datadir, ctx->datadir) != 0 || port == 0 ||
        !bbfps_host(ip, host) || thread_registry_shutdown_requested())
        return;
    if (!atomic_compare_exchange_strong(&g_retry_ctx, &ctx, NULL))
        return;
    LOG_INFO(BBFPS_SUBSYS, "P2P discovered file-service endpoint %s:%u; "
             "bootstrap retry queued for the main loop", host, (unsigned)port);
    atomic_store(&g_retry_pending, ctx);
}

void boot_bundle_fetch_poll_peer_retry(void)
{
    const struct app_context *ctx = atomic_exchange(&g_retry_pending, NULL);
    if (!ctx || thread_registry_shutdown_requested())
        return;
    const char *datadir = ctx->datadir;
    if (!boot_bundle_fetch_should_run(datadir, ctx) ||
        boot_install_bundle_pending(datadir)) {
        LOG_INFO(BBFPS_SUBSYS, "delayed bootstrap retry skipped: acquisition "
                 "disabled or state source already staged/installed");
        return;
    }
    sqlite3 *pdb = progress_store_db();
    const unsigned char used = 1;
    progress_store_tx_lock();
    bool ok = pdb && progress_meta_set(pdb, BBFPS_RETRY_KEY, &used, sizeof(used));
    progress_store_tx_unlock();
    if (!ok) {
        LOG_WARN(BBFPS_SUBSYS, "delayed bootstrap retry refused: could not "
                 "persist retry budget; falling back to P2P IBD");
        return;
    }
    LOG_INFO(BBFPS_SUBSYS, "retrying bootstrap acquisition after P2P discovery "
             "via automatic graceful respawn; verification remains mandatory");
    chain_tip_watchdog_request_respawn();
#ifdef ZCL_TESTING
    if (!g_suppress_shutdown)
#endif
    thread_registry_request_shutdown();
}

/* The registered provider: a pure copy-out of the table armed below. */
static size_t bbfps_provide(void *ctx, struct boot_bundle_peer_seed *out,
                            size_t max)
{
    (void)ctx;
    if (!out || max == 0)
        return 0; /* raw-return-ok: provider contract is a count, never a log */
    size_t n = g_armed_count < max ? g_armed_count : max;
    for (size_t i = 0; i < n; i++)
        out[i] = g_armed[i];
    return n;
}

size_t boot_bundle_fetch_armed_peer_seed_count(void)
{
    return g_armed_count;
}

void boot_bundle_fetch_disarm_peer_seeds(void)
{
    memset(g_armed, 0, sizeof(g_armed));
    g_armed_count = 0;
    boot_bundle_fetch_set_peer_source(NULL, NULL);
}

void boot_bundle_fetch_arm_peer_seeds(struct node_db *ndb)
{
    boot_bundle_fetch_disarm_peer_seeds();
    if (!ndb || !ndb->open)
        return;

    struct db_file_service rows[BBFPS_MAX];
    memset(rows, 0, sizeof(rows));
    int n = db_file_service_recent(ndb, rows, BBFPS_MAX);
    if (n <= 0) {
        LOG_INFO(BBFPS_SUBSYS,
                 "peer-discovered seeds: no peer has advertised a file service "
                 "to this node yet (file_services table empty) — the "
                 "instant-on seed set falls back to operator-named seeds only");
        return;
    }
    if (n > BBFPS_MAX)
        n = BBFPS_MAX;

    size_t skipped_no_port = 0, skipped_addr = 0;
    for (int i = 0; i < n && g_armed_count < BBFPS_MAX; i++) {
        if (rows[i].port == 0) {
            skipped_no_port++;
            continue; /* row exists but names no file service */
        }
        /* file_services.ip is the 16-byte net_addr form (IPv4-mapped for v4).
         * An onion peer's connection address has an all-zero ip here — its
         * identity lives in the torv3 field, which this table does not carry —
         * so it fails net_addr_is_valid() below and is skipped. That is the
         * right outcome today regardless: rom_fetch's transport dials with
         * getaddrinfo() and has no SOCKS/Tor route, so an onion seed could not
         * be reached even if it were named here. */
        char host[64];
        host[0] = '\0';
        if (!bbfps_host(rows[i].ip, host)) {
            skipped_addr++;
            continue;
        }
        if (strlen(host) >= sizeof(g_armed[0].host)) {
            skipped_addr++;
            continue;
        }
        /* De-dup on (host, port) — the assembler de-dups too, but keeping the
         * snapshot clean means the BBFPS_MAX budget is not spent on repeats. */
        bool dup = false;
        for (size_t j = 0; j < g_armed_count; j++)
            if (g_armed[j].port == rows[i].port &&
                strcmp(g_armed[j].host, host) == 0) { dup = true; break; }
        if (dup)
            continue;
        snprintf(g_armed[g_armed_count].host,
                 sizeof(g_armed[g_armed_count].host), "%s", host);
        /* The peer's OWN advertised port, verbatim. Never FS_PORT by default:
         * live peers really do advertise 18035 as well as 18034. */
        g_armed[g_armed_count].port = rows[i].port;
        g_armed_count++;
    }

    if (g_armed_count == 0) {
        LOG_INFO(BBFPS_SUBSYS,
                 "peer-discovered seeds: %d cached peer endpoint(s), none "
                 "usable (%zu advertised no port, %zu unusable address) — "
                 "operator-named seeds only",
                 n, skipped_no_port, skipped_addr);
        return;
    }

    boot_bundle_fetch_set_peer_source(bbfps_provide, NULL);
    LOG_INFO(BBFPS_SUBSYS,
             "peer-discovered seeds: armed %zu of %d cached peer file-service "
             "endpoint(s) advertised over zfileaddr — instant-on can now find "
             "a bundle seed with no operator flag (an address only; every byte "
             "stays content-verified and the install stays checkpoint-bound)",
             g_armed_count, n);
}

#ifdef ZCL_TESTING
void boot_bundle_fetch_arm_peer_seed_for_test(const char *host, uint16_t port)
{
    if (!host || !host[0] || g_armed_count >= BBFPS_MAX)
        return;
    if (strlen(host) >= sizeof(g_armed[0].host))
        return;
    snprintf(g_armed[g_armed_count].host, sizeof(g_armed[g_armed_count].host),
             "%s", host);
    g_armed[g_armed_count].port = port;
    g_armed_count++;
    boot_bundle_fetch_set_peer_source(bbfps_provide, NULL);
}
#endif
