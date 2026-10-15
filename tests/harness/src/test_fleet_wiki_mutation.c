/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Receiver-local wiki mutation: exact CAS, retained replay, and rollback. */
#include "test/test_core.h"
#include "models/fleet_board_post.h"
#include "models/fleet_board_post_internal.h"
#include "crypto/ed25519.h"
#include "util/thread_registry.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <pthread.h>
#include <string.h>

#define FWM_NOW INT64_C(1000000)

static bool fwm_post(struct fleet_board_post *post, unsigned author,
    const char *marker, const char *body, int64_t now, const uint8_t *parent)
{
    uint8_t seed[32] = {0}, sk[32], pk[32];
    seed[0] = (uint8_t)author; seed[31] = 71;
    ed25519_keypair(pk, sk, seed);
    memset(post, 0, sizeof(*post));
    post->kind = FLEET_BOARD_KIND_WIKI;
    post->scope = FLEET_BOARD_SCOPE_PUBLIC;
    post->created_at = (uint64_t)now; post->ttl = 60;
    (void)snprintf(post->room, sizeof(post->room), "general");
    (void)snprintf(post->agent, sizeof(post->agent), "grant-%u", author);
    (void)snprintf(post->slug, sizeof(post->slug), "mutation-page");
    (void)snprintf(post->title, sizeof(post->title), "Receiver-local page");
    (void)snprintf(post->receipt, sizeof(post->receipt), "%s", marker);
    post->text_len = (uint32_t)strlen(body);
    memcpy(post->text, body, post->text_len + 1);
    if (parent) memcpy(post->supersedes, parent, 32);
    return fleet_board_post_sign(post, sk, pk) == FLEET_BOARD_OK;
}

static enum fleet_board_wiki_write_status fwm_write(struct node_db *db,
    const struct fleet_board_post *post, const uint8_t *parent,
    struct db_fleet_board_post *out)
{
    enum fleet_board_result refusal;
    return db_fleet_board_wiki_write(db, post, parent,
        (int64_t)post->created_at, out, &refusal);
}

static int fwm_replay_cas(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: retained replay binds payload and strict newest head refuses fallback") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post first, second, retry;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&first, 19, "request-first", "original", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &first, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(memcmp(out.post.id, first.id, 32) == 0);
        ASSERT(fwm_post(&second, 20, "request-second", "replacement", FWM_NOW + 1, first.id));
        ASSERT_EQ(fwm_write(&db, &second, first.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_post(&retry, 19, "request-first", "original", FWM_NOW + 1000, NULL));
        ASSERT_EQ(fwm_write(&db, &retry, NULL, &out), FLEET_WIKI_WRITE_REPLAY);
        ASSERT(memcmp(out.post.id, first.id, 32) == 0);
        ASSERT_EQ(fleet_board_post_verify(&out.post), FLEET_BOARD_OK);
        ASSERT(fwm_post(&retry, 19, "request-first", "changed", FWM_NOW + 2, NULL));
        ASSERT_EQ(fwm_write(&db, &retry, NULL, &out), FLEET_WIKI_WRITE_COLLISION);
        ASSERT(fwm_post(&retry, 19, "request-stale", "third", FWM_NOW + 2, first.id));
        ASSERT_EQ(fwm_write(&db, &retry, first.id, &out), FLEET_WIKI_WRITE_CONFLICT);
        ASSERT(fwm_post(&retry, 19, "request-tie", "third", FWM_NOW + 1, second.id));
        ASSERT_EQ(fwm_write(&db, &retry, second.id, &out), FLEET_WIKI_WRITE_CLOCK);
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET text='corrupted' WHERE receipt='request-second'"));
        ASSERT(fwm_post(&retry, 19, "request-corrupt", "third", FWM_NOW + 3, first.id));
        ASSERT_EQ(fwm_write(&db, &retry, first.id, &out), FLEET_WIKI_WRITE_CORRUPT);
        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, FWM_NOW, &status));
        ASSERT_EQ(status.posts, 2);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

struct fwm_racer {
    struct node_db *db;
    struct fleet_board_post post;
    uint8_t parent[32];
    atomic_int *ready;
    atomic_bool *go;
    enum fleet_board_wiki_write_status status;
};
static void *fwm_race_main(void *arg)
{
    struct fwm_racer *r = arg;
    atomic_fetch_add_explicit(r->ready, 1, memory_order_release);
    while (!atomic_load_explicit(r->go, memory_order_acquire)) platform_sleep_ms(1);
    struct db_fleet_board_post out;
    r->status = fwm_write(r->db, &r->post, r->parent, &out);
    return NULL;
}

static bool fwm_race(struct node_db *db, const struct fleet_board_post *head)
{
    atomic_int ready = 0;
    atomic_bool go = false;
    struct fwm_racer racers[2] = {{.db = db, .ready = &ready, .go = &go},
        {.db = db, .ready = &ready, .go = &go}};
    if (!fwm_post(&racers[0].post, 19, "race-a", "a", FWM_NOW + 1, head->id) ||
        !fwm_post(&racers[1].post, 20, "race-b", "b", FWM_NOW + 1, head->id)) return false;
    pthread_t threads[2];
    unsigned spawned = 0;
    for (; spawned < 2; spawned++) {
        memcpy(racers[spawned].parent, head->id, 32);
        if (thread_registry_spawn("wiki-cas", fwm_race_main, &racers[spawned], &threads[spawned])) break;
    }
    while (atomic_load_explicit(&ready, memory_order_acquire) < (int)spawned) platform_sleep_ms(1);
    atomic_store_explicit(&go, true, memory_order_release);
    for (unsigned i = 0; i < spawned; i++) pthread_join(threads[i], NULL);
    if (spawned != 2) return false;
    unsigned winners = (racers[0].status == FLEET_WIKI_WRITE_OK) +
        (racers[1].status == FLEET_WIKI_WRITE_OK);
    struct db_fleet_board_post out;
    unsigned loser = racers[0].status == FLEET_WIKI_WRITE_OK ? 1 : 0;
    return winners == 1 && fwm_write(db, &racers[loser].post, head->id, &out) == FLEET_WIKI_WRITE_CONFLICT;
}

static int fwm_race_case(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: two authors racing one exact parent admit one append") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post head;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&head, 19, "race-parent", "head", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &head, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_race(&db, &head));
        int64_t checked;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 2);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

enum fwm_fault_kind { FWM_FAULT_CHAIN, FWM_FAULT_SEQ, FWM_FAULT_COMMIT, FWM_FAULT_INSERT };
struct fwm_fault { enum fwm_fault_kind kind; bool armed, prefix; unsigned reads, hits; };
static bool fwm_read_denied(struct fwm_fault *f, const char *column)
{
    static const char *const columns[] = {"id", "chain_prev", "chain_hash"};
    if (f->reads < 3) f->prefix = f->prefix && !strcmp(column, columns[f->reads]);
    bool deny = (f->kind == FWM_FAULT_CHAIN && f->reads == 2 && f->prefix) ||
        (f->kind == FWM_FAULT_SEQ && f->reads == 0 && !strcmp(column, "seq"));
    f->reads++;
    return deny;
}
static int fwm_authorizer(void *arg, int action, const char *a, const char *b,
    const char *database, const char *trigger)
{
    (void)database; (void)trigger;
    struct fwm_fault *f = arg;
    if (action == SQLITE_SELECT) { f->reads = 0; f->prefix = true; }
    bool deny = action == SQLITE_TRANSACTION && a && !strcmp(a, "COMMIT") && f->kind == FWM_FAULT_COMMIT;
    if (action == SQLITE_INSERT && a && !strcmp(a, "fleet_board_posts"))
        deny = f->kind == FWM_FAULT_INSERT;
    if (action == SQLITE_READ && a && b && !strcmp(a, "fleet_board_posts")) {
        deny = fwm_read_denied(f, b) || deny;
    }
    if (deny && f->armed) { f->armed = false; f->hits++; return SQLITE_DENY; }
    return SQLITE_OK;
}

static bool fwm_rollback_verified(struct node_db *db, int64_t high,
    bool populated, const struct fwm_fault *fault,
    enum fleet_board_wiki_write_status result)
{
    struct fleet_board_status status;
    return fault->hits == 1 && result == FLEET_WIKI_WRITE_STORAGE &&
        fleet_board_arrival_checkpoint() == high && db_fleet_board_status(db, FWM_NOW, &status) &&
        status.posts == (populated ? 1 : 0);
}

static bool fwm_retry_verified(struct node_db *db, const struct fleet_board_post *next,
    const uint8_t *parent, int64_t high, bool populated)
{
    struct db_fleet_board_post out;
    int64_t checked;
    return fwm_write(db, next, parent, &out) == FLEET_WIKI_WRITE_OK &&
        out.seq == (populated ? 2 : 1) && out.arrival == high + 1 &&
        db_fleet_board_chain_verify(db, &checked) && checked == (populated ? 2 : 1);
}

static bool fwm_fault_case(enum fwm_fault_kind kind, bool populated)
{
    struct node_db db = {0};
    if (!node_db_open(&db, ":memory:")) return false;
    struct fleet_board_post head, next;
    struct db_fleet_board_post out;
    bool ok = fwm_post(&head, 19, "fault-parent", "head", FWM_NOW, NULL);
    if (populated) ok = ok && fwm_write(&db, &head, NULL, &out) == FLEET_WIKI_WRITE_OK;
    ok = ok && fwm_post(&next, 19, "fault-next", "next", FWM_NOW + 1, populated ? head.id : NULL);
    int64_t high = fleet_board_arrival_checkpoint();
    struct fwm_fault fault = {.kind = kind, .armed = true};
    sqlite3_set_authorizer(db.db, fwm_authorizer, &fault);
    enum fleet_board_wiki_write_status result = fwm_write(&db, &next, populated ? head.id : NULL, &out);
    sqlite3_set_authorizer(db.db, NULL, NULL);
    ok = ok && fwm_rollback_verified(&db, high, populated, &fault, result);
    ok = ok && fwm_retry_verified(&db, &next, populated ? head.id : NULL, high, populated);
    node_db_close(&db);
    return ok;
}

static int fwm_storage_cases(void)
{
    int failures = 0;
    TEST("wiki mutation: one-shot head, sequence and commit failures roll back empty and nonempty stores") {
        for (unsigned kind = 0; kind < 3; kind++) {
            ASSERT(fwm_fault_case((enum fwm_fault_kind)kind, false));
            ASSERT(fwm_fault_case((enum fwm_fault_kind)kind, true));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int fwm_sequence_overflow(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: exhausted signed sequence refuses append without wrapping") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post head, next;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&head, 19, "overflow-head", "head", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &head, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET seq=9223372036854775807"));
        ASSERT(fwm_post(&next, 19, "overflow-next", "next", FWM_NOW + 1, head.id));
        int64_t high = fleet_board_arrival_checkpoint();
        ASSERT_EQ(fwm_write(&db, &next, head.id, &out), FLEET_WIKI_WRITE_STORAGE);
        ASSERT_EQ(fleet_board_arrival_checkpoint(), high);
        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, FWM_NOW, &status));
        ASSERT_EQ(status.posts, 1);
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET seq=1"));
        ASSERT(fwm_retry_verified(&db, &next, head.id, high, true));
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

static bool fwm_eviction_refusal(struct node_db *db, const struct fleet_board_post *first,
    const struct fleet_board_post *second, const struct fleet_board_post *next,
    enum fwm_fault_kind kind)
{
    struct db_fleet_board_post before, after, out;
    if (!db_fleet_board_post_find(db, second->id, &before)) return false;
    int64_t high = fleet_board_arrival_checkpoint();
    struct fwm_fault fault = {.kind = kind, .armed = true};
    sqlite3_set_authorizer(db->db, fwm_authorizer, &fault);
    enum fleet_board_wiki_write_status result = fwm_write(db, next, second->id, &out);
    sqlite3_set_authorizer(db->db, NULL, NULL);
    int64_t checked;
    return fault.hits == 1 && result == FLEET_WIKI_WRITE_STORAGE &&
        fleet_board_arrival_checkpoint() == high && db_fleet_board_have(db, first->id) &&
        db_fleet_board_post_find(db, second->id, &after) &&
        !memcmp(before.chain_hash, after.chain_hash, 32) &&
        db_fleet_board_chain_verify(db, &checked) && checked == 2;
}

static int fwm_eviction_case(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: eviction rollback preserves victim and replay ends when revision evicts") {
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_set_wiki_limits(1000, 2);
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post first, second, next, replay;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&first, 19, "evict-first", "first", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &first, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_post(&second, 19, "evict-second", "second", FWM_NOW + 1, first.id));
        ASSERT_EQ(fwm_write(&db, &second, first.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_post(&next, 19, "evict-next", "next", FWM_NOW + 2, second.id));
        ASSERT(fwm_eviction_refusal(&db, &first, &second, &next, FWM_FAULT_INSERT));
        ASSERT(fwm_eviction_refusal(&db, &first, &second, &next, FWM_FAULT_COMMIT));
        ASSERT_EQ(fwm_write(&db, &next, second.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(!db_fleet_board_have(&db, first.id));
        int64_t checked;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 2);
        ASSERT(fwm_post(&replay, 19, "evict-second", "second", FWM_NOW + 100, first.id));
        ASSERT_EQ(fwm_write(&db, &replay, first.id, &out), FLEET_WIKI_WRITE_REPLAY);
        ASSERT(fwm_post(&replay, 19, "evict-first", "first", FWM_NOW + 100, NULL));
        ASSERT_EQ(fwm_write(&db, &replay, NULL, &out), FLEET_WIKI_WRITE_CONFLICT);
        ASSERT(node_db_begin(&db));
        ASSERT_EQ(fwm_write(&db, &replay, NULL, &out), FLEET_WIKI_WRITE_BUSY);
        ASSERT(node_db_rollback(&db));
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    db_fleet_board_test_set_wiki_limits(0, 0);
    db_fleet_board_test_reset_wiki_evictions();
    return failures;
}

struct fwm_step_fault { sqlite3_stmt *target; bool armed; unsigned hits; };
static int fwm_interrupt_step(void *arg)
{
    struct fwm_step_fault *fault = arg;
    if (!fault->armed || !sqlite3_stmt_busy(fault->target)) return 0;
    fault->armed = false;
    fault->hits++;
    return 1;
}

static int fwm_head_trace(unsigned event, void *arg, void *statement, void *detail)
{
    (void)detail;
    struct fwm_step_fault *fault = arg;
    if (event == SQLITE_TRACE_PROFILE) {
        if (fault->target == statement) { fault->target = NULL; fault->armed = false; }
        return 0;
    }
    const char *sql = sqlite3_sql(statement);
    if (sql && strstr(sql, "fleet_board_posts") && strstr(sql, "ORDER BY") &&
        strstr(sql, "created_at"))
        { fault->target = statement; fault->armed = true; }
    return 0;
}

static int fwm_head_step_case(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: interrupted strict newest query refuses apparent absence") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post post;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&post, 19, "step-request", "body", FWM_NOW, NULL));
        int64_t high = fleet_board_arrival_checkpoint();
        struct fwm_step_fault fault = {0};
        /* Install before stepping: changing the progress handler inside a
         * trace callback can defer its interval to a later statement. */
        sqlite3_progress_handler(db.db, 1, fwm_interrupt_step, &fault);
        ASSERT_EQ(sqlite3_trace_v2(db.db, SQLITE_TRACE_STMT | SQLITE_TRACE_PROFILE, fwm_head_trace, &fault), SQLITE_OK);
        enum fleet_board_wiki_write_status result = fwm_write(&db, &post, NULL, &out);
        sqlite3_progress_handler(db.db, 0, NULL, NULL);
        ASSERT_EQ(sqlite3_trace_v2(db.db, 0, NULL, NULL), SQLITE_OK);
        ASSERT_EQ(fault.hits, 1);
        ASSERT_EQ(result, FLEET_WIKI_WRITE_STORAGE);
        ASSERT_EQ(fleet_board_arrival_checkpoint(), high);
        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, FWM_NOW, &status));
        ASSERT_EQ(status.posts, 0);
        ASSERT(fwm_retry_verified(&db, &post, NULL, high, false));
        PASS();
    } _test_next:;
    if (db.open) {
        sqlite3_progress_handler(db.db, 0, NULL, NULL);
        (void)sqlite3_trace_v2(db.db, 0, NULL, NULL);
        node_db_close(&db);
    }
    return failures;
}

int test_fleet_wiki_mutation(void)
{
    return fwm_replay_cas() + fwm_race_case() + fwm_storage_cases() +
        fwm_sequence_overflow() + fwm_eviction_case() + fwm_head_step_case();
}
