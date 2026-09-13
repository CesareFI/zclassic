/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "net/download.h"
#include "controllers/misc_controller.h"
#include "services/sync_monitor.h"
#include "json/json.h"
#include "rpc/server.h"
#include "../../../tools/dev/c3_mutex_probe.h"
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/perf_event.h>
#include <sys/syscall.h>
#endif

enum { SPEED_BATCH = 1024, SPEED_SAMPLES = 5, SPEED_LIMIT = 65536 };
static const struct c3_mutex_probe_api *speed_probe;

static uint64_t speed_clock(clockid_t clock_id)
{
    struct timespec t;
    if (clock_gettime(clock_id, &t)) {
        perror("download speed clock");
        abort();
    }
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static unsigned long speed_frequency(void)
{
#ifdef __linux__
    char path[128];
    int cpu = sched_getcpu();
    if (cpu < 0) return 0;
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long khz = 0;
    if (fscanf(f, "%lu", &khz) != 1) khz = 0;
    fclose(f);
    return khz;
#else
    return 0;
#endif
}

static int speed_cycles_open(void)
{
#ifdef __linux__
    struct perf_event_attr attr = {0};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    return (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
#else
    errno = ENOTSUP;
    return -1;
#endif
}

static int speed_compare(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static bool speed_seed(struct download_manager *dm, const struct uint256 *hashes,
                       const int32_t *heights, size_t count)
{
    if (dl_queue_blocks(dm, hashes, heights, count) == count) return true;
    fprintf(stderr, "download speed seed failed: requested=%zu queued=%zu\n", count, dm->queue_len);
    return false;
}

static uint64_t speed_sample(struct download_manager *dm, const struct uint256 *hashes,
                             const int32_t *heights, enum dl_work_class kind, bool *ok)
{
    unsigned long khz_before = speed_frequency();
    int cycles_fd = speed_cycles_open(), cycles_error = cycles_fd < 0 ? errno : 0;
    uint64_t cycles = 0, cycles_before = 0;
    bool cycles_ok = cycles_fd >= 0 && read(cycles_fd, &cycles_before, sizeof(cycles_before)) == sizeof(cycles_before);
    if (speed_probe) speed_probe->begin(&dm->cs);
    uint64_t wall_begin = speed_clock(CLOCK_MONOTONIC);
    uint64_t cpu_begin = speed_clock(CLOCK_THREAD_CPUTIME_ID);
    size_t added = dl_queue_blocks_class(dm, hashes, heights, SPEED_BATCH, kind);
    uint64_t cpu_ns = speed_clock(CLOCK_THREAD_CPUTIME_ID) - cpu_begin;
    uint64_t wall_ns = speed_clock(CLOCK_MONOTONIC) - wall_begin;
    if (cycles_ok) cycles_ok = read(cycles_fd, &cycles, sizeof(cycles)) == sizeof(cycles);
    if (cycles_fd >= 0) close(cycles_fd);
    struct c3_mutex_sample sample = {0};
    if (speed_probe) {
        *ok = speed_probe->read(&sample, 1) == 1 && *ok;
        speed_probe->begin(NULL);
    }
    *ok = added == 0 && *ok;
    char cycle_text[32] = "null";
    if (cycles_ok) snprintf(cycle_text, sizeof(cycle_text), "%llu", (unsigned long long)(cycles-cycles_before));
    printf("{\"schema\":\"c3.speed_scaling.v1\",\"queue_depth\":%zu,\"batch\":%u,"
           "\"class\":\"%s\",\"duplicate_pct\":100,\"cpu_ns\":%llu,\"wall_ns\":%llu,"
           "\"lock_measured\":%s,\"hold_ns\":%llu,\"cycles\":%s,\"cycles_errno\":%d,"
           "\"frequency_before_khz\":%lu,\"frequency_after_khz\":%lu,\"scans_measured\":null}\n",
           dm->queue_len, SPEED_BATCH, kind == DL_WORK_FORWARD ? "forward" : "history",
           (unsigned long long)cpu_ns, (unsigned long long)wall_ns, speed_probe ? "true" : "false",
           (unsigned long long)sample.hold_ns, cycle_text, cycles_error,
           khz_before, speed_frequency());
    return cpu_ns;
}

static int speed_scaling(const struct uint256 *hashes, const int32_t *heights)
{
    const size_t depths[] = {1024, 4096, 16384, 65536};
    int failures = 0;
    for (size_t d = 0; d < sizeof(depths)/sizeof(*depths); d++) {
        uint64_t times[2][SPEED_SAMPLES];
        bool ok = true;
        for (unsigned r = 0; r < SPEED_SAMPLES; r++) {
            for (unsigned step = 0; step < 2; step++) {
                unsigned path = (step + r) % 2;
                struct download_manager dm;
                dl_init(&dm);
                ok = speed_seed(&dm, hashes, heights, depths[d]) && ok;
                times[path][r] = speed_sample(&dm, hashes, heights,
                    path ? DL_WORK_HISTORY : DL_WORK_FORWARD, &ok);
                ok = dm.queue_len == depths[d] && ok;
                dl_free(&dm);
            }
        }
        qsort(times[0], SPEED_SAMPLES, sizeof(uint64_t), speed_compare);
        qsort(times[1], SPEED_SAMPLES, sizeof(uint64_t), speed_compare);
        uint64_t forward = times[0][2], control = times[1][2];
        bool pass = ok && control && forward <= control * 16;
        printf("{\"schema\":\"c3.speed_contract.v1\",\"queue_depth\":%zu,"
               "\"forward_cpu_ns_p50\":%llu,\"control_cpu_ns_p50\":%llu,"
               "\"maximum_ratio\":16,\"pass\":%s}\n", depths[d],
               (unsigned long long)forward, (unsigned long long)control, pass ? "true" : "false");
        if (!ok || (!pass && getenv("C3_ENFORCE_SPEED_CONTRACT"))) failures++;
    }
    return failures;
}

struct speed_load {
    struct download_manager *dm;
    const struct uint256 *hashes;
    const int32_t *heights;
    pthread_mutex_t event;
    pthread_cond_t changed;
    bool ready, go;
    size_t added;
    uint64_t enqueue_ns;
};

static void *speed_load_run(void *arg)
{
    struct speed_load *load = arg;
    if (speed_probe) speed_probe->set_role(1);
    zcl_mutex_lock(&load->dm->cs);
    pthread_mutex_lock(&load->event);
    load->ready = true;
    pthread_cond_signal(&load->changed);
    while (!load->go) pthread_cond_wait(&load->changed, &load->event);
    pthread_mutex_unlock(&load->event);
    uint64_t begin = speed_clock(CLOCK_MONOTONIC);
    load->added = dl_queue_blocks_class(load->dm, load->hashes, load->heights,
                                        SPEED_BATCH, DL_WORK_FORWARD);
    load->enqueue_ns = speed_clock(CLOCK_MONOTONIC) - begin;
    zcl_mutex_unlock(&load->dm->cs);
    return NULL;
}

static bool speed_command(struct rpc_table *table, bool sync)
{
    struct json_value params, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool ok = sync ? sync_monitor_dump_state_json(&result, NULL) :
                    rpc_table_execute(table, "downloadstats", &params, &result);
    ok = ok && result.type == JSON_OBJ;
    json_free(&result);
    json_free(&params);
    return ok;
}

static bool speed_command_sample(struct speed_load *load, struct rpc_table *table,
                                  bool sync, uint64_t *elapsed)
{
    load->ready = false;
    load->go = false;
    if (speed_probe) { speed_probe->begin(&load->dm->cs); speed_probe->set_role(2); }
    pthread_t worker;
    int error = pthread_create(&worker, NULL, speed_load_run, load);
    if (error) { fprintf(stderr, "download speed worker: %s\n", strerror(error)); return false; }
    pthread_mutex_lock(&load->event);
    while (!load->ready) pthread_cond_wait(&load->changed, &load->event);
    load->go = true;
    pthread_cond_signal(&load->changed);
    pthread_mutex_unlock(&load->event);
    uint64_t begin = speed_clock(CLOCK_MONOTONIC);
    bool ok = speed_command(table, sync);
    *elapsed = speed_clock(CLOCK_MONOTONIC) - begin;
    error = pthread_join(worker, NULL);
    if (error) { fprintf(stderr, "download speed join: %s\n", strerror(error)); abort(); }
    uint64_t observer_wait = 0, producer_hold = 0;
    if (speed_probe) {
        struct c3_mutex_sample samples[64];
        size_t count = speed_probe->read(samples, 64);
        speed_probe->begin(NULL);
        ok = count <= 64 && ok;
        for (size_t i = 0; i < count && i < 64; i++) {
            if (samples[i].role == 1) producer_hold += samples[i].hold_ns;
            if (samples[i].role == 2) observer_wait += samples[i].wait_ns;
        }
    }
    printf("{\"schema\":\"c3.command_contention.v1\",\"handler\":\"%s\","
           "\"command_ns\":%llu,\"enqueue_ns\":%llu,\"producer_hold_ns\":%llu,"
           "\"observer_mutex_wait_ns\":%llu,\"lock_measured\":%s,\"transport_measured\":false,"
           "\"frequency_khz\":%lu,\"ok\":%s}\n", sync ? "sync_monitor" : "downloadstats",
           (unsigned long long)*elapsed, (unsigned long long)load->enqueue_ns,
           (unsigned long long)producer_hold, (unsigned long long)observer_wait,
           speed_probe ? "true" : "false", speed_frequency(), ok ? "true" : "false");
    return ok && load->added == 0;
}

static int speed_commands(const struct uint256 *hashes, const int32_t *heights)
{
    struct download_manager *dm = msg_get_download_mgr();
    if (dm->queue_len || dm->num_active) { fputs("speed fixture is not empty\n", stderr); return 1; }
    if (!speed_seed(dm, hashes, heights, SPEED_LIMIT)) return 1;
    struct rpc_table table;
    rpc_table_init(&table);
    register_misc_rpc_commands(&table);
    if (rpc_is_in_warmup(NULL, 0)) set_rpc_warmup_finished();
    sync_monitor_set_context(NULL, dm, NULL);
    struct speed_load load = {.dm=dm, .hashes=hashes, .heights=heights,
        .event=PTHREAD_MUTEX_INITIALIZER, .changed=PTHREAD_COND_INITIALIZER};
    int failures = 0;
    for (unsigned sync = 0; sync < 2; sync++) {
        uint64_t elapsed[SPEED_SAMPLES] = {0};
        for (unsigned r = 0; r < SPEED_SAMPLES; r++)
            if (!speed_command_sample(&load, &table, sync != 0, &elapsed[r])) failures++;
        qsort(elapsed, SPEED_SAMPLES, sizeof(uint64_t), speed_compare);
        printf("{\"schema\":\"c3.command_contract.v1\",\"handler\":\"%s\","
               "\"p50_ns\":%llu,\"p95_ns\":%llu,\"samples\":5,\"timeouts\":null}\n",
               sync ? "sync_monitor" : "downloadstats", (unsigned long long)elapsed[2],
               (unsigned long long)elapsed[4]);
    }
    sync_monitor_set_context(NULL, NULL, NULL);
    dl_drain_for_backpressure(dm);
    pthread_cond_destroy(&load.changed);
    pthread_mutex_destroy(&load.event);
    return failures;
}

static int speed_queue_work(const struct uint256 *hashes, const int32_t *heights)
{
    struct download_manager dm;
    dl_init(&dm);
    unsigned long frequency_before = speed_frequency();
    uint64_t begin = speed_clock(CLOCK_MONOTONIC);
    bool ok = speed_seed(&dm, hashes, heights, SPEED_LIMIT);
    uint64_t enqueue_ns = speed_clock(CLOCK_MONOTONIC) - begin;
    dl_set_peer_loopback(&dm, 1, true);
    size_t completed = 0, calls = 0;
    uint64_t assign_ns = 0, receive_ns = 0;
    while (ok && dm.queue_len && calls < SPEED_LIMIT) {
        struct uint256 assigned[256];
        begin = speed_clock(CLOCK_MONOTONIC);
        size_t count = dl_assign_to_peer(&dm, 1, assigned, 256);
        assign_ns += speed_clock(CLOCK_MONOTONIC) - begin;
        if (!count) { fputs("download speed drain made no progress\n", stderr); ok = false; break; }
        begin = speed_clock(CLOCK_MONOTONIC);
        for (size_t i = 0; i < count; i++)
            if (dl_mark_received(&dm, &assigned[i]) != 1) ok = false;
        receive_ns += speed_clock(CLOCK_MONOTONIC) - begin;
        completed += count;
        calls++;
    }
    ok = ok && completed == SPEED_LIMIT && dm.queue_len == 0 && dm.num_active == 0;
    printf("{\"schema\":\"c3.queue_work.v1\",\"first_seen_enqueues\":%u,"
           "\"enqueue_ns\":%llu,\"first_seen_enqueues_per_second\":%.3f,"
           "\"assigned_and_settled\":%zu,\"assign_calls\":%zu,\"assign_ns\":%llu,"
           "\"settle_ns\":%llu,\"queue_depth_end\":%zu,\"duplicate_pct\":0,"
           "\"wire_bodies_per_second\":null,\"validated_per_second\":null,"
           "\"persisted_per_second\":null,\"frequency_before_khz\":%lu,"
           "\"frequency_after_khz\":%lu,\"ok\":%s}\n", SPEED_LIMIT,
           (unsigned long long)enqueue_ns, enqueue_ns ? 1e9 * SPEED_LIMIT / (double)enqueue_ns : 0.0,
           completed, calls, (unsigned long long)assign_ns, (unsigned long long)receive_ns,
           dm.queue_len, frequency_before, speed_frequency(), ok ? "true" : "false");
    dl_free(&dm);
    return ok ? 0 : 1;
}

int test_download_speed_contract(void)
{
    speed_probe = dlsym(RTLD_DEFAULT, "c3_mutex_probe_v1");
    if (!speed_probe && getenv("C3_REQUIRE_MUTEX_PROBE")) {
        fputs("download speed contract requires declared mutex probe\n", stderr);
        return 1;
    }
    struct uint256 *hashes = calloc(SPEED_LIMIT, sizeof(*hashes));
    int32_t *heights = calloc(SPEED_LIMIT, sizeof(*heights));
    if (!hashes || !heights) { perror("download speed allocation"); free(hashes); free(heights); return 1; }
    for (size_t i = 0; i < SPEED_LIMIT; i++) {
        heights[i] = (int32_t)i + 1;
        memcpy(hashes[i].data, &heights[i], sizeof(heights[i]));
    }
    int failures = speed_scaling(hashes, heights);
    failures += speed_commands(hashes, heights);
    failures += speed_queue_work(hashes, heights);
    free(hashes);
    free(heights);
    return failures;
}
