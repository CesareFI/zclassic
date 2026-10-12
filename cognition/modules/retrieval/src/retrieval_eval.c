/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Truthful file-level metrics for reviewed retrieval task corpora. */

#include <retrieval/retrieval.h>
#include <base/log_macros.h>

#include <limits.h>
#include <string.h>

static bool add_u64(uint64_t *sum, uint64_t value)
{
    if (!sum || UINT64_MAX - *sum < value) return false;
    *sum += value;
    return true;
}

static const char *task_invalid_paths(const struct zcl_retrieval_gold_task *task)
{
    for (size_t i = 0; i < task->relevant_count; i++) {
        if (!task->relevant_paths[i] || !task->relevant_paths[i][0])
            return "relevant_path";
        for (size_t prior = 0; prior < i; prior++)
            if (strcmp(task->relevant_paths[i], task->relevant_paths[prior]) == 0)
                return "relevant_path";
    }
    for (size_t i = 0; i < task->ranked_count; i++)
        if (!task->ranked[i].path || !task->ranked[i].path[0])
            return "ranked_path";
    return NULL;
}

/* Fixed tokens only: rejected input text never enters the diagnostic. */
static const char *task_invalid_field(const struct zcl_retrieval_gold_task *task)
{
    if (!task->task_id || !task->task_id[0]) return "task_id";
    if (!task->query || !task->query[0]) return "query";
    if (!task->relevant_paths || !task->relevant_count) return "relevant_paths";
    if ((!task->ranked && task->ranked_count) ||
        task->ranked_count > ZCL_RETRIEVAL_EVAL_RANK_MAX) return "ranked";
    return task_invalid_paths(task);
}

static bool task_reject(size_t t, const char *field, const char *reason)
{
    LOG_FAIL("retrieval", "task=%zu field=%s reason=%s", t, field, reason);
}

static bool task_validate(const struct zcl_retrieval_gold_task *tasks, size_t t)
{
    const char *field = task_invalid_field(&tasks[t]);
    const char *reason = "invalid-field";
    if (!field) {
        for (size_t prior = 0; prior < t; prior++) {
            if (strcmp(tasks[t].task_id, tasks[prior].task_id) == 0) {
                field = "task_id";
                reason = "duplicate-id";
                break;
            }
        }
    }
    if (!field) return true;
    return task_reject(t, field, reason);
}

static bool path_relevant(const struct zcl_retrieval_gold_task *task,
                          const char *path)
{
    for (size_t i = 0; i < task->relevant_count; i++)
        if (strcmp(task->relevant_paths[i], path) == 0) return true;
    return false;
}

static bool ranked_duplicate(const struct zcl_retrieval_gold_task *task,
                             size_t index)
{
    for (size_t prior = 0; prior < index; prior++)
        if (strcmp(task->ranked[prior].path,
                   task->ranked[index].path) == 0)
            return true;
    return false;
}

struct eval_totals {
    uint64_t recall5, recall20, rr;
    bool r5_available, r20_available, mrr_available, wrong_scope_available;
};

struct task_ranks {
    size_t unique, relevant5, relevant20, first_relevant;
};

static bool selection_add(const struct zcl_retrieval_ranked_file *row,
                          struct zcl_retrieval_eval_metrics *out,
                          struct eval_totals *totals)
{
    if (!add_u64(&out->unique_files_at_5, 1) ||
        !add_u64(&out->context_bytes_at_5, row->context_bytes))
        return false;
    if (!row->in_scope_available)
        totals->wrong_scope_available = false;
    else if (!row->in_scope && !add_u64(&out->wrong_scope_files_at_5, 1))
        return false;
    return true;
}

static bool task_scan(const struct zcl_retrieval_gold_task *task,
                      struct zcl_retrieval_eval_metrics *out,
                      struct eval_totals *totals, struct task_ranks *ranks)
{
    for (size_t i = 0; i < task->ranked_count; i++) {
        if (ranked_duplicate(task, i)) continue;
        ranks->unique++;
        bool relevant = path_relevant(task, task->ranked[i].path);
        if (relevant && ranks->first_relevant == 0)
            ranks->first_relevant = ranks->unique;
        if (relevant && ranks->unique <= 5) ranks->relevant5++;
        if (relevant && ranks->unique <= 20) ranks->relevant20++;
        if (ranks->unique <= 5 && !selection_add(&task->ranked[i], out, totals))
            return false;
    }
    return true;
}

static void task_score(const struct zcl_retrieval_gold_task *task,
                       const struct task_ranks *ranks, struct eval_totals *totals)
{
    bool r5 = task->ranking_complete || ranks->unique >= 5 ||
        ranks->relevant5 == task->relevant_count;
    bool r20 = task->ranking_complete || ranks->unique >= 20 ||
        ranks->relevant20 == task->relevant_count;
    bool mrr = ranks->first_relevant != 0 || task->ranking_complete;
    totals->r5_available = totals->r5_available && r5;
    totals->r20_available = totals->r20_available && r20;
    totals->mrr_available = totals->mrr_available && mrr;
    if (r5)
        totals->recall5 += (uint64_t)ranks->relevant5 *
            ZCL_RETRIEVAL_EVAL_BASIS_POINTS / task->relevant_count;
    if (r20)
        totals->recall20 += (uint64_t)ranks->relevant20 *
            ZCL_RETRIEVAL_EVAL_BASIS_POINTS / task->relevant_count;
    if (mrr && ranks->first_relevant != 0)
        totals->rr += ZCL_RETRIEVAL_EVAL_BASIS_POINTS / ranks->first_relevant;
}

static bool eval_finish(size_t task_count, const struct eval_totals *totals,
                        struct zcl_retrieval_eval_metrics *out)
{
    out->tasks = (uint32_t)task_count;
    out->recall_at_5_available = totals->r5_available;
    out->recall_at_20_available = totals->r20_available;
    out->mrr_available = totals->mrr_available;
    if (totals->r5_available)
        out->recall_at_5_bp = (uint32_t)(totals->recall5 / task_count);
    if (totals->r20_available)
        out->recall_at_20_bp = (uint32_t)(totals->recall20 / task_count);
    if (totals->mrr_available)
        out->mrr_bp = (uint32_t)(totals->rr / task_count);
    if (out->context_bytes_at_5 > UINT64_MAX - 3u) return false;
    out->approximate_tokens_at_5 = (out->context_bytes_at_5 + 3u) / 4u;
    out->wrong_scope_at_5_available = totals->wrong_scope_available &&
        out->unique_files_at_5 != 0;
    if (out->wrong_scope_at_5_available)
        out->wrong_scope_at_5_bp = (uint32_t)(
            out->wrong_scope_files_at_5 *
            ZCL_RETRIEVAL_EVAL_BASIS_POINTS / out->unique_files_at_5);
    else
        out->wrong_scope_files_at_5 = 0;
    return true;
}

bool zcl_retrieval_evaluate(
    const struct zcl_retrieval_gold_task *tasks, size_t task_count,
    struct zcl_retrieval_eval_metrics *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!tasks || task_count == 0 || task_count > UINT32_MAX) return false;
    struct eval_totals totals = {
        .r5_available = true, .r20_available = true,
        .mrr_available = true, .wrong_scope_available = true,
    };
    for (size_t t = 0; t < task_count; t++) {
        if (!task_validate(tasks, t)) return false;
        struct task_ranks ranks = {0};
        if (!task_scan(&tasks[t], out, &totals, &ranks)) return false;
        task_score(&tasks[t], &ranks, &totals);
    }
    return eval_finish(task_count, &totals, out);
}
