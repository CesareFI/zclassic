/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay build side: the test-fast object tree make maintains,
 * snapshots of its objects, its depfiles, each object's exact compile argv
 * (from `make -n -W`), and a bounded pool that runs the sensor and timed
 * compiles with per-child resource use. */
#ifndef ZCL_SEM_REPLAY_BUILD_H
#define ZCL_SEM_REPLAY_BUILD_H

#include "sem_replay.h"

/* One object of the live test-fast epoch, keyed by its source path. */
struct sr_obj {
    char *tu;
    uint64_t ino;
    int64_t mtime_ns;
    int64_t size;
    uint8_t hash[32];
};

struct sr_snap {
    char epoch[SR_PATH]; /* repo-relative live epoch directory */
    struct sr_obj *v;    /* sorted by tu */
    size_t n, cap;
};

/* The live epoch directory named by build/test-obj/.current-epoch. */
bool sr_epoch_dir(const char *repo, char out[SR_PATH]);

/* Snapshot every object under the live epoch whose source exists in the
 * checked-out tree (a reused epoch keeps objects of TUs other commits had).
 * An object whose inode, mtime and size equal prev's in the same epoch
 * reuses prev's hash. */
bool sr_snap_take(const char *repo, const struct sr_snap *prev,
                  struct sr_snap *out);
const struct sr_obj *sr_snap_find(const struct sr_snap *s, const char *tu);
bool sr_snap_save(const struct sr_snap *s, const char *path);
bool sr_snap_load(struct sr_snap *s, const char *path);
void sr_snap_free(struct sr_snap *s);

/* TUs of snap whose depfile names a path in files (sorted). missing
 * counts objects with no readable depfile. */
bool sr_deps_hits(const char *repo, const struct sr_snap *snap,
                  const struct sr_strv *files, struct sr_strv *out,
                  size_t *missing);

/* "path\tTU" for every TU of snap whose depfile names a path in files
 * (sorted): which compiles read each changed file. */
bool sr_deps_pairs(const char *repo, const struct sr_snap *snap,
                   const struct sr_strv *files, struct sr_strv *out);

/* The exact compile argv of each TU, from one `make -n -W <src>... <obj>...`
 * in repo. flags[i] holds the words after the recipe's "--" (the compiler
 * words included) for tus.v[i]. */
struct sr_argv_map {
    struct sr_strv tus; /* sorted */
    struct sr_strv *flags;
};
bool sr_make_argv(const char *repo, const char *epoch,
                  const struct sr_strv *tus, const char *log,
                  struct sr_argv_map *out);
const struct sr_strv *sr_argv_find(const struct sr_argv_map *m,
                                   const char *tu);
void sr_argv_free(struct sr_argv_map *m);

/* A child command for the pool: argv is NULL-terminated and owned. */
struct sr_task {
    const char *tu;
    char **argv;
    const char *log;
    double wall_s, cpu_s;
    int rc;
};

/* Run the tasks, at most jobs at a time, in cwd. Returns false only when a
 * task could not be started; each task's rc records its own exit. */
bool sr_pool_run(struct sr_task *t, size_t n, int jobs, const char *cwd);
void sr_task_free(struct sr_task *t);

#endif /* ZCL_SEM_REPLAY_BUILD_H */
