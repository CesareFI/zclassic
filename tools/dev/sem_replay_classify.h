/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay: what kind of change each rebuilt object carries (code,
 * or debug information only), which changed inputs any compile reads, the
 * line shifts a changed header makes, and the sensor's cost split by the
 * TUs an incremental extraction would have to sense. */
#ifndef ZCL_SEM_REPLAY_CLASSIFY_H
#define ZCL_SEM_REPLAY_CLASSIFY_H

#include "sem_replay.h"
#include "sem_replay_build.h"

/* Hard-link (else copy) every object of snap to dir/<tu>.o. The epoch
 * publishes a rebuilt object by rename, so a link keeps the old bytes. */
bool sr_keep_objects(const char *repo, const struct sr_snap *snap, const char *dir);

/* Split tus (objects whose bytes changed from before to after) by what
 * changed: code when the objects still differ after `objcopy
 * --strip-debug` (or the TU is new), debug when only debug sections
 * differ, unknown when the kept before object is missing or no longer
 * hashes to before's snapshot. Scratch objects go to tmp. */
struct sr_obj_kinds {
    struct sr_strv code, debug, unknown;
};
bool sr_classify_objects(const char *repo, const struct sr_snap *before,
                         const struct sr_snap *after, const char *keep,
                         const char *tmp, const struct sr_strv *tus,
                         const char *log, struct sr_obj_kinds *out);
void sr_obj_kinds_free(struct sr_obj_kinds *k);

/* The kind of a changed non-C input: makefile, def, doc, script, data,
 * generated or other. */
const char *sr_input_class(const char *path);

/* The TUs of pairs ("path\tTU", sorted) that read path. */
size_t sr_pairs_readers(const struct sr_strv *pairs, const char *path);
/* The changed paths of pairs that tu reads, pushed to out. */
bool sr_pairs_reads(const struct sr_strv *pairs, const char *tu, struct sr_strv *out);

/* The hunks of `git diff -U0 parent commit -- path` that shift the lines
 * after them, as "L<old line>+<delta>" words (at most eight). */
bool sr_line_shifts(const char *repo, const char *parent, const char *commit,
                    const char *path, char *out, size_t cap);

/* The after-side sensor CPU of one step (tasks.tsv), split by the TUs an
 * incremental extraction needs: those make rebuilt, those the facts plan
 * found affected, and those whose manifest bytes changed. */
struct sr_sense_split {
    double after_cpu, make_cpu, affected_cpu, manifest_cpu;
    size_t after_n, make_n, affected_n, manifest_n;
};
bool sr_sense_split(const char *tasks, const char *facts_dir,
                    const struct sr_strv *make, const struct sr_strv *affected,
                    struct sr_sense_split *out);

#endif /* ZCL_SEM_REPLAY_CLASSIFY_H */
