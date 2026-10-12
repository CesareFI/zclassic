/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay: the files a commit changes, and its change kind. */
#ifndef ZCL_SEM_REPLAY_CHANGE_H
#define ZCL_SEM_REPLAY_CHANGE_H

#include "sem_replay.h"

struct sr_change {
    struct sr_strv files;   /* every changed path, sorted */
    struct sr_strv added;   /* status A */
    struct sr_strv deleted; /* status D */
    struct sr_strv c_files; /* changed .c paths that exist after */
    size_t n_c, n_h, n_other;
    const char *kind; /* body-only, header, macro, new-file, build-system */
};

bool sr_git_parent(const char *repo, const char *commit, char out[64]);
bool sr_git_checkout(const char *repo, const char *rev, const char *log);
bool sr_git_head(const char *repo, char out[64]);
/* git cat-file blob <rev>:<path> into dest. */
bool sr_git_blob(const char *repo, const char *rev, const char *path,
                 const char *dest);

/* Read the change P..C and classify it. */
bool sr_change_load(const char *repo, const char *parent, const char *commit,
                    struct sr_change *out);
void sr_change_free(struct sr_change *c);

#endif /* ZCL_SEM_REPLAY_CHANGE_H */
