/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay: replay real commits through the incremental test-fast
 * object build, the libclang semantic sensor and dev.change.plan, and
 * measure what the facts plan saves against what make recompiled and what
 * object bytes actually changed. docs/work/SEMANTIC_MANIFEST.md
 * ("Replay on real history") describes the method and its bounds.
 *
 * External tool: it drives git, make (through devbuild when present), the
 * sensor and a z23-dev planner as child processes and links only libc,
 * SHA3 and the zjsonp pull parser. */
#ifndef ZCL_SEM_REPLAY_H
#define ZCL_SEM_REPLAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SR_PATH 4096

/* A growable list of owned strings. */
struct sr_strv {
    char **v;
    size_t n, cap;
};

bool sr_strv_push(struct sr_strv *s, const char *str);
bool sr_strv_pushn(struct sr_strv *s, const char *str, size_t len);
void sr_strv_sort_unique(struct sr_strv *s);
bool sr_strv_has(const struct sr_strv *s, const char *str); /* sorted */
void sr_strv_clear(struct sr_strv *s);
void sr_strv_free(struct sr_strv *s);

/* Resource use of one child process tree, from wait4. */
struct sr_cost {
    double wall_s;
    double cpu_s; /* user + system */
};

/* Run argv in cwd (NULL: inherit) with stdout and stderr appended to log
 * (NULL: inherit). env is NULL or a NULL-terminated "K=V" list added to the
 * environment. Returns the exit status, or -1 when the child did not exit
 * normally or could not start. */
int sr_run(char *const argv[], const char *cwd, const char *log,
           char *const env[], struct sr_cost *cost);

/* Run argv in cwd and capture its stdout (stderr goes to log, or is
 * inherited when log is NULL). On successful reading, *out is NUL-terminated
 * and owned. On setup or read failure, returns -1 with *out NULL and *len 0. */
int sr_capture(char *const argv[], const char *cwd, const char *log,
               char **out, size_t *len);

/* Success publishes owned NUL-terminated bytes. Refusal leaves *out NULL
 * and *len 0. On refusal errno identifies the open/read failure (EIO when
 * the reader supplies no error code); ENOENT identifies an absent path. */
bool sr_read_file(const char *path, char **out, size_t *len);
bool sr_write_file(const char *path, const char *data, size_t len);
bool sr_mkdirs(const char *path); /* mkdir -p */
bool sr_mkparent(const char *path);
bool sr_rmtree(const char *path);
bool sr_exists(const char *path);
bool sr_hash_file(const char *path, uint8_t out[32]);
void sr_hex(const uint8_t in[32], char out[65]);
double sr_now(void);

/* POSIX-sh word splitting of one recipe line (quotes and backslashes; no
 * expansions). Appends the words to out. */
bool sr_split_words(const char *line, size_t len, struct sr_strv *out);

/* Flatten a JSON document: cb(path, value) for every scalar, where path
 * joins object keys with '.' and writes each array index as "[]"; value is
 * the decoded string, or the raw number/true/false/null text. Refuse decoded
 * NUL in keys or strings and string decode/allocation failures. Callbacks
 * already made before refusal are not rolled back. */
typedef void (*sr_json_cb)(void *ctx, const char *path, const char *value);
bool sr_json_flatten(const char *text, size_t len, sr_json_cb cb, void *ctx);

/* Observe completed containers before popping their paths. Decode refusal
 * stops callbacks; previously completed containers remain observed. */
typedef void (*sr_json_close_cb)(void *ctx, const char *path);
bool sr_json_flatten_with_close(const char *text, size_t len, sr_json_cb cb,
                               sr_json_close_cb close_cb, void *ctx);

#endif /* ZCL_SEM_REPLAY_H */
