/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * install_selftest - declarations shared by the front-door harness
 * (install_selftest.c), its process and signal layer
 * (install_selftest_proc.c), its file and text helpers
 * (install_selftest_fs.c) and its signal qualification
 * (install_selftest_signals.c).
 */
#ifndef ZCL_INSTALL_SELFTEST_H
#define ZCL_INSTALL_SELFTEST_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

constexpr size_t ISF_HEX_LEN = 64;

/* A process environment built from KEY=VALUE strings; a later set of the
 * same key replaces the earlier one. */
struct isf_env {
    char **kv;
    size_t n;
    size_t cap;
};

/* One child: executable path, argv and environment, and the files its
 * stdout and stderr are written to (nullptr inherits). */
struct isf_job {
    const char *path;
    char *const *argv;
    char *const *envp;
    const char *out_path;
    const char *err_path;
    bool default_signals; /* reset even signals the caller ignores */
};

/* install_selftest_fs.c */
char *isf_fmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
char *isf_vfmt(const char *fmt, va_list ap);
void isf_heap_release(void);
void isf_env_set(struct isf_env *env, const char *key, const char *value);
void isf_env_add(struct isf_env *env, const char *key_value);
void isf_env_from_environ(struct isf_env *env);
bool isf_is_file(const char *path);
bool isf_file_nonempty(const char *path);
bool isf_dir_empty(const char *path);
char *isf_slurp(const char *path, size_t *len);
char *isf_slurp_trim(const char *path);
bool isf_file_has(const char *path, const char *needle);
bool isf_file_has_line(const char *path, const char *line);
bool isf_file_has_pin_line(const char *path);
bool isf_write_file(const char *path, const char *text, unsigned mode);
bool isf_copy_file(const char *src, const char *dst);
bool isf_mkdir_p(const char *path);
bool isf_rm_rf(const char *path);
bool isf_sha256_hex(const char *path, char out[ISF_HEX_LEN + 1]);
char *isf_find_in_path(const char *name, const char *path_list);
bool isf_starts_with_elf_magic(const char *path);

/* install_selftest_proc.c */
[[noreturn]] void isf_die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void isf_say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void isf_signals_init(void);
void isf_set_root(const char *path);
void isf_cleanup(void);
[[noreturn]] void isf_finish(int code);
void isf_poll(void);
void isf_nap(long ms);
long isf_now_ms(void);
pid_t isf_spawn(const struct isf_job *job);
int isf_run(const struct isf_job *job);
int isf_wait_status(pid_t pid);
bool isf_wait_readable(int fd, long timeout_ms);

/* install_selftest_signals.c */
bool isf_hold_requested(void);
int isf_signals_selftest(const char *self);
int isf_hold_main(const char *self);
[[noreturn]] void isf_hold_child(const char *mode);

#endif
