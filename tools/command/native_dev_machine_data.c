/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.app.machine.data and the data disk of dev.app.machine.boot.
 *
 * A data disk is the sparse file <home>/.z23/guests/<name>/data.img (directories
 * 0700, file 0600) that a guest sees as a writable block device. It is held
 * under an exclusive whole-file lock for as long as a run uses it, so a second
 * boot, a grow or a concurrent create of the same disk is refused by name.
 * Growth is offline: the file is extended while no machine holds it and the
 * guest sees the new size at its next boot. A disk never shrinks.
 * A run with a data disk is persistent and not repeatable: the receipt says so,
 * and the content of the disk is not an input of the run. */
#include "native_dev_machine_data.h"

#include "base/safe_alloc.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MD_PATH_MAX 1024u
#define MD_MIB (UINT64_C(1) << 20)

bool zcl_mb_data_name_valid(const char *name)
{
    size_t n = name != NULL ? strlen(name) : 0;
    if (n == 0 || n > MD_NAME_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        bool alnum = (name[i] >= 'a' && name[i] <= 'z') || (name[i] >= '0' && name[i] <= '9');
        if (!alnum && !(i != 0 && name[i] == '-')) return false;
    }
    return true;
}

static bool md_refuse(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                      const char *code, const char *phase, const char *message,
                      const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code, phase,
                           false, false, message, evidence);
    return false;
}

static bool md_bad_input(struct zcl_command_reply *reply, const char *message)
{
    return md_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT", "input", message,
                     "z23-dev discover schema " MD_PATH);
}

static bool md_bad_name(struct zcl_command_reply *reply)
{
    return md_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "DATA_DISK_NAME_INVALID", "input",
                     "name must match [a-z0-9][a-z0-9-]{0,31}", MD_PATH);
}

/* The home directory: the input key, else $HOME; absolute and bounded. */
static const char *md_home(const char *given, struct zcl_command_reply *reply)
{
    const char *home = given != NULL ? given : getenv("HOME");
    if (home == NULL || home[0] != '/' || strlen(home) > MD_PATH_MAX / 2u) {
        (void)md_bad_input(reply, "home must be an absolute path of at most 512 bytes");
        return NULL;
    }
    return home;
}

static bool md_paths(const char *home, const char *name, char *dir, char *file,
                     struct zcl_command_reply *reply)
{
    int d = snprintf(dir, MD_PATH_MAX, "%s/.z23/guests/%s", home, name);
    int f = snprintf(file, MD_PATH_MAX, "%s/.z23/guests/%s/data.img", home, name);
    if (d > 0 && f > 0 && (size_t)f < MD_PATH_MAX) return true;
    return md_bad_input(reply, "home is too long");
}

/* Data disks need owner-private directories checked without following
 * symlinks. That check exists for POSIX hosts only, so Windows refuses every
 * data disk request by name before any path is touched. */
static bool md_host_unsupported(struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_UNSUPPORTED_HOST", "host",
                    "guest data disks are not available on Windows hosts", MD_PATH);
    return true;
#else
    (void)reply;
    return false;
#endif
}

/* A real directory (never a symlink) owned by the effective user. strict also
 * requires that group and others have no access. */
static bool md_dir_real(const char *level, bool strict)
{
#if !defined(_WIN32)
    struct stat sb;
    int fd = open(level, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool ok;
    if (fd < 0) return false;
    ok = fstat(fd, &sb) == 0 && S_ISDIR(sb.st_mode) && sb.st_uid == geteuid() &&
         (!strict || (sb.st_mode & 0077) == 0);
    close(fd);
    return ok;
#else
    (void)level;
    (void)strict;
    return false;
#endif
}

static bool md_dirs_refused(struct zcl_command_reply *reply, const char *where, const char *phase)
{
    return md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_DIRECTORY_REFUSED", phase,
                     "a directory on the path is a symlink, foreign-owned or not owner-private",
                     where);
}

/* ~/.z23 is shared with other tools and may be 0755, so it is only required to
 * be a real directory of the user; guests and the disk directory are 0700. */
static bool md_ensure_dirs(const char *home, const char *dir, struct zcl_command_reply *reply)
{
    char level[MD_PATH_MAX];
    snprintf(level, sizeof level, "%s/.z23", home);
    if (platform_private_path_absent(level) ? !platform_private_directory_create(level)
                                            : !md_dir_real(level, false))
        return md_dirs_refused(reply, dir, "create");
    snprintf(level, sizeof level, "%s/.z23/guests", home);
    if (!platform_private_directory_ensure(level) || !platform_private_directory_ensure(dir))
        return md_dirs_refused(reply, dir, "create");
    return true;
}

/* The file's own attributes, never those of a symlink target. */
static bool md_stat_nofollow(const char *path, struct stat *sb)
{
#if !defined(_WIN32)
    return lstat(path, sb) == 0;
#else
    (void)path;
    (void)sb;
    errno = ENOTSUP;
    return false;
#endif
}

enum md_levels { MD_LEVELS_OK, MD_LEVELS_ABSENT, MD_LEVELS_REFUSED };

/* Validates .z23, guests and the disk directory in order without creating any. */
static enum md_levels md_levels_check(const char *home, const char *name)
{
    static const char *const fmt[] = {"%s/.z23", "%s/.z23/guests", "%s/.z23/guests/%s"};
    char level[MD_PATH_MAX];
    struct stat sb;
    for (int i = 0; i < 3; i++) {
        snprintf(level, sizeof level, fmt[i], home, name);
        if (!md_stat_nofollow(level, &sb))
            return errno == ENOENT ? MD_LEVELS_ABSENT : MD_LEVELS_REFUSED;
        if (!md_dir_real(level, i != 0)) return MD_LEVELS_REFUSED;
    }
    return MD_LEVELS_OK;
}

/* Bytes the file occupies on the host; a sparse file occupies less than its size. */
static int64_t md_allocated_bytes(const struct stat *sb)
{
#if !defined(_WIN32)
    return (int64_t)sb->st_blocks * 512;
#else
    return (int64_t)sb->st_size;
#endif
}

static bool md_file_private(const struct stat *sb)
{
#if !defined(_WIN32)
    return S_ISREG(sb->st_mode) && sb->st_uid == geteuid() && sb->st_nlink == 1;
#else
    (void)sb;
    return false;
#endif
}

static bool md_not_regular(struct zcl_command_reply *reply, const char *phase, const char *name)
{
    return md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_NOT_REGULAR", phase,
                     "data.img is not a regular file of this user with a single link", name);
}

static bool md_absent(struct zcl_command_reply *reply, const char *phase, const char *message,
                      const char *name)
{
    return md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_ABSENT", phase, message, name);
}

/* Classifies the directories and the file of an existing disk before it is
 * opened. True when the file exists and is a private regular file. */
static bool md_precheck(const char *home, const char *name, const char *dir, const char *path,
                        const char *phase, struct stat *sb, struct zcl_command_reply *reply)
{
    enum md_levels levels = md_levels_check(home, name);
    if (levels == MD_LEVELS_ABSENT)
        return md_absent(reply, phase, "no data disk of that name exists; create it first", name);
    if (levels == MD_LEVELS_REFUSED) return md_dirs_refused(reply, dir, phase);
    if (!md_stat_nofollow(path, sb))
        return errno == ENOENT
                   ? md_absent(reply, phase, "no data disk of that name exists; create it first",
                               name)
                   : md_not_regular(reply, phase, name);
    return md_file_private(sb) || md_not_regular(reply, phase, name);
}

/* ---- the locked file and its backend callbacks ---- */

bool zcl_mb_data_read_cb(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct zcl_mb_data_file *f = ctx;
    return platform_private_file_read_at(&f->file, buf, n, off);
}

bool zcl_mb_data_write_cb(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct zcl_mb_data_file *f = ctx;
    return platform_private_file_write_at(&f->file, buf, n, off);
}

bool zcl_mb_data_flush_cb(void *ctx)
{
    struct zcl_mb_data_file *f = ctx;
    return platform_private_file_flush(&f->file);
}

uint64_t zcl_mb_data_file_bytes(const struct zcl_mb_data_file *file)
{
    return file != NULL ? file->bytes : 0;
}

void zcl_mb_data_close(struct zcl_mb_data_file *file)
{
    if (file == NULL) return;
    platform_private_file_close(&file->file);
    free(file);
}

struct zcl_mb_data_file *zcl_mb_data_open(const char *home, const char *name,
                                          struct zcl_command_reply *reply)
{
    char dir[MD_PATH_MAX], path[MD_PATH_MAX];
    struct stat sb;
    struct zcl_mb_data_file *f;
    if (md_host_unsupported(reply)) return NULL;
    if (!zcl_mb_data_name_valid(name)) {
        (void)md_bad_name(reply);
        return NULL;
    }
    if (!md_paths(home, name, dir, path, reply)) return NULL;
    if (!md_precheck(home, name, dir, path, "open", &sb, reply)) return NULL;
    f = zcl_calloc(1, sizeof *f, "machine_data_file");
    if (f == NULL) {
        (void)md_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY", "open",
                        "the data disk state could not be allocated", name);
        return NULL;
    }
    platform_private_file_init(&f->file);
    if (!platform_private_file_open_locked(path, &f->file)) {
        bool held = errno == EWOULDBLOCK || errno == EAGAIN;
        free(f);
        (void)md_refuse(reply, ZCL_COMMAND_EXIT_FAILED,
                        held ? "DATA_DISK_LOCKED" : "DATA_DISK_OPEN_FAILED", "open",
                        held ? "the data disk is held by another run"
                             : "the data disk could not be opened for reading and writing",
                        name);
        return NULL;
    }
    if (fstat((int)f->file.native, &sb) != 0 || !md_file_private(&sb) ||
        !platform_private_file_size(&f->file, &f->bytes)) {
        zcl_mb_data_close(f);
        (void)md_not_regular(reply, "open", name);
        return NULL;
    }
    return f;
}

/* ---- dev.app.machine.data ---- */

static void md_success(struct zcl_command_reply *reply, const char *action, const char *name,
                       uint64_t bytes)
{
    (void)json_push_kv_str(&reply->data, "action", action);
    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)bytes);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static bool md_size_bytes(const struct json_value *in, uint64_t *bytes,
                          struct zcl_command_reply *reply)
{
    const struct json_value *v = json_get(in, "size_mib");
    if (v == NULL || v->type != JSON_INT || json_get_int(v) < 1)
        return md_bad_input(reply, "size_mib must be a positive integer");
    if (json_get_int(v) > MD_SIZE_MIB_MAX)
        return md_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "DATA_DISK_TOO_LARGE", "input",
                         "size_mib is above the 1 TiB limit", MD_PATH);
    *bytes = (uint64_t)json_get_int(v) * MD_MIB;
    return true;
}

static void md_create(const char *home, const char *name, uint64_t bytes,
                      struct zcl_command_reply *reply)
{
    char dir[MD_PATH_MAX], path[MD_PATH_MAX];
    struct platform_private_file file;
    bool ok;
    if (!md_paths(home, name, dir, path, reply) || !md_ensure_dirs(home, dir, reply)) return;
    platform_private_file_init(&file);
    if (!platform_private_file_create_locked(path, &file)) {
        (void)md_refuse(reply, ZCL_COMMAND_EXIT_FAILED,
                        platform_private_path_absent(path) ? "DATA_DISK_CREATE_FAILED" :
                                                             "DATA_DISK_EXISTS",
                        "create", "the data disk could not be created exclusively", name);
        return;
    }
    ok = platform_private_file_truncate(&file, bytes) && platform_private_file_flush(&file) &&
         platform_private_parent_flush(dir);
    platform_private_file_close(&file);
    if (!ok) {
        (void)platform_private_file_unlink_missing_ok(path);
        (void)md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_CREATE_FAILED", "create",
                        "the data disk could not be sized; nothing was kept", name);
        return;
    }
    md_success(reply, "create", name, bytes);
}

static void md_grow(const char *home, const char *name, uint64_t bytes,
                    struct zcl_command_reply *reply)
{
    struct zcl_mb_data_file *f = zcl_mb_data_open(home, name, reply);
    uint64_t before;
    if (f == NULL) return;
    before = f->bytes;
    if (bytes <= before) {
        (void)md_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "DATA_DISK_SHRINK_REFUSED", "grow",
                        "size_mib must be larger than the current size; a disk never shrinks",
                        name);
    } else if (!platform_private_file_truncate(&f->file, bytes) ||
               !platform_private_file_flush(&f->file)) {
        (void)md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_GROW_FAILED", "grow",
                        "the data disk could not be extended", name);
    } else {
        md_success(reply, "grow", name, bytes);
        (void)json_push_kv_int(&reply->data, "previous_bytes", (int64_t)before);
    }
    zcl_mb_data_close(f);
}

static void md_status(const char *home, const char *name, struct zcl_command_reply *reply)
{
    char dir[MD_PATH_MAX], path[MD_PATH_MAX];
    struct platform_private_file probe;
    struct stat sb;
    const char *state = "free";
    if (!md_paths(home, name, dir, path, reply) ||
        !md_precheck(home, name, dir, path, "status", &sb, reply))
        return;
    platform_private_file_init(&probe);
    if (platform_private_file_open_observation(path, &probe)) platform_private_file_close(&probe);
    else state = errno == EWOULDBLOCK || errno == EAGAIN ? "locked" : "unavailable";
    md_success(reply, "status", name, (uint64_t)sb.st_size);
    (void)json_push_kv_int(&reply->data, "allocated_bytes", md_allocated_bytes(&sb));
    (void)json_push_kv_bool(&reply->data, "locked", strcmp(state, "locked") == 0);
    (void)json_push_kv_str(&reply->data, "state", state);
}

/* The request's strings; NULL when a key is absent. */
struct md_request {
    const char *action, *name, *home;
};

static const char *md_str(const struct json_value *in, const char *key)
{
    const struct json_value *v = json_get(in, key);
    return v != NULL ? json_get_str(v) : NULL;
}

static bool md_action_valid(const char *action)
{
    return action != NULL && (strcmp(action, "create") == 0 || strcmp(action, "grow") == 0 ||
                              strcmp(action, "status") == 0);
}

static void md_run(const struct json_value *in, const struct md_request *r, const char *home,
                   struct zcl_command_reply *reply)
{
    uint64_t bytes = 0;
    if (strcmp(r->action, "status") == 0) md_status(home, r->name, reply);
    else if (!md_size_bytes(in, &bytes, reply)) return;
    else if (strcmp(r->action, "create") == 0) md_create(home, r->name, bytes, reply);
    else md_grow(home, r->name, bytes, reply);
}

void zcl_native_handle_dev_machine_data(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
    const struct json_value *in = request != NULL ? request->input : NULL;
    struct md_request r;
    const char *home;
    if (reply == NULL) return;
    if (md_host_unsupported(reply)) return;
    if (in == NULL || in->type != JSON_OBJ) {
        (void)md_bad_input(reply, "input must be one JSON object");
        return;
    }
    r = (struct md_request){md_str(in, "action"), md_str(in, "name"), md_str(in, "home")};
    if (!md_action_valid(r.action)) {
        (void)md_bad_input(reply, "action must be create, grow or status");
        return;
    }
    if (!zcl_mb_data_name_valid(r.name)) {
        (void)md_bad_name(reply);
        return;
    }
    home = md_home(r.home, reply);
    if (home != NULL) md_run(in, &r, home, reply);
}

/* ---- boot hooks ---- */

/* One run at a time may hold a data disk in this process; the fields other
 * than the owner belong to that run. */
static struct {
    _Atomic(const void *) owner;
    char home[MD_PATH_MAX / 2u + 1u];
    char name[MD_NAME_MAX + 1u];
    struct zcl_mb_data_file *file;
    bool attached;
} md_hold;

bool zcl_mb_data_parse(const void *owner, const struct json_value *in,
                       struct zcl_command_reply *reply)
{
    const char *name = NULL, *given = NULL, *home;
    const struct json_value *n = json_get(in, "data_disk"), *h = json_get(in, "home");
    const void *none = NULL;
    if (n == NULL && h == NULL) return true;
    if (n == NULL) return md_bad_input(reply, "home needs data_disk");
    if (json_get(in, "public_unlock") != NULL)
        return md_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "DATA_DISK_NOT_AVAILABLE", "input",
                         "data_disk is not attached under the PUBLIC owner", MD_PATH);
    if (n->type != JSON_STR || (name = json_get_str(n)) == NULL || !zcl_mb_data_name_valid(name))
        return md_bad_name(reply);
    if (h != NULL && (h->type != JSON_STR || (given = json_get_str(h)) == NULL))
        return md_bad_input(reply, "home must be an absolute path");
    home = md_home(given, reply);
    if (home == NULL) return false;
    if (!atomic_compare_exchange_strong(&md_hold.owner, &none, owner))
        return md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_LOCKED", "setup",
                         "another run in this process holds a data disk", name);
    snprintf(md_hold.home, sizeof md_hold.home, "%s", home);
    snprintf(md_hold.name, sizeof md_hold.name, "%s", name);
    return true;
}

bool zcl_mb_data_attach(const void *owner, struct rvmachine_disk **out,
                        struct zcl_command_reply *reply)
{
    enum rvmachine_status status;
    if (atomic_load(&md_hold.owner) != owner) return true;
    md_hold.file = zcl_mb_data_open(md_hold.home, md_hold.name, reply);
    if (md_hold.file == NULL) return false;
    if (md_hold.file->bytes > RVMACHINE_DISK_BYTES_MAX)
        return md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_TOO_LARGE", "attach",
                         "the data disk is above the 1 TiB limit", md_hold.name);
    status = rvmachine_disk_open_backend(out, md_hold.file->bytes, zcl_mb_data_read_cb,
                                         zcl_mb_data_write_cb, zcl_mb_data_flush_cb,
                                         md_hold.file);
    if (status != RVMACHINE_OK)
        return md_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "DATA_DISK_ATTACH_FAILED", "attach",
                         rvmachine_status_name(status), md_hold.name);
    md_hold.attached = true;
    return true;
}

void zcl_mb_data_emit(const void *owner, struct json_value *data)
{
    struct json_value row;
    if (atomic_load(&md_hold.owner) != owner || !md_hold.attached) return;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "name", md_hold.name);
    (void)json_push_kv_int(&row, "bytes", (int64_t)md_hold.file->bytes);
    (void)json_push_kv_bool(&row, "persistent", true);
    (void)json_push_kv_bool(&row, "repeatable", false);
    (void)json_push_kv(data, "data_disk", &row);
    json_free(&row);
}

void zcl_mb_data_release(const void *owner)
{
    if (atomic_load(&md_hold.owner) != owner) return;
    if (md_hold.file != NULL) (void)platform_private_file_flush(&md_hold.file->file);
    zcl_mb_data_close(md_hold.file);
    md_hold.file = NULL;
    md_hold.attached = false;
    atomic_store(&md_hold.owner, NULL);
}
