/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.app.machine.shell - boot a RISC-V kernel in the built-in
 *          machine and connect its console to the caller's terminal.
 *
 * Unlike dev.app.machine.boot this run is interactive and not repeatable: the
 * console input is whatever the caller types, the guest's idle time passes in
 * real time, and the entropy device and the boot seed come from the host OS
 * CSPRNG. The machine is built here on the rvmachine API, with the same input
 * rules as the boot command for the fields they share:
 *   1. the kernel and the optional disk are opened read-only without
 *      following a final symlink, and their identity is taken from the handle;
 *   2. the optional receipt file is created exclusively before the guest
 *      starts, so an existing path is refused and nothing is overwritten;
 *   3. the session runs (native_dev_machine_shell_session.c);
 *   4. the inputs are compared with their identity again.
 * The command framework prints the result envelope on stdout after the
 * session; it follows the console bytes, which end with a newline. */

#include "command/native_command.h"

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "native_dev_machine_shell.h"
#include "platform/positioned_file.h"
#include "platform/rng.h"
#include "rvmachine/rvmachine.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

#define MS_PATH "dev.app.machine.shell"
#define MS_KERNEL_MAX (UINT64_C(1) << 30)
#define MS_RAM_MIB_DEFAULT 1024
#define MS_EOF_QUIET_DEFAULT_MS 5000
#define MS_READ_CHUNK (1u << 20)
#define MS_RECEIPT_MAX 8192u

struct ms_file {
    const char *path; /* NULL when not given */
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before;
    bool changed;
};

struct ms_opts {
    struct ms_file kernel, disk;
    const char *bootargs, *receipt;
    int64_t ram_mib, max_instr, eof_quiet_ms;
    uint8_t escape;
    bool pipe;
};

struct ms_state {
    struct ms_opts o;
    struct ms_session s;
    struct rvmachine *m;
    int receipt_fd;
    bool elf;
    bool entropy_failed;
    uint64_t entropy_bytes, seed_bytes;
};

#ifdef ZCL_TESTING
static int g_test_in = -1, g_test_out = -1;
static bool g_test_stdin_input;
void zcl_ms_test_fds(int in_fd, int out_fd)
{
    g_test_in = in_fd;
    g_test_out = out_fd;
}

void zcl_ms_test_input_on_stdin(bool on)
{
    g_test_stdin_input = on;
}
#endif

static bool ms_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                    const char *code, const char *phase, const char *message,
                    const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code, phase, false,
                           false, message, evidence);
    return false;
}

static bool ms_bad_input(struct zcl_command_reply *reply, const char *message)
{
    return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT", "input", message,
                   "z23-dev discover schema " MS_PATH);
}

/* ---- input ---- */

/* An optional string member; the string may be empty. False when present with
 * another type. */
static bool ms_opt_str(const struct json_value *value, const char **out)
{
    *out = NULL;
    if (value == NULL || value->type == JSON_NULL) return true;
    if (value->type != JSON_STR) return false;
    *out = json_get_str(value);
    return *out != NULL;
}

/* An optional non-empty string member, refused by name when it has another
 * type or is empty. */
static bool ms_text_member(const struct json_value *in, const char *key, const char **out,
                           struct zcl_command_reply *reply)
{
    char why[96];
    if (ms_opt_str(json_get(in, key), out) && (*out == NULL || (*out)[0] != '\0')) return true;
    snprintf(why, sizeof why, "%s must be a non-empty string; omit it for none", key);
    return ms_bad_input(reply, why);
}

static bool ms_opt_int(const struct json_value *value, int64_t fallback, int64_t lo, int64_t hi,
                       int64_t *out)
{
    *out = fallback;
    if (value == NULL || value->type == JSON_NULL) return true;
    if (value->type != JSON_INT) return false;
    *out = json_get_int(value);
    return *out >= lo && *out <= hi;
}

/* escape: one letter (either case) or one of \ ] ^ _ naming a control key,
 * default "]" (Ctrl-]). The letters h, i, j and m are refused: they are the
 * backspace, tab, line feed and carriage return controls. */
static bool ms_parse_escape(const struct json_value *value, uint8_t *out)
{
    const char *text = NULL;
    unsigned char c;
    bool letter, symbol;
    *out = 0x1du;
    if (value == NULL || value->type == JSON_NULL) return true;
    if (!ms_opt_str(value, &text) || text[0] == '\0' || text[1] != '\0') return false;
    c = (unsigned char)text[0];
    letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    symbol = c >= 0x5cu && c <= 0x5fu;
    if (!letter && !symbol) return false;
    *out = c & 0x1fu;
    return *out != 0x08u && *out != 0x09u && *out != 0x0au && *out != 0x0du;
}

static bool ms_parse_stdio(const struct json_value *value, bool *pipe)
{
    const char *text = NULL;
    *pipe = false;
    if (!ms_opt_str(value, &text)) return false;
    if (text == NULL) return true;
    *pipe = strcmp(text, "pipe") == 0;
    return *pipe;
}

static bool ms_parse_numbers(const struct json_value *in, struct ms_opts *o,
                             struct zcl_command_reply *reply)
{
    if (!ms_opt_int(json_get(in, "ram_mib"), MS_RAM_MIB_DEFAULT, 64, 65536, &o->ram_mib) ||
        o->ram_mib % 2 != 0)
        return ms_bad_input(reply, "ram_mib must be an even integer in 64..65536");
    if (!ms_opt_int(json_get(in, "max_instr"), 0, 1, INT64_MAX, &o->max_instr))
        return ms_bad_input(reply, "max_instr must be a positive integer");
    if (!ms_opt_int(json_get(in, "eof_quiet_ms"), MS_EOF_QUIET_DEFAULT_MS, 0, 3600000,
                    &o->eof_quiet_ms))
        return ms_bad_input(reply, "eof_quiet_ms must be an integer in 0..3600000");
    return true;
}

static bool ms_parse(const struct json_value *in, struct ms_opts *o,
                     struct zcl_command_reply *reply)
{
    if (in == NULL || in->type != JSON_OBJ)
        return ms_bad_input(reply, "input must be one JSON object");
    if (!ms_text_member(in, "kernel", &o->kernel.path, reply)) return false;
    if (o->kernel.path == NULL)
        return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, "KERNEL_REQUIRED", "input",
                       "kernel is required: the path of a kernel image",
                       "z23-dev discover schema " MS_PATH);
    if (!ms_text_member(in, "disk", &o->disk.path, reply) ||
        !ms_text_member(in, "bootargs", &o->bootargs, reply) ||
        !ms_text_member(in, "receipt", &o->receipt, reply))
        return false;
    if (o->bootargs != NULL && strlen(o->bootargs) >= RVMACHINE_BOOTARGS_MAX)
        return ms_bad_input(reply, "bootargs must be at most 511 bytes");
    if (!ms_parse_stdio(json_get(in, "stdio"), &o->pipe))
        return ms_bad_input(reply, "stdio must be \"pipe\" when given");
    if (!ms_parse_escape(json_get(in, "escape"), &o->escape))
        return ms_bad_input(reply, "escape must be one letter other than h, i, j or m, "
                                   "or one of \\ ] ^ _");
    return ms_parse_numbers(in, o, reply);
}

/* ---- files ---- */

static bool ms_open_input(struct ms_file *f, const char *what, struct zcl_command_reply *reply)
{
    char evidence[256];
    if (f->path == NULL) return true;
    if (platform_positioned_file_open(&f->file, f->path) &&
        platform_positioned_file_snapshot(&f->file, &f->before) && f->before.size != 0)
        return true;
    snprintf(evidence, sizeof evidence, "%s: %.200s", what, f->path);
    return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "INPUT_UNREADABLE", "open",
                   "an input is not a readable, non-empty regular file (a final symlink is "
                   "not followed)", evidence);
}

static bool ms_read_at(void *ctx, uint64_t off, void *buf, size_t n)
{
    const struct ms_file *f = ctx;
    uint8_t *out = buf;
    while (n != 0) {
        size_t want = n < MS_READ_CHUNK ? n : MS_READ_CHUNK;
        int64_t got = platform_positioned_file_read(&f->file, out, want, off);
        if (got <= 0) return false;
        out += got;
        off += (uint64_t)got;
        n -= (size_t)got;
    }
    return true;
}

static uint8_t *ms_read_kernel(struct ms_file *f)
{
    uint8_t *image;
    if (f->before.size > MS_KERNEL_MAX) return NULL;
    image = zcl_malloc((size_t)f->before.size, "machine_shell_kernel");
    if (image != NULL && !ms_read_at(f, 0, image, (size_t)f->before.size)) {
        free(image);
        return NULL;
    }
    return image;
}

static void ms_recheck(struct ms_file *f)
{
    struct platform_positioned_file_snapshot now;
    if (f->path == NULL) return;
    f->changed = !platform_positioned_file_snapshot(&f->file, &now) ||
                 !platform_positioned_file_snapshot_equal(&f->before, &now);
}

/* The receipt file is created before the guest starts. */
static bool ms_open_receipt(struct ms_state *st, struct zcl_command_reply *reply)
{
    if (st->o.receipt == NULL) return true;
    st->receipt_fd = open(st->o.receipt,
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_BINARY, 0600);
    if (st->receipt_fd >= 0) return true;
    return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RECEIPT_UNWRITABLE", "open",
                   "the receipt path exists or cannot be created", st->o.receipt);
}

static bool ms_write_receipt(struct ms_state *st, const struct json_value *data)
{
    char text[MS_RECEIPT_MAX];
    size_t len, done = 0;
    if (st->receipt_fd < 0) return true;
    len = json_write(data, text, sizeof text - 1u);
    if (len >= sizeof text - 1u) return false;
    text[len++] = '\n';
    while (done < len) {
        ssize_t w = write(st->receipt_fd, text + done, len - done);
        if (w <= 0 && errno != EINTR) return false;
        if (w > 0) done += (size_t)w;
    }
    return true;
}

/* ---- the terminal ---- */

/* The leaf's own input must not have come from stdin, which is the console. */
static bool ms_input_on_stdin(void)
{
#ifdef ZCL_TESTING
    if (g_test_stdin_input) return true;
#endif
    return zcl_native_input_was_stdin();
}

static bool ms_check_stdio(struct ms_state *st, struct zcl_command_reply *reply)
{
    int in_fd = STDIN_FILENO, out_fd = STDOUT_FILENO;
#ifdef ZCL_TESTING
    if (g_test_in >= 0) in_fd = g_test_in;
    if (g_test_out >= 0) out_fd = g_test_out;
#endif
    st->s.in_fd = in_fd;
    st->s.out_fd = out_fd;
    if (ms_input_on_stdin())
        return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INPUT_ON_STDIN", "input",
                       "stdin carries the console; give the input as an argument, not --input=-",
                       MS_PATH);
    if (!st->o.pipe && !(isatty(in_fd) && isatty(out_fd)))
        return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, "NOT_A_TERMINAL", "input",
                       "stdin and stdout must be terminals; pass \"stdio\":\"pipe\" to "
                       "connect them to the console as plain byte streams", MS_PATH);
    st->s.tty = !st->o.pipe;
    return true;
}

/* ---- entropy ---- */

static size_t ms_entropy(void *ctx, uint8_t *buf, size_t n)
{
    struct ms_state *st = ctx;
    size_t done = 0;
    while (!st->entropy_failed && done < n) {
        size_t take = n - done < 4096u ? n - done : 4096u;
        if (!rng_host_fill(buf + done, take)) st->entropy_failed = true;
        else done += take;
    }
    if (st->entropy_failed) {
        memory_cleanse(buf, n);
        return 0;
    }
    st->entropy_bytes += n;
    return n;
}

static bool ms_boot_seed(void *ctx, uint8_t *buf, size_t n, size_t *got)
{
    struct ms_state *st = ctx;
    *got = 0;
    if (!rng_host_fill(buf, n)) {
        st->entropy_failed = true;
        return false;
    }
    st->seed_bytes = n;
    *got = n;
    return true;
}

/* ---- machine ---- */

static bool ms_machine_fail(struct zcl_command_reply *reply, const char *phase,
                            enum rvmachine_status status)
{
    return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "MACHINE_REFUSED", phase,
                   rvmachine_status_name(status), MS_PATH);
}

/* Builds the machine over the open disk and loads the kernel. The boot seed is
 * offered to an ELF kernel only; a flat image has no loader entry to take it. */
static bool ms_build(struct ms_state *st, const uint8_t *image, size_t len,
                     struct zcl_command_reply *reply)
{
    struct rvmachine_config config = {
        .ram_bytes = (uint64_t)st->o.ram_mib << 20, .bootargs = st->o.bootargs,
        .console = ms_console, .console_ctx = &st->s,
        .entropy = ms_entropy, .entropy_ctx = st, .entropy_fail_closed = true,
        .wait_stops = true,
        .boot_seed = st->elf ? ms_boot_seed : NULL, .boot_seed_ctx = st};
    enum rvmachine_status status = RVMACHINE_OK;
    if (st->o.disk.path != NULL)
        status = rvmachine_disk_open(&config.disk, st->o.disk.before.size, ms_read_at, &st->o.disk);
    if (status != RVMACHINE_OK) return ms_machine_fail(reply, "disk", status);
    status = rvmachine_create(&st->m, &config);
    if (status != RVMACHINE_OK) {
        rvmachine_disk_close(config.disk);
        return ms_machine_fail(reply, "create", status);
    }
    st->s.m = st->m;
    status = rvmachine_load_kernel(st->m, image, len);
    if (status == RVMACHINE_OK) return true;
    if (st->entropy_failed)
        return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "ENTROPY_SOURCE_FAILED", "load",
                       "the host OS entropy source refused the boot seed; no fallback was used",
                       MS_PATH);
    return ms_machine_fail(reply, "load", status);
}

static bool ms_prepare(struct ms_state *st, struct zcl_command_reply *reply)
{
    uint8_t *image;
    bool ok;
    if (!ms_open_input(&st->o.kernel, "kernel", reply) ||
        !ms_open_input(&st->o.disk, "disk", reply))
        return false;
    image = ms_read_kernel(&st->o.kernel);
    if (image == NULL)
        return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "INPUT_UNREADABLE", "open",
                       "the kernel could not be read in full or is over 1 GiB", st->o.kernel.path);
    st->elf = st->o.kernel.before.size >= 4u && memcmp(image, "\x7f" "ELF", 4) == 0;
    ok = ms_build(st, image, (size_t)st->o.kernel.before.size, reply) &&
         ms_open_receipt(st, reply);
    free(image);
    return ok;
}

/* ---- the result ---- */

static void ms_emit_file(struct json_value *inputs, const char *name, const struct ms_file *f)
{
    struct json_value row;
    if (f->path == NULL) return;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_int(&row, "size", (int64_t)f->before.size);
    (void)json_push_kv_bool(&row, "changed", f->changed);
    (void)json_push_kv(inputs, name, &row);
    json_free(&row);
}

static const char ms_seed_host[] = "host";
static const char ms_seed_flat[] = "not_offered_flat_image";

static void ms_emit_entropy(const struct ms_state *st, struct json_value *data)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "source", "host_os_csprng");
    (void)json_push_kv_str(&row, "guest_rng_health", "unobserved");
    (void)json_push_kv_int(&row, "device_bytes", (int64_t)st->entropy_bytes);
    (void)json_push_kv_int(&row, "boot_seed_bytes", (int64_t)st->seed_bytes);
    (void)json_push_kv_str(&row, "boot_seed", st->elf ? ms_seed_host : ms_seed_flat);
    (void)json_push_kv_bool(&row, "source_failed", st->entropy_failed);
    (void)json_push_kv(data, "entropy", &row);
    json_free(&row);
}

static void ms_emit(const struct ms_state *st, struct json_value *data)
{
    const struct ms_session *s = &st->s;
    struct json_value inputs;
    (void)json_push_kv_bool(data, "interactive", true);
    (void)json_push_kv_bool(data, "deterministic", false);
    (void)json_push_kv_str(data, "end", ms_end_name(s->end));
    if (s->end == MS_END_SIGNAL) (void)json_push_kv_int(data, "signal", s->signo);
    (void)json_push_kv_str(data, "stop", rvmachine_stop_name(s->res.stop));
    (void)json_push_kv_str(data, "stdio", st->o.pipe ? "pipe" : "terminal");
    (void)json_push_kv_int(data, "retired", (int64_t)s->res.retired);
    (void)json_push_kv_int(data, "skip", (int64_t)s->res.skip);
    (void)json_push_kv_int(data, "fw_calls", (int64_t)s->res.fw_calls);
    (void)json_push_kv_int(data, "device_work", (int64_t)s->res.device_work);
    (void)json_push_kv_int(data, "guest_time", (int64_t)s->res.guest_time);
    (void)json_push_kv_int(data, "timebase_hz", RVMACHINE_TIMEBASE_HZ);
    (void)json_push_kv_int(data, "bytes_in", (int64_t)s->bytes_in);
    (void)json_push_kv_int(data, "bytes_out", (int64_t)s->bytes_out);
    (void)json_push_kv_int(data, "ram_mib", st->o.ram_mib);
    json_init(&inputs);
    json_set_object(&inputs);
    ms_emit_file(&inputs, "kernel", &st->o.kernel);
    ms_emit_file(&inputs, "disk", &st->o.disk);
    (void)json_push_kv(data, "inputs", &inputs);
    json_free(&inputs);
    ms_emit_entropy(st, data);
}

static void ms_evidence(const struct ms_state *st, char *out, size_t cap)
{
    const struct rvmachine_result *r = &st->s.res;
    snprintf(out, cap, "end=%s stop=%s retired=%llu bytes_in=%llu bytes_out=%llu "
             "pc=0x%llx cause=0x%llx tval=0x%llx", ms_end_name(st->s.end),
             rvmachine_stop_name(r->stop), (unsigned long long)r->retired,
             (unsigned long long)st->s.bytes_in, (unsigned long long)st->s.bytes_out,
             (unsigned long long)r->pc, (unsigned long long)r->cause,
             (unsigned long long)r->tval);
}

/* The status says whether the session ended by one of its documented ends on
 * inputs that stayed still. */
static void ms_verdict(struct ms_state *st, struct zcl_command_reply *reply)
{
    char evidence[256];
    ms_evidence(st, evidence, sizeof evidence);
    if (st->s.restore_failed)
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "TERMINAL_RESTORE_FAILED", "run",
                      "the terminal attributes could not be restored; run `stty sane`", evidence);
    else if (st->entropy_failed)
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "ENTROPY_SOURCE_FAILED", "run",
                      "the host OS entropy source refused a request; no fallback was used", evidence);
    else if (st->s.end == MS_END_FAULT)
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "GUEST_FAULT", "run",
                      "the guest could not continue; pc, cause and tval are in the evidence", evidence);
    else if (st->s.end == MS_END_ERROR)
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SESSION_FAILED", "run",
                      st->s.status != RVMACHINE_OK ? rvmachine_status_name(st->s.status) :
                      "the console output could not be written", evidence);
    else if (st->o.kernel.changed || st->o.disk.changed)
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "INPUT_CHANGED", "verify",
                      "the kernel or disk changed during the session", evidence);
    else {
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
    }
}

/* The receipt carries the verdict too, so a failed session cannot be mistaken
 * for a normal one by a reader of the file alone. */
static void ms_emit_verdict(const struct zcl_command_reply *reply, struct json_value *data)
{
    struct json_value row;
    bool passed = reply->status == ZCL_COMMAND_STATUS_PASSED;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "status", passed ? "passed" : "failed");
    (void)json_push_kv_str(&row, "code", passed ? "" : reply->error.code);
    (void)json_push_kv(data, "verdict", &row);
    json_free(&row);
}

static void ms_session(struct ms_state *st, struct zcl_command_reply *reply)
{
    st->s.escape = st->o.escape;
    st->s.max_work = (uint64_t)st->o.max_instr;
    st->s.eof_quiet_ms = (uint32_t)st->o.eof_quiet_ms;
    if (!ms_run(&st->s) && st->s.setup_failed) {
        if (st->o.receipt != NULL) (void)unlink(st->o.receipt); /* created by this call */
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "TERMINAL_SETUP_FAILED", "setup",
                      "the terminal or the signal handlers could not be set up", MS_PATH);
        return;
    }
    ms_recheck(&st->o.kernel);
    ms_recheck(&st->o.disk);
    ms_emit(st, &reply->data);
    ms_verdict(st, reply);
    ms_emit_verdict(reply, &reply->data);
    if (!ms_write_receipt(st, &reply->data) && reply->status == ZCL_COMMAND_STATUS_PASSED)
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RECEIPT_WRITE_FAILED", "write",
                      "the receipt could not be written completely", st->o.receipt);
}

void zcl_native_handle_dev_machine_shell(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply)
{
    struct ms_state *st;
    if (reply == NULL) return;
    st = zcl_calloc(1, sizeof *st, "machine_shell_state");
    if (st == NULL) {
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY", "setup",
                      "the session state could not be allocated", MS_PATH);
        return;
    }
    st->receipt_fd = -1;
    platform_positioned_file_init(&st->o.kernel.file);
    platform_positioned_file_init(&st->o.disk.file);
    if (ms_parse(request != NULL ? request->input : NULL, &st->o, reply) &&
        ms_check_stdio(st, reply) && ms_prepare(st, reply))
        ms_session(st, reply);
    if (st->receipt_fd >= 0 && close(st->receipt_fd) != 0 && reply->status == ZCL_COMMAND_STATUS_PASSED)
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RECEIPT_WRITE_FAILED", "write",
                      "the receipt could not be closed", st->o.receipt);
    rvmachine_destroy(st->m);
    platform_positioned_file_close(&st->o.kernel.file);
    platform_positioned_file_close(&st->o.disk.file);
    free(st);
}
