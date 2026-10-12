/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.app.machine.boot — boot a RISC-V kernel in the built-in
 *          machine and report the run as a receipt.
 *
 * The machine itself is platform/modules/rvmachine; this leaf only handles
 * the files around it. Order matters and is fixed:
 *   1. every input (kernel, disk) is opened read-only without following a
 *      final symlink, and its identity is taken from the open handle;
 *   2. the kernel is read through that handle and loaded;
 *   3. only then is the transcript created, exclusively: an existing path is
 *      refused, and one that names an input is refused by that name, so an
 *      output can never clobber an input and a refused run writes nothing;
 *   4. the machine runs to its stop; the disk is only ever read, guest writes
 *      stay in memory;
 *   5. the inputs are checked again through the same handles.
 * Inputs are platform positioned files: the open, the reads and the identity
 * snapshot (size, modification and change times, volume and file id) are the
 * platform layer's on every host, and two snapshots are compared by its
 * predicate.
 * The reply carries the stop, the retired, skip, firmware-call and
 * device-work counts, the console byte count and its sha256 (computed here,
 * over every console byte), the script progress and the input identities. A
 * run that missed a stated goal, faulted, printed past the console limit, saw
 * an input change or could not write its transcript fails, and the same
 * receipt is then in the error's evidence.
 *
 * Entropy is explicit: a repeatable NOT secure test seed or the native OS
 * provider. OS delivery does not establish guest initialization or key safety.
 *
 * The generic fixture uses deterministic inputs and touches no network or
 * chain state. The separate PUBLIC owner uses a monotonic resource budget;
 * its attach-only result grants no mounted identity or SSH readiness. */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "command/native_builtin_kernel.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "native_dev_machine_boot_internal.h"
#include "native_dev_machine_data.h"
#include "platform/positioned_file.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "rvmachine/rvmachine.h"
#include "services/package_lifecycle.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdatomic.h>
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

#define MB_KERNEL_MAX (UINT64_C(1) << 30)
#define MB_RAM_MIB_DEFAULT 1024
#define MB_RAM_MIB_MIN 64
#define MB_RAM_MIB_MAX 65536
#define MB_WORK_DEFAULT INT64_C(1000000000)
#define MB_READ_CHUNK (1u << 20)

/* The most console bytes one run may print. The byte that reaches the limit
 * is the last one kept; the run is then stopped and fails as CONSOLE_LIMIT. */
#define MB_CONSOLE_MAX (UINT64_C(64) << 20)

/* Policy points: the leaf's test group recompiles this file with a hook that
 * runs when the machine has stopped, before the transcript is finished and
 * the inputs are looked at again, and with a small console limit. */
#if !defined(MB_TWIN_BUILD) && \
    (defined(MB_POLICY_AFTER_RUN) || defined(MB_POLICY_CONSOLE_MAX))
#error "the leaf's policy points may be replaced only by the test twin"
#endif
#ifndef MB_POLICY_AFTER_RUN
#define MB_POLICY_AFTER_RUN(st) ((void)(st))
#endif
#ifndef MB_POLICY_CONSOLE_MAX
#define MB_POLICY_CONSOLE_MAX MB_CONSOLE_MAX
#endif

static void mb_run_fail(const struct mb_state *st, struct zcl_command_reply *reply,
                        const char *code, const char *phase, const char *message);

bool zcl_mb_boot_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                    const char *code, const char *phase, const char *message,
                    const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code, phase,
                           false, false, message, evidence);
    return false;
}

bool zcl_mb_boot_bad_input(struct zcl_command_reply *reply, const char *message)
{
    return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT", "input", message,
                   "z23-dev discover schema " MB_PATH);
}

/* ---- input ---- */

/* An optional non-empty string member. False when present with another type. */
bool zcl_mb_boot_opt_str(const struct json_value *value, const char **out)
{
    *out = NULL;
    if (value == NULL || value->type == JSON_NULL) return true;
    if (value->type != JSON_STR) return false;
    *out = json_get_str(value);
    return *out != NULL && (*out)[0] != '\0';
}

bool zcl_mb_boot_opt_int(const struct json_value *value, int64_t fallback, int64_t lo,
                       int64_t hi, int64_t *out)
{
    *out = fallback;
    if (value == NULL || value->type == JSON_NULL) return true;
    if (value->type != JSON_INT) return false;
    *out = json_get_int(value);
    return *out >= lo && *out <= hi;
}

/* type_after: [[marker, text], ...]; the text of a step may be empty. */
static bool mb_parse_steps(const struct json_value *steps, struct rvmachine_script *script)
{
    if (steps == NULL || steps->type == JSON_NULL) return true;
    if (steps->type != JSON_ARR) return false;
    for (size_t i = 0; i < steps->num_children; i++) {
        const struct json_value *pair = &steps->children[i];
        const char *marker, *text;
        if (pair->type != JSON_ARR || pair->num_children != 2u ||
            pair->children[0].type != JSON_STR || pair->children[1].type != JSON_STR)
            return false;
        marker = json_get_str(&pair->children[0]);
        text = json_get_str(&pair->children[1]);
        if (marker == NULL || text == NULL ||
            !rvmachine_script_add(script, marker, strlen(marker), text, strlen(text)))
            return false;
    }
    return true;
}

/* Test-only named byte exchange; no host transport is attached. */
static bool mb_port_keys(const struct json_value *row)
{
    if (row->type != JSON_OBJ || row->num_children < 3u || row->num_children > 4u)
        return false;
    unsigned names = 0, inputs = 0, expects = 0, afters = 0;
    for (size_t k = 0; k < row->num_children; k++) {
        if (strcmp(row->keys[k], "name") == 0) names++;
        else if (strcmp(row->keys[k], "input") == 0) inputs++;
        else if (strcmp(row->keys[k], "expect") == 0) expects++;
        else if (strcmp(row->keys[k], "after") == 0) afters++;
        else return false;
    }
    return names == 1u && inputs == 1u && expects == 1u && afters <= 1u;
}

static bool mb_port_fields(const struct json_value *row, struct mb_port *p)
{
    if (!zcl_mb_boot_opt_str(json_get(row, "name"), &p->name) || p->name == NULL ||
        strlen(p->name) >= RVVIRTIO_CONSOLE_NAME_MAX ||
        !zcl_mb_boot_opt_str(json_get(row, "input"), &p->input.path) || p->input.path == NULL ||
        !zcl_mb_boot_opt_str(json_get(row, "expect"), &p->expect.path) || p->expect.path == NULL ||
        !zcl_mb_boot_opt_str(json_get(row, "after"), &p->after)) return false;
    p->ready = p->after == NULL;
    if (p->ready) return true;
    size_t n = strlen(p->after);
    return n >= 2u && n <= 255u && strchr(p->after, '\n') == p->after + n - 1u;
}

static bool mb_parse_ports(const struct json_value *ports, struct mb_state *st)
{
    if (ports == NULL) return true;
    if (ports->type != JSON_ARR || ports->num_children == 0 || ports->num_children > 2u)
        return false;
    for (size_t i = 0; i < ports->num_children; i++) {
        const struct json_value *row = &ports->children[i];
        struct mb_port *p = &st->ports[i];
        if (!mb_port_keys(row) || !mb_port_fields(row, p)) return false;
        for (size_t k = 0; k < i; k++)
            if (strcmp(st->ports[k].name, p->name) == 0) return false;
    }
    st->port_count = (unsigned)ports->num_children;
    return true;
}

static bool mb_accepted_keys(const struct json_value *row)
{
    static const char *const keys[] = {"datadir", "package_root", "output",
        "max_artifact_bytes", "max_verification_bytes"};
    if (row->type != JSON_OBJ || row->num_children != 5u) return false;
    for (size_t i = 0; i < 5u; i++) {
        unsigned found = 0;
        for (size_t j = 0; j < row->num_children; j++)
            if (strcmp(row->keys[j], keys[i]) == 0) found++;
        if (found != 1u) return false;
    }
    return true;
}

static bool mb_parse_accepted(const struct json_value *row, struct mb_state *st)
{
    int64_t capacity = 0, verification = 0;
    if (!mb_accepted_keys(row) ||
        json_get(row, "max_artifact_bytes")->type != JSON_INT ||
        json_get(row, "max_verification_bytes")->type != JSON_INT ||
        !zcl_mb_boot_opt_str(json_get(row, "datadir"), &st->accepted.datadir) ||
        !zcl_mb_boot_opt_str(json_get(row, "output"), &st->accepted.output) ||
        !zcl_mb_boot_opt_str(json_get(row, "package_root"), &st->accepted.root_hex) ||
        !st->accepted.datadir || !st->accepted.output || !st->accepted.root_hex ||
        !zcl_hex_decode_lower(st->accepted.root_hex, st->accepted.root, 32)) return false;
    if (!zcl_mb_boot_opt_int(json_get(row, "max_artifact_bytes"), 0, 1,
                    (int64_t)MB_KERNEL_MAX, &capacity) ||
        !zcl_mb_boot_opt_int(json_get(row, "max_verification_bytes"), 0, 1,
                    INT64_MAX, &verification) || (uint64_t)capacity > SIZE_MAX) return false;
    st->accepted.capacity = (uint64_t)capacity;
    st->accepted.verification = (uint64_t)verification;
    return true;
}

static bool mb_public_kernel_keys(const struct json_value *row)
{
    static const char *const keys[] = {"datadir", "observation_root",
        "max_artifact_bytes", "max_verification_bytes"};
    if (row->type != JSON_OBJ || row->num_children != 4u) return false;
    for (size_t i = 0; i < 4u; i++) {
        unsigned found = 0;
        for (size_t j = 0; j < row->num_children; j++)
            if (!strcmp(row->keys[j], keys[i])) found++;
        if (found != 1u) return false;
    }
    return true;
}

static bool mb_parse_observation_kernel(const struct json_value *row, struct mb_state *st,
    bool protected)
{
    if (!mb_public_kernel_keys(row)) return false;
    int64_t capacity = 0, verification = 0;
    if (!zcl_mb_boot_opt_str(json_get(row, "datadir"), &st->accepted.datadir) ||
        !st->accepted.datadir || !st->accepted.datadir[0] ||
        !zcl_mb_boot_opt_str(json_get(row, "observation_root"), &st->accepted.root_hex) ||
        !st->accepted.root_hex ||
        !zcl_hex_decode_lower(st->accepted.root_hex, st->accepted.root, 32) ||
        json_get(row, "max_artifact_bytes")->type != JSON_INT ||
        json_get(row, "max_verification_bytes")->type != JSON_INT ||
        !zcl_mb_boot_opt_int(json_get(row, "max_artifact_bytes"), 0, 1,
            VCS_GUEST_IMAGE_MAX_BYTES, &capacity) ||
        !zcl_mb_boot_opt_int(json_get(row, "max_verification_bytes"), 0, 1,
            INT64_MAX, &verification)) return false;
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof st->accepted.root; i++) nonzero |= st->accepted.root[i];
    if (!nonzero) return false;
    st->accepted.capacity = (uint64_t)capacity;
    st->accepted.verification = (uint64_t)verification;
    st->accepted.public_observation = !protected;
    st->accepted.protected_observation = protected;
    return true;
}

static bool mb_parse_public_kernel(const struct json_value *row, struct mb_state *st)
{
    return mb_parse_observation_kernel(row,st,false);
}

/* The built-in kernel is selected by the address of this string in accepted.output. */
static const char mb_builtin_source[] = "built_in";

static bool mb_parse_builtin(const struct json_value *flag, struct mb_state *st,
                             struct zcl_command_reply *reply)
{
    if (flag->type != JSON_BOOL || !json_get_bool(flag))
        return zcl_mb_boot_bad_input(reply, "builtin_kernel must be true");
    st->accepted.output = mb_builtin_source;
    return true;
}

static bool mb_parse_kernel(const struct json_value *in, struct mb_state *st,
                            struct zcl_command_reply *reply)
{
    const struct json_value *builtin = json_get(in, "builtin_kernel");
    const struct json_value *path = json_get(in, "kernel");
    const struct json_value *accepted = json_get(in, "accepted_kernel");
    const struct json_value *public_image = json_get(in, "public_kernel");
    const struct json_value *protected_image = json_get(in, "protected_kernel");
    if ((unsigned)(path != NULL) + (unsigned)(accepted != NULL) + (unsigned)(public_image != NULL) +
        (unsigned)(protected_image != NULL) + (unsigned)(builtin != NULL) != 1u)
        return zcl_mb_boot_bad_input(reply, "exactly one of kernel, accepted_kernel, public_kernel, protected_kernel or builtin_kernel is required");
    if (builtin) return mb_parse_builtin(builtin, st, reply);
    if (public_image) {
        if (mb_parse_public_kernel(public_image, st)) return true;
        return zcl_mb_boot_bad_input(reply, "public_kernel requires unique local observation fields and positive bounded byte limits");
    }
    if (protected_image) {
        if (mb_parse_observation_kernel(protected_image, st, true)) return true;
        return zcl_mb_boot_bad_input(reply,"protected_kernel requires unique local observation fields and positive bounded byte limits");
    }
    if (accepted != NULL) {
        if (mb_parse_accepted(accepted, st)) return true;
        return zcl_mb_boot_bad_input(reply, "accepted_kernel requires unique typed root/output/context and positive byte limits");
    }
    if (!zcl_mb_boot_opt_str(path, &st->kernel.path) || !st->kernel.path)
        return zcl_mb_boot_bad_input(reply, "kernel must be the path of a kernel image");
    return true;
}

/* Preserve existing PUBLIC refusal taxonomy before entering data parsing. */
static bool mb_called_owner_options_refuse(const struct json_value *in,
    struct zcl_command_reply *reply)
{
    if(json_get(in,"public_unlock")){
        if(json_get(in,"builtin_kernel"))
            return zcl_mb_boot_bad_input(reply,"PUBLIC unlock requires an installed or fixed PUBLIC image and host seed with no public export or script options");
        if(json_get(in,"data_disk"))
            return zcl_mb_boot_fail(reply,ZCL_COMMAND_EXIT_INVALID,"DATA_DISK_NOT_AVAILABLE","input",
                "data_disk is not attached under the PUBLIC owner",MD_PATH);
    }
    return zcl_mb_boot_bad_input(reply,"called unlock owners refuse builtin_kernel, data_disk and home");
}

static bool mb_parse_paths(const struct json_value *in, struct mb_state *st,
                           struct zcl_command_reply *reply)
{
    if (!mb_parse_kernel(in, st, reply)) return false;
    if (!zcl_mb_boot_opt_str(json_get(in, "disk"), &st->disk.path))
        return zcl_mb_boot_bad_input(reply, "disk must be the path of a disk image");
    if (!zcl_mb_boot_opt_str(json_get(in, "transcript"), &st->transcript))
        return zcl_mb_boot_bad_input(reply, "transcript must be a path");
    if (!zcl_mb_boot_opt_str(json_get(in, "bootargs"), &st->bootargs) ||
        (st->bootargs != NULL && strlen(st->bootargs) >= RVMACHINE_BOOTARGS_MAX))
        return zcl_mb_boot_bad_input(reply, "bootargs must be a string of at most 511 bytes");
    if ((json_get(in,"public_unlock") || json_get(in,"protected_unlock")) &&
        (json_get(in,"data_disk") || json_get(in,"home") || json_get(in,"builtin_kernel")))
        return mb_called_owner_options_refuse(in,reply);
    return zcl_mb_data_parse(st, in, reply);
}

/* test_entropy_seed: present, it attaches the entropy device fed by the test
 * stream of that seed; absent, the machine has no entropy device. */
static bool mb_parse_seed(const struct json_value *in, struct mb_state *st)
{
    const struct json_value *value = json_get(in, "test_entropy_seed");
    int64_t seed = 0;
    if (value == NULL || value->type == JSON_NULL) return true;
    if (!zcl_mb_boot_opt_int(value, 0, 0, INT64_MAX, &seed)) return false;
    st->seeded = true;
    st->seed = (uint64_t)seed;
    st->ent_used = SHA256_OUTPUT_SIZE; /* no block made yet */
    return true;
}

static bool mb_parse_entropy(const struct json_value *in, struct mb_state *st,
                             struct zcl_command_reply *reply)
{
    const char *source = NULL;
    if (!zcl_mb_boot_opt_str(json_get(in, "entropy"), &source) ||
        (source != NULL && strcmp(source, "host") != 0))
        return zcl_mb_boot_bad_input(reply, "entropy must be \"host\"");
    if (source == NULL) return true;
    if (st->seeded)
        return zcl_mb_boot_bad_input(reply, "entropy host and test_entropy_seed are mutually exclusive");
    st->host_entropy = true;
    return true;
}

/* early_seed enters at the loader entry with fresh host material in host mode,
 * or the test_entropy_seed stream in explicitly deterministic test mode. */
static bool mb_parse_early(const struct json_value *in, struct mb_state *st,
                           struct zcl_command_reply *reply)
{
    const char *source = NULL;
    if (!zcl_mb_boot_opt_str(json_get(in, "early_seed"), &source))
        return zcl_mb_boot_bad_input(reply, "early_seed must be \"test\" or \"host\"");
    if (source == NULL) return true;
    if (strcmp(source, "host") == 0) {
        if (!st->host_entropy)
            return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_INVALID, "SEED_SOURCE_NOT_OFFERED",
                           "input", "early_seed host requires entropy host", MB_PATH);
        st->early = true;
        return true;
    }
    if (strcmp(source, "test") != 0)
        return zcl_mb_boot_bad_input(reply, "early_seed must be \"test\" or \"host\"");
    if (!st->seeded)
        return zcl_mb_boot_bad_input(reply, "early_seed \"test\" needs test_entropy_seed");
    st->early = true;
    return true;
}

static bool mb_parse(const struct json_value *in, struct mb_state *st,
                     struct zcl_command_reply *reply)
{
    const char *until = NULL;
    int64_t ram_mib = 0, work = 0;
    if (in == NULL || in->type != JSON_OBJ)
        return zcl_mb_boot_bad_input(reply, "input must be one JSON object");
    if (!mb_parse_paths(in, st, reply)) return false;
    if (!zcl_mb_boot_opt_int(json_get(in, "ram_mib"), MB_RAM_MIB_DEFAULT, MB_RAM_MIB_MIN,
                    MB_RAM_MIB_MAX, &ram_mib) || ram_mib % 2 != 0)
        return zcl_mb_boot_bad_input(reply, "ram_mib must be an even integer in 64..65536");
    if (!zcl_mb_boot_opt_int(json_get(in, "max_instr"), MB_WORK_DEFAULT, 1, INT64_MAX, &work))
        return zcl_mb_boot_bad_input(reply, "max_instr must be a positive integer");
    st->ram_bytes = (uint64_t)ram_mib << 20;
    st->max_work = (uint64_t)work;
    if (!mb_parse_steps(json_get(in, "type_after"), &st->script))
        return zcl_mb_boot_bad_input(reply, "type_after must be an array of at most 32 "
                                   "[marker, text] string pairs with a non-empty marker");
    if (!zcl_mb_boot_opt_str(json_get(in, "until"), &until) ||
        (until != NULL && !rvmachine_script_until(&st->script, until, strlen(until))))
        return zcl_mb_boot_bad_input(reply, "until must be a string of 1..255 bytes");
    if (!mb_parse_seed(in, st))
        return zcl_mb_boot_bad_input(reply, "test_entropy_seed must be a non-negative integer");
    if (!mb_parse_entropy(in, st, reply)) return false;
    if (!mb_parse_ports(json_get(in, "ports"), st))
        return zcl_mb_boot_bad_input(reply, "ports must contain one or two unique named input/expect fixtures");
    return mb_parse_early(in, st, reply) && zcl_mb_owner_parse(in, st, reply);

}

/* The called PUBLIC owner observes fixed complete lines only. Every byte of a
 * line belongs to one actual instance/epoch, including its terminating LF. */
/* ---- files ---- */

/* Opens an input for reading, never through a final symlink, and records its
 * identity from the open handle. */
static bool mb_open_input(struct mb_file *f, const char *what,
                          struct zcl_command_reply *reply)
{
    char evidence[256];
    if (f->path == NULL) return true;
    if (platform_positioned_file_open(&f->file, f->path) &&
        platform_positioned_file_snapshot(&f->file, &f->before) && f->before.size != 0)
        return true;
    snprintf(evidence, sizeof evidence, "%s: %.200s", what, f->path);
    return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "INPUT_UNREADABLE", "open",
                   "an input is not a readable, non-empty regular file (a final "
                   "symlink is not followed)", evidence);
}

/* Reads exactly n bytes at off through an input's handle. */
static bool mb_read_at(void *ctx, uint64_t off, void *buf, size_t n)
{
    const struct mb_file *f = ctx;
    uint8_t *out = buf;
    while (n != 0) {
        size_t want = n < MB_READ_CHUNK ? n : MB_READ_CHUNK;
        int64_t got = platform_positioned_file_read(&f->file, out, want, off);
        if (got <= 0) return false;
        out += got;
        off += (uint64_t)got;
        n -= (size_t)got;
    }
    return true;
}

/* Reads the whole kernel through its handle. NULL on failure. */
static uint8_t *mb_read_kernel(struct mb_file *f, size_t *len)
{
    uint8_t *image;
    if (f->before.size > MB_KERNEL_MAX) return NULL;
    image = zcl_malloc((size_t)f->before.size, "machine_boot_kernel");
    if (image != NULL && !mb_read_at(f, 0, image, (size_t)f->before.size)) {
        free(image);
        return NULL;
    }
    *len = (size_t)f->before.size;
    return image;
}

/* True when path is the file an input handle has open: the same volume and
 * file id, read from a handle opened on path without following a final
 * symlink. (A path that is a symlink is refused as existing when the
 * transcript is created.) */
static bool mb_names_input(const char *path, const struct mb_file *f)
{
    struct platform_positioned_file named;
    struct platform_positioned_file_snapshot id;
    bool same;
    platform_positioned_file_init(&named);
    if (f->path == NULL || !platform_positioned_file_open(&named, path)) return false;
    same = platform_positioned_file_snapshot(&named, &id) &&
           id.volume == f->before.volume && id.file_low == f->before.file_low &&
           id.file_high == f->before.file_high;
    platform_positioned_file_close(&named);
    return same;
}

/* Creates the transcript. An existing path is refused, whatever it is; a path
 * that resolves to an input is refused by name. Nothing is written or
 * truncated on a refusal. */
static bool mb_open_transcript(struct mb_state *st, struct zcl_command_reply *reply)
{
    if (st->transcript == NULL) return true;
    for (unsigned i = 0; i < st->port_count; i++)
        if (mb_names_input(st->transcript, &st->ports[i].input) ||
            mb_names_input(st->transcript, &st->ports[i].expect))
            return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "TRANSCRIPT_IS_INPUT", "open",
                           "transcript aliases a port fixture input; nothing was written", st->transcript);

    if (mb_names_input(st->transcript, &st->kernel) ||
        mb_names_input(st->transcript, &st->disk))
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_INVALID, "TRANSCRIPT_IS_AN_INPUT", "open",
                       "the transcript path names the kernel or the disk image; "
                       "nothing was written", st->transcript);
    st->out_fd = open(st->transcript,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_BINARY,
                      0600);
    if (st->out_fd >= 0) return true;
    if (errno == EEXIST)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_INVALID, "TRANSCRIPT_EXISTS", "open",
                       "the transcript path already exists; it is created "
                       "exclusively and never overwritten", st->transcript);
    return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "TRANSCRIPT_UNWRITABLE", "open",
                   "the transcript file could not be created", st->transcript);
}

static void mb_flush(struct mb_state *st)
{
    size_t off = 0;
    while (st->out_fd >= 0 && !st->out_failed && off < st->buf_len) {
        ssize_t n = write(st->out_fd, st->buf + off, (unsigned)(st->buf_len - off));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) st->out_failed = true;
        else off += (size_t)n;
    }
    st->buf_len = 0;
}

/* Console sink: the hash, the transcript, the tail for the reply, the script.
 * The byte that reaches the console limit is the last one taken: the run is
 * asked to stop and nothing after that byte is taken. */
static void mb_port_console(struct mb_state *st, uint8_t byte)
{
    if (st->port_line_len < sizeof st->port_line)
        st->port_line[st->port_line_len] = byte;
    if (st->port_line_len <= sizeof st->port_line) st->port_line_len++;
    if (byte != '\n') return;
    for (unsigned i = 0; i < st->port_count; i++) {
        struct mb_port *p = &st->ports[i];
        if (!p->ready && strlen(p->after) == st->port_line_len &&
            memcmp(p->after, st->port_line, st->port_line_len) == 0) {
            /* Plain read of this single-writer machine, not callback reentry. */
            p->ready_epoch = st->m->conports[i].generation;
            p->ready = true;
        }
    }
    st->port_line_len = 0;
}

/* No public capture begins without an ordinary machine. Refusal stays sticky. */
static bool mb_public_capture(struct mb_state *st)
{
    if (st->private_export_failed) return false;
    if (rvmachine_public_export_allowed(st->m)) return true;
    st->private_export_failed = true;
    return false;
}

static void mb_console(void *ctx, uint8_t byte)
{
    struct mb_state *st = ctx;
    if (!mb_public_capture(st)) return;
    if (st->console_full) return;
    mb_port_console(st, byte);
    sha256_write(&st->sha, &byte, 1);
    st->buf[st->buf_len++] = byte;
    if (st->buf_len == MB_BUF) mb_flush(st);
    if (st->tail_len == MB_TAIL) {
        memmove(st->tail, st->tail + MB_TAIL / 2u, MB_TAIL / 2u);
        st->tail_len = MB_TAIL / 2u;
    }
    st->tail[st->tail_len++] = (byte >= 0x20 && byte < 0x7f) || byte == '\n'
                                   ? (char)byte : '.';
    rvmachine_script_console(&st->script, st->m, byte);
    if (st->script.console_bytes >= MB_POLICY_CONSOLE_MAX) {
        st->console_full = true;
        rvmachine_request_stop(st->m);
    }
}

/* Marks an input whose size, times or identity moved since the first look. */
static void mb_recheck(struct mb_file *f)
{
    struct platform_positioned_file_snapshot now;
    if (f->path == NULL) return;
    f->changed = !platform_positioned_file_snapshot(&f->file, &now) ||
                 !platform_positioned_file_snapshot_equal(&now, &f->before);
}

/* Block `block` of a test stream: the SHA-256 of the stream's label, the seed
 * and the block number. Anyone who knows the seed knows every byte, so the
 * streams are repeatable and not secure; the reply says so. */
static void mb_stream_block(const char *label, uint64_t seed, uint64_t block,
                            uint8_t out[SHA256_OUTPUT_SIZE])
{
    struct sha256_ctx sha;
    uint8_t tail[16];
    zcl_write_u64_le(tail, seed);
    zcl_write_u64_le(tail + 8, block);
    sha256_init(&sha);
    sha256_write(&sha, (const unsigned char *)label, strlen(label));
    sha256_write(&sha, tail, sizeof tail);
    sha256_finalize(&sha, out);
}

/* The test entropy source. It never runs dry. */
static size_t mb_test_entropy(void *ctx, uint8_t *buf, size_t n)
{
    struct mb_state *st = ctx;
    for (size_t i = 0; i < n; i++) {
        if (st->ent_used == SHA256_OUTPUT_SIZE) {
            mb_stream_block("z23 dev.app.machine.boot test entropy v1", st->seed,
                            st->ent_block++, st->ent_bytes);
            st->ent_used = 0;
        }
        buf[i] = st->ent_bytes[st->ent_used++];
    }
    st->ent_given += n;
    return n;
}

/* Native-only source: a failed request invalidates the whole caller span.
 * No callback mutates machine state, and no request follows a failed one. */
size_t zcl_mb_boot_host_entropy(void *ctx, uint8_t *buf, size_t n)
{
    struct mb_state *st = ctx;
    if (!st->entropy_failed) {
        size_t done = 0;
        while (done < n) {
            size_t take = n - done < 4096u ? n - done : 4096u;
            if (!rng_host_fill(buf + done, take)) {
                st->entropy_failed = true;
                break;
            }
            done += take;
        }
        if (!st->entropy_failed) {
            st->ent_given += n;
            return n;
        }
    }
    memory_cleanse(buf, n);
    return 0;
}

bool zcl_mb_boot_host_boot_seed(void *ctx, uint8_t *buf, size_t n, size_t *got)
{
    struct mb_state *st = ctx;
    *got = 0;
    uint64_t before = st->ent_given;
    size_t received = zcl_mb_boot_host_entropy(st, buf, n);
    st->ent_given = before;
    if (received != n) return false;
    st->early_given = n;
    *got = n;
    return true;
}

/* The boot seed: the first n bytes of a second stream of the same seed. Its
 * own label puts it in a domain of its own, apart from the stream the
 * entropy device hands out. */
static bool mb_test_boot_seed(void *ctx, uint8_t *buf, size_t n, size_t *got)
{
    struct mb_state *st = ctx;
    uint8_t block[SHA256_OUTPUT_SIZE];
    for (size_t done = 0; done < n; done += sizeof block) {
        size_t take = n - done < sizeof block ? n - done : sizeof block;
        mb_stream_block("z23 dev.app.machine.boot test early seed v1", st->seed,
                        done / sizeof block, block);
        memcpy(buf + done, block, take);
    }
    st->early_given = n;
    *got = n;
    return true;
}

static bool mb_machine_fail(struct zcl_command_reply *reply, const char *phase,
                            enum rvmachine_status status)
{
    return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "MACHINE_REFUSED", phase,
                   rvmachine_status_name(status), MB_PATH);
}

static bool mb_prepare_ports(struct mb_state *st, struct zcl_command_reply *reply)
{
    uint64_t total = 0;
    for (unsigned i = 0; i < st->port_count; i++) {
        struct mb_port *p = &st->ports[i];
        if (!mb_open_input(&p->input, "port input", reply) ||
            !mb_open_input(&p->expect, "port expected reply", reply)) return false;
        if (p->input.before.size == 0 || p->expect.before.size == 0 ||
            p->input.before.size > MB_PORT_BYTES - total)
            return zcl_mb_boot_bad_input(reply, "port files must be nonempty and total at most 65536 bytes");
        total += p->input.before.size;
        if (p->expect.before.size > MB_PORT_BYTES - total)
            return zcl_mb_boot_bad_input(reply, "port files total more than 65536 bytes");
        total += p->expect.before.size;
        if (!mb_read_at(&p->input, 0, p->input_bytes, (size_t)p->input.before.size) ||
            !mb_read_at(&p->expect, 0, p->expected_bytes, (size_t)p->expect.before.size))
            return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "INPUT_UNREADABLE", "read",
                           "port fixture bytes could not be read", p->name);
    }
    return true;
}

/* Never calls back into the machine. Accept only the exact expected prefix. */
static size_t mb_port_sink(void *ctx, unsigned port, const uint8_t *bytes, size_t n)
{
    struct mb_state *st = ctx;
    if (!mb_public_capture(st)) return 0;
    if (port >= st->port_count) { st->port_failed = true; return 0; }
    struct mb_port *p = &st->ports[port];
    size_t expected = (size_t)p->expect.before.size;
    if (!p->started || p->received > expected || n > expected - p->received ||
        memcmp(p->expected_bytes + p->received, bytes, n) != 0) {
        st->port_failed = true;
        return 0;
    }
    p->received += n;
    return n;
}

/* Host input is fed outside the sink, preserving every unaccepted suffix. */
static bool mb_port_feed(struct mb_state *st)
{
    bool moved = false;
    for (unsigned i = 0; i < st->port_count; i++) {
        struct mb_port *p = &st->ports[i];
        uint32_t epoch = rvmachine_conport_generation(st->m, i);
        if (p->started && epoch != p->epoch) { st->port_failed = true; continue; }
        if (p->after != NULL && p->ready && epoch != p->ready_epoch) {
            st->port_failed = true;
            continue;
        }
        if (!p->ready || !rvmachine_conport_guest_open(st->m, i)) continue;
        size_t left = (size_t)p->input.before.size - p->accepted;
        if (left == 0) continue;
        if (!p->started) { p->started = true; p->epoch = epoch; }
        size_t n = rvmachine_conport_input(st->m, i, p->input_bytes + p->accepted, left);
        p->accepted += n;
        moved = moved || n != 0;
    }
    return moved;
}

static bool mb_ports_complete(struct mb_state *st)
{
    if (st->port_failed) return false;
    for (unsigned i = 0; i < st->port_count; i++) {
        struct mb_port *p = &st->ports[i];
        if (!p->started || p->accepted != p->input.before.size ||
            p->received != p->expect.before.size || rvmachine_conport_queued(st->m, i) != 0 ||
            rvmachine_conport_consumed(st->m, i) < p->input.before.size ||
            rvmachine_conport_generation(st->m, i) != p->epoch) return false;
    }
    return true;
}

static enum rvmachine_status mb_run_ports(struct mb_state *st)
{
    for (;;) {
        uint64_t used = st->res.retired + st->res.fw_calls + st->res.device_work;
        if (used >= st->max_work || st->port_failed || st->entropy_failed) return RVMACHINE_OK;
        (void)mb_port_feed(st);
        if (st->port_failed) return RVMACHINE_OK;
        uint64_t left = st->max_work - used;
        enum rvmachine_status status = rvmachine_run(st->m, left < 4096u ? left : 4096u,
                                                    &st->res);
        if (status != RVMACHINE_OK) return status;
        bool fed = mb_port_feed(st);
        if (st->res.stop == RVMACHINE_STOP_BUDGET) continue;
        if (st->res.stop == RVMACHINE_STOP_IDLE && fed &&
            (rvmachine_pending(st->m) & RVMACHINE_PENDING_RUNNABLE) != 0u) continue;
        return status;
    }
}

/* Builds the machine over the open disk and loads the kernel. */
static bool mb_setup(struct mb_state *st, const uint8_t *image, size_t len,
                     struct zcl_command_reply *reply)
{
    struct rvmachine_config config = {.ram_bytes = st->ram_bytes,
                                      .bootargs = st->bootargs,
                                      .console = mb_console, .console_ctx = st,
                                      .entropy = st->host_entropy ? zcl_mb_boot_host_entropy :
                                                 st->seeded ? mb_test_entropy : NULL,
                                      .entropy_ctx = st,
                                      .entropy_fail_closed = st->host_entropy,
                                      .boot_seed = st->early ? (st->host_entropy ?
                                          zcl_mb_boot_host_boot_seed : mb_test_boot_seed) : NULL,
                                      .boot_seed_ctx = st};
    config.conport_count = st->port_count;
    config.conport_sink = st->port_count != 0 ? mb_port_sink : NULL;
    config.conport_ctx = st;
    for (unsigned i = 0; i < st->port_count; i++) config.conport_names[i] = st->ports[i].name;
    enum rvmachine_status status = RVMACHINE_OK;

    if (st->disk.path != NULL)
        status = rvmachine_disk_open(&config.disk, st->disk.before.size, mb_read_at,
                                     &st->disk);
    if (status != RVMACHINE_OK) return mb_machine_fail(reply, "disk", status);
    if (!zcl_mb_data_attach(st, &config.data_disk, reply)) {
        rvmachine_disk_close(config.disk);
        return false;
    }
    status = rvmachine_create(&st->m, &config);
    if (status != RVMACHINE_OK) {
        rvmachine_disk_close(config.disk); /* still ours on a failed create */
        rvmachine_disk_close(config.data_disk);
        return mb_machine_fail(reply, "create", status);
    }
    status = rvmachine_load_kernel(st->m, image, len);
    if (status != RVMACHINE_OK) return mb_machine_fail(reply, "load", status);
    return true;
}

static bool mb_public_image_read(struct mb_state *st, struct zcl_command_reply *reply)
{
    bool protected=st->accepted.protected_observation;
    const char *code=protected?"PROTECTED_IMAGE_REFUSED":"PUBLIC_IMAGE_REFUSED";
    struct zcl_result result = guest_image_admission_open(st->accepted.datadir,
        st->accepted.root, st->accepted.capacity, st->accepted.verification,
        zcl_mb_owner_image_grant, st, &st->accepted.public_reader);
    if (!result.ok)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, code, "open",
            protected?"local copied bytes did not qualify under distinct protected owner policy":
            "local copied bytes did not qualify under fixed PUBLIC owner policy", result.message);
    const uint8_t *image = NULL;
    size_t length = 0;
    result = guest_image_admission_bytes(st->accepted.public_reader, &image, &length);
    if (!result.ok || !image || !length || length > st->accepted.capacity)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, code, "read",
            protected?"the current protected image copy is unavailable":"the current PUBLIC image copy is unavailable", MB_PATH);
    st->accepted.image = zcl_malloc(length, protected?"protected owner image copy":"PUBLIC owner image copy");
    if (!st->accepted.image)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY", "read",
            protected?"the bounded protected image could not be copied":"the bounded PUBLIC image could not be copied", MB_PATH);
    memcpy(st->accepted.image, image, length);
    st->accepted.length = length;
    result = guest_image_admission_current(st->accepted.public_reader);
    if (!result.ok)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, code, "current",
            protected?"protected image policy changed after copying":"PUBLIC image policy changed after copying", result.message);
    return true;
}

bool zcl_mb_boot_accepted_read(struct mb_state *st, struct zcl_command_reply *reply)
{
    if (st->accepted.public_observation || st->accepted.protected_observation)
        return mb_public_image_read(st, reply);
    struct zcl_result result = package_lifecycle_declared_output_open(
        st->accepted.datadir, st->accepted.root, st->accepted.output,
        st->accepted.capacity, st->accepted.verification, &st->accepted.reader);
    if (!result.ok)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "ACCEPTED_KERNEL_REFUSED", "open",
                        "the installed declared kernel could not be qualified", result.message);
    st->accepted.image = zcl_malloc((size_t)st->accepted.capacity, "accepted_machine_kernel");
    if (!st->accepted.image)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY", "read",
                        "the explicit kernel capacity could not be allocated", MB_PATH);
    result = package_lifecycle_declared_output_read_verified(st->accepted.reader,
        st->accepted.image, (size_t)st->accepted.capacity, &st->accepted.length);
    if (!result.ok || !st->accepted.length)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "ACCEPTED_KERNEL_REFUSED", "read",
                        "the retained kernel copy could not be qualified", result.message);
    struct sha256_ctx sha;
    uint8_t digest[SHA256_OUTPUT_SIZE];
    sha256_init(&sha);
    sha256_write(&sha, st->accepted.image, st->accepted.length);
    sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof digest, st->accepted.image_sha256);
    return true;
}

/* Unpacks the built-in kernel against its pin and boots from the copy. */
static bool mb_prepare_builtin(struct mb_state *st, struct zcl_command_reply *reply)
{
    enum zcl_builtin_kernel_status status =
        zcl_builtin_kernel_load(&st->accepted.image, &st->accepted.length);
    if (status != ZCL_BUILTIN_KERNEL_OK) {
        char code[48];
        size_t i = 0;
        for (const char *p = zcl_builtin_kernel_status_name(status); *p && i + 1u < sizeof code; p++)
            code[i++] = (char)toupper((unsigned char)*p);
        code[i] = '\0';
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, code, "load",
                       zcl_builtin_kernel_status_name(status), MB_PATH);
    }
    memcpy(st->accepted.image_sha256, ZCL_BUILTIN_KERNEL_SHA256, sizeof st->accepted.image_sha256);
    return mb_setup(st, st->accepted.image, st->accepted.length, reply) &&
           mb_open_transcript(st, reply);
}

static bool mb_prepare(struct mb_state *st, struct zcl_command_reply *reply)
{
    uint8_t *image;
    size_t len = 0;
    bool ok;
    if (!mb_open_input(&st->kernel, "kernel", reply) ||
        !mb_open_input(&st->disk, "disk", reply))
        return false;
    if (!mb_prepare_ports(st, reply)) return false;
    if (st->accepted.output == mb_builtin_source) return mb_prepare_builtin(st, reply);
    if (st->accepted.datadir) {
        if (!zcl_mb_boot_accepted_read(st, reply)) return false;
        return mb_setup(st, st->accepted.image, st->accepted.length, reply) &&
               mb_open_transcript(st, reply);
    }
    image = mb_read_kernel(&st->kernel, &len);
    if (image == NULL)
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "INPUT_UNREADABLE", "read",
                       "the kernel image could not be read (or is above 1 GiB)",
                       st->kernel.path);
    ok = mb_setup(st, image, len, reply) && mb_open_transcript(st, reply);
    free(image);
    return ok;
}

static void mb_run(struct mb_state *st, struct zcl_command_reply *reply)
{
    unsigned char hash[SHA256_OUTPUT_SIZE];
    enum rvmachine_status status = st->port_count != 0 || st->host_entropy ? mb_run_ports(st) :
                                   rvmachine_run(st->m, st->max_work, &st->res);

    MB_POLICY_AFTER_RUN(st);
    mb_flush(st);
    if (st->out_fd >= 0 && close(st->out_fd) != 0) st->out_failed = true;
    st->out_fd = -1;
    mb_recheck(&st->kernel);
    if (st->accepted.reader) {
        size_t produced = 0;
        struct zcl_result current = package_lifecycle_declared_output_read_verified(
            st->accepted.reader, st->accepted.image, (size_t)st->accepted.capacity, &produced);
        st->accepted.changed = !current.ok || produced != st->accepted.length;
    }
    mb_recheck(&st->disk);
    for (unsigned i = 0; i < st->port_count; i++) {
        mb_recheck(&st->ports[i].input);
        mb_recheck(&st->ports[i].expect);
    }

    sha256_finalize(&st->sha, hash);
    zcl_hex_encode(hash, SHA256_OUTPUT_SIZE, st->sha_hex);
    st->tail[st->tail_len] = '\0';
    if (st->entropy_failed)
        mb_run_fail(st, reply, "ENTROPY_SOURCE_FAILED", "run",
                    "the host OS entropy source refused a request; no fallback was used");
    else if (status != RVMACHINE_OK && st->port_count != 0)
        mb_run_fail(st, reply, "MACHINE_REFUSED", "run", rvmachine_status_name(status));
    else if (status != RVMACHINE_OK) (void)mb_machine_fail(reply, "run", status);
    st->ran = status == RVMACHINE_OK;
}

/* ---- the reply ---- */

static void mb_emit_file(struct json_value *inputs, const char *name,
                         const struct mb_file *f)
{
    struct json_value row;
    if (f->path == NULL) return;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_int(&row, "size", (int64_t)f->before.size);
    (void)json_push_kv_int(&row, "mtime", f->before.modified_seconds);
    (void)json_push_kv_int(&row, "mtime_nsec", f->before.modified_nanoseconds);
    (void)json_push_kv_bool(&row, "changed", f->changed);
    (void)json_push_kv(inputs, name, &row);
    json_free(&row);
}

static void mb_emit_builtin(const struct mb_state *st, struct json_value *inputs)
{
    struct json_value row;
    if (st->accepted.output != mb_builtin_source) return;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "source", mb_builtin_source);
    (void)json_push_kv_int(&row, "size", (int64_t)st->accepted.length);
    (void)json_push_kv_str(&row, "sha256", st->accepted.image_sha256);
    (void)json_push_kv_bool(&row, "changed", false);
    (void)json_push_kv(inputs, "kernel", &row);
    json_free(&row);
}

static void mb_emit_stop(const struct mb_state *st, struct json_value *data)
{
    const struct rvmachine_result *r = &st->res;
    (void)json_push_kv_str(data, "stop", rvmachine_stop_name(r->stop));
    (void)json_push_kv_bool(data, "marker_seen", st->script.until_seen);
    (void)json_push_kv_int(data, "retired", (int64_t)r->retired);
    (void)json_push_kv_int(data, "skip", (int64_t)r->skip);
    (void)json_push_kv_int(data, "fw_calls", (int64_t)r->fw_calls);
    (void)json_push_kv_int(data, "device_work", (int64_t)r->device_work);
    (void)json_push_kv_int(data, "guest_time", (int64_t)r->guest_time);
    (void)json_push_kv_int(data, "timebase_hz", RVMACHINE_TIMEBASE_HZ);
    (void)json_push_kv_int(data, "fetch_hits", (int64_t)r->fetch_hits);
    (void)json_push_kv_int(data, "fetch_misses", (int64_t)r->fetch_misses);
    if (r->stop == RVMACHINE_STOP_SHUTDOWN || r->stop == RVMACHINE_STOP_REBOOT) {
        (void)json_push_kv_int(data, "reset_type", r->reset_type);
        (void)json_push_kv_int(data, "reset_reason", r->reset_reason);
    }
}

/* A run with the test entropy source says so, and that it is not secure. */
static void mb_emit_entropy(const struct mb_state *st, struct json_value *data)
{
    struct json_value row;
    if (!st->seeded && !st->host_entropy) return;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "source", st->host_entropy ? "host_os_csprng" : "test_seed");
    if (st->host_entropy) (void)json_push_kv_str(&row, "guest_rng_health", "unobserved");
    else (void)json_push_kv_bool(&row, "secure", false);
    (void)json_push_kv_int(&row, "bytes", (int64_t)st->ent_given);
    (void)json_push_kv_bool(&row, "source_failed", st->entropy_failed);
    (void)json_push_kv(data, "entropy", &row);
    json_free(&row);
}

/* cleared: the guest has overwritten the whole seed with zeros, which is what
 * a kernel does once it has taken it. */
static void mb_emit_early(const struct mb_state *st, struct json_value *data)
{
    struct json_value row;
    if (!st->early) return;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "source", st->host_entropy ? "host_os_csprng" : "test_seed");
    if (st->host_entropy) (void)json_push_kv_str(&row, "guest_rng_health", "unobserved");
    else (void)json_push_kv_bool(&row, "secure", false);
    (void)json_push_kv_int(&row, "bytes", (int64_t)st->early_given);
    (void)json_push_kv_bool(&row, "cleared", rvmachine_boot_seed_cleared(st->m));
    (void)json_push_kv(data, "early_seed", &row);
    json_free(&row);
}

static void mb_emit_ports(struct mb_state *st, struct json_value *data)
{
    struct json_value rows;
    if (st->port_count == 0) return;
    json_init(&rows); json_set_array(&rows);
    for (unsigned i = 0; i < st->port_count; i++) {
        struct mb_port *p = &st->ports[i];
        struct json_value row, inputs;
        json_init(&row); json_set_object(&row);
        json_init(&inputs); json_set_object(&inputs);
        (void)json_push_kv_str(&row, "name", p->name);
        (void)json_push_kv_int(&row, "generation", p->epoch);
        (void)json_push_kv_int(&row, "accepted", (int64_t)p->accepted);
        (void)json_push_kv_int(&row, "received", (int64_t)p->received);
        (void)json_push_kv_int(&row, "queued", (int64_t)rvmachine_conport_queued(st->m, i));
        (void)json_push_kv_int(&row, "driver_consumed", (int64_t)rvmachine_conport_consumed(st->m, i));
        (void)json_push_kv_bool(&row, "matched", !st->port_failed &&
                              p->received == p->expect.before.size);
        struct sha256_ctx sha;
        unsigned char digest[SHA256_OUTPUT_SIZE];
        char hex[2u * SHA256_OUTPUT_SIZE + 1u];
        sha256_init(&sha); sha256_write(&sha, p->input_bytes, (size_t)p->input.before.size);
        sha256_finalize(&sha, digest); zcl_hex_encode(digest, sizeof digest, hex);
        (void)json_push_kv_str(&row, "input_sha256", hex);
        sha256_init(&sha); sha256_write(&sha, p->expected_bytes, (size_t)p->expect.before.size);
        sha256_finalize(&sha, digest); zcl_hex_encode(digest, sizeof digest, hex);
        (void)json_push_kv_str(&row, "expected_sha256", hex);
        /* Every accepted output byte was compared; this hashes that exact prefix. */
        sha256_init(&sha); sha256_write(&sha, p->expected_bytes, p->received);
        sha256_finalize(&sha, digest); zcl_hex_encode(digest, sizeof digest, hex);
        (void)json_push_kv_str(&row, "accepted_output_sha256", hex);
        mb_emit_file(&inputs, "input", &p->input);
        mb_emit_file(&inputs, "expect", &p->expect);
        (void)json_push_kv(&row, "inputs", &inputs);
        json_free(&inputs);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(data, "ports", &rows);
    json_free(&rows);
}

static void mb_emit(struct mb_state *st, struct zcl_command_reply *reply)
{
    if (!mb_public_capture(st)) {
        (void)zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "PRIVATE_EXPORT_REFUSED", "verify",
            "private or absent machines cannot emit public evidence", MB_PATH);
        return;
    }
    struct json_value inputs;
    mb_emit_stop(st, &reply->data);
    (void)json_push_kv_int(&reply->data, "console_bytes",
                           (int64_t)st->script.console_bytes);
    (void)json_push_kv_str(&reply->data, "transcript_sha256", st->sha_hex);
    (void)json_push_kv_int(&reply->data, "script_fired", st->script.fired);
    (void)json_push_kv_int(&reply->data, "script_total", st->script.count);
    (void)json_push_kv_int(&reply->data, "ram_mib", (int64_t)(st->ram_bytes >> 20));
    (void)json_push_kv_int(&reply->data, "overlay_blocks",
                           rvmachine_disk_overlay_blocks(st->m->disk));
    json_init(&inputs);
    json_set_object(&inputs);
    mb_emit_file(&inputs, "kernel", &st->kernel);
    mb_emit_builtin(st, &inputs);
    if (st->accepted.datadir) {
        struct json_value row;
        json_init(&row); json_set_object(&row);
        (void)json_push_kv_str(&row, "package_root", st->accepted.root_hex);
        (void)json_push_kv_str(&row, "output", st->accepted.output);
        (void)json_push_kv_str(&row, "copied_sha256", st->accepted.image_sha256);
        (void)json_push_kv_int(&row, "bytes", (int64_t)st->accepted.length);
        (void)json_push_kv_int(&row, "allocated_capacity", (int64_t)st->accepted.capacity);
        (void)json_push_kv_bool(&row, "current_after_run", !st->accepted.changed);
        (void)json_push_kv_str(&row, "scope", "installed_output_at_checks; not_guest_recipe_acceptance");
        (void)json_push_kv(&inputs, "accepted_kernel", &row);
        json_free(&row);
    }
    mb_emit_file(&inputs, "disk", &st->disk);
    (void)json_push_kv(&reply->data, "inputs", &inputs);
    json_free(&inputs);
    zcl_mb_data_emit(st, &reply->data);
    mb_emit_entropy(st, &reply->data);
    mb_emit_early(st, &reply->data);
    mb_emit_ports(st, &reply->data);
    (void)json_push_kv_str(&reply->data, "console_tail", st->tail);
}

/* What fed the guest from the test seed, for the state line of a failed run. */
static const char *mb_sources_note(const struct mb_state *st)
{
    if (st->host_entropy) return st->entropy_failed ?
        " entropy=host_os_csprng,failed" : " entropy=host_os_csprng,guest_health_unobserved";
    if (st->early) return " entropy+early_seed=test_seed,not_secure";
    return st->seeded ? " entropy=test_seed,not_secure" : "";
}

/* A failed run still hands over its receipt, as the error's evidence. */
static void mb_public_run_fail(const struct mb_state *st, struct zcl_command_reply *reply,
                        const char *code, const char *phase, const char *message)
{
    const struct rvmachine_result *r = &st->res;
    char evidence[256];
    int n = snprintf(evidence, sizeof evidence,
                     "stop=%s marker_seen=%d retired=%llu skip=%llu fw_calls=%llu "
                     "device_work=%llu console_bytes=%llu script=%u/%u sha256=%s",
                     rvmachine_stop_name(r->stop), st->script.until_seen ? 1 : 0,
                     (unsigned long long)r->retired, (unsigned long long)r->skip,
                     (unsigned long long)r->fw_calls, (unsigned long long)r->device_work,
                     (unsigned long long)st->script.console_bytes, st->script.fired,
                     st->script.count, st->sha_hex);
    if (st->port_count != 0) {
        n = snprintf(evidence, sizeof evidence,
                     "stop=%s marker_seen=%d retired=%llu skip=%llu fw_calls=%llu device_work=%llu",
                     rvmachine_stop_name(r->stop), st->script.until_seen ? 1 : 0,
                     (unsigned long long)r->retired, (unsigned long long)r->skip,
                     (unsigned long long)r->fw_calls, (unsigned long long)r->device_work);
        for (unsigned i = 0; i < st->port_count && n > 0 && (size_t)n < sizeof evidence; i++) {
            const struct mb_port *p = &st->ports[i];
            int added = snprintf(evidence + n, sizeof evidence - (size_t)n,
                " p%u=%zu/%zu/%zu/%zu@%u", i, p->accepted, p->received,
                rvmachine_conport_queued(st->m, i), rvmachine_conport_consumed(st->m, i),
                rvmachine_conport_generation(st->m, i));
            if (added < 0) break;
            n += added;
        }
    }
    if (r->stop == RVMACHINE_STOP_FAULT && n > 0 && (size_t)n < sizeof evidence)
        snprintf(evidence + n, sizeof evidence - (size_t)n,
                 " pc=0x%llx cause=0x%llx tval=0x%llx", (unsigned long long)r->pc,
                 (unsigned long long)r->cause, (unsigned long long)r->tval);
    (void)zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, code, phase, message, evidence);
    /* a failed run with a test source still says what fed the guest */
    snprintf(reply->error.current_state, sizeof reply->error.current_state, "%s%s",
             rvmachine_stop_name(r->stop),
             mb_sources_note(st));
    if (st->host_entropy)
        snprintf(reply->error.current_state, sizeof reply->error.current_state,
                 "source_failed=%u bytes=%llu early_bytes=%llu",
                 st->entropy_failed ? 1u : 0u,
                 (unsigned long long)st->ent_given, (unsigned long long)st->early_given);
}

/* Before machine creation, ordinary setup errors contain no captured bytes. */
static void mb_run_fail(const struct mb_state *st, struct zcl_command_reply *reply,
                        const char *code, const char *phase, const char *message)
{
    if (st->private_export_failed ||
        (st->m && !rvmachine_public_export_allowed(st->m))) {
        (void)zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "PRIVATE_EXPORT_REFUSED", "verify",
            "private machines cannot emit public error evidence", MB_PATH);
        return;
    }
    mb_public_run_fail(st, reply, code, phase, message);
}

/* The verdict: the receipt is the data above; the status says whether every
 * stated goal was met on inputs that stayed still. */
static bool mb_inputs_changed(const struct mb_state *st)
{
    if (st->kernel.changed || st->disk.changed) return true;
    for (unsigned i = 0; i < st->port_count; i++)
        if (st->ports[i].input.changed || st->ports[i].expect.changed) return true;
    return false;
}

static bool mb_input_verdict(struct mb_state *st, struct zcl_command_reply *reply)
{
    if (st->out_failed)
        mb_run_fail(st, reply, "TRANSCRIPT_WRITE_FAILED", "write",
                    "the transcript could not be written completely");
    else if (st->accepted.changed)
        mb_run_fail(st, reply, "ACCEPTED_KERNEL_CHANGED", "verify",
                    "current installed kernel qualification changed; execution already performed is not retracted");
    else if (mb_inputs_changed(st))
        mb_run_fail(st, reply, "INPUT_CHANGED", "verify",
                    "a kernel, disk or port fixture input changed during the run");
    else return false;
    return true;
}

static void mb_public_verdict(struct mb_state *st, struct zcl_command_reply *reply)
{
    if (st->entropy_failed)
        mb_run_fail(st, reply, "ENTROPY_SOURCE_FAILED", "run",
                    "the host OS entropy source refused a request; no fallback was used");
    else if (mb_input_verdict(st, reply)) return;
    else if (st->res.stop == RVMACHINE_STOP_FAULT)
        mb_run_fail(st, reply, "GUEST_FAULT", "run",
                    "the guest could not continue; pc, cause and tval are in the "
                    "evidence");
    else if (st->console_full)
        mb_run_fail(st, reply, "CONSOLE_LIMIT", "run",
                    "the guest printed up to the console limit of 64 MiB; the run "
                    "was stopped there");
    else if ((st->port_count != 0 || st->host_entropy) &&
             st->res.retired + st->res.fw_calls + st->res.device_work > st->max_work)
        mb_run_fail(st, reply, st->port_count != 0 ? "PORT_BUDGET_EXCEEDED" :
                    "WORK_BUDGET_EXCEEDED", "run",
                    "the final atomic device round exceeded the requested work budget");
    else if (st->port_count != 0 && !mb_ports_complete(st))
        mb_run_fail(st, reply, "PORT_GOAL_MISSED", "run",
                    "named-port bytes were mismatched, reset, unopened or unconsumed");
    else if (st->script.fired < st->script.count)
        mb_run_fail(st, reply, "GOAL_MISSED", "run",
                    "a type_after marker never appeared on the console");
    else if (st->script.until_len != 0 && !st->script.until_seen)
        mb_run_fail(st, reply, "GOAL_MISSED", "run",
                    "the until text never appeared on the console");
    else {
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
    }
}

/* The public verdict never inspects private capture evidence. */
static void mb_verdict(struct mb_state *st, struct zcl_command_reply *reply)
{
    if (!mb_public_capture(st)) {
        mb_run_fail(st, reply, "PRIVATE_EXPORT_REFUSED", "verify",
                    "private or absent machines cannot emit public evidence");
        return;
    }
    mb_public_verdict(st, reply);
}

void zcl_native_handle_dev_machine_boot(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
    struct mb_state *st;
    if (reply == NULL) return;
    st = zcl_calloc(1, sizeof *st, "machine_boot_state");
    if (st == NULL) {
        (void)zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY", "setup",
                      "the run state could not be allocated", MB_PATH);
        return;
    }
    platform_positioned_file_init(&st->kernel.file);
    platform_positioned_file_init(&st->disk.file);
    platform_private_file_init(&st->owner.volume);
    platform_private_file_init(&st->owner.record);
    platform_private_file_init(&st->owner.credential);
    for (unsigned i = 0; i < 2u; i++) {
        platform_positioned_file_init(&st->ports[i].input.file);
        platform_positioned_file_init(&st->ports[i].expect.file);
    }
    st->out_fd = -1;
    rvmachine_script_init(&st->script);
    sha256_init(&st->sha);
    if (mb_parse(request != NULL ? request->input : NULL, st, reply)) {
        if (st->owner.enabled) (void)zcl_mb_owner_called(st, reply);
        else if (mb_prepare(st, reply)) mb_run(st, reply);
    }
    if (!zcl_mb_owner_dispose(st)) return; /* Refused join retains the complete capsule. */
    if (st->ran) {
        mb_emit(st, reply);
        mb_verdict(st, reply);
    }
    if (st->out_fd >= 0) close(st->out_fd);
    rvmachine_destroy(st->m);
    zcl_mb_data_release(st);
    platform_positioned_file_close(&st->kernel.file);
    platform_positioned_file_close(&st->disk.file);
    package_lifecycle_declared_output_close(&st->accepted.reader);
    guest_image_admission_close(&st->accepted.public_reader);
    if (st->accepted.image) memory_cleanse(st->accepted.image, st->accepted.length);
    free(st->accepted.image);
    for (unsigned i = 0; i < 2u; i++) {
        platform_positioned_file_close(&st->ports[i].input.file);
        platform_positioned_file_close(&st->ports[i].expect.file);
    }
    free(st);

}
