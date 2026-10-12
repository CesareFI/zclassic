/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Unprivileged, fixed-profile qualification for a direct-source verifier.
 * This produces no attestation: a driver digest cannot bind cc1, assembler,
 * loader, shared libraries, specs, or the complete filesystem lookup set.
 * HISTORICAL: the GCC 13/14 direct-source probe core, retired by
 * z23verify.fixed_result.v2; no v2 consumer accepts its output. Kept only
 * because real_tu_probe.sh still runs it. */
#define _POSIX_C_SOURCE 200809L
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "base/hex.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SOURCE "platform/modules/base/src/result.c"
static bool hash_file(const char *path, char out[65])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[16384];
    bool ok = true;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = false; break; }
        if (n == 0) break;
        sha3_256_write(&ctx, buf, (size_t)n);
    }
    if (close(fd) != 0) ok = false;
    if (!ok) return false;
    unsigned char digest[32];
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool valid_hash(const char *s)
{
    uint8_t bytes[32];
    return zcl_hex_decode_lower(s, bytes, sizeof(bytes));
}

static bool path_join(char out[PATH_MAX], const char *dir, const char *name)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", dir, name);
    return n > 0 && n < PATH_MAX;
}

/* This narrow fixture invokes only the distro GCC path. All components of
 * the resolved executable path must be root-owned and not writable by other
 * accounts; the caller cannot substitute a compiler program. */
static bool trusted_dir_chain(char parent[PATH_MAX])
{
    struct stat st;
    for (;;) {
        char *slash = strrchr(parent, '/');
        if (!slash) return false;
        if (slash == parent) parent[1] = 0;
        else *slash = 0;
        if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode) ||
            st.st_uid != 0 || (st.st_mode & 0022) != 0) return false;
        if (slash == parent) return true;
    }
}

static bool trusted_driver_path(const char *path)
{
    char parent[PATH_MAX];
    size_t len = strlen(path);
    if (len < 2 || len >= sizeof(parent)) return false;
    memcpy(parent, path, len + 1);
    struct stat st;
    if (lstat(parent, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 0022) != 0 ||
        (st.st_mode & 0111) == 0) return false;
    return trusted_dir_chain(parent);
}

static bool run_compiler(const char *compiler, char *const args[],
                         const char *output, const char *stderr_path)
{
    int fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0) return false;
    int errfd = open(stderr_path,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     0600);
    if (errfd < 0) { close(fd); return false; }
    pid_t pid = fork();
    if (pid < 0) { close(errfd); close(fd); return false; }
    if (pid == 0) {
        close(fd);
        if (dup2(errfd, STDERR_FILENO) < 0) _exit(127);
        close(errfd);
        execv(compiler, args);
        _exit(127);
    }
    close(errfd);
    close(fd);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0) return false;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return false;
    return true;
}

static int refuse(const char *reason)
{
    fprintf(stderr, "compile_core_refuse=%s\n", reason);
    return 2;
}

struct request {
    const char *compiler, *standard, *driver_claim, *source_claim;
    const char *pp_claim, *outdir;
};

struct compile_context {
    char driver[PATH_MAX], cwd[PATH_MAX];
    char mapped[PATH_MAX + 64], seed[128];
    char pp[PATH_MAX], obj[PATH_MAX], dep[PATH_MAX];
    char pp_err[PATH_MAX], compile_err[PATH_MAX];
};

static const char *parse_request(int argc, char **argv, struct request *r)
{
    if (argc != 8 || strcmp(argv[1], "compile") != 0)
        return "request_shape_unsupported";
    *r = (struct request){argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]};
    if (strcmp(r->standard, "-std=c23") != 0 &&
        strcmp(r->standard, "-std=c2x") != 0) return "standard_unsupported";
    if (!valid_hash(r->driver_claim) || !valid_hash(r->source_claim) ||
        !valid_hash(r->pp_claim)) return "hash_malformed";
    if (r->compiler[0] != '/' || r->outdir[0] != '/')
        return "path_not_absolute";
    if (strcmp(r->compiler, "/usr/bin/gcc") != 0)
        return "compiler_path_unsupported";
    if (getuid() != geteuid() || getgid() != getegid() || getuid() == 0)
        return "qualification_uid_unsafe";
    return NULL;
}

static bool source_owned_safely(void)
{
    struct stat st;
    return lstat(SOURCE, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == geteuid() && (st.st_mode & 0022) == 0;
}

static bool output_dir_owned_safely(const char *outdir)
{
    struct stat st;
    return lstat(outdir, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == geteuid() && (st.st_mode & 0777) == 0700;
}

static const char *prepare_context(const struct request *r,
                                    struct compile_context *c)
{
    char source[PATH_MAX];
    if (!realpath(r->compiler, c->driver) || !realpath(".", c->cwd) ||
        !realpath(SOURCE, source)) return "path_unresolved";
    if (!trusted_driver_path(c->driver)) return "compiler_ownership_unsafe";
    char expected_source[PATH_MAX];
    if (!path_join(expected_source, c->cwd, SOURCE) ||
        strcmp(source, expected_source) != 0)
        return "source_path_unexpected";
    if (!source_owned_safely())
        return "source_ownership_unsafe";
    if (!output_dir_owned_safely(r->outdir))
        return "output_dir_unsafe";
    char actual[65];
    if (!hash_file(c->driver, actual) ||
        strcmp(actual, r->driver_claim) != 0) return "driver_bytes_mismatch";
    if (!hash_file(SOURCE, actual) ||
        strcmp(actual, r->source_claim) != 0) return "source_bytes_mismatch";
    return NULL;
}

static const char *prepare_paths(const struct request *r,
                                  struct compile_context *c)
{
    if (snprintf(c->mapped, sizeof(c->mapped),
                 "-ffile-prefix-map=%s=/zclassic23", c->cwd)
            >= (int)sizeof(c->mapped) ||
        snprintf(c->seed, sizeof(c->seed), "-frandom-seed=%s", SOURCE)
            >= (int)sizeof(c->seed) ||
        !path_join(c->pp, r->outdir, "input.i") ||
        !path_join(c->obj, r->outdir, "result.o") ||
        !path_join(c->dep, r->outdir, "result.d") ||
        !path_join(c->pp_err, r->outdir, "preprocess.stderr") ||
        !path_join(c->compile_err, r->outdir, "compile.stderr"))
        return "path_too_long";
    return NULL;
}

static const char *compile_unit(const struct request *r,
                                struct compile_context *c)
{
    char *common[40] = {
        c->driver, (char *)r->standard, "-g", "-O3", "-march=x86-64-v3",
        "-flto=auto", "-Wall", "-Wextra", "-Werror", "-pedantic", c->mapped,
        "-gno-record-gcc-switches", "-fstack-protector-strong",
        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2", "-fcf-protection=full",
        "-fPIE", "-Iplatform/modules/sha3/include",
        "-Iplatform/modules/base/include", "-D_POSIX_C_SOURCE=200809L",
        c->seed
    };
    size_t tail = 21;
    common[tail++] = "-E";
    common[tail++] = SOURCE;
    common[tail++] = "-o";
    common[tail++] = c->pp;
    if (!run_compiler(c->driver, common, c->pp, c->pp_err))
        return "preprocess_failed";
    char actual[65];
    if (!hash_file(c->pp, actual) || strcmp(actual, r->pp_claim) != 0)
        return "preprocessed_bytes_mismatch";
    tail = 21;
    common[tail++] = "-c";
    common[tail++] = "-MD";
    common[tail++] = "-MF";
    common[tail++] = c->dep;
    common[tail++] = "-MT";
    common[tail++] = "result.o";
    common[tail++] = SOURCE;
    common[tail++] = "-o";
    common[tail++] = c->obj;
    if (!run_compiler(c->driver, common, c->obj, c->compile_err))
        return "compile_failed";
    if (!hash_file(c->driver, actual) ||
        strcmp(actual, r->driver_claim) != 0)
        return "driver_changed_during_compile";
    if (!hash_file(SOURCE, actual) ||
        strcmp(actual, r->source_claim) != 0)
        return "source_changed_during_compile";
    return NULL;
}

static const char *emit_observation(const struct request *r,
                                     const struct compile_context *c)
{
    char obj_hash[65], dep_hash[65], err_hash[65];
    if (!hash_file(c->obj, obj_hash) || !hash_file(c->dep, dep_hash) ||
        !hash_file(c->compile_err, err_hash)) return "artifact_missing";
    printf("source=%s\nrecorded_cwd=%s\nobject_sha3=%s\n"
           "dep_sha3=%s\nstderr_sha3=%s\n"
           "tool_driver_sha3=%s\npreprocessed_sha3=%s\n"
           "attest_eligible=0\nreason=tool_and_input_closure_unproven\n",
           SOURCE, c->cwd, obj_hash, dep_hash, err_hash,
           r->driver_claim, r->pp_claim);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "hash") == 0) {
        char hash[65];
        if (!hash_file(argv[2], hash)) return refuse("hash_input_invalid");
        puts(hash);
        return 0;
    }
    struct request r;
    struct compile_context c;
    const char *why = parse_request(argc, argv, &r);
    if (!why) why = prepare_context(&r, &c);
    if (!why) why = prepare_paths(&r, &c);
    if (!why) why = compile_unit(&r, &c);
    if (!why) why = emit_observation(&r, &c);
    if (why) return refuse(why);
    return 0;
}
