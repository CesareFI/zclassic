/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Fixed result.c closure format. This only combines independently supplied
 * roots; it cannot verify a mount namespace or authorize an attestation.
 * Its argv is the local direct-source probe, not the production epoch rule.
 * HISTORICAL: closure v1 (toolchain z23.gcc13.x86_64.fixed_result.v1, LF
 * environment text). Retired by z23verify.fixed_result.v2; no v2 consumer
 * accepts its output. Kept only because tree_closure_probe.sh still runs it. */
#define _GNU_SOURCE
#include "base/hex.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SOURCE "platform/modules/base/src/result.c"

struct roots {
    uint8_t tool_content[32], source_content[32];
    uint8_t tool_owner[32], source_owner[32];
    uint8_t jail_policy_claim[32], preprocessed[32];
};

static void put_u64(struct sha3_256_ctx *h, uint64_t n)
{
    uint8_t b[8];
    zcl_write_u64_le(b, n);
    sha3_256_write(h, b, sizeof(b));
}

static void put_bytes(struct sha3_256_ctx *h, const void *p, size_t n)
{
    put_u64(h, n);
    sha3_256_write(h, p, n);
}

static int safe_cwd_chars(const char *cwd)
{
    if (cwd[0] != '/' || strlen(cwd) >= PATH_MAX) return 0;
    for (const unsigned char *p = (const unsigned char *)cwd; *p; p++)
        if (!isalnum(*p) && *p != '/' && *p != '_' && *p != '-' && *p != '.')
            return 0;
    return 1;
}

static int valid_cwd(const char *cwd)
{
    if (!safe_cwd_chars(cwd)) return 0;
    char resolved[PATH_MAX];
    if (!realpath(cwd, resolved) || strcmp(cwd, resolved) != 0) return 0;
    char source[PATH_MAX], source_resolved[PATH_MAX];
    int n = snprintf(source, sizeof(source), "%s/%s", cwd, SOURCE);
    struct stat st;
    return n > 0 && n < (int)sizeof(source) &&
           lstat(source, &st) == 0 && S_ISREG(st.st_mode) &&
           realpath(source, source_resolved) != NULL &&
           strcmp(source, source_resolved) == 0;
}

/* Text in the attestation uses decimal-length-prefixed arguments. It has no
 * shell quoting or embedded NUL and is unambiguous even if later profiles
 * add an argument containing spaces. */
static int append_arg(char *out, size_t cap, size_t *used, const char *arg)
{
    size_t n = strlen(arg);
    int wrote = snprintf(out + *used, cap - *used, "%zu:", n);
    if (wrote < 0 || (size_t)wrote >= cap - *used) return 0;
    *used += (size_t)wrote;
    if (n >= cap - *used) return 0;
    memcpy(out + *used, arg, n);
    *used += n;
    out[*used] = '\0';
    return 1;
}

static int build_argv(char out[8192], const char *cwd)
{
    char mapped[PATH_MAX + 64];
    int n = snprintf(mapped, sizeof(mapped),
                     "-ffile-prefix-map=%s=/zclassic23", cwd);
    if (n < 0 || n >= (int)sizeof(mapped)) return 0;
    const char *args[] = {
        "/usr/bin/gcc", "-std=c2x", "-g", "-O3", "-march=x86-64-v3",
        "-flto=auto", "-Wall", "-Wextra", "-Werror", "-pedantic", mapped,
        "-gno-record-gcc-switches", "-fstack-protector-strong",
        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2", "-fcf-protection=full",
        "-fPIE", "-Iplatform/modules/sha3/include",
        "-Iplatform/modules/base/include", "-D_POSIX_C_SOURCE=200809L",
        "-frandom-seed=" SOURCE, "-c", "-MD", "-MF", "/work/result.d",
        "-MT", "result.o", SOURCE, "-o", "/work/result.o"
    };
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; i < sizeof(args) / sizeof(args[0]); i++)
        if (!append_arg(out, 8192, &used, args[i])) return 0;
    return 1;
}

static void hash_environment(uint8_t out[32])
{
    /* The future child must use execve(envp) with precisely these entries.
     * Inherited GCC_EXEC_PREFIX/COMPILER_PATH/CPATH cannot enter this key. */
    static const char *const env[] = {
        "LC_ALL=C", "TZ=UTC", "TMPDIR=/work", "PATH=/usr/bin:/bin"
    };
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    static const char domain[] = "z23.verify.fixed_result.env.v1";
    put_bytes(&h, domain, sizeof(domain) - 1);
    for (size_t i = 0; i < sizeof(env) / sizeof(env[0]); i++)
        put_bytes(&h, env[i], strlen(env[i]));
    sha3_256_finalize(&h, out);
}

static void hash_closure(const struct roots *r, const char *cwd,
                         const char *argv, const uint8_t env[32],
                         uint8_t out[32])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    static const char domain[] = "z23.verify.fixed_result.closure.v1";
    put_bytes(&h, domain, sizeof(domain) - 1);
    sha3_256_write(&h, r->tool_content, 32);
    sha3_256_write(&h, r->source_content, 32);
    sha3_256_write(&h, r->tool_owner, 32);
    sha3_256_write(&h, r->source_owner, 32);
    sha3_256_write(&h, r->jail_policy_claim, 32);
    sha3_256_write(&h, r->preprocessed, 32);
    put_bytes(&h, cwd, strlen(cwd));
    put_bytes(&h, argv, strlen(argv));
    sha3_256_write(&h, env, 32);
    put_bytes(&h, SOURCE, sizeof(SOURCE) - 1);
    sha3_256_finalize(&h, out);
}

static int parse_roots(char **argv, struct roots *r)
{
    uint8_t *fields[] = {
        r->tool_content, r->source_content, r->tool_owner,
        r->source_owner, r->jail_policy_claim, r->preprocessed
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if (!zcl_hex_decode_lower(argv[i + 2], fields[i], 32)) return 0;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 9 || strcmp(argv[1], "combine") != 0) {
        fprintf(stderr, "fixed_result_refuse=request_shape_unsupported\n");
        return 2;
    }
    struct roots r;
    if (!parse_roots(argv, &r)) {
        fprintf(stderr, "fixed_result_refuse=hash_malformed\n");
        return 2;
    }
    const char *cwd = argv[8];
    if (!valid_cwd(cwd)) {
        fprintf(stderr, "fixed_result_refuse=cwd_or_source_unsupported\n");
        return 2;
    }
    char argv_norm[8192];
    if (!build_argv(argv_norm, cwd)) {
        fprintf(stderr, "fixed_result_refuse=argv_limit\n");
        return 2;
    }
    uint8_t env[32], closure[32];
    char env_hex[65], closure_hex[65], tool_hex[65];
    hash_environment(env);
    hash_closure(&r, cwd, argv_norm, env, closure);
    zcl_hex_encode(env, sizeof(env), env_hex);
    zcl_hex_encode(closure, sizeof(closure), closure_hex);
    zcl_hex_encode(r.tool_content, sizeof(r.tool_content), tool_hex);
    printf("toolchain_id=z23.gcc13.x86_64.fixed_result.v1:%s\n"
           "argv_norm=%s\nrecorded_cwd=%s\nenvironment_sha3=%s\n"
           "closure_sha3=%s\nattest_eligible=0\n"
           "reason=probe_profile_and_jail_unverified\n",
           tool_hex, argv_norm, cwd, env_hex, closure_hex);
    return 0;
}
