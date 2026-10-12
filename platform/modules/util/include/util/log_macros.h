/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Forwarding header plus source-origin stamp. The LOG_* / GUARD* macros live
 * in platform/modules/base (the in-tree dependency sink: it references
 * nothing but libc). ~63% of the tree includes this path, so it stays put.
 *
 * Every ERROR-rank macro reached through this header appends a trailing
 * `origin=<basename>:<line>` token, so `grep -a -m1 'origin=' node.log`
 * lands on the first real fault instead of the first incidental
 * `file.c:123` string in ambient instrumentation. LOG_WARN / LOG_INFO are
 * unchanged, and so is every byte base emits before the token.
 *
 * The stamp lives here, not in base/log_macros.h, on purpose: base is a
 * content-addressed package whose root is pinned (through sha3) by the
 * sealed core, so editing base would move the core seal. This header is
 * outside every package and outside core/, and it is the include path most
 * of the tree already uses. Code that includes base/log_macros.h directly
 * keeps the base format (which already carries file:line and function
 * mid-line); include this header to get the trailing token. */

#ifndef ZCL_LOG_MACROS_FORWARD_H
#define ZCL_LOG_MACROS_FORWARD_H

#include <string.h>

#include "base/log_macros.h"

/* Bare filename of a __FILE__ path. Checks both separators unconditionally
 * (never a platform #ifdef) so a path built on one host still yields a
 * bare filename when logged from a binary that ran on another. */
static inline const char *zcl_log_origin_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');
    if (bslash && (!slash || bslash > slash))
        slash = bslash;
    return slash ? slash + 1 : path;
}

/* One ERROR-rank line: the exact base body "[domain] file:line func(): msg"
 * followed by " origin=<basename>:<line>". */
#define ZCL_LOG_ERROR_ORIGIN(domain, fmt, ...) \
    ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR, "[%s] %s:%d %s(): " fmt " origin=%s:%d\n", \
            (domain), __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__, \
            zcl_log_origin_basename(__FILE__), __LINE__)

#undef LOG_FAIL
#define LOG_FAIL(domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
    return false; \
} while (0)

#undef LOG_ERR
#define LOG_ERR(domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
    return -1; \
} while (0)

#undef LOG_NULL
#define LOG_NULL(domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
    return NULL; \
} while (0)

#undef LOG_RETURN
#define LOG_RETURN(val, domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
    return (val); \
} while (0)

#undef LOG_ERROR
#define LOG_ERROR(domain, fmt, ...) do { \
    ZCL_LOG_ERROR_ORIGIN(domain, fmt __VA_OPT__(,) __VA_ARGS__); \
} while (0)

#undef GUARD
#define GUARD(cond, domain, fmt, ...) do { \
    if (!(cond)) { \
        ZCL_LOG_ERROR_ORIGIN(domain, "GUARD FAILED: " fmt __VA_OPT__(,) __VA_ARGS__); \
        return false; \
    } \
} while (0)

#undef GUARD_NOT_NULL
#define GUARD_NOT_NULL(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_ERROR_ORIGIN(domain, "%s is NULL", (label)); \
        return false; \
    } \
} while (0)

#undef GUARD_NOT_NULL_RET_NULL
#define GUARD_NOT_NULL_RET_NULL(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_ERROR_ORIGIN(domain, "%s is NULL", (label)); \
        return NULL; \
    } \
} while (0)

#undef GUARD_NOT_NULL_ERR
#define GUARD_NOT_NULL_ERR(ptr, domain, label) do { \
    if (!(ptr)) { \
        ZCL_LOG_ERROR_ORIGIN(domain, "%s is NULL", (label)); \
        return -1; \
    } \
} while (0)

#endif /* ZCL_LOG_MACROS_FORWARD_H */
