/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: open one dev-only shared library. The calls sit inside the
 * dev-build region so a release link contains none of them. */
#ifdef ZCL_DEV_BUILD
#ifndef _WIN32
#include <dlfcn.h>
#endif
#endif

#include "hotswap/dev_library.h"

#include <stddef.h>

void *zcl_dev_library_open(const char *path)
{
#ifdef ZCL_DEV_BUILD
#ifndef _WIN32
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#else
    (void)path;
    return NULL;
#endif
#else
    (void)path;
    return NULL;
#endif
}

void *zcl_dev_library_symbol(void *handle, const char *name)
{
#ifdef ZCL_DEV_BUILD
#ifndef _WIN32
    return dlsym(handle, name);
#else
    (void)handle;
    (void)name;
    return NULL;
#endif
#else
    (void)handle;
    (void)name;
    return NULL;
#endif
}

const char *zcl_dev_library_error(void)
{
#ifdef ZCL_DEV_BUILD
#ifndef _WIN32
    return dlerror();
#else
    return NULL;
#endif
#else
    return NULL;
#endif
}
