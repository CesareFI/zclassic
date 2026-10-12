/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev-only opener for one shared library the headless node does
 * not map at startup. */
#ifndef ZCL_HOTSWAP_DEV_LIBRARY_H
#define ZCL_HOTSWAP_DEV_LIBRARY_H

/* Open path and return a handle, or NULL. A release build and Windows
 * return NULL. The handle is intentionally never closed. */
void *zcl_dev_library_open(const char *path);

/* Resolve name in handle, or NULL. */
void *zcl_dev_library_symbol(void *handle, const char *name);

/* Text for the last open or resolve failure, or NULL. */
const char *zcl_dev_library_error(void);

#endif /* ZCL_HOTSWAP_DEV_LIBRARY_H */
