/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Open the wallet GUI library only after an explicit GUI launch.
 * A headless z23-dev process does not map GTK or WebKit at startup.
 */
#include "hotswap/dev_library.h"
#include "platform/os_proc.h"
#include "views/wallet_gui.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ZCL_WALLET_GUI_SO "libz23walletgui.so"
#define ZCL_WALLET_GUI_WALK 5

typedef int (*zcl_wallet_gui_fn)(int argc, char **argv, const char *datadir);

static int gui_dirname(char *path)
{
    char *slash = strrchr(path, '/');
    if (slash == NULL || slash == path)
        return -1;
    *slash = '\0';
    return 0;
}

static int gui_join(char *out, size_t cap, const char *dir)
{
    int n = snprintf(out, cap, "%s/%s", dir, ZCL_WALLET_GUI_SO);
    if (n < 0 || (size_t)n >= cap) {
        fprintf(stderr, "wallet gui: companion path does not fit in %zu bytes\n", cap);
        return -1;
    }
    return 0;
}

static void *gui_open_file(const char *path)
{
    void *handle = zcl_dev_library_open(path);
    const char *err;
    if (handle != NULL)
        return handle;
    err = zcl_dev_library_error();
    fprintf(stderr, "wallet gui: cannot load %s (%s)\n",
            path, err != NULL ? err : "open failed");
    return NULL;
}

static void *gui_load(void)
{
    char exe[4096];
    char path[4096];
    int depth;

    if (!os_proc_exe_path(exe, sizeof exe)) {
        fprintf(stderr, "wallet gui: executable path is unavailable\n");
        return NULL;
    }
    for (depth = 0; depth < ZCL_WALLET_GUI_WALK; depth++) {
        if (gui_dirname(exe) != 0) {
            fprintf(stderr, "wallet gui: executable path has no directory\n");
            return NULL;
        }
        if (gui_join(path, sizeof path, exe) != 0)
            return NULL;
        if (access(path, R_OK) != 0)
            continue;
        return gui_open_file(path);
    }
    fprintf(stderr, "wallet gui: %s is not beside the executable\n", ZCL_WALLET_GUI_SO);
    return NULL;
}

int wallet_gui_main(int argc, char **argv, const char *datadir)
{
    void *handle;
    void *symbol;
    zcl_wallet_gui_fn fn = NULL;
    const char *err;

    handle = gui_load();
    if (handle == NULL)
        return 1;
    symbol = zcl_dev_library_symbol(handle, "z23_wallet_gui_main");
    if (symbol == NULL || sizeof symbol != sizeof fn) {
        err = zcl_dev_library_error();
        fprintf(stderr, "wallet gui: z23_wallet_gui_main is missing (%s)\n",
                err != NULL ? err : "symbol missing");
        return 1;
    }
    memcpy(&fn, &symbol, sizeof fn);
    return fn(argc, argv, datadir);
}
