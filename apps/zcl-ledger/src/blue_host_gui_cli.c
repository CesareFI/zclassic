/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_host_gui.h"
#include "blue_host_gui_window.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int write_views(const char *directory, const blue_host_gui_facts *facts) {
    struct stat info;
    if (stat(directory, &info) != 0 || !S_ISDIR(info.st_mode)) return 1;
    const char *names[] = {"light.png", "dark.png", "large.png",
                           "large-dark.png"};
    const bool dark[] = {false, true, false, true};
    const bool large[] = {false, false, true, true};
    for (size_t i = 0; i < 4; ++i) {
        char path[512];
        int wrote = snprintf(path, sizeof path, "%s/%s", directory, names[i]);
        if (wrote < 0 || (size_t)wrote >= sizeof path ||
            !blue_host_gui_render_png(path, facts, dark[i], large[i])) {
            fprintf(stderr, "offscreen render failed for %s\n", names[i]);
            return 1;
        }
        puts(names[i]);
    }
    return 0;
}

static int present_representative(const char *shot_path) {
    blue_host_gui_facts facts;
    if (!blue_host_gui_load_representative(&facts)) {
        fputs("representative payment facts unavailable\n", stderr);
        return 1;
    }
    blue_host_gui_bind_status status = blue_host_gui_bind(
        &facts, &facts, facts.digest, sizeof facts.digest);
    if (status != BLUE_HOST_GUI_BIND_MATCH) return 1;
    int presented = blue_host_gui_present(&facts, shot_path);
    if (presented == 3)
        fputs("windowed launcher failed: no window-system client is linked\n",
              stderr);
    return presented;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--window") == 0)
        return present_representative(NULL);
    if (argc == 3 && strcmp(argv[1], "--window-shot") == 0)
        return present_representative(argv[2]);
    if (argc != 3 || strcmp(argv[1], "--offscreen") != 0) {
        fprintf(stderr, "Usage: %s --offscreen DIRECTORY\n"
                        "       %s --window\n"
                        "       %s --window-shot PNG\n",
                argv[0], argv[0], argv[0]);
        return 2;
    }
    blue_host_gui_facts facts;
    if (!blue_host_gui_load_representative(&facts)) {
        fputs("representative payment facts unavailable\n", stderr);
        return 1;
    }
    blue_host_gui_bind_status status = blue_host_gui_bind(
        &facts, &facts, facts.digest, sizeof facts.digest);
    if (status != BLUE_HOST_GUI_BIND_MATCH ||
        !blue_host_gui_write_log(stdout, &facts, status) ||
        write_views(argv[2], &facts) != 0)
        return 1;
    return 0;
}
