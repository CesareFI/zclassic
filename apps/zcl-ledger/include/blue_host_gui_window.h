/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_HOST_GUI_WINDOW_H
#define ZCL_BLUE_HOST_GUI_WINDOW_H

#include "blue_host_gui.h"

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Blue host window requires ISO C23"
#endif

/* Open the dark payment window, or save that same window when shot_path
 * is set. Returns 3 when the window system cannot start. The window
 * shows facts only. It does not sign and it does not install. */
int blue_host_gui_present(const blue_host_gui_facts *facts,
                          const char *shot_path);

#endif
