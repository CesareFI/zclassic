/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Links the standalone fixed-result image builder, the tree
 *          closure walk and the seccomp generator into the test harness,
 *          so the verifier_images group calls the very code root runs.
 *          Their CLIs (the fixed_result_*_main.c files and tree_closure.c main)
 *          stay out; the group compiles and runs those separately. */
#if defined(__linux__) && defined(__x86_64__)
#define ZCL_TREE_CLOSURE_NO_MAIN 1
#include "verify/tree_closure.c"
#include "verify/fixed_result_image.c"
#include "verify/fixed_result_image_elf.c"
#include "verify/fixed_result_image_run.c"
#include "verify/fixed_result_image_build.c"
#include "verify/fixed_result_image_proof.c"
#include "verify/fixed_result_seccomp.c"
#else
typedef int zcl_verifier_images_linux_x86_64_only;
#endif
