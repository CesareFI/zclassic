/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK shape admission. A capsule candidate is dlopen'ed into a
 * child of the resident image: every symbol it references but no longer
 * defines binds RTLD_LAZY to the resident's own (stale) copy, and every
 * constructor it carries runs at load. The HOT_FORK lane therefore admits
 * only implementation-only edits. The candidate unity object's ELF shape
 * (defined global symbols, writable and thread-local state with its size
 * and initializer relocations, init/fini sections) must equal the shape of
 * the resident's own build objects, build/dev-obj/epochs/<epoch>/<tu>.o for
 * every TU the capsule compiles; every header those objects were built from
 * must be unchanged and the candidate may include no other; and every symbol
 * the candidate leaves undefined must resolve in the running image or the
 * libraries it loads. Anything else — including every missing or
 * contradicting fact — is refused by a named HOT_FORK_SHAPE_* reason and the
 * save falls back to the restart path.
 *
 * Linux/ELF only; every other platform refuses by name.
 */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_HOTFORK_SHAPE_H
#define ZCL_TOOLS_DEV_DEVLOOP_HOTFORK_SHAPE_H

#include <stdbool.h>
#include <stddef.h>

/* Every refusal's why-text starts with this prefix, then the reason name. */
#define ZCL_HOTFORK_SHAPE_REASON "HOT_FORK_SHAPE_"

/* The facts one HOT_FORK build is judged against, captured before the
 * candidate compile. `generation` names the resident image, its epoch build
 * session and the capsule's resident build objects and depfiles; it joins
 * the artifact cache key, so a cached artifact is only ever reused inside
 * the resident generation that admitted it. `unbound` holds the refusal for
 * the first missing or contradicting fact ("" when every fact is present). */
struct zcl_hotfork_shape {
    const char *root;
    const char *source_tu;
    const char *sibling_tus;
    const char *adapter_id;
    const char *cc;
    const char *compiler_id;
    const char *cflags;
    char epoch[65];
    char toolchain[65];
    char generation[65];
    char image[96]; /* running image dev-ino-size-mtime; names its kept objects */
    char adapter_tus[1024]; /* sources the story adapter compiles, '|'-joined */
    char unbound[320];
};

/* Captures the resident generation for one capsule. Never fails: a missing
 * fact is recorded in `unbound` and refused by zcl_hotfork_shape_admit(). */
void zcl_hotfork_shape_begin(struct zcl_hotfork_shape *shape, const char *root,
                             const char *source_tu, const char *sibling_tus,
                             const char *adapter_id, const char *cc,
                             const char *compiler_id, const char *cflags);

/* `prior` is the caller's own verdict so far; false passes through untouched
 * (its why-text is kept). Otherwise true only when the candidate object's
 * shape equals the resident build objects' shape inside an unchanged
 * generation, toolchain and dependency closure. `depfile` is the candidate
 * compile's make depfile; the per-capsule binding record is kept beside it
 * (".d" becomes ".shape") and is written only by an admitted candidate. */
bool zcl_hotfork_shape_admit(bool prior, const struct zcl_hotfork_shape *shape,
                             const char *candidate_object, const char *depfile,
                             char *why, size_t why_len);

/* The resident call closure of one capsule, judged after its candidate is
 * built or reused and before its story runs. The story calls into the
 * running image for every function its TU set does not compile, and a body
 * edit there keeps the ABI the shape checks read. Every identifier of the
 * TU set's and story adapter's current bytes that the code index places
 * in-tree seeds codeindex_forward_closure(); each closure TU the resident
 * epoch holds an object for must still be the running image's input (the
 * object no newer than the image, no input its depfile names newer than the
 * object). True only then. No index, no placed seed, a truncated closure or
 * a stale TU refuses with a HOT_FORK_SHAPE_CALL_CLOSURE_* or
 * HOT_FORK_SHAPE_NO_BASELINE reason, never a green story. */
bool zcl_hotfork_shape_closure_admit(const char *root, const char *source_tu,
                                     const char *sibling_tus,
                                     const char *adapter_id, char *why,
                                     size_t why_len);

/* True when `why` is a HOT_FORK shape refusal (a restart fallback), not a
 * compile failure. */
bool zcl_hotfork_shape_refused(const char *why);

#if defined(ZCL_TESTING)
/* Test seam over the running-image symbol facts the guard reads: 1 when
 * `image` defines `name` (its .symtab globals, or with `dynamic` its
 * .dynsym plus every library it names as mapped in this process), 0 when
 * it does not, -1 when the image cannot be read. `parses` receives the
 * number of image parses this process has made. */
int zcl_hotfork_shape_test_image_defines(const char *image, const char *name,
                                         bool dynamic, unsigned long *parses);
#endif

#endif /* ZCL_TOOLS_DEV_DEVLOOP_HOTFORK_SHAPE_H */
