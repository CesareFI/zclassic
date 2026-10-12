/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: FreeBSD riscv64 initial process stack. At the program entry a0 and
 * sp point at argc, followed by argv[] and NULL, envp[] and NULL, then the
 * auxv pairs ended by AT_NULL, sp 16-byte aligned (sys/riscv/riscv
 * exec_machdep.c exec_setregs: a0 = stack, sp = STACKALIGN(stack)). */
#include "rvuser_internal.h"
#include "base/serialize_le.h"
#include <string.h>

enum { AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5, AT_PAGESZ = 6, AT_BASE = 7, AT_ENTRY = 9 };
#define AUX_MAX 7u
#define PHENT_SIZE 56u
#define SP_REG 2u
#define A0_REG 10u

struct ru_aux {
    uint64_t key[AUX_MAX], val[AUX_MAX];
    unsigned n;
};

static unsigned ru_count(const char *const *v)
{
    unsigned n = 0;
    while (v && v[n] && n <= RU_ARGS_MAX) n++;
    return n;
}

static void ru_aux_add(struct ru_aux *a, uint64_t key, uint64_t val)
{
    a->key[a->n] = key;
    a->val[a->n++] = val;
}

static void ru_aux_fill(struct ru_aux *a, const struct ru_image *img)
{
    a->n = 0;
    ru_aux_add(a, AT_PAGESZ, RU_PAGE);
    if (img->phdr_addr != 0) ru_aux_add(a, AT_PHDR, img->phdr_addr);
    ru_aux_add(a, AT_PHENT, PHENT_SIZE);
    ru_aux_add(a, AT_PHNUM, img->phnum);
    /* FreeBSD __elfN(freebsd_copyout_auxargs) (sys/kern/imgact_elf.c) emits AT_PHDR, AT_PHENT,
     * AT_PHNUM, AT_PAGESZ, AT_ENTRY and AT_BASE; img->phdr_addr and img->entry already include
     * the static-PIE load bias (et_dyn_addr). AT_BASE is the interpreter base: 0 with no
     * PT_INTERP, which is every program this loader accepts. */
    ru_aux_add(a, AT_BASE, 0);
    ru_aux_add(a, AT_ENTRY, img->entry);
    ru_aux_add(a, AT_NULL, 0);
}

/* Bytes of NUL-terminated strings, or UINT64_MAX when above limit. */
static uint64_t ru_strings_size(const char *const *v, unsigned n, uint64_t limit)
{
    uint64_t total = 0;
    for (unsigned i = 0; i < n; i++) {
        total += (uint64_t)strlen(v[i]) + 1u;
        if (total > limit) return UINT64_MAX;
    }
    return total;
}

/* Copy the strings below *cur and record each guest address in addrs. False, with nothing
 * written for the failing string, when the guest pointer helper refuses the range. */
static bool ru_push_strings(struct ru_proc *p, const char *const *v, unsigned n, uint64_t *cur,
                            uint64_t *addrs)
{
    for (unsigned i = 0; i < n; i++) {
        size_t len = strlen(v[i]) + 1u;
        if (len > *cur) return false;
        uint8_t *dst = ru_guest_ptr(p, *cur - len, len);
        if (!dst) return false;
        *cur -= len;
        memcpy(dst, v[i], len);
        addrs[i] = *cur;
    }
    return true;
}

/* Store one word at *at and advance; false (no store) when the guest pointer is refused. */
static bool ru_put_word(struct ru_proc *p, uint64_t *at, uint64_t v)
{
    uint8_t *dst = ru_guest_ptr(p, *at, 8);
    if (!dst) return false;
    zcl_write_u64_le(dst, v);
    *at += 8u;
    return true;
}

static bool ru_put_vec(struct ru_proc *p, uint64_t *at, const uint64_t *addrs, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        if (!ru_put_word(p, at, addrs[i])) return false;
    return ru_put_word(p, at, 0);
}

static bool ru_put_table(struct ru_proc *p, uint64_t sp, const uint64_t *av, unsigned argc,
                         const uint64_t *ev, unsigned envc, const struct ru_aux *aux)
{
    uint64_t at = sp;
    if (!ru_put_word(p, &at, argc) || !ru_put_vec(p, &at, av, argc) ||
        !ru_put_vec(p, &at, ev, envc))
        return false;
    for (unsigned i = 0; i < aux->n; i++)
        if (!ru_put_word(p, &at, aux->key[i]) || !ru_put_word(p, &at, aux->val[i])) return false;
    return true;
}

enum rvuser_error ru_stack_build(struct ru_proc *p, const struct ru_image *img,
                                 const char *const *argv, const char *const *envp,
                                 size_t stack_bytes)
{
    unsigned argc = ru_count(argv), envc = ru_count(envp);
    if (argc > RU_ARGS_MAX || envc > RU_ARGS_MAX) return RVUSER_ERR_ARGS;
    if (p->mem.base > UINT64_MAX - p->mem.size || p->mem.size <= stack_bytes) return RVUSER_ERR_NO_STACK;
    uint64_t top = p->mem.base + p->mem.size, floor = top - stack_bytes;
    uint64_t sa = ru_strings_size(argv, argc, stack_bytes);
    uint64_t se = ru_strings_size(envp, envc, stack_bytes);
    if (sa == UINT64_MAX || se == UINT64_MAX || sa + se >= stack_bytes) return RVUSER_ERR_NO_STACK;
    uint64_t av[RU_ARGS_MAX + 1u], ev[RU_ARGS_MAX + 1u], cur = top;
    struct ru_aux aux;
    ru_aux_fill(&aux, img);
    if (!ru_push_strings(p, envp, envc, &cur, ev) || !ru_push_strings(p, argv, argc, &cur, av))
        return RVUSER_ERR_NO_STACK;
    uint64_t words = 1u + argc + 1u + envc + 1u + 2u * aux.n;
    if (cur < floor || cur - floor < words * 8u + 16u) return RVUSER_ERR_NO_STACK;
    uint64_t sp = (cur - words * 8u) & ~15ull;
    if (!ru_put_table(p, sp, av, argc, ev, envc, &aux)) return RVUSER_ERR_NO_STACK;
    p->hart.x[SP_REG] = sp;
    p->hart.x[A0_REG] = sp;
    return RVUSER_ERR_NONE;
}
