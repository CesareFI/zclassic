/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The static half of tool-image discovery: reads an x86-64 ELF
 *          file's PT_INTERP and DT_NEEDED entries with bounded reads (it
 *          never runs the file, unlike ldd) and materializes the loader
 *          and the shared-object closure from the loader's default
 *          directories. RPATH and RUNPATH are refused, not interpreted. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fixed_result_image.h"

#include "base/safe_alloc.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRE_MAX_PHDRS 64u
#define FRE_MAX_DYN 512u
#define FRE_MAX_NEEDED 32u
#define FRE_MAX_OBJECTS 64u

/* The glibc x86-64 multiarch default directories, in the loader's order
 * (ld.so --list-diagnostics: path.system_dirs). */
static const char *const k_fre_system_dirs[] = {
    "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib", "/usr/lib"
};

struct fre_elf {
    int fd;
    Elf64_Phdr ph[FRE_MAX_PHDRS];
    unsigned phnum;
    char interp[PATH_MAX];
    char needed[FRE_MAX_NEEDED][NAME_MAX + 1];
    unsigned needed_count;
};

static bool fre_read(int fd, void *buf, size_t n, uint64_t off)
{
    ssize_t got = pread(fd, buf, n, (off_t)off);
    return got == (ssize_t)n;
}

static const char *fre_header(struct fre_elf *e)
{
    unsigned char id[EI_NIDENT];
    Elf64_Ehdr eh;
    if (!fre_read(e->fd, id, sizeof(id), 0) || memcmp(id, ELFMAG, SELFMAG) != 0 ||
        id[EI_CLASS] != ELFCLASS64 || id[EI_DATA] != ELFDATA2LSB ||
        !fre_read(e->fd, &eh, sizeof(eh), 0) || eh.e_machine != EM_X86_64 ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        eh.e_phnum > FRE_MAX_PHDRS ||
        !fre_read(e->fd, e->ph, sizeof(Elf64_Phdr) * eh.e_phnum, eh.e_phoff))
        return ZCL_FRI_WHY_ELF;
    e->phnum = eh.e_phnum;
    return NULL;
}

static const char *fre_interp(struct fre_elf *e)
{
    for (unsigned i = 0; i < e->phnum; i++) {
        const Elf64_Phdr *p = &e->ph[i];
        if (p->p_type != PT_INTERP) continue;
        if (p->p_filesz < 2 || p->p_filesz > sizeof(e->interp) ||
            !fre_read(e->fd, e->interp, p->p_filesz, p->p_offset) ||
            e->interp[p->p_filesz - 1] != '\0' || e->interp[0] != '/' ||
            strlen(e->interp) != p->p_filesz - 1)
            return ZCL_FRI_WHY_ELF;
    }
    return NULL;
}

/* A dynamic-section virtual address to its file offset via PT_LOAD. */
static bool fre_offset(const struct fre_elf *e, uint64_t vaddr, uint64_t *off)
{
    for (unsigned i = 0; i < e->phnum; i++) {
        const Elf64_Phdr *p = &e->ph[i];
        if (p->p_type == PT_LOAD && vaddr >= p->p_vaddr &&
            vaddr - p->p_vaddr < p->p_filesz) {
            *off = vaddr - p->p_vaddr + p->p_offset;
            return true;
        }
    }
    return false;
}

static const char *fre_needed_name(struct fre_elf *e, uint64_t strtab,
                                   uint64_t strsz, uint64_t name)
{
    char *out = e->needed[e->needed_count];
    size_t cap = sizeof(e->needed[0]);
    if (name >= strsz) return ZCL_FRI_WHY_ELF;
    size_t n = (size_t)(strsz - name) < cap ? (size_t)(strsz - name) : cap;
    ssize_t got = pread(e->fd, out, n, (off_t)(strtab + name));
    if (got <= 0) return ZCL_FRI_WHY_ELF;
    size_t len = strnlen(out, (size_t)got);
    if (len == 0 || len == (size_t)got || strchr(out, '/'))
        return ZCL_FRI_WHY_ELF;
    e->needed_count++;
    return NULL;
}

/* The string table's address and size; RPATH/RUNPATH refuses. */
static const char *fre_dyn_strtab(const Elf64_Dyn *d, size_t count,
                                  uint64_t *strtab, uint64_t *strsz)
{
    for (size_t i = 0; i < count && d[i].d_tag != DT_NULL; i++) {
        if (d[i].d_tag == DT_RPATH || d[i].d_tag == DT_RUNPATH)
            return ZCL_FRI_WHY_ELF_SEARCH;
        if (d[i].d_tag == DT_STRTAB) *strtab = d[i].d_un.d_ptr;
        if (d[i].d_tag == DT_STRSZ) *strsz = d[i].d_un.d_val;
    }
    return NULL;
}

static const char *fre_dynamic(struct fre_elf *e, const Elf64_Phdr *dyn)
{
    Elf64_Dyn d[FRE_MAX_DYN];
    size_t count = dyn->p_filesz / sizeof(Elf64_Dyn);
    if (count == 0 || count > FRE_MAX_DYN ||
        !fre_read(e->fd, d, count * sizeof(Elf64_Dyn), dyn->p_offset))
        return ZCL_FRI_WHY_ELF;
    uint64_t strtab = 0, strsz = 0, off = 0;
    const char *why = fre_dyn_strtab(d, count, &strtab, &strsz);
    if (why) return why;
    if (!strtab || !strsz || !fre_offset(e, strtab, &off)) return ZCL_FRI_WHY_ELF;
    for (size_t i = 0; i < count && d[i].d_tag != DT_NULL; i++) {
        if (d[i].d_tag != DT_NEEDED) continue;
        if (e->needed_count == FRE_MAX_NEEDED) return ZCL_FRI_WHY_LIMIT;
        why = fre_needed_name(e, off, strsz, d[i].d_un.d_val);
        if (why) return why;
    }
    return NULL;
}

static const char *fre_parse(struct fre_elf *e, const char *path)
{
    memset(e, 0, sizeof(*e));
    e->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (e->fd < 0) return errno == ENOENT ? ZCL_FRI_WHY_MISSING
                                          : ZCL_FRI_WHY_UNREADABLE;
    const char *why = fre_header(e);
    if (!why) why = fre_interp(e);
    for (unsigned i = 0; !why && i < e->phnum; i++)
        if (e->ph[i].p_type == PT_DYNAMIC) why = fre_dynamic(e, &e->ph[i]);
    close(e->fd);
    return why;
}

bool zcl_fri_elf_interp(const char *path, char interp[PATH_MAX],
                        const char **why)
{
    struct fre_elf e;
    *why = fre_parse(&e, path);
    if (*why) return false;
    snprintf(interp, PATH_MAX, "%s", e.interp);
    return true;
}

struct fre_closure {
    char done[FRE_MAX_OBJECTS][PATH_MAX];
    unsigned count;
    zcl_fri_path_fn seen;
    void *ctx;
};

static bool fre_seen(struct fre_closure *c, const char *physical)
{
    for (unsigned i = 0; i < c->count; i++)
        if (strcmp(c->done[i], physical) == 0) return true;
    return false;
}

static bool fre_fail(struct zcl_fri_image *img, const char *why,
                     const char *path)
{
    if (!img->why) {
        img->why = why;
        snprintf(img->why_path, sizeof(img->why_path), "%s", path);
    }
    return false;
}

static bool fre_object(struct zcl_fri_image *img, struct fre_closure *c,
                       const char *host_path, unsigned depth);

static bool fre_needed(struct zcl_fri_image *img, struct fre_closure *c,
                       const char *name, unsigned depth)
{
    for (size_t i = 0; i < sizeof(k_fre_system_dirs) / sizeof(*k_fre_system_dirs); i++) {
        char path[PATH_MAX], host[PATH_MAX];
        struct stat st;
        if (snprintf(path, sizeof(path), "%s/%s", k_fre_system_dirs[i], name)
                >= PATH_MAX ||
            snprintf(host, sizeof(host), "%s%s", img->host_root, path) >= PATH_MAX)
            return fre_fail(img, ZCL_FRI_WHY_LIMIT, name);
        if (stat(host, &st) == 0 && S_ISREG(st.st_mode))
            return fre_object(img, c, path, depth + 1u);
    }
    return fre_fail(img, ZCL_FRI_WHY_ELF_NEEDED, name);
}

static bool fre_deps(struct zcl_fri_image *img, struct fre_closure *c,
                     const char *host, unsigned depth)
{
    struct fre_elf e;
    const char *why = fre_parse(&e, host);
    if (why) return fre_fail(img, why, host);
    if (e.interp[0] && !fre_object(img, c, e.interp, depth + 1u)) return false;
    for (unsigned i = 0; i < e.needed_count; i++)
        if (!fre_needed(img, c, e.needed[i], depth)) return false;
    return true;
}

static bool fre_object(struct zcl_fri_image *img, struct fre_closure *c,
                       const char *host_path, unsigned depth)
{
    char physical[PATH_MAX], host[PATH_MAX];
    if (depth > 16u) return fre_fail(img, ZCL_FRI_WHY_LIMIT, host_path);
    if (!zcl_fri_add_host_path(img, host_path, physical)) return false;
    if (fre_seen(c, physical)) return true;
    if (c->count == FRE_MAX_OBJECTS) return fre_fail(img, ZCL_FRI_WHY_LIMIT, host_path);
    snprintf(c->done[c->count++], PATH_MAX, "%s", physical);
    if (c->seen && !c->seen(c->ctx, physical))
        return fre_fail(img, ZCL_FRI_WHY_ALLOC, physical);
    if (snprintf(host, sizeof(host), "%s%s", img->host_root, physical) >= PATH_MAX)
        return fre_fail(img, ZCL_FRI_WHY_LIMIT, physical);
    return fre_deps(img, c, host, depth);
}

bool zcl_fri_add_elf_closure(struct zcl_fri_image *img, const char *host_path,
                             zcl_fri_path_fn seen, void *ctx)
{
    struct fre_closure *c = zcl_calloc(1, sizeof(*c), "fre_closure");
    if (!c) return fre_fail(img, ZCL_FRI_WHY_ALLOC, host_path);
    c->seen = seen;
    c->ctx = ctx;
    bool ok = fre_object(img, c, host_path, 0);
    free(c);
    return ok;
}

bool zcl_fri_add_elf_deps(struct zcl_fri_image *img, const char *host_file)
{
    struct fre_closure *c = zcl_calloc(1, sizeof(*c), "fre_closure");
    if (!c) return fre_fail(img, ZCL_FRI_WHY_ALLOC, host_file);
    bool ok = fre_deps(img, c, host_file, 0);
    free(c);
    return ok;
}
