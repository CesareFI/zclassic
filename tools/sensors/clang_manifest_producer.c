/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The producer digest of a semantic manifest: the loaded compiler front end's build ids and the producer image's own bytes. */
/* dl_iterate_phdr() and dladdr() are GNU extensions; set it before the first
 * header pulls in <features.h>. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "clang_manifest_core.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/os_proc.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <elf.h>
#include <link.h>
#elif defined(__APPLE__)
#include <libproc.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#endif

/* The digest names every image whose bytes decide what the facts say:
 *   - the producer image itself (the sensor executable, read through
 *     os_proc_open_self_exe): SHA3-256 of its file bytes, because its
 *     extraction rules are ours;
 *   - the main program when it is not the producer (the clang driver) and
 *     every loaded image whose file name starts with "libclang" or "libLLVM"
 *     (the front end): its GNU build id on Linux.
 * Darwin has no GNU build ids here. It binds the producer, front end, and
 * every loaded image outside the protected dyld shared cache to its
 * backing vnode, complete file digest, and stable read-only mapped bytes.
 * If a file was replaced or changed after load, the digest is unavailable.
 * Images are hashed sorted by file name, each as
 *   u8 tag ('S' bytes, 'B' build id, 'G' type grammar) || u32le name_len ||
 *   name || u32le id_len || id,
 * after the domain. The 'G' entry (name "type-grammar") is the rule the
 * front end layer spells canonical types by (cm_core.type_grammar), so two
 * builds of the sensor that spell types differently never share a digest.
 * Anything that cannot be named (no build id, an unreadable image, a
 * platform without a loader walk, no type grammar) leaves the digest all
 * zero, which every consumer treats as an unknown producer. Darwin's fact
 * emitter refuses in that case. */
#define CM_PRODUCER_DOMAIN "zcl.semantic_producer.v1"
#if defined(__APPLE__)
#define CM_PRODUCER_MAX 128
#else
#define CM_PRODUCER_MAX 32
#endif
#define CM_BUILD_ID_MAX 64

struct cm_image {
    char name[256];
    char tag;
    uint8_t id[CM_BUILD_ID_MAX];
    size_t id_len;
};

struct cm_images {
    struct cm_image v[CM_PRODUCER_MAX];
    size_t n;
    bool failed;
    bool self_seen;
};

static const char *cm_base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

static int cm_image_cmp(const void *a, const void *b)
{
    const struct cm_image *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    if (c != 0)
        return c;
    c = (x->tag > y->tag) - (x->tag < y->tag);
#if defined(__APPLE__)
    /* Different images may share a basename; keep their digest order stable. */
    if (c == 0)
        c = memcmp(x->id, y->id,
                   x->id_len < y->id_len ? x->id_len : y->id_len);
    if (c == 0)
        c = (x->id_len > y->id_len) - (x->id_len < y->id_len);
#endif
    return c;
}

static void cm_hash_images(struct cm_images *im, uint8_t out[32])
{
    struct sha3_256_ctx h;
    uint8_t len[4];
    if (im->n > 1)
        qsort(im->v, im->n, sizeof(im->v[0]), cm_image_cmp);
    sha3_256_init(&h);
    sha3_256_write(&h, (const unsigned char *)CM_PRODUCER_DOMAIN,
                   strlen(CM_PRODUCER_DOMAIN));
    for (size_t k = 0; k < im->n; k++) {
        const struct cm_image *m = &im->v[k];
        size_t nl = strlen(m->name);
        sha3_256_write(&h, (const unsigned char *)&m->tag, 1);
        zcl_write_u32_le(len, (uint32_t)nl);
        sha3_256_write(&h, len, sizeof(len));
        sha3_256_write(&h, (const unsigned char *)m->name, nl);
        zcl_write_u32_le(len, (uint32_t)m->id_len);
        sha3_256_write(&h, len, sizeof(len));
        sha3_256_write(&h, m->id, m->id_len);
    }
    sha3_256_finalize(&h, out);
}

#if defined(__linux__)

/* Stop the walk: this image cannot be named, so the digest stays zero. */
static int cm_image_fail(struct cm_images *im)
{
    im->failed = true;
    return 1;
}

static bool cm_starts(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* The GNU build id note of one loaded image; false when it has none. */
static bool cm_build_id(const struct dl_phdr_info *info, struct cm_image *m)
{
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        const uint8_t *p = (const uint8_t *)(info->dlpi_addr + ph->p_vaddr);
        size_t off = 0;
        if (ph->p_type != PT_NOTE)
            continue;
        while (off + sizeof(ElfW(Nhdr)) <= ph->p_memsz) {
            const ElfW(Nhdr) *nh = (const ElfW(Nhdr) *)(p + off);
            size_t name_at = off + sizeof(*nh);
            size_t desc_at = name_at + ((nh->n_namesz + 3u) & ~3u);
            size_t next = desc_at + ((nh->n_descsz + 3u) & ~3u);
            if (next > ph->p_memsz)
                break;
            if (nh->n_type == NT_GNU_BUILD_ID && nh->n_namesz == 4 &&
                memcmp(p + name_at, "GNU", 4) == 0 && nh->n_descsz > 0 &&
                nh->n_descsz <= CM_BUILD_ID_MAX) {
                memcpy(m->id, p + desc_at, nh->n_descsz);
                m->id_len = nh->n_descsz;
                return true;
            }
            off = next;
        }
    }
    return false;
}

/* True when this very function's code lies in one of the image's segments. */
static bool cm_is_self(const struct dl_phdr_info *info)
{
    uintptr_t here = (uintptr_t)&cm_producer_digest;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        uintptr_t lo = (uintptr_t)(info->dlpi_addr + ph->p_vaddr);
        if (ph->p_type == PT_LOAD && here >= lo && here - lo < ph->p_memsz)
            return true;
    }
    return false;
}

static int cm_image_cb(struct dl_phdr_info *info, size_t size, void *ctx)
{
    struct cm_images *im = ctx;
    const char *name = info->dlpi_name;
    char exe[PATH_MAX];
    bool main_program = name == NULL || name[0] == '\0';
    bool self = cm_is_self(info);
    struct cm_image *m;
    (void)size;
    if (main_program) {
        if (!os_proc_exe_path(exe, sizeof(exe)))
            return cm_image_fail(im);
        name = exe;
    }
    if (!self && !main_program && !cm_starts(cm_base_name(name), "libclang") &&
        !cm_starts(cm_base_name(name), "libLLVM"))
        return 0;
    if (im->n == CM_PRODUCER_MAX)
        return cm_image_fail(im);
    m = &im->v[im->n++];
    memset(m, 0, sizeof(*m));
    if (strlen(cm_base_name(name)) >= sizeof(m->name))
        return cm_image_fail(im);
    memcpy(m->name, cm_base_name(name), strlen(cm_base_name(name)) + 1);
    if (self) {
        im->self_seen = true;
        m->tag = 'S';
        m->id_len = 32;
        if (!cm_stream_sha3(main_program ? os_proc_open_self_exe()
                                       : fopen(name, "rb"),
                          m->id))
            return cm_image_fail(im);
        return 0;
    }
    m->tag = 'B';
    if (!cm_build_id(info, m))
        return cm_image_fail(im);
    return 0;
}

/* Walk every loaded image into im. */
static void cm_walk_images(struct cm_images *im)
{
    (void)dl_iterate_phdr(cm_image_cb, im);
}

#elif defined(__APPLE__)

#define CM_DARWIN_COMMANDS_MAX (1024u * 1024u)
#define CM_DARWIN_MAPPED_MAX (512u * 1024u * 1024u)

/* dyld supplies the header and slide of the image actually mapped into this
 * process. The on-disk name alone is not evidence of those mapped bytes. */
static bool cm_mach_commands(const struct mach_header *header,
                             const uint8_t **p, const uint8_t **end)
{
    const struct mach_header_64 *h = (const void *)header;
    if (h == NULL || h->magic != MH_MAGIC_64 || h->ncmds > 4096 ||
        h->sizeofcmds > CM_DARWIN_COMMANDS_MAX)
        return false;
    *p = (const uint8_t *)(h + 1);
    *end = *p + h->sizeofcmds;
    return true;
}

static bool cm_mach_is_self(const struct mach_header *header, intptr_t slide)
{
    const uint8_t *p, *end;
    uintptr_t here = (uintptr_t)&cm_producer_digest;
    if (!cm_mach_commands(header, &p, &end))
        return false;
    while (p < end) {
        const struct load_command *cmd = (const void *)p;
        if ((size_t)(end - p) < sizeof(*cmd) || cmd->cmdsize < sizeof(*cmd) ||
            cmd->cmdsize > (size_t)(end - p))
            return false;
        if (cmd->cmd == LC_SEGMENT_64 &&
            cmd->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const void *)p;
            uintptr_t start = (uintptr_t)(seg->vmaddr + (uint64_t)slide);
            if (seg->vmsize > 0 && here >= start &&
                here - start < seg->vmsize)
                return true;
        }
        p += cmd->cmdsize;
    }
    return false;
}

/* The read-only mapped segments are stable across process launches. The
 * writable segments contain rebased pointers and front-end runtime state;
 * their bytes are not an image identity. The backing-vnode check below binds
 * every segment, including writable ones, to the complete file digest. */
static bool cm_mach_mapped_sha3(const struct mach_header *header,
                                intptr_t slide, uint8_t out[32])
{
    static const char domain[] = "zcl.semantic_darwin_mapped.v1";
    const uint8_t *p, *end;
    struct sha3_256_ctx h;
    uint8_t len[8];
    size_t total = 0;
    if (!cm_mach_commands(header, &p, &end))
        return false;
    sha3_256_init(&h);
    sha3_256_write(&h, (const uint8_t *)domain, sizeof(domain) - 1);
    while (p < end) {
        const struct load_command *cmd = (const void *)p;
        if ((size_t)(end - p) < sizeof(*cmd) || cmd->cmdsize < sizeof(*cmd) ||
            cmd->cmdsize > (size_t)(end - p))
            return false;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const void *)p;
            if (cmd->cmdsize < sizeof(*seg))
                return false;
            if ((seg->initprot & VM_PROT_READ) &&
                !(seg->initprot & VM_PROT_WRITE) && seg->vmsize > 0) {
                uintptr_t start =
                    (uintptr_t)(seg->vmaddr + (uint64_t)slide);
                if (seg->vmsize > CM_DARWIN_MAPPED_MAX - total || start == 0)
                    return false;
                total += (size_t)seg->vmsize;
                sha3_256_write(&h, (const uint8_t *)seg->segname,
                               sizeof(seg->segname));
                zcl_write_u64_le(len, seg->vmsize);
                sha3_256_write(&h, len, sizeof(len));
                sha3_256_write(&h, (const uint8_t *)start,
                               (size_t)seg->vmsize);
            }
        }
        p += cmd->cmdsize;
    }
    if (total == 0)
        return false;
    sha3_256_finalize(&h, out);
    return true;
}

/* Prove that the opened pathname still names the vnode behind dyld's mapped
 * image. A replacement after load changes the vnode; an in-place edit after
 * process start changes ctime. Both refuse even when version and mtime agree. */
static bool cm_mach_backing_matches(const struct mach_header *header,
                                    const struct stat *st)
{
    struct proc_regionwithpathinfo region = {0};
    struct proc_bsdinfo process = {0};
    const struct vinfo_stat *v;
    int pid = getpid();
    if (proc_pidinfo(pid, PROC_PIDREGIONPATHINFO,
                     (uint64_t)(uintptr_t)header, &region,
                     (int)sizeof(region)) != (int)sizeof(region) ||
        proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &process,
                     (int)sizeof(process)) != (int)sizeof(process))
        return false;
    v = &region.prp_vip.vip_vi.vi_stat;
    if (v->vst_dev != (uint32_t)st->st_dev ||
        v->vst_ino != (uint64_t)st->st_ino ||
        v->vst_size != st->st_size ||
        v->vst_mtime != st->st_mtimespec.tv_sec ||
        v->vst_mtimensec != st->st_mtimespec.tv_nsec ||
        v->vst_ctime != st->st_ctimespec.tv_sec ||
        v->vst_ctimensec != st->st_ctimespec.tv_nsec)
        return false;
    if ((uint64_t)st->st_ctimespec.tv_sec > process.pbi_start_tvsec ||
        ((uint64_t)st->st_ctimespec.tv_sec == process.pbi_start_tvsec &&
         (uint64_t)st->st_ctimespec.tv_nsec >
             process.pbi_start_tvusec * 1000u))
        return false;
    return true;
}

static bool cm_mach_file_sha3(const char *path,
                              const struct mach_header *header,
                              uint8_t out[32])
{
    FILE *fp = fopen(path, "rb");
    struct stat before, after;
    struct sha3_256_ctx h;
    unsigned char buf[65536];
    size_t n;
    bool ok;
    if (fp == NULL)
        return false;
    if (fstat(fileno(fp), &before) != 0 ||
        !cm_mach_backing_matches(header, &before)) {
        (void)fclose(fp);
        return false;
    }
    sha3_256_init(&h);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha3_256_write(&h, buf, n);
    ok = ferror(fp) == 0 && fstat(fileno(fp), &after) == 0 &&
         before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size &&
         before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
         before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
         before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
         before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec &&
         cm_mach_backing_matches(header, &after);
    (void)fclose(fp);
    if (ok)
        sha3_256_finalize(&h, out);
    return ok;
}

static bool cm_mach_add(struct cm_images *im, const char *path,
                         const struct mach_header *header, intptr_t slide,
                         bool self)
{
    const char *base = cm_base_name(path);
    struct cm_image *file, *mapped;
    size_t name_len = strlen(base);
    if (im->n + 2 > CM_PRODUCER_MAX || name_len + 8 >= sizeof(im->v[0].name))
        return false;
    file = &im->v[im->n++];
    mapped = &im->v[im->n++];
    memset(file, 0, sizeof(*file));
    memset(mapped, 0, sizeof(*mapped));
    (void)snprintf(file->name, sizeof(file->name), "%s:file", base);
    (void)snprintf(mapped->name, sizeof(mapped->name), "%s:mapped", base);
    file->tag = mapped->tag = 'S';
    file->id_len = mapped->id_len = 32;
    if (!cm_mach_file_sha3(path, header, file->id) ||
        !cm_mach_mapped_sha3(header, slide, mapped->id))
        return false;
    im->self_seen |= self;
    return true;
}

static void cm_walk_images(struct cm_images *im)
{
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *path = _dyld_get_image_name(i);
        const struct mach_header *header = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        bool self = cm_mach_is_self(header, slide);
        if (path == NULL || header == NULL) {
            im->failed = true;
            return;
        }
        if (!self && i != 0 && _dyld_shared_cache_contains_path(path) &&
            strncmp(cm_base_name(path), "libclang", 8) != 0 &&
            strncmp(cm_base_name(path), "libLLVM", 7) != 0)
            continue;
        if (!cm_mach_add(im, path, header, slide, self)) {
            im->failed = true;
            return;
        }
    }
}

#else

/* No loader walk here: the producer cannot name itself, so the digest
 * stays zero. */
static void cm_walk_images(struct cm_images *im)
{
    (void)cm_base_name;
    im->failed = true;
}

#endif

/* The type grammar as one more hashed entry ('G'): two producers that spell
 * canonical types by different rules never share a digest, whatever their
 * image bytes. */
static bool cm_add_grammar(struct cm_images *im, const char *grammar)
{
    struct cm_image *m;
    size_t n = grammar != NULL ? strlen(grammar) : 0;
    if (n == 0 || n > CM_BUILD_ID_MAX || im->n == CM_PRODUCER_MAX)
        return false;
    m = &im->v[im->n++];
    memset(m, 0, sizeof(*m));
    memcpy(m->name, "type-grammar", sizeof("type-grammar"));
    m->tag = 'G';
    memcpy(m->id, grammar, n);
    m->id_len = n;
    return true;
}

bool cm_producer_digest(const char *type_grammar, uint8_t out[32])
{
    struct cm_images *im = zcl_calloc(1, sizeof(*im), "clang_manifest.producer");
    bool ok;
    memset(out, 0, 32);
    if (im == NULL)
        return false;
    cm_walk_images(im);
    ok = !im->failed && im->self_seen && cm_add_grammar(im, type_grammar);
    if (ok)
        cm_hash_images(im, out);
    free(im);
    return ok;
}
