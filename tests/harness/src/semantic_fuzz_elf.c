/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read the functions and data objects of an x86-64 ET_REL object for the semantic-facts fuzz oracle: each symbol's bytes and relocations, digested raw and with each relocation resolved to the content it addresses, and an executable's DT_RUNPATH. */
#include "test/semantic_fuzz.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The on-disk ELF64 encoding, spelled out so the values this reader
 * enforces are visible where they are enforced. The hotswap probe
 * (engine/modules/hotswap) reads only shared objects' dynamic segment; a
 * relocatable object needs the section, symbol and RELA tables. */
#define EHDR_SIZE 64u
#define SHDR_SIZE 64u
#define SYM_SIZE 24u
#define RELA_SIZE 24u
#define DYN_SIZE 16u
#define PHDR_SIZE 56u
#define PT_LOAD_ 1u
#define PT_DYNAMIC_ 2u
#define ET_REL_ 1u
#define EM_X86_64_ 62u
#define SHT_SYMTAB_ 2u
#define SHT_STRTAB_ 3u
#define SHT_RELA_ 4u
#define SHT_DYNAMIC_ 6u
#define SHT_NOBITS_ 8u
#define SHF_EXECINSTR_ 0x4u
#define SHF_MERGE_ 0x10u
#define SHF_STRINGS_ 0x20u
#define STB_LOCAL_ 0u
#define STT_NOTYPE_ 0u
#define STT_OBJECT_ 1u
#define STT_FUNC_ 2u
#define STT_SECTION_ 3u
#define SHN_LORESERVE_ 0xff00u
#define DT_RPATH_ 15u
#define DT_NEEDED_ 1u
#define DT_STRTAB_ 5u
#define DT_STRSZ_ 10u
#define DT_RUNPATH_ 29u
#define MAX_SHNUM 65536u
#define MAX_IMAGE (256u * 1024u * 1024u)
/* x86-64 PC-relative relocations whose 4-byte field ends the instruction
 * in the code a compiler emits: the addressed byte is at addend + 4. */
#define R_PC32_ 2u
#define R_PLT32_ 4u
#define R_GOTPCREL_ 9u
#define R_GOTPCRELX_ 41u
#define R_REX_GOTPCRELX_ 42u
/* An addend beyond this addresses nothing a section of an image can hold. */
#define MAX_ADDEND ((int64_t)1 << 40)
/* A NOBITS section may claim any size; past this one nothing resolves. */
#define MAX_SECTION ((uint64_t)1 << 48)

struct shdr {
    uint32_t name, type, link, info;
    uint64_t flags, addr, offset, size, entsize;
};

struct elf {
    const uint8_t *b;
    size_t n;
    struct shdr *sh;
    uint32_t shnum, shstrndx;
    uint32_t symtab; /* section index of SHT_SYMTAB, 0 none */
    char *err;
    size_t errlen;
};

/* [off, off+len) inside the image, without wraparound. */
static const uint8_t *at(const struct elf *e, uint64_t off, uint64_t len)
{
    if (len > e->n || off > e->n - len)
        return NULL;
    return e->b + off;
}

static bool refuse(struct elf *e, const char *what)
{
    (void)snprintf(e->err, e->errlen, "%s", what);
    return false;
}

/* A NUL-terminated string at offset `off` of string section `sec`. */
static const char *str_at(const struct elf *e, uint32_t sec, uint64_t off)
{
    const struct shdr *s;
    const uint8_t *p;
    if (sec == 0 || sec >= e->shnum)
        return NULL;
    s = &e->sh[sec];
    if (off >= s->size || (p = at(e, s->offset, s->size)) == NULL)
        return NULL;
    if (memchr(p + off, 0, (size_t)(s->size - off)) == NULL)
        return NULL;
    return (const char *)p + off;
}

static bool read_header(struct elf *e, bool rel)
{
    const uint8_t *h = at(e, 0, EHDR_SIZE);
    if (h == NULL || memcmp(h, "\177ELF", 4) != 0)
        return refuse(e, "not an ELF image");
    if (h[4] != 2 || h[5] != 1)
        return refuse(e, "not ELF64 little-endian");
    if (rel && (zcl_read_u16_le(h + 16) != ET_REL_ ||
                zcl_read_u16_le(h + 18) != EM_X86_64_))
        return refuse(e, "not an x86-64 relocatable object");
    if (zcl_read_u16_le(h + 58) != SHDR_SIZE)
        return refuse(e, "unexpected section header size");
    e->shnum = zcl_read_u16_le(h + 60);
    e->shstrndx = zcl_read_u16_le(h + 62);
    if (e->shnum == 0 || e->shstrndx >= e->shnum)
        return refuse(e, "extended section numbering");
    return true;
}

static bool read_sections(struct elf *e)
{
    uint64_t shoff = zcl_read_u64_le(e->b + 40);
    const uint8_t *t = at(e, shoff, (uint64_t)e->shnum * SHDR_SIZE);
    if (t == NULL)
        return refuse(e, "section header table out of range");
    e->sh = zcl_calloc(e->shnum, sizeof(*e->sh), "sfz.elf.sh");
    if (e->sh == NULL)
        return refuse(e, "out of memory");
    for (uint32_t k = 0; k < e->shnum; k++) {
        const uint8_t *s = t + (size_t)k * SHDR_SIZE;
        struct shdr *d = &e->sh[k];
        d->name = zcl_read_u32_le(s);
        d->type = zcl_read_u32_le(s + 4);
        d->flags = zcl_read_u64_le(s + 8);
        d->addr = zcl_read_u64_le(s + 16);
        d->offset = zcl_read_u64_le(s + 24);
        d->size = zcl_read_u64_le(s + 32);
        d->link = zcl_read_u32_le(s + 40);
        d->info = zcl_read_u32_le(s + 44);
        d->entsize = zcl_read_u64_le(s + 56);
        if (d->type != SHT_NOBITS_ && at(e, d->offset, d->size) == NULL)
            return refuse(e, "section out of range");
        if (d->type == SHT_SYMTAB_)
            e->symtab = k;
    }
    return true;
}

static bool open_elf(struct elf *e, const uint8_t *img, size_t n, bool rel,
                     char *err, size_t errlen)
{
    memset(e, 0, sizeof(*e));
    e->b = img;
    e->n = n;
    e->err = err;
    e->errlen = errlen;
    return read_header(e, rel) && read_sections(e);
}

/* Symbol k of the symbol table: its name, binding, type, section, value
 * and size. */
struct sym {
    const char *name;
    uint32_t type, bind, shndx;
    uint64_t value, size;
};

static uint64_t nsyms(const struct elf *e)
{
    return e->sh[e->symtab].size / SYM_SIZE;
}

static bool sym_at(const struct elf *e, uint64_t k, struct sym *out)
{
    const struct shdr *st = &e->sh[e->symtab];
    const uint8_t *s;
    if (k >= nsyms(e))
        return false;
    s = e->b + st->offset + k * SYM_SIZE;
    out->type = s[4] & 0xfu;
    out->bind = s[4] >> 4;
    out->shndx = zcl_read_u16_le(s + 6);
    out->value = zcl_read_u64_le(s + 8);
    out->size = zcl_read_u64_le(s + 16);
    /* a section symbol is named by its section, as objdump prints it */
    if (out->type == STT_SECTION_ && out->shndx < e->shnum)
        out->name = str_at(e, e->shstrndx, e->sh[out->shndx].name);
    else
        out->name = str_at(e, st->link, zcl_read_u32_le(s));
    return out->name != NULL;
}

/* True when symbol s is defined in a section of this image. */
static bool defined_here(const struct elf *e, const struct sym *s)
{
    return s->shndx != 0 && s->shndx < SHN_LORESERVE_ && s->shndx < e->shnum;
}

/* ---- the resolved relocation target ------------------------------------------ */

static void put_u64(struct sha3_256_ctx *c, uint64_t v)
{
    uint8_t b[8];
    zcl_write_u64_le(b, v);
    sha3_256_write(c, b, sizeof(b));
}

static void put_tag(struct sha3_256_ctx *c, uint8_t tag)
{
    sha3_256_write(c, &tag, 1);
}

static void put_str(struct sha3_256_ctx *c, const char *s)
{
    sha3_256_write(c, (const unsigned char *)s, strlen(s) + 1);
}

/* [off, off+len) of section sec, length first; a NOBITS section holds
 * zeros, so its length alone. */
static void put_range(const struct elf *e, const struct shdr *sec, uint64_t off,
                      uint64_t len, struct sha3_256_ctx *c)
{
    put_u64(c, len);
    if (sec->type != SHT_NOBITS_)
        sha3_256_write(c, e->b + sec->offset + off, (size_t)len);
}

static bool pc_relative(uint32_t type)
{
    return type == R_PC32_ || type == R_PLT32_ || type == R_GOTPCREL_ ||
           type == R_GOTPCRELX_ || type == R_REX_GOTPCRELX_;
}

/* In section `shndx`: the function or object whose bytes hold `off`
 * (held), and the first function, object or label past it (has_next). */
struct near {
    struct sym hold, next;
    bool held, has_next;
};

/* A function, object or label of section shndx: what bounds content. */
static bool bounds_content(const struct sym *s, uint32_t shndx)
{
    return s->shndx == shndx && (s->type == STT_NOTYPE_ ||
                                 s->type == STT_OBJECT_ || s->type == STT_FUNC_);
}

static bool holds(const struct sym *s, uint64_t off)
{
    return s->type != STT_NOTYPE_ && s->size > 0 && s->value <= off &&
           off - s->value < s->size;
}

/* False, refusing the image, on a malformed symbol. */
static bool nearest(struct elf *e, uint32_t shndx, uint64_t off, struct near *n)
{
    memset(n, 0, sizeof(*n));
    for (uint64_t k = 1; k < nsyms(e); k++) {
        struct sym s;
        if (!sym_at(e, k, &s))
            return refuse(e, "unterminated symbol name");
        if (!bounds_content(&s, shndx))
            continue;
        if (!n->held && holds(&s, off)) {
            n->hold = s;
            n->held = true;
        }
        if (s.value > off && (!n->has_next || s.value < n->next.value)) {
            n->next = s;
            n->has_next = true;
        }
    }
    return true;
}

/* A NUL-terminated string of a SHF_MERGE|SHF_STRINGS section at `off`,
 * each character `es` bytes wide. */
static bool put_string(struct elf *e, const struct shdr *sec, uint64_t off,
                       struct sha3_256_ctx *c)
{
    uint64_t es = sec->entsize ? sec->entsize : 1, end = off;
    static const uint8_t zero[16] = {0};
    if (es > sizeof(zero) || sec->type == SHT_NOBITS_)
        return refuse(e, "string section with an unexpected entry size");
    while (end <= sec->size && sec->size - end >= es &&
           memcmp(e->b + sec->offset + end, zero, (size_t)es) != 0)
        end += es;
    if (end > sec->size || sec->size - end < es)
        return refuse(e, "unterminated string in a merged string section");
    put_tag(c, 'S');
    put_range(e, sec, off, end + es - off, c);
    return true;
}

/* The function (by name: its bytes are judged as that function's) or the
 * object (its bytes) that holds `off`, with the position within it. */
static bool put_held(struct elf *e, const struct shdr *sec, const struct sym *h,
                     uint64_t off, struct sha3_256_ctx *c)
{
    bool code = (sec->flags & SHF_EXECINSTR_) != 0;
    if (h->value > sec->size || h->size > sec->size - h->value)
        return refuse(e, "symbol outside its section");
    put_tag(c, code ? 'C' : 'O');
    put_str(c, h->name);
    put_u64(c, off - h->value);
    if (!code)
        put_range(e, sec, h->value, h->size, c);
    return true;
}

/* The content at `off` of the section a local symbol names: a merged
 * string or constant, the function or object it lands in, else the bytes
 * up to the next symbol or the section end. */
static bool put_content(struct elf *e, uint32_t shndx, uint64_t off,
                        struct sha3_256_ctx *c)
{
    const struct shdr *sec = &e->sh[shndx];
    struct near n;
    uint64_t end;
    if ((sec->flags & (SHF_MERGE_ | SHF_STRINGS_)) == (SHF_MERGE_ | SHF_STRINGS_))
        return put_string(e, sec, off, c);
    if ((sec->flags & SHF_MERGE_) != 0 && sec->entsize > 0 &&
        sec->size - off >= sec->entsize) {
        put_tag(c, 'E');
        put_range(e, sec, off, sec->entsize, c);
        return true;
    }
    if (!nearest(e, shndx, off, &n))
        return false;
    if (n.held)
        return put_held(e, sec, &n.hold, off, c);
    end = n.has_next && n.next.value < sec->size ? n.next.value : sec->size;
    put_tag(c, 'R');
    put_range(e, sec, off, end - off, c);
    return true;
}

/* The target of one relocation, into c: for a section or local symbol
 * defined here, the content it addresses; for any other, its name and the
 * addend, since the addend then says where in that symbol it points. */
static bool put_target(struct elf *e, const struct sym *t, uint32_t type,
                       int64_t addend, struct sha3_256_ctx *c)
{
    uint64_t size;
    int64_t off;
    if ((t->type != STT_SECTION_ && t->bind != STB_LOCAL_) || !defined_here(e, t)) {
        put_tag(c, 'N');
        put_str(c, t->name);
        put_u64(c, (uint64_t)addend);
        return true;
    }
    size = e->sh[t->shndx].size;
    /* both bounded, so the sum cannot wrap */
    off = size <= MAX_SECTION && t->value <= size && addend <= MAX_ADDEND &&
                  addend >= -MAX_ADDEND
              ? (int64_t)t->value + addend + (pc_relative(type) ? 4 : 0)
              : -1;
    if (off < 0 || (uint64_t)off > size) {
        put_tag(c, 'X'); /* outside the section: nothing to resolve */
        put_u64(c, (uint64_t)addend);
        return true;
    }
    return put_content(e, t->shndx, (uint64_t)off, c);
}

/* Digest the RELA entries of section `sec` that patch [lo, hi): offset
 * from lo and type into both contexts; then the target's name and addend
 * into `raw`, and the resolved target into `res`. */
static bool digest_relocs(struct elf *e, uint32_t sec, uint64_t lo, uint64_t hi,
                          struct sha3_256_ctx *raw, struct sha3_256_ctx *res)
{
    for (uint32_t r = 0; r < e->shnum; r++) {
        const struct shdr *rs = &e->sh[r];
        if (rs->type != SHT_RELA_ || rs->info != sec)
            continue;
        if (rs->link != e->symtab)
            return refuse(e, "relocations against another symbol table");
        for (uint64_t q = 0; q < rs->size / RELA_SIZE; q++) {
            const uint8_t *p = e->b + rs->offset + q * RELA_SIZE;
            uint64_t off = zcl_read_u64_le(p), info = zcl_read_u64_le(p + 8);
            uint8_t rec[12];
            struct sym t;
            if (off < lo || off >= hi)
                continue;
            if (!sym_at(e, info >> 32, &t))
                return refuse(e, "relocation names no symbol");
            zcl_write_u64_le(rec, off - lo);
            zcl_write_u32_le(rec + 8, (uint32_t)info);
            sha3_256_write(raw, rec, sizeof(rec));
            sha3_256_write(res, rec, sizeof(rec));
            put_str(raw, t.name);
            sha3_256_write(raw, p + 16, 8);
            if (!put_target(e, &t, (uint32_t)info,
                            (int64_t)zcl_read_u64_le(p + 16), res))
                return false;
        }
    }
    return true;
}

static bool add_sym(struct elf *e, const struct sym *s, struct sfz_syms *out)
{
    const struct shdr *sec;
    struct sha3_256_ctx raw, res;
    struct sfz_sym *f;
    if (!defined_here(e, s))
        return true; /* undefined, absolute or common: no bytes here */
    sec = &e->sh[s->shndx];
    if (s->size > sec->size || s->value > sec->size - s->size)
        return refuse(e, "symbol outside its section");
    if (s->type == STT_FUNC_ && sec->type == SHT_NOBITS_)
        return refuse(e, "function in a NOBITS section");
    if (strlen(s->name) >= SFZ_NAME_MAX)
        return refuse(e, "symbol name too long");
    f = &out->v[out->n];
    memset(f, 0, sizeof(*f));
    memcpy(f->name, s->name, strlen(s->name) + 1);
    f->object = s->type == STT_OBJECT_;
    f->local = s->bind == STB_LOCAL_;
    f->shndx = s->shndx;
    f->value = s->value;
    f->size = s->size;
    sha3_256_init(&raw);
    sha3_256_init(&res);
    put_range(e, sec, s->value, s->size, &raw);
    put_range(e, sec, s->value, s->size, &res);
    if (!digest_relocs(e, s->shndx, s->value, s->value + s->size, &raw, &res))
        return false;
    sha3_256_finalize(&raw, f->raw);
    sha3_256_finalize(&res, f->resolved);
    out->n++;
    return true;
}

/* A function, or a data object the source names: a compiler-private
 * label (.L.str, a string literal) is no entity a plan can seed, and its
 * content is judged through the relocations that address it. */
static bool judged(const struct sym *s)
{
    return s->type == STT_FUNC_ ||
           (s->type == STT_OBJECT_ && strncmp(s->name, ".L", 2) != 0);
}

bool sfz_elf_syms(const uint8_t *img, size_t n, struct sfz_syms *out,
                  char *err, size_t errlen)
{
    struct elf e;
    uint64_t nsym;
    bool ok;
    memset(out, 0, sizeof(*out));
    ok = open_elf(&e, img, n, true, err, errlen);
    ok = ok && (e.symtab != 0 || refuse(&e, "no symbol table"));
    nsym = ok ? nsyms(&e) : 0;
    out->v = ok ? zcl_calloc(nsym ? nsym : 1, sizeof(*out->v), "sfz.elf.syms")
                : NULL;
    ok = ok && (out->v != NULL || refuse(&e, "out of memory"));
    for (uint64_t k = 1; ok && k < nsym; k++) {
        struct sym s;
        ok = sym_at(&e, k, &s) || refuse(&e, "unterminated symbol name");
        if (ok && judged(&s))
            ok = add_sym(&e, &s, out);
    }
    free(e.sh);
    if (!ok)
        sfz_syms_free(out);
    return ok;
}

void sfz_syms_free(struct sfz_syms *f)
{
    free(f->v);
    f->v = NULL;
    f->n = 0;
}

const struct sfz_sym *sfz_sym_find(const struct sfz_syms *f, const char *name,
                                   size_t k)
{
    for (size_t i = 0; i < f->n; i++)
        if (strcmp(f->v[i].name, name) == 0 && k-- == 0)
            return &f->v[i];
    return NULL;
}

/* ── DT_RUNPATH ─────────────────────────────────────────────────────────── */

static bool read_image(const char *path, uint8_t **out, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long size;
    bool ok = false;
    *out = NULL;
    if (fp == NULL)
        return false;
    if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) > 0 &&
        (unsigned long)size <= MAX_IMAGE && fseek(fp, 0, SEEK_SET) == 0) {
        *out = zcl_malloc((size_t)size, "sfz.elf.image");
        ok = *out != NULL && fread(*out, 1, (size_t)size, fp) == (size_t)size;
        *len = (size_t)size;
    }
    (void)fclose(fp);
    if (!ok) {
        free(*out);
        *out = NULL;
    }
    return ok;
}

/* The string DT_RUNPATH names in dynamic section `sec` (DT_RPATH when
 * there is no DT_RUNPATH). */
static bool dyn_path(const struct elf *e, uint32_t sec, char *out, size_t outlen)
{
    const struct shdr *d = &e->sh[sec];
    const char *found = NULL;
    for (uint64_t q = 0; q < d->size / DYN_SIZE; q++) {
        const uint8_t *p = e->b + d->offset + q * DYN_SIZE;
        uint64_t tag = zcl_read_u64_le(p);
        const char *s;
        if (tag != DT_RUNPATH_ && tag != DT_RPATH_)
            continue;
        s = str_at(e, d->link, zcl_read_u64_le(p + 8));
        if (s != NULL && (found == NULL || tag == DT_RUNPATH_))
            found = s;
    }
    return found != NULL && (size_t)snprintf(out, outlen, "%s", found) < outlen;
}

bool sfz_elf_runpath(const char *path, char *out, size_t outlen)
{
    uint8_t *img = NULL;
    size_t n = 0;
    char err[128];
    struct elf e = {0};
    bool ok = read_image(path, &img, &n) &&
              open_elf(&e, img, n, false, err, sizeof(err));
    bool found = false;
    for (uint32_t k = 0; ok && !found && k < e.shnum; k++)
        if (e.sh[k].type == SHT_DYNAMIC_)
            found = dyn_path(&e, k, out, outlen);
    free(e.sh);
    free(img);
    return found;
}

static bool load_maps(const struct elf *e, const uint8_t *p,
                      uint64_t file_off, uint64_t va, uint64_t size)
{
    uint64_t off = zcl_read_u64_le(p + 8);
    uint64_t start = zcl_read_u64_le(p + 16);
    uint64_t filesz = zcl_read_u64_le(p + 32);
    return zcl_read_u32_le(p) == PT_LOAD_ &&
           at(e, off, filesz) != NULL &&
           zcl_read_u64_le(p + 40) >= filesz && va >= start &&
           file_off >= off && va - start == file_off - off &&
           size <= filesz && file_off - off <= filesz - size;
}

static bool dyn_program_bound(const struct elf *e, const struct shdr *d,
                              const struct shdr *strings)
{
    uint64_t phoff = zcl_read_u64_le(e->b + 32);
    uint16_t phentsize = zcl_read_u16_le(e->b + 54);
    uint16_t phnum = zcl_read_u16_le(e->b + 56);
    const uint8_t *ph = at(e, phoff, (uint64_t)phentsize * phnum);
    if (ph == NULL || phentsize != PHDR_SIZE || phnum == 0)
        return false;
    unsigned loader_dynamic = 0;
    bool mapped_strings = false;
    bool mapped_dynamic = false;
    uint64_t dynamic_va = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *p = ph + (size_t)i * PHDR_SIZE;
        if (zcl_read_u32_le(p) != PT_DYNAMIC_)
            continue;
        loader_dynamic++;
        if (zcl_read_u64_le(p + 8) != d->offset ||
            zcl_read_u64_le(p + 32) != d->size ||
            zcl_read_u64_le(p + 40) < d->size)
            return false;
        dynamic_va = zcl_read_u64_le(p + 16);
    }
    if (loader_dynamic != 1)
        return false;
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *p = ph + (size_t)i * PHDR_SIZE;
        if (zcl_read_u32_le(p) == PT_LOAD_ &&
            (at(e, zcl_read_u64_le(p + 8), zcl_read_u64_le(p + 32)) == NULL ||
             zcl_read_u64_le(p + 40) < zcl_read_u64_le(p + 32)))
            return false;
        mapped_dynamic |= load_maps(e, p, d->offset, dynamic_va, d->size);
        mapped_strings |= load_maps(e, p, strings->offset, strings->addr,
                                    strings->size);
    }
    return mapped_dynamic && mapped_strings;
}

struct dyn_need_state {
    bool found, strtab, strsz;
};

static bool dyn_need_tag(const struct elf *e, const struct shdr *d,
                         const struct shdr *strings, const char *soname,
                         const uint8_t *p, struct dyn_need_state *state)
{
    uint64_t tag = zcl_read_u64_le(p);
    uint64_t value = zcl_read_u64_le(p + 8);
    if (tag == DT_RPATH_ || tag == DT_RUNPATH_)
        return false;
    if (tag == DT_STRTAB_) {
        if (state->strtab || value != strings->addr)
            return false;
        state->strtab = true;
    }
    if (tag == DT_STRSZ_) {
        if (state->strsz || value != strings->size)
            return false;
        state->strsz = true;
    }
    if (tag == DT_NEEDED_) {
        const char *s = str_at(e, d->link, value);
        if (s == NULL)
            return false;
        if (strcmp(s, soname) == 0)
            state->found = true;
    }
    return true;
}

/* -1 malformed/path override, 0 no match, 1 exact dependency. */
static int dyn_need_without_path(const struct elf *e, uint32_t sec,
                                 const char *soname)
{
    const struct shdr *d = &e->sh[sec];
    if (d->size % DYN_SIZE != 0 || d->link == 0 || d->link >= e->shnum ||
        e->sh[d->link].type != SHT_STRTAB_)
        return -1;
    const struct shdr *strings = &e->sh[d->link];
    if (!dyn_program_bound(e, d, strings))
        return -1;
    struct dyn_need_state state = {0};
    for (uint64_t q = 0; q < d->size / DYN_SIZE; q++) {
        const uint8_t *p = e->b + d->offset + q * DYN_SIZE;
        uint64_t tag = zcl_read_u64_le(p);
        if (tag == 0)
            return state.found && state.strtab && state.strsz ? 1 : 0;
        if (!dyn_need_tag(e, d, strings, soname, p, &state))
            return -1;
    }
    return -1;
}

bool sfz_elf_needs_without_runpath(const char *path, const char *soname)
{
    if (path == NULL || soname == NULL || soname[0] == '\0')
        return false;
    uint8_t *img = NULL;
    size_t n = 0;
    char err[128];
    struct elf e = {0};
    bool ok = read_image(path, &img, &n) &&
              open_elf(&e, img, n, false, err, sizeof(err));
    bool seen = false;
    int result = -1;
    for (uint32_t k = 0; ok && k < e.shnum; k++) {
        if (e.sh[k].type != SHT_DYNAMIC_)
            continue;
        if (seen) {
            result = -1;
            break;
        }
        seen = true;
        result = dyn_need_without_path(&e, k, soname);
    }
    free(e.sh);
    free(img);
    return ok && seen && result == 1;
}
