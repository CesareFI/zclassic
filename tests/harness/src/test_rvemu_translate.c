/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "test/test_core.h"
#include "rvemu/translate.h"
#include <string.h>

struct rvt_fixture {
    uint64_t tables[3][512];
    unsigned reads, writes;
    bool deny_read, deny_write, race;
};
static int rvt_read(void *ctx, uint64_t pa, uint64_t *pte)
{
    struct rvt_fixture *f = ctx;
    f->reads++;
    if (f->deny_read || pa < 4096 || pa >= 16384 || (pa & 7)) return -1;
    *pte = f->tables[(pa / 4096) - 1][(pa % 4096) / 8];
    return 0;
}
static int rvt_exchange(void *ctx, uint64_t pa, uint64_t expected, uint64_t desired)
{
    struct rvt_fixture *f = ctx;
    f->writes++;
    if (f->deny_write || pa < 4096 || pa >= 16384 || (pa & 7)) return -1;
    uint64_t *slot = &f->tables[(pa / 4096) - 1][(pa % 4096) / 8];
    if (f->race) { *slot = 0; return 1; }
    if (*slot != expected) return 1;
    *slot = desired;
    return 0;
}
static void rvt_setup(struct rvt_fixture *f, struct rvemu_translation_request *r,
                      struct rvemu_page_table_io *io)
{
    memset(f, 0, sizeof(*f));
    *r = (struct rvemu_translation_request){.va = UINT64_C(0x12345067),
        .satp = (UINT64_C(8) << 60) | 1, .effective_priv = RVEMU_PRIV_S,
        .access = RVEMU_ACCESS_LOAD, .ad_policy = RVEMU_AD_FAULT};
    *io = (struct rvemu_page_table_io){.ctx=f, .read64=rvt_read,
        .compare_exchange64=rvt_exchange};
    f->tables[0][(r->va >> 30) & 511] = (UINT64_C(2) << 10) | 1;
    f->tables[1][(r->va >> 21) & 511] = (UINT64_C(3) << 10) | 1;
    f->tables[2][(r->va >> 12) & 511] = (UINT64_C(0x45678) << 10) | 0xcf;
}
static uint64_t *rvt_leaf(struct rvt_fixture *f, const struct rvemu_translation_request *r)
{ return &f->tables[2][(r->va >> 12) & 511]; }

static int rvt_base_case(void)
{
    int failures = 0;
    struct rvt_fixture f;
    struct rvemu_translation_request r;
    struct rvemu_page_table_io io;
    struct rvemu_translation out;
    TEST("Sv39: three physical reads map a base page; Bare and M never walk") {
        rvt_setup(&f, &r, &io);
        out = rvemu_translate_sv39(&r, &io);
        ASSERT(out.status == RVEMU_TRANSLATED && out.pa == UINT64_C(0x45678067));
        ASSERT(out.page_shift == 12 && f.reads == 3 && f.writes == 0);
        r.effective_priv = RVEMU_PRIV_M;
        ASSERT(rvemu_translate_sv39(&r, NULL).pa == r.va);
        r.effective_priv = RVEMU_PRIV_S; r.satp = 0;
        ASSERT(rvemu_translate_sv39(&r, NULL).pa == r.va);
    }
_test_next:;
    return failures;
}

static int rvt_fault_case(void)
{
    int failures = 0;
    struct rvt_fixture f;
    struct rvemu_translation_request r;
    struct rvemu_page_table_io io;
    struct rvemu_translation out;
    TEST("Sv39: canonical addresses, reserved PTEs and access faults carry original tval") {
        rvt_setup(&f, &r, &io); r.va = UINT64_C(1) << 39;
        out = rvemu_translate_sv39(&r, &io);
        ASSERT(out.status == RVEMU_TRANSLATION_PAGE_FAULT && out.cause == 13);
        ASSERT(out.tval == r.va && f.reads == 0);
        rvt_setup(&f, &r, &io); *rvt_leaf(&f,&r) |= UINT64_C(1) << 63;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATION_PAGE_FAULT);
        rvt_setup(&f,&r,&io); f.deny_read=true; r.access=RVEMU_ACCESS_FETCH;
        out=rvemu_translate_sv39(&r,&io);
        ASSERT(out.status == RVEMU_TRANSLATION_ACCESS_FAULT && out.cause == 1 && out.tval == r.va);
    }
_test_next:;
    return failures;
}

static int rvt_permission_case(void)
{
    int failures = 0;
    struct rvt_fixture f;
    struct rvemu_translation_request r;
    struct rvemu_page_table_io io;
    TEST("Sv39: user permissions, SUM and MXR distinguish fetch/load/store") {
        rvt_setup(&f,&r,&io); *rvt_leaf(&f,&r) |= 16;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATION_PAGE_FAULT);
        r.mstatus=UINT64_C(1)<<18;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATED);
        r.access=RVEMU_ACCESS_FETCH;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATION_PAGE_FAULT);
        rvt_setup(&f,&r,&io); r.effective_priv=RVEMU_PRIV_U;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATION_PAGE_FAULT);
        *rvt_leaf(&f,&r)=(UINT64_C(0x45678)<<10)|0x59;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATION_PAGE_FAULT);
        r.mstatus=UINT64_C(1)<<19;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATED);
        r.access=RVEMU_ACCESS_STORE;
        ASSERT(rvemu_translate_sv39(&r,&io).cause == 15);
    }
_test_next:;
    return failures;
}

static int rvt_superpage_case(void)
{
    int failures = 0;
    struct rvt_fixture f;
    struct rvemu_translation_request r;
    struct rvemu_page_table_io io;
    struct rvemu_translation out;
    TEST("Sv39: superpage alignment and nonleaf reserved fields refuse") {
        rvt_setup(&f,&r,&io);
        f.tables[0][0]=(UINT64_C(0x40000)<<10)|0xcf;
        out=rvemu_translate_sv39(&r,&io);
        ASSERT(out.status == RVEMU_TRANSLATED && out.page_shift == 30);
        ASSERT(out.pa == (UINT64_C(0x40000000)|(r.va&UINT64_C(0x3fffffff))));
        f.tables[0][0] |= UINT64_C(1)<<10;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATION_PAGE_FAULT);
        rvt_setup(&f,&r,&io); f.tables[0][0] |= 64;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATION_PAGE_FAULT);
    }
_test_next:;
    return failures;
}

static int rvt_ad_case(void)
{
    int failures = 0;
    struct rvt_fixture f;
    struct rvemu_translation_request r;
    struct rvemu_page_table_io io;
    struct rvemu_translation out;
    TEST("Sv39: A/D faults or atomic update; racing PTE retries without stale overwrite") {
        rvt_setup(&f,&r,&io); *rvt_leaf(&f,&r) &= ~UINT64_C(192);
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATION_PAGE_FAULT);
        ASSERT(f.writes==0);
        r.ad_policy=RVEMU_AD_UPDATE; r.access=RVEMU_ACCESS_STORE;
        ASSERT(rvemu_translate_sv39(&r,&io).status == RVEMU_TRANSLATED);
        ASSERT((*rvt_leaf(&f,&r)&192)==192 && f.writes==1);
        *rvt_leaf(&f,&r) &= ~UINT64_C(192); f.race=true; f.reads=0;
        out=rvemu_translate_sv39(&r,&io);
        ASSERT(out.status==RVEMU_TRANSLATION_RETRY && out.pa==0);
        ASSERT(*rvt_leaf(&f,&r)==0 && f.reads==3);
        rvt_setup(&f,&r,&io); *rvt_leaf(&f,&r)&=~UINT64_C(64);
        r.ad_policy=RVEMU_AD_UPDATE; f.deny_write=true;
        ASSERT(rvemu_translate_sv39(&r,&io).status==RVEMU_TRANSLATION_ACCESS_FAULT);
    }
_test_next:;
    return failures;
}

static int rvt_edge_case(void)
{
    int failures = 0;
    struct rvt_fixture f;
    struct rvemu_translation_request r;
    struct rvemu_page_table_io io;
    struct rvemu_translation out;
    TEST("Sv39: 2MiB pages and sign-extended high addresses map; reserved high bits fault") {
        rvt_setup(&f, &r, &io);
        f.tables[1][(r.va >> 21) & 511] = (UINT64_C(0x45600) << 10) | 0xcf;
        out = rvemu_translate_sv39(&r, &io);
        ASSERT(out.status == RVEMU_TRANSLATED && out.page_shift == 21);
        ASSERT(out.pa == (UINT64_C(0x45600000) | (r.va & UINT64_C(0x1fffff))));
        r.va |= UINT64_C(0xffffffc000000000);
        f.tables[0][(r.va >> 30) & 511] = (UINT64_C(2) << 10) | 1;
        ASSERT(rvemu_translate_sv39(&r, &io).status == RVEMU_TRANSLATED);
        for (unsigned bit = 54; bit < 64; bit++) {
            rvt_setup(&f, &r, &io);
            *rvt_leaf(&f, &r) |= UINT64_C(1) << bit;
            ASSERT(rvemu_translate_sv39(&r, &io).status == RVEMU_TRANSLATION_PAGE_FAULT);
        }
    }
_test_next:;
    return failures;
}

int rvemu_translate_known_answers(void)
{
    return rvt_base_case() + rvt_fault_case() + rvt_permission_case() +
           rvt_superpage_case() + rvt_ad_case() + rvt_edge_case();
}
