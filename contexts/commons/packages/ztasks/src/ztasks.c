/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: bounded reusable task state and canonical schema, without host authority. */
#include "../include/ztasks/ztasks.h"
#include <stdio.h>
#include <string.h>
static bool state_refuse(const char *why) { fprintf(stderr,"ztasks: %s\n",why); return false; }
static void put32(unsigned char *p, uint32_t v) {
    for (unsigned i=0; i<4; ++i) p[i]=(unsigned char)(v >> (8u*i));
}
static uint32_t get32(const unsigned char *p) {
    uint32_t v=0; for (unsigned i=0; i<4; ++i) v |= (uint32_t)p[i] << (8u*i); return v;
}
static void put64(unsigned char *p, uint64_t v) {
    put32(p, (uint32_t)v); put32(p+4, (uint32_t)(v>>32));
}
static uint64_t get64(const unsigned char *p) { return get32(p) | ((uint64_t)get32(p+4)<<32); }
bool ta_title_valid(const char *s) {
    if (!s) return false;
    bool visible=false;
    for (unsigned i=0;i<TA_TITLE;++i) {
        unsigned char c=(unsigned char)s[i];
        if (!c) return visible;
        if (c<32 || c>126) return false;
        visible |= c!=' ';
    }
    return false;
}
bool ta_state_encode(const struct ta_state *s, unsigned char *b, uint32_t *length) {
    if (s->count>TA_MAX_TASKS) return state_refuse("task count");
    memset(b,0,TA_PAYLOAD); put32(b,TA_SCHEMA); put32(b+4,s->count);
    put64(b+8,s->revision); put64(b+16,s->last_write);
    for (uint32_t i=0;i<s->count;++i) {
        const struct ta_task *t=&s->tasks[i];
        if (!t->id || t->done>1 || !ta_title_valid(t->title)) return state_refuse("invalid task");
        for (uint32_t j=0;j<i;++j) if (s->tasks[j].id==t->id) return state_refuse("duplicate task ID");
        unsigned char *p=b+24u+i*108u;
        put64(p,t->id); put32(p+8,t->done); memcpy(p+12,t->title,strlen(t->title));
    }
    *length=24u+s->count*108u; return true;
}
bool ta_state_decode(const unsigned char *b, uint32_t length, struct ta_state *s) {
    if (length<24 || get32(b)!=TA_SCHEMA || get32(b+4)>TA_MAX_TASKS || length!=24u+get32(b+4)*108u)
        return state_refuse("state schema or size");
    struct ta_state next={.count=get32(b+4),.revision=get64(b+8),.last_write=get64(b+16)};
    for (uint32_t i=0;i<next.count;++i) {
        const unsigned char *p=b+24u+i*108u;
        next.tasks[i].id=get64(p); next.tasks[i].done=get32(p+8); memcpy(next.tasks[i].title,p+12,TA_TITLE);
    }
    unsigned char canonical[TA_PAYLOAD]; uint32_t n;
    if (!ta_state_encode(&next,canonical,&n) || n!=length || memcmp(b,canonical,n)!=0)
        return state_refuse("noncanonical task state; prior value retained");
    *s=next; return true;
}
