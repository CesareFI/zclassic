/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: exact round-trip and failed migration preservation acceptance. */
#include "ztasks/ztasks.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"ztasks test line %d: %s\n",__LINE__,#x); return false; } } while (0)
static bool refuses_loss(void) {
    struct ta_state saved={.revision=9,.last_write=12,.count=1,
        .tasks={{.id=3,.title="Keep my edits"}}};
    unsigned char wire[TA_PAYLOAD],before[TA_PAYLOAD],after[TA_PAYLOAD]; uint32_t size,n,m;
    CHECK(ta_state_encode(&saved,wire,&size)); CHECK(ta_state_encode(&saved,before,&n));
    wire[24+12+15]=1; /* Nonzero bytes after the title's terminator. */
    CHECK(!ta_state_decode(wire,size,&saved));
    CHECK(ta_state_encode(&saved,after,&m)); CHECK(n==m && memcmp(before,after,n)==0);
    wire[0]=2; CHECK(!ta_state_decode(wire,size,&saved));
    CHECK(ta_state_encode(&saved,after,&m)); CHECK(n==m && memcmp(before,after,n)==0);
    return true;
}
static bool round_trip(void) {
    struct ta_state a={.revision=7,.last_write=8,.count=2,
        .tasks={{.id=1,.title="Buy milk"},{.id=2,.done=1,.title="Book dentist"}}},b={0};
    unsigned char wire[TA_PAYLOAD],other[TA_PAYLOAD]; uint32_t n,m;
    CHECK(ta_state_encode(&a,wire,&n)); CHECK(ta_state_decode(wire,n,&b));
    CHECK(ta_state_encode(&b,other,&m)); CHECK(n==m && memcmp(wire,other,n)==0);
    a.tasks[1].id=1; CHECK(!ta_state_encode(&a,wire,&n));
    return true;
}
int main(void) {
    if (ta_title_valid(NULL) || ta_title_valid("") || ta_title_valid("   ") || ta_title_valid("bad\nline")) return 1;
    if (!round_trip() || !refuses_loss()) return 1;
    puts("ztasks PASS: exact reload; empty title, duplicate ID and lossy schema refused; prior state retained");
    return 0;
}
