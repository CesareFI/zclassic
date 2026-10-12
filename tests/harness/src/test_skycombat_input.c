/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* purpose: exercise actual joystick controller lifecycle with no device effects. */
#include "test/test_core.h"
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "sky_combat/controllers/input_controller_fast.h"
#ifdef __linux__
#include <linux/joystick.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#endif
static unsigned opens,closes,reads,ioctls;
#ifdef __linux__
static int fixture_fd=-1;
static bool fail_malloc,emit_event;
static int16_t fixture_event_value=16384;
static void *fixture_malloc(size_t size) { return fail_malloc ? NULL : malloc(size); }
static int fixture_open(const char *path,int flags,...) {
    assert(!strcmp(path,"/dev/input/js0")); assert(flags==(O_RDONLY|O_NONBLOCK)); ++opens;
    if(fixture_fd<0) errno=ENOENT;
    return fixture_fd;
}
static int fixture_close(int fd) { assert(fd==fixture_fd); ++closes; return 0; }
static int fixture_ioctl(int fd,unsigned long request,...) {
    assert(fd==fixture_fd); ++ioctls; va_list args; va_start(args,request); void *out=va_arg(args,void *); va_end(args);
    if(request==JSIOCGNAME(128)) strcpy(out,"ASTRO C40 consenting fixture");
    else { assert(request==JSIOCGAXES); *(unsigned char *)out=8; }
    return 0;
}
static ssize_t fixture_read(int fd,void *out,size_t size) {
    assert(fd==fixture_fd && size>=sizeof(struct js_event)); ++reads;
    if(emit_event) {
        struct js_event event={.type=JS_EVENT_AXIS,.number=0,.value=fixture_event_value};
        memcpy(out,&event,sizeof(event)); emit_event=false; return (ssize_t)sizeof(event);
    }
    errno=EAGAIN; return -1;
}
#define open fixture_open
#define close fixture_close
#define ioctl fixture_ioctl
#define read fixture_read
#define malloc fixture_malloc
#else
/* Off Linux, count and refuse any accidental device call without effects. */
#define open(...) (++opens, -1)
#define close(...) (++closes, 0)
#define read(...) (++reads, -1)
#define ioctl(...) (++ioctls, -1)
#endif
/* Entire actual owned controller, not extracted functions or a replacement. */
#include "../../../apps/skycombat/src/models/input_model_fast.c"
#include "../../../apps/skycombat/src/controllers/input_controller_fast.c"
#undef open
#undef close
#undef ioctl
#undef read
#undef malloc
int test_skycombat_input(void);
int test_skycombat_input(void) {
    int failures = 0;
    input_controller_fast_t *c=NULL;
    opens=closes=reads=ioctls=0;
#ifdef __linux__
    fixture_fd=-1; fail_malloc=false; emit_event=false; fixture_event_value=16384;
#endif
    input_model_fast_t model,before;
    input_model_fast_init(&model);
#ifndef __linux__
    model.connected=true;
    model.is_astro_c40=true;
#endif
    ASSERT(input_controller_fast_create(NULL)==NULL);
    input_controller_fast_destroy(NULL); input_controller_fast_update(NULL);
    input_controller_fast_set_batching(NULL,true,3);
    c=input_controller_fast_create(&model);
    ASSERT(c != NULL); ASSERT_EQ(c->fd,-1);
    ASSERT(!model.connected); ASSERT(!c->event_buffer); ASSERT(!c->use_event_batching);
#ifndef __linux__
    ASSERT(!model.is_astro_c40);
#endif
    memcpy(&before,&model,sizeof(model)); input_controller_fast_update(c);
    ASSERT(!memcmp(&before,&model,sizeof(model)));
    input_controller_fast_destroy(c); c=NULL;
    ASSERT_EQ(closes,0); ASSERT_EQ(reads,0); ASSERT_EQ(ioctls,0);
#ifdef __linux__
    ASSERT(opens==1);
    fixture_fd=0; c=input_controller_fast_create(&model);
    ASSERT(c != NULL); ASSERT_EQ(c->fd,0);
    ASSERT(model.connected); ASSERT(model.is_astro_c40);
    ASSERT(c->event_buffer != NULL); ASSERT(c->use_event_batching);
    emit_event=true; input_controller_fast_update(c);
    ASSERT_EQ(model.raw.axes[0],16384); ASSERT_EQ(model.frame_count,1); ASSERT(model.connected);
    unsigned reads_before_single=reads;
    input_controller_fast_set_batching(c,false,0);
    fixture_event_value=-16384; emit_event=true; input_controller_fast_update(c);
    ASSERT_EQ(model.raw.axes[0],-16384); ASSERT(reads>reads_before_single);
    ASSERT_EQ(model.frame_count,2); ASSERT(model.connected);
    fail_malloc=true; input_controller_fast_set_batching(c,true,3);
    ASSERT(!c->event_buffer); ASSERT(!c->use_event_batching); ASSERT_EQ(c->buffer_size,0);
    input_controller_fast_destroy(c); c=NULL; ASSERT(closes==1);
    c=input_controller_fast_create(&model);
    ASSERT(c != NULL); ASSERT(model.connected);
    ASSERT(!c->event_buffer); ASSERT(!c->use_event_batching); ASSERT_EQ(c->buffer_size,0);
    input_controller_fast_destroy(c); c=NULL; ASSERT(closes==2);
    puts("PASS whole Linux controller: null/no-device/fd0/batched/single/allocation-refusal lifecycle; intercepted OS device ports only");
#else
    ASSERT(opens==0);
    model.connected=true;
    model.is_astro_c40=true;
    c=input_controller_fast_create(&model); ASSERT(c != NULL); ASSERT_EQ(c->fd,-1);
    ASSERT(!model.connected); ASSERT(!model.is_astro_c40);
    memcpy(&before,&model,sizeof(model));
    c->use_event_batching=true; c->buffer_size=3;
    input_controller_fast_set_batching(c,true,64);
    ASSERT(!c->event_buffer); ASSERT(!c->use_event_batching); ASSERT_EQ(c->buffer_size,0);
    c->use_event_batching=true; c->buffer_size=3;
    input_controller_fast_set_batching(c,false,0);
    ASSERT(!c->event_buffer); ASSERT(!c->use_event_batching); ASSERT_EQ(c->buffer_size,0);
    input_controller_fast_update(c); ASSERT(!memcmp(&before,&model,sizeof(model)));
    model.connected=true; input_controller_fast_update(c); ASSERT(!model.connected);
    /* The fixture intercepts this synthetic descriptor; no stdin is closed. */
    c->fd=0;
    input_controller_fast_destroy(c); c=NULL;
    ASSERT_EQ(opens,0); ASSERT_EQ(reads,0); ASSERT_EQ(ioctls,0); ASSERT_EQ(closes,0);
    puts("PASS whole unsupported-platform controller: null/no-device/inert-update/batching-refusal/stale-connected-refusal/cleanup; zero device ports");
#endif
_test_next:;
    input_controller_fast_destroy(c);
    return failures;
}
