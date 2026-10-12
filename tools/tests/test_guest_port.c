/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Verify guest-port relay bytes, backpressure, descriptor custody and refusals.
 */
#ifndef __FreeBSD__
#define _XOPEN_SOURCE 700
#endif
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
static pid_t child = -1, producer = -1;
static void fail(const char *s) { fprintf(stderr,"FAIL %s\n",s); if(producer>0) { kill(producer,SIGKILL); waitpid(producer,NULL,0); } if(child>0) { kill(child,SIGKILL); waitpid(child,NULL,0); } exit(1); }
static void transfer(int fd, unsigned char *b, size_t n, int writing)
{
    while(n) {
        struct pollfd p={fd,writing?POLLOUT:POLLIN,0};
        if(poll(&p,1,5000)<=0) fail("bounded transfer timeout");
        ssize_t k=writing?write(fd,b,n):read(fd,b,n);
        if(k<0 && (errno==EINTR || errno==EAGAIN)) continue;
        if(k<=0) fail("transfer EOF/error");
        b+=k; n-=(size_t)k;
    }
}
static int pty(char *name, size_t cap)
{
    int fd=posix_openpt(O_RDWR|O_NOCTTY|O_NONBLOCK);
    if(fd<0 || grantpt(fd)<0 || unlockpt(fd)<0) fail("pty allocation");
    char *p=ptsname(fd); if(!p || strlen(p)>=cap) fail("pty name");
    memcpy(name,p,strlen(p)+1); return fd;
}
static int raw(int fd)
{
    struct termios t;
    tcflag_t pending=0;
#ifdef PENDIN
    pending=PENDIN;
#endif
    return tcgetattr(fd,&t)==0 && !(t.c_lflag&(ICANON|ECHO|ISIG|IEXTEN|pending)) &&
        !(t.c_oflag&OPOST) && !(t.c_iflag&(IXON|ICRNL|IMAXBEL)) &&
        (t.c_cflag&CSIZE)==CS8 && t.c_cc[VMIN]==1 && t.c_cc[VTIME]==0;
}
static int wait_owned(pid_t pid)
{
    int status=0;
    for(int i=0;i<500;i++) {
        pid_t r=waitpid(pid,&status,WNOHANG);
        if(r==pid) return status;
        if(r<0) fail("owned child wait");
        struct pollfd w={-1,0,0};poll(&w,1,10);
    }
    fail("owned child deadline"); return 0;
}
static void launch(const char *binary,const char *t,const char *p,int input,
    int output[2],int errors[2])
{
    if(pipe(output)<0 || pipe(errors)<0) fail("session pipes");
    child=fork(); if(child<0) fail("session fork");
    if(child==0) {
        if(dup2(input,0)<0 || dup2(output[1],1)<0 || dup2(errors[1],2)<0) _exit(127);
        for(int fd=3;fd<256;fd++) close(fd);
        execl(binary,binary,t,p,(char *)NULL); _exit(127);
    }
    close(output[1]);close(errors[1]);
}
static void check_refusal(int status,int output,int errors,int master)
{
    if(!WIFEXITED(status)||WEXITSTATUS(status)!=1) fail("regular P accepted");
    unsigned char bytes[128];
    if(read(output,bytes,sizeof(bytes))!=0) fail("refusal forwarded stdout");
    ssize_t n=read(errors,bytes,sizeof(bytes));
    const char *expected="guest-port: P_RAW_REFUSED\n";
    if(n!=(ssize_t)strlen(expected)||memcmp(bytes,expected,(size_t)n)) fail("named P refusal");
    struct pollfd check={master,POLLIN,0};
    if(poll(&check,1,20)>0 && (check.revents&POLLIN)) fail("refusal forwarded T");
}
static void regular_p_refusal(const char *binary,const char *tname,const char *dir,int master)
{
    char path[512];
    int length=snprintf(path,sizeof(path),"%s/regular",dir);
    if(length<0 || (size_t)length>=sizeof(path)) fail("regular path");
    int regular=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);
    if(regular<0) fail("regular fixture");
    close(regular);
    int input=open("/dev/null",O_RDONLY),output[2],errors[2];
    if(input<0) fail("refusal input");
    launch(binary,tname,path,input,output,errors);close(input);
    int status=wait_owned(child);child=-1;
    check_refusal(status,output[0],errors[0],master);
    close(output[0]);close(errors[0]);unlink(path);
}
static void absent_t_refusal(const char *binary,const char *dir)
{
    char path[512];
    int length=snprintf(path,sizeof(path),"%s/absent",dir);
    if(length<0 || (size_t)length>=sizeof(path)) fail("absent path");
    int input=open("/dev/null",O_RDONLY),output[2],errors[2];
    if(input<0) fail("absent refusal input");
    launch(binary,path,path,input,output,errors);close(input);
    int status=wait_owned(child);child=-1;
    if(!WIFEXITED(status) || WEXITSTATUS(status)!=1) fail("absent tty accepted");
    char bytes[128];ssize_t n=read(errors[0],bytes,sizeof(bytes));
    const char *expected="guest-port: T_RAW_REFUSED\n";
    if(n!=(ssize_t)strlen(expected) || memcmp(bytes,expected,(size_t)n))
        fail("named absent T refusal");
    if(read(output[0],bytes,sizeof(bytes))!=0) fail("absent refusal forwarded stdout");
    close(output[0]);close(errors[0]);
    puts("PASS named absent-tty refusal");
}
static void cooked_baseline(int fd)
{
    struct termios cooked;
    if(tcgetattr(fd,&cooked)<0) fail("cooked baseline read");
    cooked.c_lflag |= ICANON|ECHO|ISIG|IEXTEN;
#ifdef PENDIN
    cooked.c_lflag |= PENDIN;
#endif
    cooked.c_iflag |= ICRNL|IXON|IMAXBEL;
    cooked.c_oflag |= OPOST;
    if(tcsetattr(fd,TCSANOW,&cooked)<0 || tcgetattr(fd,&cooked)<0 ||
        (cooked.c_lflag&(ICANON|ECHO))!=(ICANON|ECHO) ||
        !(cooked.c_iflag&IMAXBEL) || raw(fd))
        fail("explicit cooked baseline");
#ifdef PENDIN
    if(!(cooked.c_lflag&PENDIN)) fail("seeded pending input baseline");
#endif
}
static void backpressure(int source, int sink, const unsigned char *expected)
{
    pid_t writer=fork(); if(writer<0) fail("backpressure fork");
    if(writer==0) {
        child=-1;
        for(int i=0;i<512;i++) transfer(source,(unsigned char *)expected,256,1);
        _exit(0);
    }
    producer=writer;
    /* Consumer is deliberately stopped: total exceeds both the 4096-byte
       relay buffer and normal PTY/pipe capacities. The producer must wait. */
    struct pollfd pause={-1,0,0};poll(&pause,1,200);
    int status=0;
    pid_t observed=waitpid(writer,&status,WNOHANG);
    if(observed!=0) { if(observed>0) producer=-1; fail("producer did not backpressure"); }
    unsigned char actual[256];
    for(int i=0;i<512;i++) {
        transfer(sink,actual,sizeof(actual),0);
        if(memcmp(actual,expected,sizeof(actual))) fail("backpressure exact suffix");
    }
    int finished=0;
    for(int i=0;i<500;i++) {
        if(waitpid(writer,&status,WNOHANG)==writer) { finished=1;break; }
        struct pollfd w={-1,0,0};poll(&w,1,10);
    }
    if(!finished) fail("backpressure producer deadline");
    producer=-1;
    if(!WIFEXITED(status)||WEXITSTATUS(status)!=0) fail("backpressure producer exit");
}
struct fixture {
    char tn[128],pn[128],nn[128],alias[512];
    int tm,pm,nm,ts,ps,input[2],output[2],errors[2];
};
static void setup_ptys(struct fixture *f)
{
    f->tm=pty(f->tn,sizeof(f->tn)); f->pm=pty(f->pn,sizeof(f->pn)); f->nm=pty(f->nn,sizeof(f->nn));
    f->ts=open(f->tn,O_RDWR|O_NOCTTY);f->ps=open(f->pn,O_RDWR|O_NOCTTY);
    if(f->ts<0 || f->ps<0) fail("monitor descriptors");
}
static void start_session(struct fixture *f,const char *binary,const char *dir)
{
    int length=snprintf(f->alias,sizeof(f->alias),"%s/port",dir);
    if(length<0 || (size_t)length>=sizeof(f->alias) || symlink(f->tn,f->alias)<0) fail("alias");
    regular_p_refusal(binary,f->tn,dir,f->tm);
    /* The refusal configures T before P fails: verify fresh cooked baselines. */
    cooked_baseline(f->ts);cooked_baseline(f->ps);
    if(pipe(f->input)<0) fail("input pipe");
    launch(binary,f->alias,f->pn,f->input[0],f->output,f->errors);close(f->input[0]);
    for(int i=0;i<500 && (!raw(f->ts)||!raw(f->ps));i++) {
        struct pollfd waitfd={-1,0,0};poll(&waitfd,1,10);
    }
    if(!raw(f->ts)||!raw(f->ps)) fail("raw before forwarding");
}
static void traffic(struct fixture *f,const unsigned char expected[256])
{
    if(unlink(f->alias)<0 || symlink(f->nn,f->alias)<0) fail("replace alias");
    unsigned char actual[256];
    for(int j=0;j<32;j++) {
        transfer(f->input[1],(unsigned char *)expected,256,1);transfer(f->tm,actual,sizeof(actual),0);
        if(memcmp(expected,actual,sizeof(actual))) fail("held T binary preservation");
        transfer(f->pm,(unsigned char *)expected,256,1);transfer(f->output[0],actual,sizeof(actual),0);
        if(memcmp(expected,actual,sizeof(actual))) fail("P binary preservation");
    }
    backpressure(f->input[1],f->tm,expected);backpressure(f->pm,f->output[0],expected);
    struct pollfd other={f->nm,POLLIN,0};
    if(poll(&other,1,20)>0 && (other.revents&POLLIN)) fail("path reopened");
}
static void terminal_eof(struct fixture *f,unsigned char expected[256])
{
    close(f->input[1]);
    unsigned char actual[256];
    transfer(f->pm,expected,256,1);transfer(f->output[0],actual,sizeof(actual),0);
    if(memcmp(expected,actual,sizeof(actual))) fail("P after input EOF");
    close(f->pm);close(f->ps);
    int status=wait_owned(child);child=-1;
    if(!WIFEXITED(status)||WEXITSTATUS(status)!=0) fail("port EOF exit");
    unsigned char error[256];
    if(read(f->errors[0],error,sizeof(error))!=0) fail("unexpected transport diagnostics");
}
/* Observe real operations without replacing termios or relay behavior. */
static int probe_audit=-1,probe_tty=-1,probe_progress=-1;
static int probe_open(const char *path,int flags)
{
    int fd=open(path,flags);
    if(fd>=0) {
        probe_tty=fd;
        if(write(probe_audit,"O",1)!=1) { close(fd);return -1; }
    }
    return fd;
}
static int probe_close(int fd)
{
    if(fd==probe_tty && write(probe_audit,"C",1)!=1) return -1;
    return close(fd);
}
static ssize_t probe_read(int fd,void *bytes,size_t size)
{
    ssize_t n=read(fd,bytes,size);
    if(fd==probe_tty && n>0 && probe_progress>=0 &&
        write(probe_progress,&n,sizeof n)!=(ssize_t)sizeof n) return -1;
    return n;
}
#define main guest_port_probe_main
#define open probe_open
#define close probe_close
#define read probe_read
#include "../guest_port.c"
#undef main
#undef open
#undef close
#undef read

static void raw_bell_readback(void)
{
    struct termios flags={0};
    flags.c_cflag=CS8;flags.c_cc[VMIN]=1;
    if(!raw_flags(&flags)) fail("raw readback baseline");
    flags.c_iflag=IMAXBEL;
    if(raw_flags(&flags)) fail("raw readback accepted IMAXBEL");
#ifdef PENDIN
    flags.c_iflag=0;flags.c_lflag=PENDIN;
    if(raw_flags(&flags)) fail("raw readback accepted PENDIN");
#endif
}

enum single_mode { SINGLE_EXEC, SINGLE_COUNTED, SINGLE_DRAIN, SINGLE_READY_FAILURE };
struct single_fixture {
    char name[128],other[128],alias[512];
    int master,replacement,monitor,input[2],output[2],errors[2],audit[2],progress[2];
    size_t prefilled;
    enum single_mode mode;
};
static void single_setup(struct single_fixture *f,const char *dir,enum single_mode mode)
{
    f->mode=mode;
    f->master=pty(f->name,sizeof f->name);
    f->replacement=pty(f->other,sizeof f->other);
    f->monitor=open(f->name,O_RDWR|O_NOCTTY);
    if(f->monitor<0 || pipe(f->input)<0 || pipe(f->output)<0 ||
        pipe(f->errors)<0 || pipe(f->audit)<0 || pipe(f->progress)<0) fail("single fixture");
    int n=snprintf(f->alias,sizeof f->alias,"%s/single-%d",dir,mode);
    if(n<0 || (size_t)n>=sizeof f->alias || symlink(f->name,f->alias)<0) fail("single alias");
    cooked_baseline(f->monitor);
}
static void prefill_output(struct single_fixture *f,const unsigned char expected[256])
{
    int flags=fcntl(f->output[1],F_GETFL);
    if(flags<0 || fcntl(f->output[1],F_SETFL,flags|O_NONBLOCK)<0) fail("prefill flags");
    for(;;) {
        ssize_t n=write(f->output[1],expected,256);
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
        if(n!=256 || f->prefilled>=1024*1024) fail("bounded output prefill");
        f->prefilled+=256;
    }
    if(f->prefilled==0 || fcntl(f->output[1],F_SETFL,flags)<0) fail("prefill restore");
}
static void single_child(struct single_fixture *f,const char *binary)
{
    if(dup2(f->input[0],0)<0 || dup2(f->output[1],1)<0 || dup2(f->errors[1],2)<0) _exit(127);
    for(int fd=3;fd<256;fd++) {
        if(f->mode!=SINGLE_EXEC && fd==f->audit[1]) continue;
        if(f->mode==SINGLE_DRAIN && fd==f->progress[1]) continue;
        close(fd);
    }
    if(f->mode!=SINGLE_EXEC) {
        probe_audit=f->audit[1];
        probe_progress=f->mode==SINGLE_DRAIN ? f->progress[1] : -1;
        char *args[]={(char *)binary,f->alias,NULL};
        _exit(guest_port_probe_main(2,args));
    }
    execl(binary,binary,f->alias,(char *)NULL);_exit(127);
}
static void single_launch(struct single_fixture *f,const char *binary)
{
    if(f->mode==SINGLE_READY_FAILURE) { close(f->errors[0]);f->errors[0]=-1; }
    child=fork();if(child<0) fail("single fork");
    if(child==0) single_child(f,binary);
    close(f->input[0]);close(f->output[1]);close(f->errors[1]);
    close(f->audit[1]);close(f->progress[1]);
}
static void single_ready(struct single_fixture *f)
{
    const char ready[]="guest-port: RAW_READY\n";
    unsigned char actual[sizeof ready-1];
    transfer(f->errors[0],actual,sizeof actual,0);
    if(memcmp(actual,ready,sizeof actual) || !raw(f->monitor)) fail("single raw readiness");
}
static void single_traffic(struct single_fixture *f,const unsigned char expected[256])
{
    if(unlink(f->alias)<0 || symlink(f->other,f->alias)<0) fail("single replace alias");
    unsigned char actual[256];
    transfer(f->input[1],(unsigned char *)expected,256,1);transfer(f->master,actual,256,0);
    if(memcmp(expected,actual,256)) fail("single held TX");
    transfer(f->master,(unsigned char *)expected,256,1);transfer(f->output[0],actual,256,0);
    if(memcmp(expected,actual,256)) fail("single held RX");
    backpressure(f->input[1],f->master,expected);backpressure(f->master,f->output[0],expected);
    struct pollfd p={f->replacement,POLLIN,0};
    if(poll(&p,1,20)>0 && (p.revents&POLLIN)) fail("single reopened alias");
    close(f->input[1]);f->input[1]=-1;
    transfer(f->master,(unsigned char *)expected,256,1);transfer(f->output[0],actual,256,0);
    if(memcmp(expected,actual,256)) fail("single RX after input EOF");
}
static void single_hangup(struct single_fixture *f)
{
    close(f->master);close(f->monitor);f->master=-1;f->monitor=-1;
}
static void single_drain(struct single_fixture *f,const unsigned char expected[256])
{
    transfer(f->master,(unsigned char *)expected,256,1);
    size_t received=0;
    while(received<256) {
        ssize_t n=0;
        transfer(f->progress[0],(unsigned char *)&n,sizeof n,0);
        if(n<=0 || (size_t)n>256-received) fail("observed real port read");
        received+=(size_t)n;
    }
    /* All payload is in the relay; stdout is full. HUP must not discard it. */
    single_hangup(f);
    struct pollfd pause={-1,0,0};poll(&pause,1,100);
    int status=0;
    pid_t observed;
    do { observed=waitpid(child,&status,WNOHANG); } while(observed<0 && errno==EINTR);
    if(observed<0) fail("HUP owned child observation");
    if(observed>0) { child=-1;fail("HUP dropped blocked output"); }
    unsigned char actual[256];
    for(size_t bytes=0;bytes<f->prefilled+256;bytes+=256) {
        transfer(f->output[0],actual,256,0);
        if(memcmp(expected,actual,256)) fail("HUP exact buffered suffix");
    }
}
static void single_finish(struct single_fixture *f)
{
    int status=wait_owned(child);child=-1;
    int expected=f->mode==SINGLE_READY_FAILURE ? 1 : 0;
    if(!WIFEXITED(status) || WEXITSTATUS(status)!=expected) fail("single terminal status");
    char text[64];
    if(f->mode==SINGLE_READY_FAILURE) {
        if(read(f->output[0],text,sizeof text)!=0) fail("failed READY forwarded stdout");
        struct pollfd p={f->master,POLLIN,0};
        if(poll(&p,1,20)>0 && (p.revents&POLLIN)) fail("failed READY forwarded port");
    } else if(read(f->errors[0],text,sizeof text)!=0) fail("single unexpected diagnostics");
    ssize_t got=read(f->audit[0],text,sizeof text);
    if(f->mode!=SINGLE_EXEC && (got!=2 || memcmp(text,"OC",2))) fail("single one open and close");
}
static void single_cleanup(struct single_fixture *f)
{
    if(f->master>=0) close(f->master);
    if(f->monitor>=0) close(f->monitor);
    if(f->input[1]>=0) close(f->input[1]);
    if(f->errors[0]>=0) close(f->errors[0]);
    close(f->replacement);close(f->output[0]);close(f->audit[0]);close(f->progress[0]);
    unlink(f->alias);
}
static void single_session(const char *binary,const char *dir,enum single_mode mode)
{
    struct single_fixture f={0};single_setup(&f,dir,mode);
    unsigned char expected[256];for(unsigned i=0;i<256;i++) expected[i]=(unsigned char)i;
    if(mode==SINGLE_DRAIN) prefill_output(&f,expected);
    if(mode==SINGLE_READY_FAILURE) transfer(f.input[1],expected,256,1);
    single_launch(&f,binary);
    if(mode!=SINGLE_READY_FAILURE) {
        single_ready(&f);
        if(mode==SINGLE_DRAIN) single_drain(&f,expected);
        else { single_traffic(&f,expected);single_hangup(&f); }
    }
    single_finish(&f);single_cleanup(&f);
}
static void fill_tx_pipe(int fd)
{
    int flags=fcntl(fd,F_GETFL);
    if(flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0) fail("pending TX nonblocking");
    unsigned char bytes[4096]={0};size_t total=0;
    for(;;) {
        ssize_t n=write(fd,bytes,sizeof bytes);
        if(n>0) { total+=(size_t)n;if(total>1048576) fail("pending TX capacity bound");continue; }
        if(n<0 && errno==EINTR) continue;
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
        fail("pending TX fill");
    }
}
static void pending_tx_child(int tx,int rx,int input,int errors)
{
    if(dup2(input,0)<0 || dup2(errors,2)<0) _exit(127);
    int nullfd=open("/dev/null",O_WRONLY);
    if(nullfd<0 || dup2(nullfd,1)<0) _exit(127);
    for(int fd=3;fd<256;fd++) if(fd!=tx && fd!=rx) close(fd);
    _exit(relay(tx,rx));
}
static void pending_tx_eof(void)
{
    int tx[2],rx[2],input[2],errors[2];
    if(pipe(tx)<0 || pipe(rx)<0 || pipe(input)<0 || pipe(errors)<0) fail("pending TX pipes");
    fill_tx_pipe(tx[1]);
    if(write(input[1],"accepted",8)!=8) fail("pending TX input");
    close(input[1]);close(rx[1]);
    child=fork();if(child<0) fail("pending TX fork");
    if(child==0) pending_tx_child(tx[1],rx[0],input[0],errors[1]);
    close(errors[1]);close(tx[1]);close(rx[0]);close(input[0]);
    int status=wait_owned(child);child=-1;
    if(!WIFEXITED(status) || WEXITSTATUS(status)!=1) fail("pending TX EOF silently succeeded");
    char diagnostic[128];ssize_t got=read(errors[0],diagnostic,sizeof diagnostic);
    const char *expected="guest-port: T_TRUNCATED\n";
    if(got!=(ssize_t)strlen(expected) || memcmp(diagnostic,expected,(size_t)got))
        fail("pending TX EOF named refusal");
    close(tx[0]);close(errors[0]);
}
static void closed_stream_child(const char *binary,const char *port,int missing,
    int duplex,int input,int output,int errors)
{
    if(dup2(input,0)<0 || dup2(output,1)<0 || dup2(errors,2)<0) _exit(127);
    for(int fd=3;fd<256;fd++) close(fd);
    close(missing);
    execl(binary,binary,port,duplex ? (char *)NULL : port,(char *)NULL);
    _exit(127);
}
static void closed_stream_result(int status,int output,int errors,int slave,int master)
{
    if(!WIFEXITED(status) || WEXITSTATUS(status)!=1) fail("closed stream accepted");
    char bytes[128];ssize_t n=read(errors,bytes,sizeof bytes);
    const char *expected="guest-port: STREAM_SETUP_REFUSED\n";
    if(n!=(ssize_t)strlen(expected) || memcmp(bytes,expected,(size_t)n))
        fail("closed stream named refusal");
    if(read(output,bytes,sizeof bytes)!=0 || raw(slave)) fail("closed stream port touched");
    struct pollfd check={master,POLLIN,0};
    if(poll(&check,1,20)>0 && (check.revents&POLLIN)) fail("closed stream forwarded");
}
static void closed_stream(const char *binary,int missing,int duplex)
{
    char name[128];int master=pty(name,sizeof name);
    int slave=open(name,O_RDWR|O_NOCTTY),input[2],output[2],errors[2];
    if(slave<0 || pipe(input)<0 || pipe(output)<0 || pipe(errors)<0)
        fail("closed stream fixture");
    cooked_baseline(slave);
    if(write(input[1],"must not forward",16)!=16) fail("closed stream payload");
    child=fork();if(child<0) fail("closed stream fork");
    if(child==0) closed_stream_child(binary,name,missing,duplex,input[0],output[1],errors[1]);
    close(input[0]);close(input[1]);close(output[1]);close(errors[1]);
    int status=wait_owned(child);child=-1;
    closed_stream_result(status,output[0],errors[0],slave,master);
    close(output[0]);close(errors[0]);close(slave);close(master);
}
int main(int argc,char **argv)
{
    if(argc!=3) fail("fixture arguments");
    absent_t_refusal(argv[1],argv[2]);
    raw_bell_readback();
    for(int missing=0;missing<2;missing++)
        for(int duplex=0;duplex<2;duplex++) closed_stream(argv[1],missing,duplex);
    for(enum single_mode mode=SINGLE_EXEC;mode<=SINGLE_READY_FAILURE;mode++)
        single_session(argv[1],argv[2],mode);
    struct fixture f={0};setup_ptys(&f);start_session(&f,argv[1],argv[2]);
    unsigned char expected[256];for(int i=0;i<256;i++) expected[i]=(unsigned char)i;
    traffic(&f,expected);terminal_eof(&f,expected);
    close(f.tm);close(f.ts);close(f.nm);close(f.output[0]);close(f.errors[0]);unlink(f.alias);
    pending_tx_eof();
    puts("PASS single/two-port held descriptors, all bytes, backpressure, READY gate/failure, HUP drain, EOF and refusals");
    return 0;
}
