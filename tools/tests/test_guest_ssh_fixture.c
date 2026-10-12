/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Observe fixed SSH launcher arguments and native terminal descriptor setup.
 */
#ifndef __FreeBSD__
#define _XOPEN_SOURCE 700
#endif
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int mode, opened, closed, exec_called, held=-1, flag_reads;
static const char *port;
static struct stat console;
static pid_t owned_child=-1;
static char alias[1024],replacement[1024];
static void check(int good,const char *why)
{
    if(!good) {
        fprintf(stderr,"FAIL %s mode=%d\n",why,mode);
        if(owned_child>0) { kill(owned_child,SIGKILL); waitpid(owned_child,NULL,0); }
        _exit(90);
    }
}
static int fixture_open(const char *name,int flags)
{
    check(!strcmp(name,"/dev/vtcon/z23.l0.p"),"fixed P path");
    check((flags & (O_NOCTTY|O_CLOEXEC|O_NONBLOCK))==(O_NOCTTY|O_CLOEXEC|O_NONBLOCK),"open flags");
    opened++;
    held=open(port,flags);
    if(mode==12 && held>=0) {
        check(unlink(alias)==0 && symlink(replacement,alias)==0,"replace P alias after open");
    }
    return held;
}
static int fixture_close(int fd)
{
    closed++;
    return close(fd);
}
static int fixture_fcntl(int fd,int command,...)
{
    if(command==F_GETFD) return fcntl(fd,command);
    if(command==F_GETFL) {
        if(fd==2) return fcntl(fd,command);
        flag_reads++;
        if(mode==4 && flag_reads==2) { errno=EIO; return -1; }
        int result=fcntl(fd,command);
        return mode==5 && flag_reads==2 ? result|O_NONBLOCK : result;
    }
    va_list ap; va_start(ap,command); int value=va_arg(ap,int); va_end(ap);
    if((mode==3 && command==F_DUPFD_CLOEXEC) || (mode==11 && command==F_SETFL)) {
        errno=EIO; return -1;
    }
    int result=fcntl(fd,command,value);
    if(command==F_DUPFD_CLOEXEC) held=result;
    return result;
}
static int fixture_dup2(int from,int to)
{
    if((mode==6 && to==0) || (mode==7 && to==1)) { errno=EIO; return -1; }
    return dup2(from,to);
}
static int fixture_tcgetattr(int fd,struct termios *t)
{
    int result=tcgetattr(fd,t);
    if(mode==9 && result==0) t->c_lflag|=ICANON;
    return result;
}
static void exact_io(int fd,unsigned char *bytes,size_t count,int writing)
{
    while(count) {
        struct pollfd p={fd,writing?POLLOUT:POLLIN,0};
        check(poll(&p,1,3000)>0,"bounded byte transfer");
        ssize_t n=writing?write(fd,bytes,count):read(fd,bytes,count);
        if(n<0 && errno==EINTR) continue;
        check(n>0,"byte transfer"); bytes+=n; count-=(size_t)n;
    }
}
static int option(char *const args[],const char *value)
{
    for(int i=4;args[i] && args[i+1];i++)
        if(!strcmp(args[i],"-o") && !strcmp(args[i+1],value)) return 1;
    return 0;
}
static void check_argv(const char *path,char *const args[])
{
    check(!strcmp(path,"/usr/bin/ssh") && !strcmp(args[0],path),"fixed executable");
    check(!strcmp(args[1],"-F") && !strcmp(args[2],"/usr/local/etc/z23-fixture/ssh_config") &&
        !strcmp(args[3],"-T"),"fixed configuration and no tty");
    const char *required[]={"StrictHostKeyChecking=yes",
        "UserKnownHostsFile=/usr/local/etc/z23-fixture/known_hosts","GlobalKnownHostsFile=/dev/null",
        "UpdateHostKeys=no","IdentityAgent=none","IdentitiesOnly=yes","BatchMode=yes",
        "PasswordAuthentication=no","KbdInteractiveAuthentication=no","ForwardAgent=no",
        "ForwardX11=no","ClearAllForwardings=yes","ControlMaster=no","ControlPath=none",
        "PermitLocalCommand=no","RequestTTY=no","KexAlgorithms=mlkem768x25519-sha256",
        "ProxyCommand=/usr/local/libexec/z23-guest-port /dev/vtcon/z23.l0.t"};
    for(size_t i=0;i<sizeof(required)/sizeof(required[0]);i++) check(option(args,required[i]),"required SSH option");
    if(mode==0) {
        for(size_t i=0;i<sizeof(required)/sizeof(required[0]);i++)
            fprintf(stderr,"asserted %s\n",required[i]);
    }
    int n=0; while(args[n]) n++;
    check(n==42 && !strcmp(args[n-2],"z23-fixture") && !strcmp(args[n-1],"/bin/cat"),"fixed destination and command");
}
static void check_environment(char *const env[])
{
    check(env[0] && env[1] && !env[2] && !strcmp(env[0],"LANG=C") && !strcmp(env[1],"LC_ALL=C"),"minimal environment");
}
static void check_stdio(void)
{
    struct stat a,b,c;
    check(fstat(0,&a)==0 && fstat(1,&b)==0 && fstat(2,&c)==0,"stdio descriptors");
    check(a.st_dev==b.st_dev && a.st_ino==b.st_ino,"single held description");
    check(console.st_dev==c.st_dev && console.st_ino==c.st_ino,"console retained");
    check(!(fcntl(0,F_GETFL)&O_NONBLOCK) && !(fcntl(1,F_GETFL)&O_NONBLOCK),"blocking stdio");
    check(!(fcntl(0,F_GETFD)&FD_CLOEXEC) && !(fcntl(1,F_GETFD)&FD_CLOEXEC),"stdio survives exec");
}
static void check_raw_ownership(void)
{
    struct termios t;
    check(tcgetattr(0,&t)==0 && !(t.c_lflag&(ICANON|ECHO|ISIG|IEXTEN)) &&
        !(t.c_oflag&OPOST) && !(t.c_iflag&(IXON|ICRNL)),"actual raw tty");
    check(opened==1 && closed==((mode==1 || mode==2)?2:1),"descriptor ownership closes");
    check(fcntl(held,F_GETFD)<0 && errno==EBADF,"held original closed");
}
static int fixture_execve(const char *path,char *const args[],char *const env[])
{
    exec_called++;
    check(mode<=2 || mode==8 || mode==12,"no exec after setup failure");
    check_argv(path,args);
    check_environment(env);
    check_stdio();
    check_raw_ownership();
    if(mode==8) { errno=ENOENT; return -1; }
    unsigned char bytes[256],received[256];
    for(int i=0;i<256;i++) bytes[i]=(unsigned char)i;
    exact_io(1,bytes,sizeof(bytes),1); exact_io(0,received,sizeof(received),0);
    check(!memcmp(bytes,received,sizeof(bytes)),"all bytes round trip");
    _exit(0);
}
#define open fixture_open
#define close fixture_close
#define fcntl fixture_fcntl
#define dup2 fixture_dup2
#define tcgetattr fixture_tcgetattr
#define execve fixture_execve
#define main guest_ssh_main
#include "../guest_ssh_fixture.c"
#undef main
#undef execve
#undef tcgetattr
#undef dup2
#undef fcntl
#undef close
#undef open

struct pty_fixture { int master,keeper,other; };
static struct pty_fixture setup_ptys(void)
{
    int master=posix_openpt(O_RDWR|O_NOCTTY|O_NONBLOCK);
    check(master>=0 && grantpt(master)==0 && unlockpt(master)==0,"PTY allocation");
    port=ptsname(master); check(port!=NULL,"PTY path");
    /* Keep the slave present while the child reaches open, avoiding a master
     * hangup race on platforms that report HUP before the first slave open. */
    int keeper=open(port,O_RDWR|O_NOCTTY|O_CLOEXEC);
    check(keeper>=0,"PTY keeper");
    int other=-1;
    if(mode==12) {
        check(symlink(port,alias)==0,"P alias fixture");
        other=posix_openpt(O_RDWR|O_NOCTTY|O_NONBLOCK);
        check(other>=0 && grantpt(other)==0 && unlockpt(other)==0,"replacement PTY");
        const char *name=ptsname(other); check(name!=NULL,"replacement name");
        int n=snprintf(replacement,sizeof(replacement),"%s",name);
        check(n>0 && (size_t)n<sizeof(replacement),"replacement path length");
        port=alias;
    }
    check(fstat(2,&console)==0,"console witness");
    return (struct pty_fixture){master,keeper,other};
}
static void child_descriptors(struct pty_fixture f)
{
    close(f.master); close(f.keeper); if(f.other>=0) close(f.other);
    if(mode==1 || mode==2 || mode==3) close(0);
    if(mode==2) close(1);
    if(mode==10) close(2);
    if(mode==13) check(fcntl(2,F_SETFD,FD_CLOEXEC)==0,"console CLOEXEC injection");
    if(mode==14) {
        int rd=open("/dev/null",O_RDONLY);
        check(rd>=0 && dup2(rd,2)==2,"read-only console injection"); close(rd);
    }
}
static void child_run(struct pty_fixture f)
{
    child_descriptors(f);
    char *args[]={"guest-ssh-fixture",NULL};
    int result=guest_ssh_main(1,args);
    check(result==1,"injected failure refused");
    check(exec_called==(mode==8?1:0),"no exec after setup failure");
    check(opened==((mode==10 || mode>=13)?0:1),"failure open count");
    check(closed==((mode==10 || mode>=13)?0:1),"failure closes owned port");
    _exit(0);
}
static void echo_bytes(int master)
{
    unsigned char received[256],expected[256];
    exact_io(master,received,sizeof(received),0);
    for(int i=0;i<256;i++) expected[i]=(unsigned char)i;
    check(!memcmp(received,expected,sizeof(received)),"wire all bytes");
    exact_io(master,received,sizeof(received),1);
}
static int wait_child(pid_t child)
{
    int status=0; pid_t done=0;
    for(int i=0;i<500 && !done;i++) {
        done=waitpid(child,&status,WNOHANG); check(done>=0,"wait child");
        if(!done) { struct pollfd p={-1,0,0}; poll(&p,1,10); }
    }
    if(!done) { kill(child,SIGKILL); waitpid(child,&status,0); }
    owned_child=-1;
    return done==child && WIFEXITED(status) && WEXITSTATUS(status)==0;
}
static void run_case(int which)
{
    mode=which;
    struct pty_fixture f=setup_ptys();
    pid_t child=fork(); check(child>=0,"fork");
    owned_child=child;
    if(child==0) child_run(f);
    if(mode<=2 || mode==12) echo_bytes(f.master);
    int success=wait_child(child);
    close(f.master); close(f.keeper);
    if(f.other>=0) { close(f.other); check(unlink(alias)==0,"remove owned alias"); }
    check(success,"child result");
    printf("PASS native launcher mode %d\n",mode);
}
int main(int argc,char **argv)
{
    check(argc==2,"fixture directory argument");
    int n=snprintf(alias,sizeof(alias),"%s/p-alias",argv[1]);
    check(n>0 && (size_t)n<sizeof(alias),"alias length");
    for(int i=0;i<=14;i++) run_case(i);
    puts("PASS PTY/FD observer only; SSH execution and guest acceptance not exercised");
    return 0;
}
