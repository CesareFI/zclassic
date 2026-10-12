/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Relay binary payloads through retained raw guest-port descriptors.
 */
#ifndef __FreeBSD__
#define _POSIX_C_SOURCE 200809L
#endif
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

struct buffer { unsigned char bytes[4096]; size_t used; };
static int refuse(const char *name) { fprintf(stderr, "guest-port: %s\n", name); return 1; }
#include "guest_port.h"
static int consume(int fd, struct buffer *b)
{
    ssize_t n = write(fd, b->bytes, b->used);
    if (n > 0) { b->used -= (size_t)n; memmove(b->bytes, b->bytes+n, b->used); return 0; }
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
    return -1;
}
static int fill(int fd, struct buffer *b, bool *eof, short events)
{
    ssize_t n = read(fd, b->bytes+b->used, sizeof(b->bytes)-b->used);
    if (n > 0) { b->used += (size_t)n; return 0; }
    if (n == 0 || (n < 0 && errno == EIO && (events & POLLHUP))) { *eof = true; return 0; }
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
    return -1;
}
static int setup_streams(int flags[2])
{
    flags[0]=fcntl(STDIN_FILENO,F_GETFL); flags[1]=fcntl(STDOUT_FILENO,F_GETFL);
    if(flags[0]<0 || flags[1]<0 || fcntl(STDIN_FILENO,F_SETFL,flags[0]|O_NONBLOCK)<0 ||
        fcntl(STDOUT_FILENO,F_SETFL,flags[1]|O_NONBLOCK)<0) return refuse("STREAM_SETUP_REFUSED");
    return 0;
}
static int validate_streams(void)
{
    int input=fcntl(STDIN_FILENO,F_GETFL),output=fcntl(STDOUT_FILENO,F_GETFL);
    if(input<0 || output<0 || (input&O_ACCMODE)==O_WRONLY ||
        (output&O_ACCMODE)==O_RDONLY) return refuse("STREAM_SETUP_REFUSED");
    return 0;
}
static int restore_streams(const int flags[2], int result)
{
    for(int fd=0;fd<2;fd++) {
        if(flags[fd]>=0 && fcntl(fd,F_SETFL,flags[fd])<0) {
            refuse("STREAM_RESTORE_REFUSED"); result=1;
        }
    }
    return result;
}
static int setup_sigpipe(struct sigaction *old_action)
{
    struct sigaction action={0}; action.sa_handler=SIG_IGN;
    if(sigemptyset(&action.sa_mask)<0 || sigaction(SIGPIPE,&action,old_action)<0)
        return refuse("SIGNAL_SETUP_REFUSED");
    return 0;
}
static int relay_step(int t, int p, struct buffer *tx, struct buffer *rx,
    bool *input_eof, bool *port_eof, const struct pollfd fds[4])
{
    for(int i=0;i<4;i++) if(fds[i].revents&POLLNVAL) return refuse("DESCRIPTOR_REFUSED");
    if(fds[1].revents && consume(t,tx)<0) return refuse("T_WRITE_REFUSED");
    if(fds[3].revents && consume(STDOUT_FILENO,rx)<0) return refuse("OUTPUT_REFUSED");
    if(fds[0].revents && fill(STDIN_FILENO,tx,input_eof,fds[0].revents)<0) return refuse("INPUT_REFUSED");
    if(fds[2].revents && fill(p,rx,port_eof,fds[2].revents)<0) return refuse("P_READ_REFUSED");
    return 0;
}
static int relay(int t, int p)
{
    struct buffer tx={0},rx={0};
    bool input_eof=false,port_eof=false;
    for(;;) {
        if(port_eof && rx.used==0) return tx.used ? refuse("T_TRUNCATED") : 0;
        struct pollfd fds[4]={
            {input_eof || tx.used==sizeof(tx.bytes) ? -1 : STDIN_FILENO,POLLIN,0},
            {tx.used ? t : -1,POLLOUT,0},
            {port_eof || rx.used==sizeof(rx.bytes) ? -1 : p,POLLIN,0},
            {rx.used ? STDOUT_FILENO : -1,POLLOUT,0}
        };
        if(poll(fds,4,-1)<0) {
            if(errno==EINTR) continue;
            return refuse("POLL_REFUSED");
        }
        if(relay_step(t,p,&tx,&rx,&input_eof,&port_eof,fds)) return 1;
    }
}
int main(int argc, char **argv)
{
    if(argc!=2 && argc!=3) return refuse("usage PORT_PATH | T_PATH P_PATH");
    if(validate_streams()) return 1;
    bool duplex=argc==2;
    int t=open_raw(argv[1]);
    if(t<0) return refuse("T_RAW_REFUSED");
    int p=duplex ? t : open_raw(argv[2]);
    if(p<0) { close(t); return refuse("P_RAW_REFUSED"); }
    int flags[2]={-1,-1},result=1;
    struct sigaction old_action;
    if(setup_streams(flags)) goto done;
    if(setup_sigpipe(&old_action)) goto done;
    if(duplex && (fprintf(stderr,"guest-port: RAW_READY\n")<0 || fflush(stderr)!=0))
        result=refuse("READY_REFUSED");
    else result=relay(t,p);
    if(sigaction(SIGPIPE,&old_action,NULL)<0) { refuse("SIGNAL_RESTORE_REFUSED"); result=1; }
 done:
    result=restore_streams(flags,result);
    if(p!=t) close(p);
    close(t);
    return result;
}
