/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Map the held payload port to a fixed SSH fixture command.
 */
#ifndef __FreeBSD__
#define _POSIX_C_SOURCE 200809L
#endif
#define _DARWIN_C_SOURCE
#include <stdio.h>
#include "guest_port.h"

static int ssh_refuse(const char *reason)
{
    fprintf(stderr,"guest-ssh-fixture: %s\n",reason);
    return 1;
}

/* The fixture owner verifies and freezes this config and its local identity
 * inputs before launch. This helper neither provisions nor exports keys. */
static int ssh_launch(void)
{
    char *const args[]={
        "/usr/bin/ssh", "-F", "/usr/local/etc/z23-fixture/ssh_config", "-T",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=/usr/local/etc/z23-fixture/known_hosts",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
        "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=no", "-o", "ControlPath=none",
        "-o", "PermitLocalCommand=no", "-o", "RequestTTY=no",
        "-o", "KexAlgorithms=mlkem768x25519-sha256",
        "-o", "ProxyCommand=/usr/local/libexec/z23-guest-port /dev/vtcon/z23.l0.t",
        "z23-fixture", "/bin/cat", NULL
    };
    char *const env[]={"LANG=C", "LC_ALL=C", NULL};
    execve(args[0],args,env);
    return ssh_refuse("EXEC_REFUSED");
}

static int ssh_stdio(int fd)
{
    int flags=fcntl(fd,F_GETFL);
    if(flags<0 || fcntl(fd,F_SETFL,flags & ~O_NONBLOCK)<0)
        return ssh_refuse("BLOCKING_SETUP_REFUSED");
    flags=fcntl(fd,F_GETFL);
    if(flags<0 || (flags & O_NONBLOCK)) return ssh_refuse("BLOCKING_READBACK_REFUSED");
    if(dup2(fd,STDIN_FILENO)<0 || dup2(fd,STDOUT_FILENO)<0)
        return ssh_refuse("STDIO_DUP_REFUSED");
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;
    if(argc!=1) return ssh_refuse("usage: no arguments");
    /* A missing console must not be occupied by the subsequently opened P. */
    int console_flags=fcntl(STDERR_FILENO,F_GETFD);
    int console_mode=fcntl(STDERR_FILENO,F_GETFL);
    if(console_flags<0 || (console_flags & FD_CLOEXEC) || console_mode<0 ||
        (console_mode & O_ACCMODE)==O_RDONLY) return ssh_refuse("CONSOLE_REFUSED");
    int fd=open_raw("/dev/vtcon/z23.l0.p");
    if(fd<0) return ssh_refuse("P_RAW_REFUSED");
    if(fd<3) {
        int held=fcntl(fd,F_DUPFD_CLOEXEC,3);
        if(held<0) { close(fd); return ssh_refuse("RELOCATE_REFUSED"); }
        if(close(fd)<0) { close(held); return ssh_refuse("RELOCATE_CLOSE_REFUSED"); }
        fd=held;
    }
    int result=ssh_stdio(fd);
    if(close(fd)<0) return ssh_refuse("HELD_CLOSE_REFUSED");
    if(result) return result;
    return ssh_launch();
}
