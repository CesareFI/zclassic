/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * A real same-UID SOCK_SEQPACKET peer for the fixed worker refusal probe. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    int fd[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fd) != 0)
        return 2;
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
        close(fd[0]);
        if (dup2(fd[1], STDIN_FILENO) < 0) _exit(127);
        close(fd[1]);
        execl(argv[1], argv[1], "serve", (char *)NULL);
        _exit(127);
    }
    close(fd[1]);
    close(fd[0]);
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return 2;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 2 ? 0 : 1;
}
