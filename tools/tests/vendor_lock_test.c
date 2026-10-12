/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Exercise vendor lock serialization and process-group death recovery. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int failure(const char *reason)
{
    fprintf(stderr, "vendor_lock_test: %s (errno=%d)\n", reason, errno);
    return 1;
}

static int wait_ok(pid_t child, int expected)
{
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != expected)
        return failure("unexpected child result");
    return 0;
}

static pid_t launch(const char *helper, const char *lock, const char *timeout,
                    const char *command, int notify, int isolated)
{
    pid_t child = fork();
    if (child != 0) return child;
    if (isolated && setsid() < 0) _exit(98);
    if (notify >= 0 && dup2(notify, 7) < 0) _exit(98);
    execl(helper, helper, lock, timeout, "/bin/sh", "-c", command,
          (char *)NULL);
    _exit(99);
}

static int ready(int fd, int milliseconds)
{
    struct pollfd event = {.fd = fd, .events = POLLIN};
    int result = poll(&event, 1, milliseconds);
    if (result <= 0 || !(event.revents & POLLIN)) return 0;
    char byte;
    return read(fd, &byte, 1) == 1;
}

static int kill_group(pid_t holder)
{
    if (kill(-holder, SIGKILL)) return failure("group kill failed");
    int status;
    if (waitpid(holder, &status, 0) != holder || !WIFSIGNALED(status) ||
        WTERMSIG(status) != SIGKILL)
        return failure("holder group did not die");
    return 0;
}

static int exercise(char **argv, pid_t holder, int *holder_pipe, int *waiter_pipe)
{
    int result = 1;
    pid_t waiter = -1;
    if (!ready(holder_pipe[0], 5000)) {
        failure("holder did not acquire");
        goto cleanup;
    }
    pid_t refused = launch(argv[1], argv[2], "0", "exit 0", -1, 0);
    if (refused < 0 || wait_ok(refused, 75)) goto cleanup;
    waiter = launch(argv[1], argv[2], "5", "printf x >&7",
                    waiter_pipe[1], 0);
    if (waiter < 0) { failure("waiter fork failed"); goto cleanup; }
    if (ready(waiter_pipe[0], 200)) {
        failure("legitimate holder was reclaimed");
        goto cleanup;
    }
    /* Exactly the native timeout mechanism: every holder descendant dies.
     * No trap, unlink, owner record, or stale-lock cleanup is involved. */
    if (kill_group(holder)) goto cleanup;
    holder = -1;
    if (!ready(waiter_pipe[0], 5000) || wait_ok(waiter, 0)) {
        failure("waiter was not admitted after kernel release");
        goto cleanup;
    }
    waiter = -1;
    pid_t next = launch(argv[1], argv[2], "0", "exit 0", -1, 0);
    if (next < 0 || wait_ok(next, 0)) goto cleanup;
    result = 0;
    puts("vendor_lock_test: serialize, live holder, SIGKILL group recovery PASS");
cleanup:
    if (holder > 0) { (void)kill(-holder, SIGKILL); (void)waitpid(holder, NULL, 0); }
    if (waiter > 0) { (void)kill(waiter, SIGKILL); (void)waitpid(waiter, NULL, 0); }
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 3) return failure("expected helper and private lock path");
    int holder_pipe[2], waiter_pipe[2];
    if (pipe(holder_pipe) || pipe(waiter_pipe)) return failure("pipe failed");
    pid_t holder = launch(argv[1], argv[2], "0",
                         "printf x >&7; sleep 60 & wait", holder_pipe[1], 1);
    if (holder < 0) return failure("holder fork failed");
    int result = exercise(argv, holder, holder_pipe, waiter_pipe);
    close(holder_pipe[0]); close(holder_pipe[1]);
    close(waiter_pipe[0]); close(waiter_pipe[1]);
    return result;
}
