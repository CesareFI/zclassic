/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Configure and verify raw terminal flags for guest-port tools.
 */
#ifndef Z23_GUEST_PORT_H
#define Z23_GUEST_PORT_H
#include <fcntl.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#if defined(__FreeBSD__) && !defined(PENDIN)
#error FreeBSD native terminal flags must be visible
#endif
#ifdef PENDIN
#define GUEST_PORT_PENDING_INPUT PENDIN
#else
#define GUEST_PORT_PENDING_INPUT 0
#endif
static bool raw_flags(const struct termios *t)
{
    return !(t->c_iflag & (IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXOFF|IMAXBEL)) &&
        !(t->c_oflag & OPOST) && !(t->c_lflag & (ECHO|ECHONL|ICANON|ISIG|IEXTEN|GUEST_PORT_PENDING_INPUT)) &&
        (t->c_cflag & (CSIZE|PARENB)) == CS8 && t->c_cc[VMIN] == 1 && t->c_cc[VTIME] == 0;
}
static int open_raw(const char *path)
{
    int fd = open(path, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
    if (fd < 0) return -1;
    struct termios t;
    if (tcgetattr(fd, &t) < 0) { close(fd); return -1; }
    t.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXOFF|IMAXBEL);
    t.c_oflag &= ~OPOST;
    t.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN|GUEST_PORT_PENDING_INPUT);
    t.c_cflag = (t.c_cflag & ~(CSIZE|PARENB)) | CS8;
    t.c_cc[VMIN] = 1; t.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &t) < 0 || tcgetattr(fd, &t) < 0 || !raw_flags(&t)) {
        close(fd); return -1;
    }
    return fd;
}
#endif
