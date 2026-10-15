/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: Linux immutable descriptor execution and trusted descendant cleanup. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_core.h"
#include "platform/supervised_process.h"
/* Exact resource sentinels, not elapsed-time subtraction. */
enum { FIXTURE_NO_PID = -1, FIXTURE_NO_FD = -1 };
#include "platform/clock.h"
#if defined(__linux__)
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <elf.h>
#include "sha3/sha3.h"

static int64_t fixture_deadline(void)
{
    return clock_now_monotonic_ns() + INT64_C(5000000000);
}

static int fixture_echo(int argc, char **argv)
{
    if (argc != 5 || !getenv("SUPERVISED_ALLOWED") || getenv("SUPERVISED_AMBIENT")) return 31;
    int ambient = atoi(argv[2]), writer = atoi(argv[3]), reader = atoi(argv[4]);
    if (fcntl(ambient, F_GETFD) >= 0 || errno != EBADF) return 32;
    if ((fcntl(writer, F_GETFL) & O_ACCMODE) != O_WRONLY ||
        (fcntl(reader, F_GETFL) & O_ACCMODE) != O_RDONLY) return 33;
    uint8_t bytes[4096];
    ssize_t n;
    while ((n = read(STDIN_FILENO, bytes, sizeof(bytes))) > 0) {
        size_t offset = 0;
        while (offset < (size_t)n) {
            ssize_t written = write(STDOUT_FILENO, bytes + offset, (size_t)n - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return 34;
            offset += (size_t)written;
        }
    }
    return n == 0 ? 0 : 35;
}

static int fixture_tree(void)
{
    pid_t intermediate = fork();
    if (intermediate < 0) return 36;
    if (!intermediate) {
        if (setsid() < 0) _exit(37);
        pid_t leaf = fork();
        if (leaf < 0) _exit(38);
        if (leaf) _exit(0);
        pid_t self = getpid();
        if (write(STDOUT_FILENO, &self, sizeof(self)) != (ssize_t)sizeof(self)) _exit(39);
        for (;;) pause();
    }
    for (;;) pause();
}

static int fixture_cwd(void)
{
    char path[1024];
    if (!getcwd(path, sizeof(path))) return 40;
    size_t length = strlen(path);
    return write(STDOUT_FILENO, path, length) == (ssize_t)length ? 0 : 41;
}

int supervised_fixture_dispatch(int argc, char **argv);
int supervised_fixture_dispatch(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[1], "--supervised-fixture-echo")) return fixture_echo(argc, argv);
    if (argc == 2 && !strcmp(argv[1], "--supervised-fixture-tree")) return fixture_tree();
    if (argc == 2 && !strcmp(argv[1], "--supervised-fixture-hold"))
        for (;;) pause();
    if (argc == 2 && !strcmp(argv[1], "--supervised-fixture-exit-one")) return 1;
    if (argc == 2 && !strcmp(argv[1], "--supervised-fixture-cwd")) return fixture_cwd();
    return -1;
}

static int sealed_snapshot(const char *path)
{
    int input = open(path, O_RDONLY | O_CLOEXEC);
    int image = memfd_create("supervised-fixture", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (input < 0 || image < 0) {
        if (input >= 0) close(input);
        if (image >= 0) close(image);
        return -1;
    }
    uint8_t bytes[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(input, bytes, sizeof(bytes))) > 0) {
        size_t offset = 0;
        while (offset < (size_t)n) {
            ssize_t written = write(image, bytes + offset, (size_t)n - offset);
            if (written <= 0) { ok = false; break; }
            offset += (size_t)written;
        }
        if (!ok) break;
    }
    close(input);
    int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (n < 0 || !ok || fcntl(image, F_ADD_SEALS, seals) < 0) {
        close(image); return -1;
    }
    return image;
}

static bool wait_bytes(int fd, void *output, size_t length)
{
    uint8_t *bytes = output;
    size_t offset = 0;
    int64_t deadline = fixture_deadline();
    while (offset < length && clock_now_monotonic_ns() < deadline) {
        struct pollfd entry = {.fd = fd, .events = POLLIN};
        if (poll(&entry, 1, 20) <= 0) continue;
        ssize_t n = read(fd, bytes + offset, length - offset);
        if (n <= 0) return false;
        offset += (size_t)n;
    }
    return offset == length;
}

static bool exact_eof(int fd)
{
    struct pollfd entry = {.fd = fd, .events = POLLIN};
    int64_t deadline = fixture_deadline();
    while (clock_now_monotonic_ns() < deadline) {
        if (poll(&entry, 1, 20) <= 0) continue;
        uint8_t byte;
        return read(fd, &byte, 1) == 0;
    }
    return false;
}

static struct platform_supervised_spec tree_spec(int image, int null_fd, int output,
    struct platform_supervised_fd_map maps[3])
{
    static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-tree", NULL};
    static const char *const env[] = {NULL};
    maps[0] = (struct platform_supervised_fd_map){null_fd, 0};
    maps[1] = (struct platform_supervised_fd_map){output, 1};
    maps[2] = (struct platform_supervised_fd_map){null_fd, 2};
    return (struct platform_supervised_spec){.executable_fd = image, .argv = argv,
        .env = env, .maps = maps, .map_count = 3, .launch_deadline_ns = fixture_deadline(),
        .cleanup_timeout_ms = 1000};
}

/* Failed fixture cleanup retains explicit handle custody for the final retry.
 * These are test-local ownership slots, not a runtime queue or authority. */
static struct platform_supervised_process retained_custody[8];
static size_t retained_count;

static bool fixture_cleanup(struct platform_supervised_process *process)
{
    if (process->supervisor_pid < 0) return true;
    enum platform_supervised_state state = platform_supervised_stop(process, fixture_deadline());
    if (state == PLATFORM_SUPERVISED_CLEAN) return true;
    fprintf(stderr, "supervised fixture cleanup incomplete: supervisor=%lld state=%d errno=%d\n",
        (long long)process->supervisor_pid, (int)state, process->observation.error_number);
    if (retained_count < sizeof(retained_custody) / sizeof(retained_custody[0])) {
        retained_custody[retained_count++] = *process;
        platform_supervised_init(process);
    }
    return false;
}

static bool tree_cleanup(struct platform_supervised_process *process, int leaf_fd)
{
    if (leaf_fd >= 0) {
        if (!platform_supervised_fixture_pidfd_kill(leaf_fd))
            fprintf(stderr, "supervised fixture: owned descendant emergency kill failed errno=%d\n", errno);
        close(leaf_fd);
    }
    return fixture_cleanup(process);
}

static enum platform_supervised_state await_clean(struct platform_supervised_process *process);

static int supervised_tree(int image, bool owner_eof)
{
    int failures = 0;
    int pipes[2] = {-1, -1}, null_fd = -1, leaf_fd = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: setsid double-fork descendant cleanup gives EOF and ECHILD") {
        ASSERT(pipe2(pipes, O_CLOEXEC) == 0);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, pipes[1], maps);
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(pipes[1]); pipes[1] = -1;
        pid_t leaf = -1;
        ASSERT(wait_bytes(pipes[0], &leaf, sizeof(leaf)));
        ASSERT(leaf > 1);
        leaf_fd = platform_supervised_fixture_pidfd_open(leaf);
        ASSERT(leaf_fd >= 0);
        if (owner_eof) {
            platform_supervised_owner_eof(&process);
            ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        } else ASSERT_EQ(platform_supervised_stop(&process, fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.no_children);
        ASSERT(process.observation.engine_exit_observed);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
        ASSERT(exact_eof(pipes[0]));
        struct pollfd exited = {.fd = leaf_fd, .events = POLLIN};
        ASSERT(poll(&exited, 1, 0) > 0);
    } TEST_END
    if (!tree_cleanup(&process, leaf_fd)) failures++;
    if (null_fd >= 0) close(null_fd);
    for (size_t i = 0; i < 2; ++i) if (pipes[i] >= 0) close(pipes[i]);
    return failures;
}

static enum platform_supervised_state await_clean(struct platform_supervised_process *process)
{
    int64_t deadline = fixture_deadline();
    while (clock_now_monotonic_ns() < deadline) {
        enum platform_supervised_state state = platform_supervised_poll(process);
        if (process->supervisor_pid < 0) return state;
        struct pollfd delay = {.fd = -1};
        (void)poll(&delay, 0, 20);
    }
    return PLATFORM_SUPERVISED_INCOMPLETE;
}

static bool send_step(int fd, const uint8_t *input, size_t length,
    size_t *sent, bool *ended)
{
    if (*sent < length) {
        ssize_t n = send(fd, input + *sent, length - *sent, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) *sent += (size_t)n;
        else if (n < 0 && errno != EAGAIN && errno != EINTR) return false;
    }
    if (*sent == length && !*ended) {
        if (shutdown(fd, SHUT_WR) < 0) return false;
        *ended = true;
    }
    return true;
}

static bool receive_step(int fd, uint8_t *output, size_t length, size_t *received)
{
    ssize_t n = recv(fd, output + *received, length - *received, MSG_DONTWAIT);
    if (n > 0) *received += (size_t)n;
    else if (n == 0) return false;
    else if (errno != EAGAIN && errno != EINTR) return false;
    return true;
}

static bool binary_roundtrip(int fd)
{
    uint8_t input[65536], output[65536];
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (uint8_t)i;
    size_t sent = 0, received = 0;
    bool ended = false;
    int64_t deadline = fixture_deadline();
    while (received < sizeof(output) && clock_now_monotonic_ns() < deadline) {
        if (!send_step(fd, input, sizeof(input), &sent, &ended) ||
            !receive_step(fd, output, sizeof(output), &received)) return false;
        struct pollfd ready = {.fd = fd, .events = POLLIN | POLLOUT};
        (void)poll(&ready, 1, 20);
    }
    return sent == sizeof(input) && received == sizeof(output) && !memcmp(input, output, sizeof(input));
}

static int supervised_mapping(int image)
{
    int failures = 0;
    int sockets[2] = {-1, -1}, read_fd = -1, write_fd = -1, ambient = -1;
    const char *prior = getenv("SUPERVISED_AMBIENT");
    char *saved = prior ? strdup(prior) : NULL;
    bool changed_env = false;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: collision-safe mapping, exact binary stdio, no ambient FD or environment") {
        ASSERT(!prior || saved);
        ASSERT(setenv("SUPERVISED_AMBIENT", "must-not-leak", 1) == 0);
        changed_env = true;
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
        int original = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(original >= 0);
        read_fd = fcntl(original, F_DUPFD_CLOEXEC, 32);
        close(original);
        original = open("/dev/null", O_WRONLY | O_CLOEXEC);
        ASSERT(original >= 0);
        write_fd = fcntl(original, F_DUPFD_CLOEXEC, 32);
        ambient = fcntl(original, F_DUPFD, 90);
        close(original);
        ASSERT(read_fd >= 32 && read_fd <= 63);
        ASSERT(write_fd >= 32 && write_fd <= 63);
        ASSERT(ambient >= 90);
        char ambient_text[24], writer_text[24], reader_text[24];
        ASSERT(snprintf(ambient_text, sizeof(ambient_text), "%d", ambient) > 0);
        ASSERT(snprintf(writer_text, sizeof(writer_text), "%d", read_fd) > 0);
        ASSERT(snprintf(reader_text, sizeof(reader_text), "%d", write_fd) > 0);
        const char *const argv[] = {"supervised-fixture", "--supervised-fixture-echo",
            ambient_text, writer_text, reader_text, NULL};
        const char *const env[] = {"SUPERVISED_ALLOWED=ok", NULL};
        struct platform_supervised_fd_map maps[] = {
            {sockets[1], 0}, {sockets[1], 1}, {write_fd, 2},
            {write_fd, read_fd}, {read_fd, write_fd}};
        struct platform_supervised_spec spec = {.executable_fd = image, .argv = argv,
            .env = env, .maps = maps, .map_count = 5,
            .launch_deadline_ns = fixture_deadline(), .cleanup_timeout_ms = 1000};
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(sockets[1]); sockets[1] = -1;
        ASSERT(binary_roundtrip(sockets[0]));
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.no_children);
        ASSERT(process.observation.engine_exit_observed);
        ASSERT(WIFEXITED(process.observation.engine_wait_status));
        ASSERT_EQ(WEXITSTATUS(process.observation.engine_wait_status), 0);
        ASSERT(exact_eof(sockets[0]));
        ASSERT_EQ(platform_supervised_stop(&process, fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    for (size_t i = 0; i < 2; ++i) if (sockets[i] >= 0) close(sockets[i]);
    if (read_fd >= 0) close(read_fd);
    if (write_fd >= 0) close(write_fd);
    if (ambient >= 0) close(ambient);
    if (changed_env) {
        if (saved) (void)setenv("SUPERVISED_AMBIENT", saved, 1);
        else (void)unsetenv("SUPERVISED_AMBIENT");
    }
    free(saved);
    return failures;
}

static int supervised_failures(int image)
{
    int failures = 0;
    int null_fd = -1, invalid = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: invalid sealing, actual exec failure, and exhausted cleanup deadline retain truth") {
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        spec.executable_fd = null_fd;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
        invalid = memfd_create("invalid-elf", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        ASSERT(invalid >= 0);
        ASSERT_EQ(write(invalid, "\177ELF", 4), 4);
        ASSERT(fcntl(invalid, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
        spec.executable_fd = invalid;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_LAUNCH_FAILED);
        ASSERT(process.observation.error_number != 0);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        spec.executable_fd = image;
        static const char *const hold[] = {"supervised-fixture", "--supervised-fixture-hold", NULL};
        spec.argv = hold;
        spec.launch_deadline_ns = fixture_deadline();
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(platform_supervised_stop(&process, 0), PLATFORM_SUPERVISED_INCOMPLETE);
        ASSERT(process.supervisor_pid > 0);
        ASSERT_EQ(platform_supervised_stop(&process, fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.no_children);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (invalid >= 0) close(invalid);
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int supervised_fast_exit(int image)
{
    int failures = 0;
    int null_fd = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: successful exec exit one is observed separately from launch") {
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-exit-one", NULL};
        spec.argv = argv;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.engine_exit_observed);
        ASSERT(WIFEXITED(process.observation.engine_wait_status));
        ASSERT_EQ(WEXITSTATUS(process.observation.engine_wait_status), 1);
        ASSERT(process.observation.no_children);
        ASSERT_EQ(platform_supervised_poll(&process), PLATFORM_SUPERVISED_CLEAN);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int supervised_wait_custody(int image)
{
    int failures = 0;
    int null_fd = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: automatic supervisor reaping refuses before fork") {
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-hold", NULL};
        spec.argv = argv;
        struct sigaction prior;
        ASSERT(sigaction(SIGCHLD, NULL, &prior) == 0);
        for (unsigned policy = 0; policy < 2; ++policy) {
            struct sigaction changed = {.sa_handler = policy ? SIG_DFL : SIG_IGN};
            sigemptyset(&changed.sa_mask);
            if (policy) changed.sa_flags = SA_NOCLDWAIT;
            int installed = sigaction(SIGCHLD, &changed, NULL);
            enum platform_supervised_state state = installed == 0 ?
                platform_supervised_start(&process, &spec) : PLATFORM_SUPERVISED_OBSERVATION_FAILED;
            /* Restore BEFORE every assertion/TEST_CASE longjmp exit. */
            int restored = sigaction(SIGCHLD, &prior, NULL);
            ASSERT_EQ(restored, 0);
            ASSERT_EQ(installed, 0);
            ASSERT_EQ(state, PLATFORM_SUPERVISED_INVALID);
            ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
            ASSERT_EQ(process.control_fd, FIXTURE_NO_FD);
        }
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int retry_retained_custody(void)
{
    int failures = 0;
    for (size_t i = 0; i < retained_count; ++i) {
        struct platform_supervised_process *process = &retained_custody[i];
        enum platform_supervised_state state = platform_supervised_stop(process, fixture_deadline());
        if (state != PLATFORM_SUPERVISED_CLEAN) {
            fprintf(stderr, "supervised fixture retains incomplete custody: supervisor=%lld fd=%d state=%d\n",
                (long long)process->supervisor_pid, process->control_fd, (int)state);
            platform_supervised_owner_eof(process);
            failures++;
        }
    }
    return failures;
}


static void image_fixture(uint8_t bytes[1024], bool dynamic)
{
    memset(bytes, 0, 1024);
    Elf64_Ehdr h = {.e_type = ET_EXEC, .e_version = EV_CURRENT, .e_entry = 0x400300,
        .e_phoff = sizeof(h), .e_ehsize = sizeof(h), .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = dynamic ? 3 : 1};
    memcpy(h.e_ident, ELFMAG, SELFMAG); h.e_ident[EI_CLASS] = ELFCLASS64;
    h.e_ident[EI_DATA] = ELFDATA2LSB; h.e_ident[EI_VERSION] = EV_CURRENT;
#if defined(__x86_64__)
    h.e_machine = EM_X86_64;
    const char *loader = "/lib64/ld-linux-x86-64.so.2";
#else
    h.e_machine = EM_AARCH64;
    const char *loader = "/lib/ld-linux-aarch64.so.1";
#endif
    Elf64_Phdr ph[3] = {{.p_type = PT_LOAD, .p_flags = PF_R | PF_X,
        .p_filesz = 1024, .p_memsz = 1024, .p_vaddr = 0x400000, .p_align = 4096}};
    ph[1] = (Elf64_Phdr){.p_type = PT_DYNAMIC, .p_offset = 256, .p_vaddr = 0x400100,
        .p_filesz = 5 * sizeof(Elf64_Dyn), .p_memsz = 5 * sizeof(Elf64_Dyn)};
    ph[2] = (Elf64_Phdr){.p_type = PT_INTERP, .p_offset = 512, .p_filesz = strlen(loader) + 1};
    Elf64_Dyn entries[5] = {{.d_tag = DT_STRTAB, .d_un.d_ptr = 0x400190},
        {.d_tag = DT_STRSZ, .d_un.d_val = 10}, {.d_tag = DT_NEEDED, .d_un.d_val = 0},
        {.d_tag = DT_NULL}, {.d_tag = DT_NULL}};
    memcpy(bytes, &h, sizeof(h)); memcpy(bytes + sizeof(h), ph, h.e_phnum * sizeof(ph[0]));
    memcpy(bytes + 256, entries, sizeof(entries)); memcpy(bytes + 400, "libc.so.6", 10);
    memcpy(bytes + 512, loader, strlen(loader) + 1);
}

static void image_fixture_hash(const uint8_t *bytes, size_t length, uint8_t digest[32])
{
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    sha3_256_write(&hash, bytes, length); sha3_256_finalize(&hash, digest);
}

static bool image_fixture_refused(const uint8_t bytes[1024])
{
    uint8_t digest[32]; image_fixture_hash(bytes, 1024, digest);
    int fd = -1;
    enum platform_supervised_image_result result = platform_supervised_image_capture(bytes, 1024, digest, &fd);
    if (fd >= 0) close(fd);
    return result == PLATFORM_SUPERVISED_IMAGE_REFUSED && fd == -1;
}

static int supervised_image_capture(void)
{
    int failures = 0, fd = -1; uint8_t bytes[1024], digest[32], copied[1024];
    TEST_CASE("supervised_process: native image capture policy and immutable digest") {
        image_fixture(bytes, false); image_fixture_hash(bytes, sizeof(bytes), digest);
        ASSERT_EQ(platform_supervised_image_capture(bytes, sizeof(bytes), digest, &fd), PLATFORM_SUPERVISED_IMAGE_OK);
        ASSERT_EQ(pread(fd, copied, sizeof(copied), 0), sizeof(copied));
        ASSERT(!memcmp(bytes, copied, sizeof(bytes)));
        ASSERT_EQ(pwrite(fd, "x", 1, 0), -1); ASSERT_EQ(errno, EPERM);
        close(fd); fd = -1;
        image_fixture(bytes, true); image_fixture_hash(bytes, sizeof(bytes), digest);
        ASSERT_EQ(platform_supervised_image_capture(bytes, sizeof(bytes), digest, &fd), PLATFORM_SUPERVISED_IMAGE_OK);
        close(fd); fd = -1;
        digest[0] ^= 1;
        ASSERT(platform_supervised_image_capture(bytes, sizeof(bytes), digest, &fd) != PLATFORM_SUPERVISED_IMAGE_OK);
        ASSERT_EQ(fd, FIXTURE_NO_FD);
        ASSERT_EQ(platform_supervised_image_capture(bytes, PLATFORM_SUPERVISED_IMAGE_MAX + 1u, digest, &fd), PLATFORM_SUPERVISED_IMAGE_REFUSED);
    } TEST_END
    if (fd >= 0) close(fd);
    return failures;
}

static int supervised_image_refusals(void)
{
    int failures = 0; uint8_t bytes[1024];
    const int64_t forbidden[] = {DT_RPATH, DT_RUNPATH, DT_AUDIT, DT_DEPAUDIT, DT_FILTER, DT_AUXILIARY, DT_TEXTREL};
    TEST_CASE("supervised_process: loader authority and malformed ELF refuse") {
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
            image_fixture(bytes, true); Elf64_Dyn entry = {.d_tag = forbidden[i]};
            memcpy(bytes + 256 + 3 * sizeof(entry), &entry, sizeof(entry));
            ASSERT(image_fixture_refused(bytes));
        }
        image_fixture(bytes, true); memcpy(bytes + 400, "/BAD/x.so", 10);
        ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, true); bytes[513] = 'x'; ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); bytes[EI_CLASS] = ELFCLASS32; ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); bytes[EI_DATA] = ELFDATA2MSB; ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); Elf64_Phdr ph;
        memcpy(&ph, bytes + sizeof(Elf64_Ehdr), sizeof(ph)); ph.p_flags |= PF_W;
        memcpy(bytes + sizeof(Elf64_Ehdr), &ph, sizeof(ph)); ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, true); memcpy(&ph, bytes + sizeof(Elf64_Ehdr) + sizeof(ph), sizeof(ph));
        ph.p_vaddr++; memcpy(bytes + sizeof(Elf64_Ehdr) + sizeof(ph), &ph, sizeof(ph));
        ASSERT(image_fixture_refused(bytes));
    } TEST_END
    return failures;
}

static int supervised_image_geometry(void)
{
    int failures = 0; uint8_t bytes[1024];
    TEST_CASE("supervised_process: native machine, bounds and page permissions") {
        image_fixture(bytes, false); Elf64_Ehdr h;
        memcpy(&h, bytes, sizeof(h)); h.e_machine = EM_NONE;
        memcpy(bytes, &h, sizeof(h)); ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); memcpy(&h, bytes, sizeof(h)); h.e_phoff = UINT64_MAX;
        memcpy(bytes, &h, sizeof(h)); ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); memcpy(&h, bytes, sizeof(h));
        h.e_phnum = 2; h.e_entry = 0x400100; memcpy(bytes, &h, sizeof(h));
        Elf64_Phdr ph[2]; memcpy(&ph[0], bytes + sizeof(h), sizeof(ph[0]));
        ph[0].p_filesz = 768; ph[0].p_memsz = 768;
        ph[1] = (Elf64_Phdr){.p_type = PT_LOAD, .p_flags = PF_R | PF_W,
            .p_offset = 768, .p_vaddr = 0x400300, .p_filesz = 128, .p_memsz = 128, .p_align = 1};
        memcpy(bytes + sizeof(h), ph, sizeof(ph));
        ASSERT(image_fixture_refused(bytes)); /* Byte-disjoint RX/RW still share a native page. */
    } TEST_END
    return failures;
}

static int supervised_cwd(int image, const char *directory)
{
    int failures = 0, cwd = -1, null_fd = -1, sockets[2] = {-1, -1};
    struct platform_supervised_process process; platform_supervised_init(&process);
    TEST_CASE("supervised_process: trusted CWD descriptor and default parent custody") {
        cwd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(cwd >= 0); ASSERT(null_fd >= 0);
        ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets), 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, sockets[1], maps);
        const char *const argv[] = {"supervised-fixture", "--supervised-fixture-cwd", NULL};
        spec.argv = argv; spec.use_cwd_fd = true; spec.cwd_fd = null_fd;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
        spec.cwd_fd = cwd;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(sockets[1]); sockets[1] = -1;
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        char observed[1024] = {0};
        ASSERT_EQ(read(sockets[0], observed, sizeof(observed) - 1), (ssize_t)strlen(directory));
        ASSERT(!strcmp(observed, directory));
        ASSERT(exact_eof(sockets[0]));
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (cwd >= 0) close(cwd);
    if (null_fd >= 0) close(null_fd);
    for (size_t i = 0; i < 2; ++i) if (sockets[i] >= 0) close(sockets[i]);
    return failures;
}

int test_supervised_process(void);
int test_supervised_process(void)
{
    int failures = 0;
    int image = -1;
    char directory[1024] = {0}, path[1200];
    TEST_CASE("supervised_process: sealed registered fixture image") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "supervised-image"));
        ASSERT(snprintf(path, sizeof(path), "%s/image", directory) > 0);
        ASSERT(symlink("/proc/self/exe", path) == 0);
        image = sealed_snapshot(path);
        ASSERT(image >= 0);
        ASSERT(unlink(path) == 0);
        int replacement = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        ASSERT(replacement >= 0);
        ssize_t written = write(replacement, "replaced path", 13);
        close(replacement);
        ASSERT_EQ(written, 13);
        ASSERT_EQ(pwrite(image, "x", 1, 0), -1);
        ASSERT_EQ(errno, EPERM);
        failures += supervised_mapping(image);
        failures += supervised_tree(image, false);
        failures += supervised_tree(image, true);
        failures += supervised_failures(image);
        failures += supervised_fast_exit(image);
        failures += supervised_wait_custody(image);
        failures += supervised_cwd(image, directory);
        failures += supervised_image_capture();
        failures += supervised_image_refusals();
        failures += supervised_image_geometry();
    } TEST_END
    if (image >= 0) close(image);
    if (directory[0]) test_rm_rf(directory);
    failures += retry_retained_custody();
    return failures;
}
#else
int supervised_fixture_dispatch(int argc, char **argv);
int supervised_fixture_dispatch(int argc, char **argv)
{
    (void)argc; (void)argv;
    return -1;
}
int test_supervised_process(void);
int test_supervised_process(void)
{
    int failures = 0;
    TEST_CASE("supervised_process: unqualified platform refuses before launch") {
        struct platform_supervised_process process;
        platform_supervised_init(&process);
        ASSERT_EQ(platform_supervised_start(&process, NULL), PLATFORM_SUPERVISED_UNSUPPORTED);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
    } TEST_END
    return failures;
}
#endif
void supervised_fixture_exit_if_requested(int argc, char **argv);
void supervised_fixture_exit_if_requested(int argc, char **argv)
{
    int status = supervised_fixture_dispatch(argc, argv);
    if (status >= 0) exit(status);
}
