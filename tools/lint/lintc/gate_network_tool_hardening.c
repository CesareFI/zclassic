/* Copyright 2026 Rhett Creighton - Licensed under Apache-2.0
 *
 * purpose: C23 lint gate — check-network-tool-hardening. Verifies that the
 * tree's Internet-facing standalone tools — build/bin/zclassic23-acme (TLS
 * client to the public ACME/CDN network), build/bin/agent_sha3, and, when
 * built, build/bin/z23-clang-manifest — carry the ELF mitigations the tree
 * declares through HARDEN_CFLAGS/HARDEN_LDFLAGS: PIE (ET_DYN), a GNU_RELRO
 * segment, BIND_NOW eager binding, and a non-executable GNU_STACK.
 *
 * Why a gate and not a comment: the Makefile rules for these tools build
 * straight from source and deliberately exclude the node's release
 * LDFLAGS — but for years they also excluded HARDEN_*, and the mitigations
 * were only accidentally present wherever the distro compiler happens to
 * enable them by default (observed: Ubuntu's gcc papers over PIE, RELRO,
 * BIND_NOW, stack protector and fortify simultaneously, so an unpatched
 * tree produces a fully hardened-looking binary HERE and a soft one on any
 * other toolchain). A declaration a gate can refuse is the durable form.
 *
 * Host-bound, like the rest of the ELF tooling: on a non-Linux host (or a
 * host without readelf) the run reports UNOBSERVED/UNPROVEN instead of
 * pretending an ELF verdict exists. readelf is part of binutils, a base
 * toolchain component on every Linux builder.
 *
 * The verdict is a pure function of the captured readelf -h/-l/-d text so
 * the selftest can prove both directions with control binaries: one built
 * -no-pie -Wl,-z,norelro (must be refused) and one built with the full
 * mitigation set (must be accepted).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "lintc.h"

enum { NTH_BUFCAP = 65536, NTH_WHY = 192 };

struct nth_tool {
    const char *path;       /* relative to the tree the gate runs in */
    const char *make_target;/* named as the fix when the binary is absent */
    bool optional;          /* checked only when the artifact exists */
};

static const struct nth_tool k_nth_tools[] = {
    { "build/bin/zclassic23-acme", "build/bin/zclassic23-acme", false },
    { "build/bin/agent_sha3", "build/bin/agent_sha3", false },
    { "build/bin/z23-clang-manifest", "clang-manifest", true },
};
enum { NTH_NTOOLS = (int)(sizeof k_nth_tools / sizeof k_nth_tools[0]) };

static bool nth_on_linux(void)
{
    struct utsname u;
    if (uname(&u) != 0)
        return false;
    return strcmp(u.sysname, "Linux") == 0;
}

static bool nth_readelf_avail(void)
{
    FILE *p = popen("command -v readelf 2>/dev/null", "r");
    if (!p)
        return false;
    char line[256];
    bool ok = fgets(line, sizeof(line), p) != NULL && line[0] != '\0';
    if (pclose(p) < 0)
        return false;
    return ok;
}

/* Capture all stdout+stderr of "readelf <flags> <path>" into buf. */
static bool nth_capture(const char *flags, const char *path,
                        char *buf, size_t cap)
{
    char cmd[1024];
    int n = snprintf(cmd, sizeof(cmd), "readelf %s -- '%s' 2>&1",
                     flags, path);
    if (n <= 0 || (size_t)n >= sizeof(cmd))
        return false;
    FILE *p = popen(cmd, "r");
    if (!p)
        return false;
    size_t used = 0;
    for (;;) {
        if (used + 1 >= cap) {
            (void)pclose(p);
            return false; /* truncated capture is UNPROVEN, not a verdict */
        }
        size_t got = fread(buf + used, 1, cap - used - 1, p);
        used += got;
        if (got == 0)
            break;
    }
    buf[used] = 0;
    int rc = pclose(p);
    return rc == 0;
}

/* Line containing needle, or NULL. */
static const char *nth_line(const char *text, const char *needle)
{
    const char *p = text;
    size_t nlen = strlen(needle);
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len >= nlen) {
            const char *hit = strstr(p, needle);
            if (hit && (size_t)(hit - p) + nlen <= len)
                return p;
        }
        p = eol ? eol + 1 : NULL;
    }
    return NULL;
}

/* Last space-separated token of text[0..*len): returns its start and sets
 * *len to the end of the text before it. An empty token means no text left. */
static size_t nth_last_token(const char *text, size_t *len, size_t *end)
{
    size_t n = *len;
    while (n > 0 && (text[n - 1] == ' ' || text[n - 1] == '\r'))
        n--;
    *end = n;
    while (n > 0 && text[n - 1] != ' ')
        n--;
    *len = n;
    return n;
}

/* True when the program-header entry starting at `entry` carries an E flag.
 * `readelf -W -l` prints one entry per line ending "... MemSiz Flg Align":
 * walk back from the Align token over the flag letters (R, W, E) up to the
 * MemSiz hex field, so text of other entries is never scanned. */
static bool nth_stack_is_exec(const char *entry)
{
    const char *eol = strchr(entry, '\n');
    size_t len = eol ? (size_t)(eol - entry) : strlen(entry);
    size_t end;
    (void)nth_last_token(entry, &len, &end); /* Align */
    for (;;) {
        size_t start = nth_last_token(entry, &len, &end);
        if (start == end || strncmp(entry + start, "0x", 2) == 0)
            return false; /* no flag token left, or MemSiz reached */
        if (memchr(entry + start, 'E', end - start))
            return true;
    }
}

/* Pure verdict over captured readelf text: returns true when every
 * declared mitigation is present. On refusal, why names what is missing. */
static bool nth_verdict(const char *elf_h, const char *elf_l,
                        const char *elf_d, char *why, size_t why_cap)
{
    why[0] = 0;
    const char *type = nth_line(elf_h, "Type:");
    if (!type || !strstr(type, "DYN")) {
        snprintf(why, why_cap, "not position-independent (ELF Type is not DYN)");
        return false;
    }
    if (!nth_line(elf_l, "GNU_RELRO")) {
        snprintf(why, why_cap, "no GNU_RELRO segment");
        return false;
    }
    if (!strstr(elf_d, "BIND_NOW") &&
        !(strstr(elf_d, "FLAGS_1") && strstr(elf_d, "NOW"))) {
        snprintf(why, why_cap, "no BIND_NOW eager binding");
        return false;
    }
    const char *stack = nth_line(elf_l, "GNU_STACK");
    if (!stack) {
        snprintf(why, why_cap, "no GNU_STACK segment");
        return false;
    }
    bool exec = nth_stack_is_exec(stack);
    if (exec) {
        snprintf(why, why_cap, "executable GNU_STACK (flags include E)");
        return false;
    }
    return true;
}

static int nth_check_one(const struct nth_tool *tool, char *why, size_t why_cap)
{
    char h[NTH_BUFCAP], l[NTH_BUFCAP], d[NTH_BUFCAP];
    if (!nth_capture("-h", tool->path, h, sizeof(h)) ||
        !nth_capture("-W -l", tool->path, l, sizeof(l)) ||
        !nth_capture("-d", tool->path, d, sizeof(d))) {
        snprintf(why, why_cap, "UNPROVEN — readelf could not inspect %s",
                 tool->path);
        return 2;
    }
    if (!nth_verdict(h, l, d, why, why_cap))
        return 1;
    return 0;
}

int check_network_tool_hardening_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (!nth_on_linux()) {
        printf("check_network_tool_hardening: UNOBSERVED — readelf is an ELF "
               "tool and this is not a Linux host; the Makefile still carries "
               "the HARDEN_ flags (they are defined empty off Linux)\n");
        return 0;
    }
    if (!nth_readelf_avail()) {
        fprintf(stderr,
                "check_network_tool_hardening: UNPROVEN — readelf(1) not "
                "found; it ships with binutils, a base toolchain component. "
                "Install binutils and rerun.\n");
        return 2;
    }
    int violations = 0, unproven = 0, scanned = 0;
    for (int i = 0; i < NTH_NTOOLS; i++) {
        const struct nth_tool *t = &k_nth_tools[i];
        struct stat st;
        if (stat(t->path, &st) != 0) {
            if (t->optional) {
                printf("check_network_tool_hardening: %s absent — optional "
                       "sensor, checked only when built\n", t->path);
                continue;
            }
            fprintf(stderr,
                    "check_network_tool_hardening: FAIL — %s is missing; "
                    "build it with 'make %s' (the lint umbrella builds it "
                    "via check-standalone-tools-link)\n",
                    t->path, t->make_target);
            violations++;
            continue;
        }
        scanned++;
        char why[NTH_WHY];
        int rc = nth_check_one(t, why, sizeof(why));
        if (rc == 2) {
            fprintf(stderr, "check_network_tool_hardening: %s\n", why);
            unproven++;
        } else if (rc == 1) {
            fprintf(stderr,
                    "check_network_tool_hardening: FAIL — %s: %s. The "
                    "Makefile rule for this tool must carry $(HARDEN_CFLAGS) "
                    "and $(HARDEN_LDFLAGS) (see HARDEN_* near the top of "
                    "the Makefile).\n",
                    t->path, why);
            violations++;
        }
    }
    if (scanned < 2) {
        fprintf(stderr,
                "check_network_tool_hardening: UNPROVEN — only %d tool(s) "
                "scanned (floor 2); the required tools must exist for a "
                "verdict.\n",
                scanned);
        return 2;
    }
    if (unproven > 0)
        return 2;
    if (violations > 0)
        return 1;
    printf("check_network_tool_hardening: PASS — %d network tool(s) carry "
           "PIE, GNU_RELRO, BIND_NOW and a non-executable stack\n", scanned);
    return 0;
}

/* Build one control binary; returns the compiler's exit status (127 when
 * the compiler itself could not run). */
static int nth_cc(const char *cc, const char *src, const char *out,
                  const char *extra)
{
    char cmd[2048];
    int n = snprintf(cmd, sizeof(cmd), "%s -std=c23 -O1 %s '%s' -o '%s' 2>&1",
                     cc, extra ? extra : "", src, out);
    if (n <= 0 || (size_t)n >= sizeof(cmd))
        return 127;
    FILE *p = popen(cmd, "r");
    if (!p)
        return 127;
    char sink[512];
    while (fgets(sink, sizeof(sink), p))
        ;
    return pclose(p);
}

/* Compile the two control binaries the selftest proves the verdict logic
 * against: an unhardened one that must be refused, and a fully flagged one
 * that must be accepted. */
static bool nth_selftest_build_controls(const char *cc, const char *src,
                                        const char *neg, const char *pos,
                                        char *why, size_t why_cap)
{
    if (nth_cc(cc, src, neg, "-no-pie -Wl,-z,norelro") != 0) {
        snprintf(why, why_cap,
                 "the negative control (%s -no-pie) did not link on this "
                 "host", cc);
        return false;
    }
    if (nth_cc(cc, src, pos,
               "-fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack") != 0) {
        snprintf(why, why_cap,
                 "the positive control (explicit mitigation flags) did not "
                 "link on this host");
        return false;
    }
    return true;
}

/* Create the scratch dir (under TMPDIR, else ./test-tmp — the bare-tmp
 * gate's rule applies to gates too) and write the tiny control source.
 * Returns false with why set when the setup is not provable here. */
static bool nth_selftest_setup(char *dir, size_t dir_cap, char *src,
                               size_t src_cap, char *why, size_t why_cap)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !tmp[0]) {
        if (mkdir("./test-tmp", 0755) != 0 && errno != EEXIST) {
            snprintf(why, why_cap, "cannot create ./test-tmp (%s)",
                     strerror(errno));
            return false;
        }
        tmp = "./test-tmp";
    }
    int n = snprintf(dir, dir_cap, "%s/zcl-nth-selftest.XXXXXX", tmp);
    if (n <= 0 || (size_t)n >= dir_cap || !mkdtemp(dir)) {
        snprintf(why, why_cap,
                 "cannot create a scratch dir under TMPDIR (the bare-tmp "
                 "gate's rule applies to gates too)");
        return false;
    }
    int s = snprintf(src, src_cap, "%s/probe.c", dir);
    if (s <= 0 || (size_t)s >= src_cap) {
        snprintf(why, why_cap, "scratch path does not fit");
        return false;
    }
    FILE *f = fopen(src, "w");
    if (!f) {
        snprintf(why, why_cap, "cannot write %.120s (%s)", src,
                 strerror(errno));
        return false;
    }
    fputs("int main(void){return 0;}\n", f);
    fclose(f);
    return true;
}

/* Fixture readelf texts in `readelf -W` layout: a fully hardened PIE whose
 * GNU_STACK entry is followed by a GNU_RELRO entry, so the stack flags are
 * not the tail of the program-header text. */
#define NTH_FIX_H \
    "  Type:                              DYN (Position-Independent Executable file)\n"
#define NTH_FIX_L(stack_flags) \
    "Program Headers:\n" \
    "  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align\n" \
    "  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x0010a8 0x0010a8 R   0x1000\n" \
    "  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 " stack_flags " 0x10\n" \
    "  GNU_RELRO      0x002e10 0x0000000000003e10 0x0000000000003e10 0x0001f0 0x0001f0 R   0x1\n"
#define NTH_FIX_D \
    " 0x000000000000001e (FLAGS)                BIND_NOW\n"

static int nth_selftest_stack_fixtures(void)
{
    char why[NTH_WHY];
    if (nth_verdict(NTH_FIX_H, NTH_FIX_L("RWE"), NTH_FIX_D, why,
                    sizeof(why))) {
        fprintf(stderr, "check_network_tool_hardening selftest: FAIL — an "
                "executable GNU_STACK followed by GNU_RELRO was ACCEPTED\n");
        return 1;
    }
    if (!strstr(why, "executable GNU_STACK")) {
        fprintf(stderr, "check_network_tool_hardening selftest: FAIL — "
                "executable GNU_STACK refused for the wrong reason: %s\n",
                why);
        return 1;
    }
    if (!nth_verdict(NTH_FIX_H, NTH_FIX_L("RW "), NTH_FIX_D, why,
                     sizeof(why))) {
        fprintf(stderr, "check_network_tool_hardening selftest: FAIL — a "
                "non-executable GNU_STACK was REFUSED: %s\n", why);
        return 1;
    }
    return 0;
}

int check_network_tool_hardening_selftest(void)
{
    if (nth_selftest_stack_fixtures() != 0)
        return 1;
    if (!nth_on_linux()) {
        printf("check_network_tool_hardening selftest: UNOBSERVED — not a "
               "Linux host\n");
        return 0;
    }
    char dir[1024], src[1400], neg[1400], pos[1400], why[NTH_WHY];
    if (!nth_selftest_setup(dir, sizeof(dir), src, sizeof(src),
                            why, sizeof(why))) {
        fprintf(stderr, "check_network_tool_hardening selftest: UNPROVEN — "
                "%s\n", why);
        return 2;
    }
    (void)snprintf(neg, sizeof(neg), "%s/neg", dir);
    (void)snprintf(pos, sizeof(pos), "%s/pos", dir);

    const char *cc = getenv("CC");
    if (!cc || !cc[0])
        cc = "cc";
    if (!nth_selftest_build_controls(cc, src, neg, pos, why, sizeof(why))) {
        fprintf(stderr, "check_network_tool_hardening selftest: UNPROVEN — "
                "%s\n", why);
        return 2;
    }
    struct nth_tool neg_tool = { neg, "selftest", false };
    struct nth_tool pos_tool = { pos, "selftest", false };
    int neg_rc = nth_check_one(&neg_tool, why, sizeof(why));
    if (neg_rc != 1) {
        fprintf(stderr, "check_network_tool_hardening selftest: FAIL — the "
                "unhardened control binary was %s (want refusal: %s)\n",
                neg_rc == 0 ? "ACCEPTED" : "UNPROVEN", why);
        return 1;
    }
    int pos_rc = nth_check_one(&pos_tool, why, sizeof(why));
    if (pos_rc != 0) {
        fprintf(stderr, "check_network_tool_hardening selftest: FAIL — the "
                "hardened control binary was %s (want accept: %s)\n",
                pos_rc == 1 ? "REFUSED" : "UNPROVEN", why);
        return 1;
    }
    char rm[1600];
    (void)snprintf(rm, sizeof(rm), "rm -rf -- '%s'", dir);
    FILE *rp = popen(rm, "r");
    if (rp)
        (void)pclose(rp);
    printf("check_network_tool_hardening selftest: PASS — the unhardened "
           "control is refused and the hardened control is accepted\n");
    return 0;
}
