/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"
#include "test/zcode_dht_acceptance_peer.h"

#if !defined(_WIN32)
/* Exercise the real attack caller without copying the private identity reader. */
#define ZCL_DHT_ACCEPTANCE_PEER_TEST 1
#include "../../../tools/zcode_dht_acceptance_peer.c"

static FILE *attack_capture_file(void)
{
    char path[4096];
    int fd = test_mkstemp(path, sizeof(path), "dht_peer_capture");
    if (fd < 0)
        return NULL;
    if (unlink(path) != 0) {
        close(fd);
        return NULL;
    }
    FILE *capture = fdopen(fd, "w+");
    if (!capture)
        close(fd);
    return capture;
}

static bool capture_attack_refusal(const char *datadir, char *error,
                                   size_t error_cap, int *status)
{
    *status = -1;
    error[0] = '\0';
    FILE *capture = attack_capture_file();
    if (!capture)
        return false;
    int saved = dup(STDERR_FILENO);
    if (saved < 0) {
        fclose(capture);
        return false;
    }
    bool ok = fflush(stderr) == 0;
    if (ok)
        ok = dup2(fileno(capture), STDERR_FILENO) >= 0;
    if (ok)
        *status = attack_peer("127.0.0.1", 9, datadir);
    if (fflush(stderr) != 0)
        ok = false;
    if (dup2(saved, STDERR_FILENO) < 0)
        ok = false;
    if (close(saved) != 0)
        ok = false;
    rewind(capture);
    size_t n = fread(error, 1, error_cap - 1, capture);
    error[n] = '\0';
    if (ferror(capture))
        ok = false;
    if (fclose(capture) != 0)
        ok = false;
    return ok;
}

static int overlong_identity_refusal(void)
{
    int failures = 0;
    TEST("DHT acceptance attack refuses truncated identity path by name") {
        char datadir[1389], error[256];
        memset(datadir, 'x', 1385);
        memcpy(datadir + 1385, "/dd", 4);
        int status;
        ASSERT(capture_attack_refusal(datadir, error, sizeof(error), &status));
        ASSERT_EQ(status, 2);
        ASSERT(strstr(error, "identity-datadir too long (max 1383 characters)") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int unreadable_identity_refusal(void)
{
    int failures = 0;
    TEST("DHT acceptance attack names an unreadable identity") {
        char root[4096], error[256];
        test_make_tmpdir(root, sizeof(root), "dht_peer", "identity");
        int status;
        bool captured = capture_attack_refusal(root, error, sizeof(error), &status);
        int removed = rmdir(root);
        ASSERT(captured);
        ASSERT_EQ(removed, 0);
        ASSERT_EQ(status, 2);
        ASSERT(strstr(error, "identity load failed: identity unreadable") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_zcode_dht_acceptance_peer(void)
{
#if !defined(_WIN32)
    return overlong_identity_refusal() + unreadable_identity_refusal();
#else
    return 0;
#endif
}
