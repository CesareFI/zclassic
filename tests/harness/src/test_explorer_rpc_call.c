/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for explorer RPC-proxy failure hygiene. A dead RPC backend
 * must leave a valid empty C string so callers never parse uninitialized stack.
 */

#include "test/test_core.h"
#include "../../../contexts/explorer/controllers/src/explorer_controller_internal.h"
#include "views/explorer_tx_view.h"
#include "views/format_helpers.h"
#include "zutf8/zutf8.h"

#include <string.h>

struct ex_rpc_block_case {
    const char *hash;
    const char *display;
    bool linked;
};

static bool ex_rpc_block_case_matches(const struct ex_rpc_block_case *c)
{
    struct explorer_tx_rpc_view_data d = {
        .has_block = true, .block_height = 42,
        .txid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    };
    uint8_t resp[8192];
    snprintf(d.blockhash, sizeof(d.blockhash), "%s", c->hash);
    size_t n = explorer_view_tx_rpc(&d, resp, sizeof(resp));
    if (n == 0 || n >= sizeof(resp) ||
        !zutf8_validate_n((const char *)resp, n)) return false;
    resp[n] = '\0';
    char expected[256];
    if (c->linked)
        snprintf(expected, sizeof(expected),
            "<a href='/explorer/block/%s'>%s</a> (height 42)</div>",
            c->hash, c->display);
    else
        snprintf(expected, sizeof(expected),
            "<div class='val hash'>%s (height 42)</div>", c->display);
    bool ok = strstr((char *)resp, expected) != NULL &&
        strstr((char *)resp, " onclick='") == NULL &&
        strstr((char *)resp, "<b>") == NULL &&
        strstr((char *)resp, "</body></html>") != NULL;
    if (!c->linked)
        ok = ok && strstr((char *)resp, "href='/explorer/block/") == NULL;
    return ok;
}

static int ex_rpc_block_hash_checks(void)
{
    static const struct ex_rpc_block_case cases[] = {
        {"x' onclick='alert(1)", "x&#39; onclick=&#39;aler...", false},
        {"a?b#c", "a?b#c...", false},
        {"a/b", "a/b...", false},
        {"<b>&\"'", "&lt;b&gt;&amp;&quot;&#39;...", false},
        {"0123456789abcdef", "0123456789abcdef...", false},
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "0123456789abcdef...", true},
        {"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
         "ABCDEF0123456789...", true},
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
         "0123456789abcdef...", false},
        {"0123456789abcde&tail", "0123456789abcde&amp;...", false},
        {"aaaaaaaaaaaaaaa\xc3\xa9", "aaaaaaaaaaaaaaa...", false},
        {"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"tail",
         "&quot;&quot;&quot;&quot;&quot;&quot;&quot;&quot;"
         "&quot;&quot;&quot;&quot;&quot;&quot;&quot;&quot;...", false},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool ok = ex_rpc_block_case_matches(&cases[i]);
        printf("explorer: RPC transaction block hash case %zu... %s\n",
               i, ok ? "OK" : "FAIL");
        if (!ok) failures++;
    }
    return failures;
}

/* Use the same external blockhash extraction as the RPC controller. */
static bool ex_rpc_external_hash_matches(const char *hash, const char *display,
                                         bool linked)
{
    char json[128], extracted[65] = "";
    snprintf(json, sizeof(json), "{\"blockhash\":\"%s\"}", hash);
    if (!zcl_json_extract_str(json, "blockhash", extracted, sizeof(extracted)))
        return false;
    const struct ex_rpc_block_case c = {extracted, display, linked};
    return ex_rpc_block_case_matches(&c);
}

static bool ex_rpc_invalid_hash_refused(const char *hash, bool external)
{
    struct explorer_tx_rpc_view_data d = {.has_block = true};
    uint8_t resp[8192], before[8192];
    memset(resp, 0xa5, sizeof(resp));
    memcpy(before, resp, sizeof(before));
    if (external) {
        char json[128];
        snprintf(json, sizeof(json), "{\"blockhash\":\"%s\"}", hash);
        if (!zcl_json_extract_str(json, "blockhash", d.blockhash,
                                  sizeof(d.blockhash))) return false;
    } else if (hash) {
        snprintf(d.blockhash, sizeof(d.blockhash), "%s", hash);
    } else {
        memset(d.blockhash, 'a', sizeof(d.blockhash));
    }
    return explorer_view_tx_rpc(&d, resp, sizeof(resp)) == 0 &&
           memcmp(resp, before, sizeof(resp)) == 0;
}

static int ex_rpc_utf8_checks(void)
{
    static const char *invalid[] = {
        "\x80", "\xc3", "\xff", "aaaaaaaaaaaaaaaa\xc3",
    };
    int failures = 0;
    bool ok = ex_rpc_external_hash_matches("aaaaaaaaaaaaaaa\xc3\xa9",
                                           "aaaaaaaaaaaaaaa...", false);
    printf("explorer: external UTF-8 boundary... %s\n", ok ? "OK" : "FAIL");
    if (!ok) failures++;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        for (unsigned external = 0; external < 2; external++) {
            ok = ex_rpc_invalid_hash_refused(invalid[i], external != 0);
            printf("explorer: invalid UTF-8 case %zu external %u... %s\n",
                   i, external, ok ? "OK" : "FAIL");
            if (!ok) failures++;
        }
    }
    ok = ex_rpc_invalid_hash_refused(NULL, false);
    printf("explorer: unterminated blockhash... %s\n", ok ? "OK" : "FAIL");
    if (!ok) failures++;
    return failures;
}

static int ex_rpc_external_link_checks(void)
{
    static const struct ex_rpc_block_case cases[] = {
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
         "0123456789abcdef...", true},
        {"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
         "ABCDEF0123456789...", true},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool ok = ex_rpc_external_hash_matches(cases[i].hash, cases[i].display,
                                               cases[i].linked);
        printf("explorer: external ASCII link %zu... %s\n", i, ok ? "OK" : "FAIL");
        if (!ok) failures++;
    }
    return failures;
}

int test_explorer_rpc_call(void)
{
    printf("\n=== explorer RPC call guards ===\n");
    int failures = 0;
    failures += ex_rpc_block_hash_checks();
    failures += ex_rpc_utf8_checks();
    failures += ex_rpc_external_link_checks();

    explorer_set_state(NULL, NULL, NULL, NULL, NULL);
    explorer_set_rpc("user", "pass", 1);

    printf("rpc_call dead port returns -1 and clears output... ");
    {
        char buf[64];
        memset(buf, 0xA5, sizeof(buf));
        int n = rpc_call("getblockcount", "[]", buf, sizeof(buf));
        bool ok = (n == -1 && buf[0] == '\0');
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_call rejects zero-sized output buffer... ");
    {
        char buf[1] = { 'x' };
        int n = rpc_call("getblockcount", "[]", buf, 0);
        bool ok = (n == -1 && buf[0] == 'x');
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_call rejects NULL output buffer... ");
    {
        int n = rpc_call("getblockcount", "[]", NULL, 64);
        bool ok = (n == -1);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("explorer block RPC failure renders not-found view... ");
    {
        uint8_t resp[4096];
        size_t n = explorer_handle_request("GET", "/explorer/block/241",
                                           NULL, 0, resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = n > 0 &&
                  strstr((const char *)resp, "404 Not Found") != NULL &&
                  strstr((const char *)resp, "Block Not Found") != NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("explorer RPC call guards: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
