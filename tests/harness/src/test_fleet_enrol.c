/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_fleet_enrol — adversarial proof that one-paste fleet enrolment
 * admits exactly what its signatures say and nothing else.
 *
 * Every case is a string somebody could paste: a token with one byte
 * changed, a token minted by another key, a receipt edited after signing, an
 * invite used twice, a taken name, a hand-appended roster line. Each is a way
 * to get a machine into the fleet or point the owner's ssh bridge at one.
 *
 * Fixtures live under test-tmp/ with XDG_STATE_HOME and HOME redirected, so
 * the operator's real fleet key, roster and ~/.ssh/authorized_keys are never
 * touched.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "crypto/ed25519.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "net/acme_b64url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FE_NOW 1757030400
#define FE_TTL 24
/* 56 base32 characters then ".onion": a v3 locator with the right shape and
 * no owner; self-reported, never dialed. */
#define FE_ONION \
    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

static char g_fe_state[PATH_MAX];
static char g_fe_home[PATH_MAX];
static char g_fe_saved_xdg[PATH_MAX];
static char g_fe_saved_home[PATH_MAX];
static bool g_fe_saved;

/* Point the state-root resolver and the ssh bridge at this case's own tree;
 * called per TEST so a case can have a virgin box (no key, no roster). */
static void fe_isolate(const char *tag)
{
    char base[PATH_MAX - 64];
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");
    test_make_tmpdir(base, sizeof(base), "fleet_enrol", tag);
    if (!g_fe_saved) {
        g_fe_saved = true;
        (void)snprintf(g_fe_saved_xdg, sizeof(g_fe_saved_xdg), "%s",
                       xdg ? xdg : "");
        (void)snprintf(g_fe_saved_home, sizeof(g_fe_saved_home), "%s",
                       home ? home : "");
    }
    (void)snprintf(g_fe_state, sizeof(g_fe_state), "%s/state", base);
    (void)snprintf(g_fe_home, sizeof(g_fe_home), "%s/home", base);
    setenv("XDG_STATE_HOME", g_fe_state, 1);
    setenv("HOME", g_fe_home, 1);
}

static void fe_restore(void)
{
    if (!g_fe_saved) return;
    if (g_fe_saved_xdg[0]) setenv("XDG_STATE_HOME", g_fe_saved_xdg, 1);
    else unsetenv("XDG_STATE_HOME");
    if (g_fe_saved_home[0]) setenv("HOME", g_fe_saved_home, 1);
    else unsetenv("HOME");
}

/* A deterministic keypair, so a case can play the other box. */
static void fe_key(uint8_t byte, uint8_t seed[32], uint8_t pubkey[32])
{
    uint8_t secret[32];
    memset(seed, byte, 32);
    ed25519_keypair(pubkey, secret, seed);
    memset(secret, 0, sizeof(secret));
}

static struct fleet_box_facts fe_facts(void)
{
    struct fleet_box_facts facts = {0};
    (void)snprintf(facts.hostname, sizeof(facts.hostname), "build-box-7");
    (void)snprintf(facts.os, sizeof(facts.os), "Linux");
    (void)snprintf(facts.os_version, sizeof(facts.os_version), "Test 1.0");
    (void)snprintf(facts.arch, sizeof(facts.arch), "x86_64");
    (void)snprintf(facts.toolchain, sizeof(facts.toolchain), "test cc 1.0");
    (void)snprintf(facts.git_head, sizeof(facts.git_head), "0123456789abcdef");
    facts.cores = 8;
    facts.ram_mb = 32768;
    facts.disk_free_mb = 900000;
    return facts;
}

static size_t fe_occurrences(const char *body, const char *needle)
{
    size_t n = 0, step = strlen(needle);
    for (const char *at = strstr(body, needle); at; at = strstr(at + step,
                                                               needle))
        ++n;
    return n;
}

/* How many wire bytes a pasted record decodes to; 0 when not decodable. */
static size_t fe_wire_len(const char *text)
{
    uint8_t wire[FLEET_ENROL_MACHINE_WIRE_MAX];
    size_t len = 0;
    if (!acme_b64url_decode(text, wire, sizeof(wire), &len)) return 0;
    return len;
}

/* Decode `text`, flip one bit at `offset`, re-encode: a hostile paste that is
 * still valid base64url. */
static bool fe_tamper(const char *text, size_t offset, char *out, size_t cap)
{
    uint8_t wire[FLEET_ENROL_MACHINE_WIRE_MAX];
    size_t len = 0;
    if (!acme_b64url_decode(text, wire, sizeof(wire), &len) || offset >= len)
        return false;
    wire[offset] ^= 0x01u;
    return acme_b64url_encode(wire, len, out, cap) != 0;
}

/* One sealed roster line for `name` under `box_seed`, admitted at `port` by
 * `op_seed`: the whole ceremony in one helper. */
static bool fe_row(const char *name, uint8_t op_byte, uint8_t box_byte,
                   uint16_t port, const char *ssh, char *out, size_t cap)
{
    uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_receipt parsed;
    struct fleet_box_facts facts = fe_facts();
    size_t invite_len = 0, receipt_len = 0;
    const char *why = NULL;
    fe_key(op_byte, op_seed, op_pub);
    fe_key(box_byte, box_seed, box_pub);
    return fleet_invite_mint(name, FE_TTL, "", op_seed, op_pub, FE_NOW, token,
                             sizeof(token), &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire, sizeof(invite_wire),
                              &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, FE_ONION, &facts, ssh,
                              box_seed, box_pub, NULL, receipt,
                              sizeof(receipt),
                              &why) &&
           fleet_receipt_parse(receipt, &parsed, receipt_wire,
                               sizeof(receipt_wire), &receipt_len, &why) &&
           fleet_machine_mint(receipt_wire, receipt_len, FE_NOW, port, op_seed,
                              op_pub, out, cap, &why);
}

/* ── the invite ─────────────────────────────────────────────────────────── */

static int test_fe_invite_round_trip(void)
{
    int failures = 0;
    TEST("fleet enrol: an invite this box minted parses back to the same "
         "fields and verifies against the key inside it") {
        uint8_t seed[32], pubkey[32];
        uint8_t wire[FLEET_ENROL_INVITE_WIRE_MAX];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite minted, parsed;
        size_t wire_len = 0;
        const char *why = NULL;
        fe_key(0x11, seed, pubkey);
        ASSERT(fleet_invite_mint("studio", FE_TTL, "relay.example:2222", seed,
                                 pubkey, FE_NOW, token, sizeof(token), &minted,
                                 &why));
        /* The product is one pasteable line: no whitespace, no padding. */
        ASSERT(strchr(token, ' ') == NULL && strchr(token, '\n') == NULL &&
               strchr(token, '=') == NULL);
        ASSERT(fleet_invite_parse(token, &parsed, wire, sizeof(wire),
                                  &wire_len, &why));
        ASSERT_STR_EQ(parsed.name, "studio");
        ASSERT_STR_EQ(parsed.relay, "relay.example:2222");
        ASSERT_EQ(parsed.expires_unix, (int64_t)(FE_NOW + FE_TTL * 3600));
        ASSERT(memcmp(parsed.operator_pubkey, pubkey, 32) == 0);
        ASSERT(memcmp(parsed.nonce, minted.nonce, sizeof(parsed.nonce)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_invite_tampered(void)
{
    int failures = 0;
    TEST("fleet enrol: one changed byte anywhere in an invite is refused, "
         "including the operator key an attacker would swap in") {
        uint8_t seed[32], pubkey[32], other_seed[32], other_pub[32];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite, parsed;
        const char *why = NULL;
        size_t body = 0;
        fe_key(0x21, seed, pubkey);
        fe_key(0x22, other_seed, other_pub);
        ASSERT(fleet_invite_mint("studio", FE_TTL, "", seed, pubkey, FE_NOW,
                                 token, sizeof(token), &invite, &why));
        /* Every byte of the signed body, one at a time. */
        ASSERT(fe_wire_len(token) > 0u);
        for (body = 0; body < fe_wire_len(token); ++body) {
            ASSERT(fe_tamper(token, body, forged, sizeof(forged)));
            why = NULL;
            ASSERT(!fleet_invite_parse(forged, &parsed, NULL, 0, NULL, &why));
            ASSERT(why != NULL);
        }
        /* A token re-signed by another key verifies internally but names a
         * stranger: `fleet admit` refuses it as invite_not_ours. */
        why = NULL;
        ASSERT(fleet_invite_mint("studio", FE_TTL, "", other_seed, other_pub,
                                 FE_NOW, forged, sizeof(forged), &invite,
                                 &why));
        ASSERT(fleet_invite_parse(forged, &parsed, NULL, 0, NULL, &why));
        ASSERT(memcmp(parsed.operator_pubkey, pubkey, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_invite_bounds(void)
{
    int failures = 0;
    TEST("fleet enrol: the human name is required, unique in spelling, and "
         "the invite lifetime is bounded at both ends") {
        uint8_t seed[32], pubkey[32];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        const char *why = NULL;
        fe_key(0x31, seed, pubkey);
        /* Names an owner can say out loud. */
        ASSERT(fleet_enrol_name_valid("studio"));
        ASSERT(fleet_enrol_name_valid("node-4"));
        ASSERT(fleet_enrol_name_valid("a1"));
        /* One spelling per machine: no capitals, dots, underscores or edge
         * dashes; not too short or too long. */
        ASSERT(!fleet_enrol_name_valid("Studio"));
        ASSERT(!fleet_enrol_name_valid("studio.two"));
        ASSERT(!fleet_enrol_name_valid("studio_two"));
        ASSERT(!fleet_enrol_name_valid("-studio"));
        ASSERT(!fleet_enrol_name_valid("studio-"));
        ASSERT(!fleet_enrol_name_valid("a"));
        ASSERT(!fleet_enrol_name_valid(""));
        ASSERT(!fleet_enrol_name_valid(NULL));
        ASSERT(!fleet_enrol_name_valid("this-name-is-far-too-long-to-say"));
        /* A refused name never becomes a token. */
        ASSERT(!fleet_invite_mint("Studio", FE_TTL, "", seed, pubkey, FE_NOW,
                                  token, sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_NAME_INVALID);
        ASSERT(!fleet_invite_mint("studio", 0, "", seed, pubkey, FE_NOW, token,
                                  sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_TTL_INVALID);
        ASSERT(!fleet_invite_mint("studio", 169, "", seed, pubkey, FE_NOW,
                                  token, sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_TTL_INVALID);
        /* A relay endpoint cannot smuggle a newline into a roster line or an
         * authorized_keys entry. */
        ASSERT(!fleet_invite_mint("studio", FE_TTL, "host\nmore", seed, pubkey,
                                  FE_NOW, token, sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_RELAY_INVALID);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the receipt ────────────────────────────────────────────────────────── */

static int test_fe_receipt(void)
{
    int failures = 0;
    TEST("fleet enrol: a receipt carries the box's own signature over its "
         "own facts, and an edited fact is refused") {
        uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
        uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        struct fleet_receipt parsed;
        struct fleet_box_facts facts = fe_facts();
        size_t invite_len = 0;
        const char *why = NULL;
        fe_key(0x41, op_seed, op_pub);
        fe_key(0x42, box_seed, box_pub);
        ASSERT(fleet_invite_mint("studio", FE_TTL, "", op_seed, op_pub, FE_NOW,
                                 token, sizeof(token), &invite, &why));
        ASSERT(fleet_invite_parse(token, &invite, invite_wire,
                                  sizeof(invite_wire), &invite_len, &why));
        ASSERT(fleet_receipt_mint(invite_wire, invite_len, FE_ONION, &facts,
                                  "ssh-ed25519 AAAAkey owner@box", box_seed,
                                  box_pub, NULL, receipt,
                                  sizeof(receipt), &why));
        ASSERT(fleet_receipt_parse(receipt, &parsed, NULL, 0, NULL, &why));
        /* The invite travels intact so the manager re-checks its own
         * signature. */
        ASSERT_STR_EQ(parsed.invite.name, "studio");
        ASSERT(memcmp(parsed.invite.operator_pubkey, op_pub, 32) == 0);
        ASSERT(memcmp(parsed.box_pubkey, box_pub, 32) == 0);
        ASSERT_STR_EQ(parsed.facts.hostname, "build-box-7");
        ASSERT_EQ(parsed.facts.cores, 8u);
        ASSERT_STR_EQ(parsed.ssh_pubkey, "ssh-ed25519 AAAAkey owner@box");
        /* The locator rides under the same box signature; outside the signed
         * body a carrier could point the fleet at an unclaimed address. */
        ASSERT_STR_EQ(parsed.onion, FE_ONION);
        /* Every signed byte, one at a time (a fact, the embedded invite, the
         * ssh key the bridge would authorize, the box key, the signature). */
        ASSERT(fe_wire_len(receipt) > 0u);
        for (size_t at = 0; at < fe_wire_len(receipt); ++at) {
            ASSERT(fe_tamper(receipt, at, forged, sizeof(forged)));
            why = NULL;
            ASSERT(!fleet_receipt_parse(forged, &parsed, NULL, 0, NULL, &why));
            ASSERT(why != NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── the roster ─────────────────────────────────────────────────────────── */

static int test_fe_roster_seal(void)
{
    int failures = 0;
    TEST("fleet enrol: a roster line is only this fleet's row when this "
         "operator key sealed it") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t op_pub[32], op_seed[32], other_pub[32], other_seed[32];
        struct fleet_machine machine;
        const char *why = NULL;
        fe_key(0x51, op_seed, op_pub);
        fe_key(0x52, other_seed, other_pub);
        ASSERT(fe_row("studio", 0x51, 0x53, 22200, "", row, sizeof(row)));
        ASSERT(fleet_machine_parse(row, op_pub, &machine, &why));
        ASSERT_STR_EQ(machine.receipt.invite.name, "studio");
        ASSERT_EQ(machine.relay_port, (uint16_t)22200);
        ASSERT_EQ(machine.enrolled_at, (int64_t)FE_NOW);
        /* A line sealed by somebody else is not readable as this fleet's
         * row, so hand-editing cannot invent one. */
        why = NULL;
        ASSERT(!fleet_machine_parse(row, other_pub, &machine, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_roster_admission(void)
{
    int failures = 0;
    TEST("fleet enrol: a name belongs to one box, a box keeps its port, and "
         "a line this key did not seal is counted but never listed") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t op_pub[32], op_seed[32], box_a[32], box_b[32], seed[32];
        struct fleet_roster_scan scan = {0};
        const char *why = NULL;
        fe_isolate("admission");
        fe_key(0x61, op_seed, op_pub);
        fe_key(0x62, seed, box_a);
        fe_key(0x63, seed, box_b);
        /* Empty roster: nothing taken, the first port free. */
        ASSERT(fleet_roster_scan(op_pub, "studio", box_a, &scan, &why));
        ASSERT_EQ(scan.rows, 0u);
        ASSERT_EQ(scan.next_port, (uint16_t)FLEET_ENROL_PORT_FIRST);
        ASSERT(!scan.name_taken && !scan.same_box);
        ASSERT(fe_row("studio", 0x61, 0x62, FLEET_ENROL_PORT_FIRST, "", row,
                      sizeof(row)));
        ASSERT(fleet_roster_append(row, &why));
        /* A DIFFERENT box asking for a name that is taken is refused. */
        ASSERT(fleet_roster_scan(op_pub, "studio", box_b, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);
        ASSERT(scan.name_taken);
        ASSERT(!scan.same_box);
        ASSERT_EQ(scan.next_port, (uint16_t)(FLEET_ENROL_PORT_FIRST + 1));
        /* The same box re-enrolling keeps its port, so re-running admit after
         * a lost reply grants nothing new. */
        ASSERT(fleet_roster_scan(op_pub, "studio", box_a, &scan, &why));
        ASSERT(scan.same_box);
        ASSERT(!scan.name_taken);
        ASSERT_EQ(scan.existing_port, (uint16_t)FLEET_ENROL_PORT_FIRST);
        /* A row appended under a different key raises the unverifiable count,
         * not the row count. */
        ASSERT(fe_row("intruder", 0x64, 0x65, FLEET_ENROL_PORT_FIRST + 1, "",
                      row, sizeof(row)));
        ASSERT(fleet_roster_append(row, &why));
        ASSERT(fleet_roster_scan(op_pub, "intruder", box_b, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);
        ASSERT_EQ(scan.unverifiable, 1u);
        ASSERT(!scan.name_taken);
        PASS();
    } _test_next:;
    return failures;
}

/* ── importing a roster line on a box that is not the manager ──────────── */

static int test_fe_roster_import(void)
{
    int failures = 0;
    TEST("fleet enrol: a roster line is imported only after the operator key "
         "this box trusts verifies it; a forged line and a wrong operator key "
         "leave the roster untouched") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        char foreign[FLEET_ENROL_MACHINE_TEXT_MAX];
        char twin[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t op_seed[32], op_pub[32], other_seed[32], other_pub[32];
        struct fleet_machine machine;
        struct fleet_roster_scan scan = {0};
        const char *why = NULL;
        bool appended = true;
        fe_isolate("import");
        fe_key(0x81, op_seed, op_pub);    /* the operator this box trusts */
        fe_key(0x91, other_seed, other_pub); /* somebody else's operator */
        ASSERT(fe_row("studio", 0x81, 0x82, FLEET_ENROL_PORT_FIRST, "", row,
                      sizeof(row)));

        /* A forged line: the genuine line with one byte changed; valid
         * base64url, no longer its seal. */
        ASSERT(fe_tamper(row, fe_wire_len(row) / 2, forged, sizeof(forged)));
        ASSERT(!fleet_roster_import(forged, op_pub, &machine, &appended,
                                    &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        ASSERT(!appended);

        /* A wrong operator key both ways: a genuine line against an untrusted
         * key, and another operator's line against the key it does match. */
        ASSERT(!fleet_roster_import(row, other_pub, &machine, &appended,
                                    &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        ASSERT(fe_row("studio", 0x91, 0x82, FLEET_ENROL_PORT_FIRST, "",
                      foreign, sizeof(foreign)));
        ASSERT(!fleet_roster_import(foreign, op_pub, &machine, &appended,
                                    &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);

        /* None of the three reached the file, even as an unverifiable row. */
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 0u);
        ASSERT_EQ(scan.unverifiable, 0u);

        /* The genuine line, against the trusted key, is imported once. */
        ASSERT(fleet_roster_import(row, op_pub, &machine, &appended, &why));
        ASSERT(appended);
        ASSERT_STR_EQ(machine.receipt.invite.name, "studio");
        ASSERT_EQ(machine.relay_port, (uint16_t)FLEET_ENROL_PORT_FIRST);
        ASSERT(fleet_roster_import(row, op_pub, &machine, &appended, &why));
        ASSERT(!appended);
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);

        /* A different box under a name the roster already gives away is
         * refused by name, even though the operator sealed it. */
        ASSERT(fe_row("studio", 0x81, 0x83, FLEET_ENROL_PORT_FIRST + 1, "",
                      twin, sizeof(twin)));
        ASSERT(!fleet_roster_import(twin, op_pub, &machine, &appended, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_NAME_TAKEN);
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_replay(void)
{
    int failures = 0;
    TEST("fleet enrol: an invite nonce is spendable exactly once") {
        uint8_t nonce[FLEET_ENROL_NONCE_BYTES];
        uint8_t other[FLEET_ENROL_NONCE_BYTES];
        bool seen = true;
        const char *why = NULL;
        fe_isolate("replay");
        memset(nonce, 0xa5, sizeof(nonce));
        memset(other, 0x5a, sizeof(other));
        ASSERT(fleet_nonce_seen(nonce, &seen, &why));
        ASSERT(!seen);
        ASSERT(fleet_nonce_spend(nonce, &why));
        ASSERT(fleet_nonce_seen(nonce, &seen, &why));
        ASSERT(seen);
        /* Spending one invite does not burn another. */
        ASSERT(fleet_nonce_seen(other, &seen, &why));
        ASSERT(!seen);
        PASS();
    } _test_next:;
    return failures;
}

/* fleet_invite_mint() must assign out->nonce. Every case pre-fills the
 * caller's struct with a FIXED pattern, so a mint that leaves the nonce
 * unwritten yields identical nonces and fails deterministically (otherwise
 * every invite carried the all-zero nonce, the spent-invite ledger burned it on
 * the first admission, and a manager could admit exactly one computer). */
static int test_fe_invite_nonce_fresh(void)
{
    int failures = 0;
    TEST("fleet enrol: every invite carries its own random nonce, drawn by "
         "the mint and never inherited from the caller's memory") {
        enum { FE_MINTS = 8 };
        uint8_t op_seed[32], op_pub[32];
        uint8_t zero[FLEET_ENROL_NONCE_BYTES];
        uint8_t stale[FLEET_ENROL_NONCE_BYTES];
        static char token[FE_MINTS][FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite[FE_MINTS];
        struct fleet_invite parsed;
        const char *why = NULL;
        size_t i = 0, j = 0;
        fe_key(0xb1, op_seed, op_pub);
        memset(zero, 0, sizeof(zero));
        memset(stale, 0xee, sizeof(stale));
        for (i = 0; i < FE_MINTS; i++) {
            /* Half the mints get a zeroed struct, half a poisoned one, so
             * neither "leave it" nor "zero it" passes. */
            memset(&invite[i], (i % 2u) ? 0xee : 0x00, sizeof(invite[i]));
            ASSERT(fleet_invite_mint("studio", FE_TTL, "", op_seed, op_pub,
                                     FE_NOW, token[i], sizeof(token[i]),
                                     &invite[i], &why));
            /* The mint OVERWROTE whatever the caller handed it. */
            ASSERT(memcmp(invite[i].nonce, zero, sizeof(zero)) != 0);
            ASSERT(memcmp(invite[i].nonce, stale, sizeof(stale)) != 0);
        }
        /* Pairwise distinct: a repeat means a constant, a reset counter or no
         * draw at all. */
        for (i = 0; i < FE_MINTS; i++)
            for (j = i + 1; j < FE_MINTS; j++)
                ASSERT(memcmp(invite[i].nonce, invite[j].nonce,
                              FLEET_ENROL_NONCE_BYTES) != 0);
        /* The nonce is in the signed body, so two invites for one name and
         * key are different lines. */
        ASSERT(strcmp(token[0], token[1]) != 0);
        /* It survives the wire: the recorded nonce is what the box presents
         * back. */
        ASSERT(fleet_invite_parse(token[1], &parsed, NULL, 0, NULL, &why));
        ASSERT(memcmp(parsed.nonce, invite[1].nonce,
                      FLEET_ENROL_NONCE_BYTES) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Admit one machine, then a second: the whole ceremony twice against one
 * manager key, asking the spent-invite ledger what `fleet admit` asks it in
 * the same order, so a repeating nonce refuses the second box. */
static int test_fe_admit_two_machines(void)
{
    int failures = 0;
    TEST("fleet enrol: one manager admits a second machine — two invites, "
         "two unspent nonces, two rows on the roster") {
        static const char *const names[2] = { "studio", "annex" };
        static const uint8_t box_bytes[2] = { 0xc2, 0xc3 };
        uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
        uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
        uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
        uint8_t nonce[2][FLEET_ENROL_NONCE_BYTES];
        static char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        static char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
        static char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        struct fleet_receipt parsed;
        struct fleet_box_facts facts = fe_facts();
        struct fleet_roster_scan scan = {0};
        size_t invite_len = 0, receipt_len = 0, i = 0;
        bool seen = true;
        const char *why = NULL;
        fe_isolate("admit-two");
        fe_key(0xc1, op_seed, op_pub);
        for (i = 0; i < 2u; i++) {
            fe_key(box_bytes[i], box_seed, box_pub);
            /* The manager mints into a zeroed struct (the live condition
             * behind the all-zero nonce), so a mint that draws no nonce fails
             * the second lap. */
            memset(&invite, 0, sizeof(invite));
            ASSERT(fleet_invite_mint(names[i], FE_TTL, "", op_seed, op_pub,
                                     FE_NOW, token, sizeof(token), &invite,
                                     &why));
            /* The box joins. */
            ASSERT(fleet_invite_parse(token, &invite, invite_wire,
                                      sizeof(invite_wire), &invite_len, &why));
            memcpy(nonce[i], invite.nonce, FLEET_ENROL_NONCE_BYTES);
            ASSERT(fleet_receipt_mint(invite_wire, invite_len, FE_ONION,
                                      &facts, "", box_seed, box_pub, NULL,
                                      receipt, sizeof(receipt), &why));
            ASSERT(fleet_receipt_parse(receipt, &parsed, receipt_wire,
                                       sizeof(receipt_wire), &receipt_len,
                                       &why));
            /* The manager admits: the replay question first, as fe_admit
             * asks it, then the seal and the row. */
            ASSERT(fleet_nonce_seen(parsed.invite.nonce, &seen, &why));
            ASSERT(!seen);
            ASSERT(fleet_machine_mint(receipt_wire, receipt_len, FE_NOW,
                                      (uint16_t)(FLEET_ENROL_PORT_FIRST + i),
                                      op_seed, op_pub, row, sizeof(row),
                                      &why));
            ASSERT(fleet_roster_append(row, &why));
            ASSERT(fleet_nonce_spend(parsed.invite.nonce, &why));
        }
        /* Two machines, two nonces, and neither invite reusable. */
        ASSERT(memcmp(nonce[0], nonce[1], FLEET_ENROL_NONCE_BYTES) != 0);
        ASSERT(fleet_nonce_seen(nonce[0], &seen, &why));
        ASSERT(seen);
        ASSERT(fleet_nonce_seen(nonce[1], &seen, &why));
        ASSERT(seen);
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 2u);
        ASSERT_EQ(scan.unverifiable, 0u);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the ssh bridge ─────────────────────────────────────────────────────── */

static int test_fe_bridge(void)
{
    int failures = 0;
    TEST("fleet enrol: the bridge line is one restricted loopback forward, "
         "byte for byte, and adding it twice adds one line") {
        char line[FLEET_ENROL_SSH_MAX + 256];
        char path[PATH_MAX];
        char body[4096];
        char dir[PATH_MAX];
        const char *key = "ssh-ed25519 AAAAC3NzaC1 owner@box";
        const char *why = NULL;
        FILE *f = NULL;
        size_t read = 0;
        bool added = false;
        fe_isolate("bridge");
        ASSERT(fleet_bridge_line(key, 22207, "studio", line, sizeof(line)));
        /* Written out in full: a test that asks the subject to build the
         * string cannot notice it changing, and every token is a denial. */
        ASSERT_STR_EQ(line,
                      "restrict,port-forwarding,permitlisten=\"127.0.0.1:22207\" "
                      "ssh-ed25519 AAAAC3NzaC1 owner@box z23-fleet-studio");
        /* No key, a name outside the grammar, or a port outside the closed
         * range never becomes a line at all. */
        ASSERT(!fleet_bridge_line("", 22207, "studio", line, sizeof(line)));
        ASSERT(!fleet_bridge_line(key, 22207, "Studio", line, sizeof(line)));
        ASSERT(!fleet_bridge_line(key, 22, "studio", line, sizeof(line)));
        ASSERT(fleet_bridge_line(key, 22207, "studio", line, sizeof(line)));
        (void)snprintf(dir, sizeof(dir), "%s/.ssh", g_fe_home);
        (void)mkdir(g_fe_home, 0700);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(fleet_bridge_authorize(line, "studio", &added, &why));
        ASSERT(added);
        /* Idempotent per box name: a second admit is a no-op. */
        added = true;
        ASSERT(fleet_bridge_authorize(line, "studio", &added, &why));
        ASSERT(!added);
        (void)snprintf(path, sizeof(path), "%s/authorized_keys", dir);
        f = fopen(path, "r");
        ASSERT(f != NULL);
        read = fread(body, 1, sizeof(body) - 1u, f);
        (void)fclose(f);
        body[read] = '\0';
        /* Exactly one grant and one line per box: a duplicate append would be
         * a second standing authorization. */
        ASSERT(fe_occurrences(body, "z23-fleet-studio") == 1u);
        ASSERT(fe_occurrences(body, "permitlisten") == 1u);
        ASSERT(fe_occurrences(body, "\n") == 1u);
        ASSERT_STR_EQ(body + strlen(body) - 1u, "\n");
        PASS();
    } _test_next:;
    return failures;
}

static bool fe_bridge_fixture(const char *path, const char *bytes, size_t n,
                              bool write)
{
    char body[256];
    if (n > sizeof(body)) return false;
    FILE *f = fopen(path, write ? "wb" : "rb");
    if (!f) return false;
    size_t got = write ? fwrite(bytes, 1, n, f) : fread(body, 1, sizeof(body), f);
    bool ok = !ferror(f); int closed = fclose(f);
    return ok && closed == 0 && got == n && (write || memcmp(body, bytes, n) == 0);
}

static int test_fe_bridge_nul(void)
{
    int failures = 0;
    TEST("fleet enrol: a NUL before or after a bridge grant refuses unchanged") {
        const char record[] = "\0\nrestrict,port-forwarding,permitlisten=\"127.0.0.1:22207\" "
                              "ssh-ed25519 AAAAC3NzaC1 owner@box z23-fleet-studio\n";
        const struct { const char *bytes; size_t size; bool accepted; } cases[] = {
            /* No existing grant: the NUL must also prevent a fresh append. */
            {"\0", 1u, false},
            /* Include the terminating NUL as a measured byte after the tag. */
            {record + 2, sizeof(record) - 2u, false},
            {record, sizeof(record) - 1u, false},
            {record + 2, sizeof(record) - 3u, true},
            /* A complete duplicate grant at EOF needs no final newline. */
            {record + 2, sizeof(record) - 4u, true},
        };
        char path[PATH_MAX], dir[PATH_MAX];
        const char *why = NULL; bool added;
        fe_isolate("bridge-nul");
        (void)snprintf(dir, sizeof(dir), "%s/.ssh", g_fe_home);
        (void)mkdir(g_fe_home, 0700); ASSERT(mkdir(dir, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/authorized_keys", dir);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            ASSERT(fe_bridge_fixture(path, cases[i].bytes, cases[i].size, true));
            added = true;
            bool ok = fleet_bridge_authorize(record + 2, "studio", &added, &why);
            ASSERT_EQ(ok, cases[i].accepted);
            ASSERT(!added);
            ASSERT_STR_EQ(why ? why : "",
                          cases[i].accepted ? "" : FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
            ASSERT(fe_bridge_fixture(path, cases[i].bytes, cases[i].size, false));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_ssh_record(void)
{
    int failures = 0;
    TEST("fleet enrol: the dedicated key consumes one complete measured record") {
        const char key[] = "ssh-ed25519 AAAAC3NzaC1 owner@box";
        const char hidden[] = "ssh-ed25519 AAAAC3NzaC1 owner@box\0junk\n";
        char large[FLEET_ENROL_SSH_MAX + 4];
        char path[PATH_MAX], dir[PATH_MAX], out[FLEET_ENROL_SSH_MAX + 1];
        memset(large, 'x', sizeof(large));
        const struct { const char *body; size_t len; bool accepted; } cases[] = {
            {hidden, sizeof(hidden) - 1u, false},
            {large, FLEET_ENROL_SSH_MAX + 1u, false},
            {large, sizeof(large), false},
            {"ssh-ed25519 key\nextra", 21u, false},
            {"ssh-ed25519 key\rjunk\n", 21u, false},
            {key, sizeof(key) - 1u, true},
            {"ssh-ed25519 key\n", 16u, true},
            {"ssh-ed25519 key\r\n", 17u, true},
            {large, FLEET_ENROL_SSH_MAX, true},
        };
        fe_isolate("ssh-record");
        (void)snprintf(dir, sizeof(dir), "%s/.ssh", g_fe_home);
        (void)mkdir(g_fe_home, 0700);
        ASSERT(mkdir(dir, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/z23_fleet.pub", dir);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            FILE *f = fopen(path, "wb");
            ASSERT(f != NULL);
            size_t written = fwrite(cases[i].body, 1, cases[i].len, f);
            int closed = fclose(f);
            ASSERT_EQ(written, cases[i].len);
            ASSERT_EQ(closed, 0);
            memset(out, '!', sizeof(out));
            fleet_enrol_ssh_pubkey(out, sizeof(out));
            ASSERT_EQ(out[0] != '\0', cases[i].accepted);
            if (cases[i].accepted) {
                size_t len = cases[i].len;
                if (cases[i].body[len - 1u] == '\n') --len;
                if (cases[i].body[len - 1u] == '\r') --len;
                ASSERT_EQ(strlen(out), len);
                ASSERT(memcmp(out, cases[i].body, len) == 0);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── the onion locator ──────────────────────────────────────────────────── */

static int test_fe_onion_grammar(void)
{
    int failures = 0;
    TEST("fleet enrol: the onion column accepts a v3 locator and empty, and "
         "refuses everything a reader could mistake for one") {
        char shorter[80], capital[80], ported[80], bad_port[80];
        size_t n = strlen(FE_ONION);
        /* Empty (no persistent onion yet) is a missing column, not a bad
         * one. */
        ASSERT(fleet_enrol_onion_valid(""));
        ASSERT(fleet_enrol_onion_valid(FE_ONION));
        /* An explicit port is allowed; the address is a locator. */
        ASSERT(snprintf(ported, sizeof(ported), "%s:9050", FE_ONION) > 0);
        ASSERT(fleet_enrol_onion_valid(ported));
        /* A v2 address is 16 characters; a truncated v3 body must refuse. */
        ASSERT(n < sizeof(shorter));
        memcpy(shorter, FE_ONION, n + 1u);
        memmove(shorter + 16, shorter + n - 6, 7);
        ASSERT(!fleet_enrol_onion_valid(shorter));
        /* One spelling per address: an uppercase body would be a second row. */
        memcpy(capital, FE_ONION, n + 1u);
        capital[0] = 'A';
        ASSERT(!fleet_enrol_onion_valid(capital));
        /* '1', '0' and '8' are not RFC 4648 base32; a swapped hand-typed
         * address is refused. */
        memcpy(capital, FE_ONION, n + 1u);
        capital[3] = '1';
        ASSERT(!fleet_enrol_onion_valid(capital));
        /* The suffix is checked, not assumed. */
        memcpy(capital, FE_ONION, n + 1u);
        capital[n - 1] = 'x';
        ASSERT(!fleet_enrol_onion_valid(capital));
        /* A port is digits, and only as many as a port has. */
        ASSERT(snprintf(bad_port, sizeof(bad_port), "%s:90x0", FE_ONION) > 0);
        ASSERT(!fleet_enrol_onion_valid(bad_port));
        ASSERT(snprintf(bad_port, sizeof(bad_port), "%s:", FE_ONION) > 0);
        ASSERT(!fleet_enrol_onion_valid(bad_port));
        ASSERT(snprintf(bad_port, sizeof(bad_port), "%s:123456", FE_ONION) > 0);
        ASSERT(!fleet_enrol_onion_valid(bad_port));
        /* A hostname or IP literal is not an onion identity. */
        ASSERT(!fleet_enrol_onion_valid("relay.example.com"));
        ASSERT(!fleet_enrol_onion_valid("192.0.2.1:9050"));
        PASS();
    } _test_next:;
    return failures;
}

/* A receipt with an intact signature but a non-locator onion field is refused
 * on the way in: a signature proves who wrote it, not that it is dialable. */
static int test_fe_onion_refused_at_mint(void)
{
    int failures = 0;
    TEST("fleet enrol: a receipt is refused by name when its onion is not a "
         "v3 locator") {
        uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
        uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        struct fleet_box_facts facts = fe_facts();
        size_t invite_len = 0;
        const char *why = NULL;
        fe_key(0x81, op_seed, op_pub);
        fe_key(0x82, box_seed, box_pub);
        ASSERT(fleet_invite_mint("studio", FE_TTL, "", op_seed, op_pub, FE_NOW,
                                 token, sizeof(token), &invite, &why));
        ASSERT(fleet_invite_parse(token, &invite, invite_wire,
                                  sizeof(invite_wire), &invite_len, &why));
        why = NULL;
        ASSERT(!fleet_receipt_mint(invite_wire, invite_len, "node4.local",
                                   &facts, "", box_seed, box_pub, NULL,
                                   receipt,
                                   sizeof(receipt), &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ONION_INVALID);
        /* And an absent locator is not an error: the box simply has none. */
        why = NULL;
        ASSERT(fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                                  box_seed, box_pub, NULL, receipt,
                                  sizeof(receipt),
                                  &why));
        ASSERT(why == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── fleet.machines pages past the render cap ───────────────────────────── */

static const char *fe_listed_name(const struct zcl_command_reply *reply,
                                  size_t index)
{
    const struct json_value *rows = json_get(&reply->data, "machines");
    const struct json_value *row = rows ? json_at(rows, index) : NULL;
    const struct json_value *verified = row ? json_get(row, "verified") : NULL;
    return json_get_str(json_get(verified, "name"));
}

/* The shipped leaf: the catalog validator, then the registered handler.
 * `reply` is initialized before any return; on false it has been freed, on
 * true the caller owns it. A validator refusal never reaches the handler. */
static bool fe_machines_call(const char *body, struct zcl_command_reply *reply,
                             char *why, size_t why_cap)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "fleet.machines", NULL);
    struct zcl_command_request request = {0};
    struct json_value input;
    zcl_command_reply_init(reply, "zcl.fleet.machines.v1");
    json_init(&input);
    why[0] = '\0';
    if (!spec || !spec->handler ||
        !json_read(&input, body, strlen(body)) ||
        !zcl_command_registry_input_validate(spec, &input, why, why_cap)) {
        json_free(&input);
        zcl_command_reply_free(reply);
        return false;
    }
    request.spec = spec;
    request.input = &input;
    spec->handler(&request, reply);
    json_free(&input);
    return true;
}

static int test_fe_machines_page(void)
{
    int failures = 0;
    TEST("fleet machines: offset and limit page verified rows past the "
         "render cap, and an unverifiable line does not take a slot") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char name[8];
        char past[8];
        char before[8];
        char query[64];
        char why_text[192];
        const char *why = NULL;
        uint8_t op_pub[32], op_seed[32];
        struct zcl_command_reply reply;
        const struct zcl_command_spec *spec = NULL;
        const struct json_value *flag = NULL;
        uint32_t i = 0;
        uint32_t cap = (uint32_t)FLEET_ENROL_ROSTER_MAX;
        fe_isolate("machines-page");
        fe_key(0xa1, op_seed, op_pub);
        ASSERT(fleet_enrol_operator_write(op_pub, &why));
        spec = zcl_command_registry_find(zcl_command_catalog(),
                                        "fleet.machines", NULL);
        ASSERT(spec != NULL);
        ASSERT(strstr(spec->input_keys, "offset") != NULL);
        ASSERT(strstr(spec->input_keys, "limit") != NULL);

        /* Empty input is still the first page. An empty roster says so. */
        ASSERT(fe_machines_call("{}", &reply, why_text, sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")), -1);
        flag = json_get(&reply.data, "truncated");
        ASSERT(flag && flag->type == JSON_BOOL && !json_get_bool(flag));
        zcl_command_reply_free(&reply);

        /* A line sealed by somebody else sits in the file and must not
         * shift the verified page. */
        ASSERT(fe_row("intruder", 0xb2, 0xb3, FLEET_ENROL_PORT_FIRST, "", row,
                      sizeof(row)));
        ASSERT(fleet_roster_append(row, &why));
        for (i = 0; i < cap + 1u; i++) {
            ASSERT(snprintf(name, sizeof(name), "m%02u", i) > 0);
            ASSERT(fe_row(name, 0xa1, (uint8_t)(0x10u + (i % 200u)),
                          (uint16_t)(FLEET_ENROL_PORT_FIRST + (i % cap)),
                          "", row, sizeof(row)));
            ASSERT(fleet_roster_append(row, &why));
        }
        ASSERT(snprintf(before, sizeof(before), "m%02u", cap - 1u) > 0);
        ASSERT(snprintf(past, sizeof(past), "m%02u", cap) > 0);

        /* The default page stops at the render cap and names the next one. */
        ASSERT(fe_machines_call("{}", &reply, why_text, sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total")),
                  (int64_t)cap + 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")),
                  (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "offset")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")),
                  (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "unverifiable")), 1);
        flag = json_get(&reply.data, "truncated");
        ASSERT(flag && flag->type == JSON_BOOL && json_get_bool(flag));
        ASSERT_STR_EQ(fe_listed_name(&reply, 0), "m00");
        ASSERT_STR_EQ(fe_listed_name(&reply, (size_t)cap - 1u), before);
        zcl_command_reply_free(&reply);

        /* The row past the render cap is the first row of the next page. */
        ASSERT(snprintf(query, sizeof(query),
                        "{\"offset\":%u,\"limit\":8}", cap) > 0);
        ASSERT(fe_machines_call(query, &reply, why_text, sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "offset")), (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "limit")), 8);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")), -1);
        flag = json_get(&reply.data, "truncated");
        ASSERT(flag && flag->type == JSON_BOOL && !json_get_bool(flag));
        ASSERT_STR_EQ(fe_listed_name(&reply, 0), past);
        zcl_command_reply_free(&reply);

        /* A page that straddles the cap returns both sides, in order. */
        ASSERT(snprintf(query, sizeof(query),
                        "{\"offset\":%u,\"limit\":2}", cap - 1u) > 0);
        ASSERT(fe_machines_call(query, &reply, why_text, sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 2);
        ASSERT_STR_EQ(fe_listed_name(&reply, 0), before);
        ASSERT_STR_EQ(fe_listed_name(&reply, 1), past);
        zcl_command_reply_free(&reply);

        /* A limit above the render cap is one page, not a bigger reply. */
        ASSERT(fe_machines_call("{\"limit\":1000000}", &reply, why_text,
                                sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "limit")), (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")),
                  (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")),
                  (int64_t)cap);
        zcl_command_reply_free(&reply);

        /* The validator is the gate the shell uses. These never dispatch. */
        ASSERT(!fe_machines_call("{\"offset\":\"1\"}", &reply, why_text,
                                 sizeof(why_text)));
        ASSERT(strstr(why_text, "offset") != NULL);
        ASSERT(!fe_machines_call("{\"offset\":-1}", &reply, why_text,
                                 sizeof(why_text)));
        ASSERT(strstr(why_text, "offset") != NULL);
        ASSERT(!fe_machines_call("{\"limit\":0}", &reply, why_text,
                                 sizeof(why_text)));
        ASSERT(strstr(why_text, "limit") != NULL);
        ASSERT(!fe_machines_call("{\"page\":1}", &reply, why_text,
                                 sizeof(why_text)));
        ASSERT(strstr(why_text, "unknown input key") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── rendering ──────────────────────────────────────────────────────────── */

static int test_fe_render(void)
{
    int failures = 0;
    TEST("fleet enrol: what the operator attested and what the box claimed "
         "are rendered as two objects that never merge") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char text[4096];
        uint8_t op_pub[32], op_seed[32];
        struct fleet_machine machine;
        struct json_value out;
        const struct json_value *verified = NULL, *self = NULL;
        const char *why = NULL;
        fe_key(0x71, op_seed, op_pub);
        ASSERT(fe_row("studio", 0x71, 0x72, 22203, "", row, sizeof(row)));
        ASSERT(fleet_machine_parse(row, op_pub, &machine, &why));
        json_init(&out);
        fleet_machine_render(&machine, &out);
        verified = json_get(&out, "verified");
        self = json_get(&out, "self_reported");
        ASSERT(verified != NULL && self != NULL);
        /* The name leads the verified object as the machine's handle. */
        ASSERT_STR_EQ(json_get_str(json_get(verified, "name")), "studio");
        ASSERT_EQ(json_get_int(json_get(verified, "relay_port")), 22203);
        /* A hardware claim is never in the verified object, and the name is
         * never in the self-reported one. */
        ASSERT(json_get(verified, "hostname") == NULL);
        ASSERT(json_get(verified, "cores") == NULL);
        ASSERT(json_get(self, "name") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(self, "onion")), FE_ONION);
        /* The locator is a column, never the handle. */
        ASSERT(json_get(verified, "onion") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(self, "hostname")), "build-box-7");
        ASSERT_EQ(json_get_int(json_get(self, "cores")), 8);
        /* Nothing private reaches the render: no seed, no key material beyond
         * the public one. */
        ASSERT(json_write(&out, text, sizeof(text)) > 0);
        ASSERT(strstr(text, "seed") == NULL);
        ASSERT(strstr(text, "private") == NULL);
        json_free(&out);
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_enrol(void)
{
    int failures = 0;
    failures += test_fe_invite_round_trip();
    failures += test_fe_invite_tampered();
    failures += test_fe_invite_bounds();
    failures += test_fe_receipt();
    failures += test_fe_roster_seal();
    failures += test_fe_roster_admission();
    failures += test_fe_roster_import();
    failures += test_fe_replay();
    failures += test_fe_invite_nonce_fresh();
    failures += test_fe_admit_two_machines();
    failures += test_fe_bridge();
    failures += test_fe_bridge_nul();
    failures += test_fe_ssh_record();
    failures += test_fe_onion_grammar();
    failures += test_fe_onion_refused_at_mint();
    failures += test_fe_machines_page();
    failures += test_fe_render();
    fe_restore();
    return failures;
}
