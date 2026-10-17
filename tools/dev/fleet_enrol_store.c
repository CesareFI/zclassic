/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The machine roster, the spent-invite nonce list, and the one
 *          restricted ssh line the bridge adds.
 *          See tools/dev/fleet_enrol.h for the contract.
 *
 * The roster is an append-only text file of operator-sealed lines under
 * platform_state_root()/fleet/. Append-only because a roster that can be
 * rewritten in place is a roster whose history nobody can check, and
 * text-of-signed-records because then the file itself carries no authority:
 * every line is re-verified against the operator public key on every read,
 * and a line this key did not seal is counted as unverifiable and never
 * rendered. Editing the file by hand can therefore delete rows, but cannot
 * invent one.
 *
 * The nonce list is the replay refusal. One spent invite nonce per line, in
 * hex. A nonce is spent only AFTER the roster line is durable, so a refusal
 * later in admission can never burn an invite the owner then cannot use.
 */

#include "fleet_enrol.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEET_DOMAIN "fleet-enrol"
#define FLEET_ROSTER_LEAF "machines.roster"
#define FLEET_NONCE_LEAF "invites.spent"
#define FLEET_HEAD_LEAF "roster.head"
#define FLEET_PIN_LEAF "operator.pin"

/* Ceilings on the two files this module reads whole. The roster cannot
 * usefully exceed one line per assignable relay port, and the nonce list is
 * one 33-byte line per invite ever spent; both refuse a pasted blob rather
 * than swallowing it. */
#define FLEET_ROSTER_MAX_BYTES \
    ((size_t)FLEET_ENROL_ROSTER_MAX * (size_t)FLEET_ENROL_MACHINE_TEXT_MAX)
#define FLEET_NONCE_MAX_BYTES (64u * 1024u)
/* An authorized_keys file this box will read whole before appending to it.
 * Larger than any real one and small enough that reading it is bounded. */
#define FLEET_BRIDGE_MAX_BYTES (256u * 1024u)

static void fe_why(const char **why, const char *token)
{
    if (why) *why = token;
}

/* Read one whole state file into `buf`. A missing file is not an error: it
 * is an empty roster, which is what a manager has before the first box
 * joins. `len` is set to the byte count read, always NUL-terminated. */
static bool fe_slurp(const char *leaf, char *buf, size_t cap, size_t *len,
                     const char **why)
{
    struct platform_positioned_file file;
    char path[FLEET_ENROL_PATH_MAX];
    uint64_t size = 0;
    *len = 0;
    buf[0] = '\0';
    if (!fleet_enrol_state_path(leaf, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return true;
    bool ok = platform_positioned_file_size(&file, &size) && size < cap;
    if (ok && size)
        ok = platform_positioned_file_read(&file, buf, (size_t)size, 0) ==
             (int64_t)size;
    platform_positioned_file_close(&file);
    if (!ok) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        LOG_WARN(FLEET_DOMAIN,
                 "cannot read the fleet state file whole: path=%s", path);
        return false;
    }
    *len = (size_t)size;
    buf[*len] = '\0';
    return true;
}

/* Append one NUL-terminated line plus its newline, under an exclusive
 * whole-file lock so two admissions on one box cannot interleave halves of
 * two lines. */
static bool fe_append_line(const char *leaf, const char *line,
                           const char *unwritable_why, const char **why)
{
    struct platform_private_file file;
    char path[FLEET_ENROL_PATH_MAX];
    char buffer[FLEET_ENROL_MACHINE_TEXT_MAX + 2];
    uint64_t size = 0;
    int n = snprintf(buffer, sizeof(buffer), "%s\n", line);
    if (n <= 0 || (size_t)n >= sizeof(buffer)) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    if (!fleet_enrol_state_path(leaf, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked_create_wait(path, &file)) {
        fe_why(why, unwritable_why);
        return false;
    }
    bool ok = platform_private_file_size(&file, &size) &&
              platform_private_file_write_at(&file, buffer, (size_t)n, size) &&
              platform_private_file_authority_flush(&file);
    platform_private_file_close(&file);
    if (!ok) {
        fe_why(why, unwritable_why);
        LOG_WARN(FLEET_DOMAIN, "cannot append one fleet line: path=%s", path);
        return false;
    }
    return true;
}

/* Walk NUL-terminated text line by line, calling `visit` on each non-empty
 * line. The buffer is modified in place (each newline becomes a NUL). */
static void fe_each_line(char *text, void (*visit)(char *, void *), void *user)
{
    char *at = text;
    while (at && *at) {
        char *end = strchr(at, '\n');
        if (end) *end = '\0';
        if (*at) visit(at, user);
        at = end ? end + 1 : NULL;
    }
}

/* ── roster ─────────────────────────────────────────────────────────────── */

struct fe_walk {
    const uint8_t *operator_pubkey;
    const char *name;                /* NULL when not answering "taken?" */
    const uint8_t *box_pubkey;       /* NULL when not answering "same box?" */
    struct fleet_roster_scan *scan;
    bool used[FLEET_ENROL_ROSTER_MAX];
    void (*visit)(const struct fleet_machine *, void *);
    void *user;
    struct fleet_machine machine;    /* one row at a time; never an array */
};

static void fe_walk_line(char *line, void *user)
{
    struct fe_walk *w = user;
    const char *why = NULL;
    uint16_t port = 0;
    if (!fleet_machine_parse(line, w->operator_pubkey, &w->machine, &why)) {
        w->scan->unverifiable++;
        return;
    }
    w->scan->rows++;
    port = w->machine.relay_port;
    if (port >= FLEET_ENROL_PORT_FIRST && port <= FLEET_ENROL_PORT_LAST)
        w->used[port - FLEET_ENROL_PORT_FIRST] = true;
    if (w->box_pubkey &&
        memcmp(w->machine.receipt.box_pubkey, w->box_pubkey,
               FLEET_ENROL_PUBKEY_BYTES) == 0) {
        /* A box re-enrolling keeps its identity and its port. That is what
         * makes re-running `fleet admit` after a lost reply idempotent
         * rather than a second grant under a second port. */
        w->scan->same_box = true;
        w->scan->existing_port = port;
    } else if (w->name && strcmp(w->machine.receipt.invite.name, w->name) == 0) {
        w->scan->name_taken = true;
    }
    if (w->visit) w->visit(&w->machine, w->user);
}

static bool fe_roster_walk(struct fe_walk *w, const char **why)
{
    char *text = zcl_malloc(FLEET_ROSTER_MAX_BYTES + 1u, "fleet-roster");
    size_t len = 0;
    memset(w->scan, 0, sizeof(*w->scan));
    memset(w->used, 0, sizeof(w->used));
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    if (!fe_slurp(FLEET_ROSTER_LEAF, text, FLEET_ROSTER_MAX_BYTES + 1u, &len,
                  why)) {
        free(text);
        return false;
    }
    fe_each_line(text, fe_walk_line, w);
    free(text);
    for (int i = 0; i < FLEET_ENROL_ROSTER_MAX; ++i) {
        if (!w->used[i]) {
            w->scan->next_port = (uint16_t)(FLEET_ENROL_PORT_FIRST + i);
            break;
        }
    }
    if (w->scan->unverifiable)
        LOG_WARN(FLEET_DOMAIN,
                 "fleet roster carries %u line(s) this operator key did not "
                 "seal; they are counted, never listed",
                 (unsigned)w->scan->unverifiable);
    return true;
}

bool fleet_roster_scan(const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       const char *name,
                       const uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       struct fleet_roster_scan *out, const char **why)
{
    struct fe_walk w = {0};
    w.operator_pubkey = operator_pubkey;
    w.name = name;
    w.box_pubkey = box_pubkey;
    w.scan = out;
    fe_why(why, NULL);
    return fe_roster_walk(&w, why);
}

bool fleet_roster_each(const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       void (*visit)(const struct fleet_machine *, void *),
                       void *user, struct fleet_roster_scan *out,
                       const char **why)
{
    struct fe_walk w = {0};
    w.operator_pubkey = operator_pubkey;
    w.scan = out;
    w.visit = visit;
    w.user = user;
    fe_why(why, NULL);
    return fe_roster_walk(&w, why);
}

struct fe_raw_walk {
    void (*visit)(const char *line, void *user);
    void *user;
};

static void fe_raw_line(char *line, void *user)
{
    struct fe_raw_walk *w = user;
    /* A line longer than one machine line can be is not one; it is never
     * handed on, so a pasted blob cannot reach a verifier. */
    if (strlen(line) < (size_t)FLEET_ENROL_MACHINE_TEXT_MAX)
        w->visit(line, w->user);
}

bool fleet_roster_each_line(void (*visit)(const char *line, void *user),
                            void *user, const char **why)
{
    struct fe_raw_walk w = { visit, user };
    size_t len = 0;
    char *text = NULL;
    fe_why(why, NULL);
    if (!visit) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    text = zcl_malloc(FLEET_ROSTER_MAX_BYTES + 1u, "fleet-roster-lines");
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    if (!fe_slurp(FLEET_ROSTER_LEAF, text, FLEET_ROSTER_MAX_BYTES + 1u, &len,
                  why)) {
        free(text);
        return false;
    }
    fe_each_line(text, fe_raw_line, &w);
    free(text);
    return true;
}

bool fleet_roster_append(const char *line, const char **why)
{
    fe_why(why, NULL);
    return fe_append_line(FLEET_ROSTER_LEAF, line,
                          FLEET_ENROL_WHY_ROSTER_UNWRITABLE, why);
}

/* ── strict state files: the roster head and the operator pin ─────────────
 *
 * fe_slurp treats every failure to open as "no file yet", which is right
 * for a roster that does not exist and WRONG for a revocation list or a
 * pin: an unreadable head must never read as "nothing revoked", and an
 * unreadable pin must never read as "never pinned". These reads tell the
 * two apart: only a path that is truly absent is absent. */

enum fe_read { FE_READ_OK = 0, FE_READ_ABSENT, FE_READ_BAD };

static enum fe_read fe_read_strict(const char *leaf, char *buf, size_t cap,
                                   size_t *len)
{
    struct platform_positioned_file file;
    char path[FLEET_ENROL_PATH_MAX];
    uint64_t size = 0;
    *len = 0;
    buf[0] = '\0';
    if (!fleet_enrol_state_path(leaf, path, sizeof(path)))
        return FE_READ_BAD;
    if (platform_private_path_absent(path))
        return FE_READ_ABSENT;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return FE_READ_BAD;
    bool ok = platform_positioned_file_size(&file, &size) && size > 0 &&
              size < cap &&
              platform_positioned_file_read(&file, buf, (size_t)size, 0) ==
                  (int64_t)size;
    platform_positioned_file_close(&file);
    if (!ok)
        return FE_READ_BAD;
    buf[size] = '\0';
    *len = (size_t)size;
    return FE_READ_OK;
}

/* Replace one leaf atomically: stage beside it, flush, rename over it. A
 * reader sees the old file or the new one, never half of either. */
static bool fe_replace_leaf(const char *leaf, const char *text, size_t len,
                            const char *unwritable_why, const char **why)
{
    struct platform_private_file file;
    char path[FLEET_ENROL_PATH_MAX];
    char stage[FLEET_ENROL_PATH_MAX + 8];
    fe_why(why, unwritable_why);
    if (!fleet_enrol_state_path(leaf, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    if (snprintf(stage, sizeof(stage), "%s.stage", path) >= (int)sizeof(stage))
        LOG_FAIL(FLEET_DOMAIN, "fleet state path too long to stage: leaf=%s",
                 leaf);
    (void)platform_private_file_unlink_missing_ok(stage);
    platform_private_file_init(&file);
    bool ok = platform_private_file_create(stage, &file) &&
              platform_private_file_write_at(&file, text, len, 0) &&
              platform_private_file_truncate(&file, len) &&
              platform_private_file_authority_flush(&file) &&
              platform_private_file_replace(&file, stage, path);
    if (!ok) {
        platform_private_file_close(&file);
        (void)platform_private_file_unlink_missing_ok(stage);
        LOG_FAIL(FLEET_DOMAIN, "cannot replace one fleet state file: leaf=%s",
                 leaf);
    }
    fe_why(why, NULL);
    return true;
}

/* ── the operator pin ─────────────────────────────────────────────────────
 *
 * The first import records which operator key this box took a roster from.
 * A later import under a different key is a changed fleet root and is
 * refused by name unless the owner says so. It is a sibling of the key
 * `fleet join` records, so the join path is untouched. */

struct fe_pin {
    bool present;
    uint8_t key[FLEET_ENROL_PUBKEY_BYTES];
};

static bool fe_pin_read(struct fe_pin *pin, const char **why)
{
    char text[FLEET_ENROL_PUBKEY_HEX + 2];
    size_t len = 0;
    memset(pin, 0, sizeof(*pin));
    enum fe_read r = fe_read_strict(FLEET_PIN_LEAF, text, sizeof(text), &len);
    if (r == FE_READ_ABSENT)
        return true;
    if (r != FE_READ_OK || len != (size_t)(FLEET_ENROL_PUBKEY_HEX - 1) ||
        !zcl_hex_decode_lower(text, pin->key, FLEET_ENROL_PUBKEY_BYTES)) {
        memset(pin, 0, sizeof(*pin));
        fe_why(why, FLEET_ENROL_WHY_PIN_UNREADABLE);
        LOG_FAIL(FLEET_DOMAIN,
                 "the recorded fleet operator pin is not 64 lowercase hex "
                 "digits; refusing rather than pinning over it");
    }
    pin->present = true;
    return true;
}

static bool fe_pin_write(const uint8_t key[FLEET_ENROL_PUBKEY_BYTES],
                         const char **why)
{
    char hex[FLEET_ENROL_PUBKEY_HEX];
    zcl_hex_encode(key, FLEET_ENROL_PUBKEY_BYTES, hex);
    return fe_replace_leaf(FLEET_PIN_LEAF, hex, FLEET_ENROL_PUBKEY_HEX - 1,
                           FLEET_ENROL_WHY_ROSTER_UNWRITABLE, why);
}

/* May an import sealed by `fp` go ahead? `write` says the pin must be
 * (re)written once the import has succeeded. */
static bool fe_pin_gate(const uint8_t fp[FLEET_ENROL_PUBKEY_BYTES],
                        bool confirm, bool *write, const char **why)
{
    struct fe_pin pin;
    *write = false;
    if (!fe_pin_read(&pin, why))
        return false;
    if (!pin.present) {
        *write = true;
        return true;
    }
    if (memcmp(pin.key, fp, FLEET_ENROL_PUBKEY_BYTES) == 0)
        return true;
    if (!confirm) {
        fe_why(why, FLEET_ENROL_WHY_ROOT_CHANGED);
        LOG_WARN(FLEET_DOMAIN,
                 "fleet_root_changed: this import is sealed by an operator "
                 "key other than the one this box pinned; pass "
                 "confirm_operator_change=yes to re-pin");
        return false;
    }
    *write = true;
    return true;
}

/* ── the roster head ────────────────────────────────────────────────────── */

enum fleet_head_state fleet_head_load(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    struct fleet_head *out, const char **why)
{
    char *text = zcl_malloc(FLEET_ENROL_HEAD_TEXT_MAX + 4u, "fleet-head");
    enum fleet_head_state state = FLEET_HEAD_BAD;
    size_t len = 0;
    enum fe_read r;
    fe_why(why, NULL);
    memset(out, 0, sizeof(*out));
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_UNREADABLE);
        return FLEET_HEAD_BAD;
    }
    r = fe_read_strict(FLEET_HEAD_LEAF, text, FLEET_ENROL_HEAD_TEXT_MAX + 4u,
                       &len);
    if (r == FE_READ_ABSENT) {
        free(text);
        return FLEET_HEAD_ABSENT;
    }
    while (r == FE_READ_OK && len > 0 &&
           (text[len - 1] == '\n' || text[len - 1] == '\r'))
        text[--len] = '\0';
    if (r == FE_READ_OK && fleet_head_parse(text, out, NULL) &&
        memcmp(out->operator_pubkey, operator_pubkey,
               FLEET_ENROL_PUBKEY_BYTES) == 0)
        state = FLEET_HEAD_OK;
    free(text);
    if (state != FLEET_HEAD_OK) {
        memset(out, 0, sizeof(*out));
        fe_why(why, FLEET_ENROL_WHY_HEAD_UNREADABLE);
        LOG_WARN(FLEET_DOMAIN,
                 "fleet_head_unreadable: the roster head exists and is "
                 "empty, unreadable, corrupt, or not sealed by this fleet's "
                 "operator key; failing closed");
    }
    return state;
}

static bool fe_head_same(const struct fleet_head *a, const struct fleet_head *b)
{
    return a->seq == b->seq && a->issued_at == b->issued_at &&
           a->n_revoked == b->n_revoked &&
           memcmp(a->operator_pubkey, b->operator_pubkey,
                  FLEET_ENROL_PUBKEY_BYTES) == 0 &&
           memcmp(a->revoked, b->revoked,
                  (size_t)a->n_revoked * FLEET_ENROL_PUBKEY_BYTES) == 0 &&
           memcmp(a->signature, b->signature, FLEET_ENROL_SIG_BYTES) == 0;
}

/* The sequence rule against the head already held. `store` says the new
 * head must be written. A held head that cannot be trusted has no sequence
 * to protect, so it is replaced rather than leaving the box unrepairable. */
static bool fe_head_rule(const struct fleet_head *fresh,
                         const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                         bool *store, const char **why)
{
    struct fleet_head *held = zcl_malloc(sizeof(*held), "fleet-head-held");
    enum fleet_head_state state;
    *store = true;
    if (!held) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_UNREADABLE);
        return false;
    }
    state = fleet_head_load(operator_pubkey, held, NULL);
    if (state == FLEET_HEAD_OK && fresh->seq < held->seq) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_STALE);
        LOG_WARN(FLEET_DOMAIN, "fleet_head_stale: held seq=%llu, offered "
                 "seq=%llu", (unsigned long long)held->seq,
                 (unsigned long long)fresh->seq);
        free(held);
        return false;
    }
    if (state == FLEET_HEAD_OK && fresh->seq == held->seq) {
        bool same = fe_head_same(fresh, held);
        free(held);
        *store = false;
        if (same)
            return true;
        fe_why(why, FLEET_ENROL_WHY_HEAD_CONFLICT);
        LOG_WARN(FLEET_DOMAIN, "fleet_head_conflict: two different heads "
                 "carry the same sequence");
        return false;
    }
    free(held);
    return true;
}

bool fleet_head_import(const char *line,
                       const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       bool confirm_operator_change, struct fleet_head *out,
                       bool *replaced, const char **why)
{
    bool store = false, pin = false;
    fe_why(why, NULL);
    *replaced = false;
    if (!line || !operator_pubkey || !fleet_head_is_line(line) ||
        strlen(line) >= (size_t)FLEET_ENROL_HEAD_TEXT_MAX) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    if (!fleet_head_parse(line, out, NULL)) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        return false;
    }
    /* Sealed by itself is not enough: it must be sealed by the key this box
     * trusts. Another operator's head is a changed fleet root, whatever the
     * pin says; this box is never told to trust it by a head it was given. */
    if (memcmp(out->operator_pubkey, operator_pubkey,
               FLEET_ENROL_PUBKEY_BYTES) != 0) {
        fe_why(why, FLEET_ENROL_WHY_ROOT_CHANGED);
        LOG_WARN(FLEET_DOMAIN, "fleet_root_changed: this head is sealed by "
                 "an operator key other than the one this box trusts");
        return false;
    }
    if (!fe_pin_gate(out->operator_pubkey, confirm_operator_change, &pin, why) ||
        !fe_head_rule(out, operator_pubkey, &store, why))
        return false;
    if (store) {
        if (!fe_replace_leaf(FLEET_HEAD_LEAF, line, strlen(line),
                             FLEET_ENROL_WHY_ROSTER_UNWRITABLE, why))
            return false;
        *replaced = true;
    }
    return !pin || fe_pin_write(out->operator_pubkey, why);
}

/* A machine row must not be imported for a box the live head revokes, and
 * must not be imported past a head this box cannot trust. */
static bool fe_row_head_gate(
    const struct fleet_machine *row,
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES], const char **why)
{
    struct fleet_head *head = zcl_malloc(sizeof(*head), "fleet-head-gate");
    enum fleet_head_state state;
    bool revoked;
    if (!head) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_UNREADABLE);
        return false;
    }
    state = fleet_head_load(operator_pubkey, head, why);
    revoked = state == FLEET_HEAD_OK &&
              fleet_head_revokes(head, row->receipt.box_pubkey);
    free(head);
    if (state == FLEET_HEAD_BAD)
        return false;
    if (revoked) {
        fe_why(why, FLEET_ENROL_WHY_BOX_REVOKED);
        LOG_WARN(FLEET_DOMAIN, "fleet_box_revoked: the roster head revokes "
                 "this box; its row is not imported");
        return false;
    }
    return true;
}

bool fleet_roster_import_pinned(const char *line,
                                const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                                bool confirm_operator_change,
                                struct fleet_machine *out, bool *appended,
                                const char **why)
{
    struct fleet_roster_scan scan = {0};
    bool pin = false;
    fe_why(why, NULL);
    *appended = false;
    if (!line || !operator_pubkey ||
        strlen(line) >= (size_t)FLEET_ENROL_MACHINE_TEXT_MAX) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    /* Verify FIRST, against the key this box already trusts, and only
     * then look at the file: a line nobody this box trusts sealed never
     * reaches the roster, not even as a counted unverifiable row. */
    if (!fleet_machine_parse(line, operator_pubkey, out, NULL)) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        return false;
    }
    if (!fe_pin_gate(operator_pubkey, confirm_operator_change, &pin, why) ||
        !fe_row_head_gate(out, operator_pubkey, why))
        return false;
    if (!fleet_roster_scan(operator_pubkey, out->receipt.invite.name,
                           out->receipt.box_pubkey, &scan, why))
        return false;
    if (scan.name_taken && !scan.same_box) {
        fe_why(why, FLEET_ENROL_WHY_NAME_TAKEN);
        return false;
    }
    if (!scan.same_box) {
        if (!fleet_roster_append(line, why))
            return false;
        *appended = true;
    }
    /* already held: importing twice adds nothing, but it is still an import
     * from this operator, so the pin is recorded all the same. */
    return !pin || fe_pin_write(operator_pubkey, why);
}

bool fleet_roster_import(const char *line,
                         const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                         struct fleet_machine *out, bool *appended,
                         const char **why)
{
    return fleet_roster_import_pinned(line, operator_pubkey, false, out,
                                      appended, why);
}

/* ── spent invite nonces ────────────────────────────────────────────────── */

struct fe_nonce_hunt {
    const char *hex;
    bool seen;
};

static void fe_nonce_line(char *line, void *user)
{
    struct fe_nonce_hunt *hunt = user;
    if (strcmp(line, hunt->hex) == 0) hunt->seen = true;
}

bool fleet_nonce_seen(const uint8_t nonce[FLEET_ENROL_NONCE_BYTES], bool *seen,
                      const char **why)
{
    char *text = zcl_malloc(FLEET_NONCE_MAX_BYTES + 1u, "fleet-invite-nonces");
    char hex[FLEET_ENROL_NONCE_HEX];
    struct fe_nonce_hunt hunt = { hex, false };
    size_t len = 0;
    fe_why(why, NULL);
    *seen = false;
    zcl_hex_encode(nonce, FLEET_ENROL_NONCE_BYTES, hex);
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    if (!fe_slurp(FLEET_NONCE_LEAF, text, FLEET_NONCE_MAX_BYTES + 1u, &len,
                  why)) {
        free(text);
        return false;
    }
    fe_each_line(text, fe_nonce_line, &hunt);
    free(text);
    *seen = hunt.seen;
    return true;
}

bool fleet_nonce_spend(const uint8_t nonce[FLEET_ENROL_NONCE_BYTES],
                       const char **why)
{
    char hex[FLEET_ENROL_NONCE_HEX];
    fe_why(why, NULL);
    zcl_hex_encode(nonce, FLEET_ENROL_NONCE_BYTES, hex);
    return fe_append_line(FLEET_NONCE_LEAF, hex,
                          FLEET_ENROL_WHY_ROSTER_UNWRITABLE, why);
}

/* ── rendering ──────────────────────────────────────────────────────────── */

void fleet_machine_render(const struct fleet_machine *machine,
                          struct json_value *out)
{
    char fingerprint[FLEET_ENROL_PUBKEY_HEX];
    struct json_value verified, self_reported;
    zcl_hex_encode(machine->receipt.box_pubkey, FLEET_ENROL_PUBKEY_BYTES,
                   fingerprint);
    json_init(&verified);
    json_set_object(&verified);
    /* What the operator signature actually attests: the operator decided
     * this name, this key, this port, at this time. */
    (void)json_push_kv_str(&verified, "name", machine->receipt.invite.name);
    (void)json_push_kv_str(&verified, "box_pubkey", fingerprint);
    (void)json_push_kv_int(&verified, "enrolled_at", machine->enrolled_at);
    (void)json_push_kv_int(&verified, "relay_port", machine->relay_port);
    (void)json_push_kv_bool(&verified, "bridge_key_present",
                            machine->receipt.ssh_pubkey[0] != '\0');

    json_init(&self_reported);
    json_set_object(&self_reported);
    /* What the BOX said about itself. Signed by the box, measured by
     * nobody. Kept in its own object so no reader can mistake one for the
     * other by reading a flat row. */
    /* The locator sits beside the name — first in this object, so a reader
     * scanning `fleet machines` finds "who" and "where" together. It stays
     * on the self_reported side because the box asserted it and nobody has
     * dialled it; moving it under `verified` would be a lie about what the
     * operator signature covers. */
    (void)json_push_kv_str(&self_reported, "onion", machine->receipt.onion);
    (void)json_push_kv_str(&self_reported, "hostname",
                           machine->receipt.facts.hostname);
    (void)json_push_kv_str(&self_reported, "os", machine->receipt.facts.os);
    (void)json_push_kv_str(&self_reported, "os_version",
                           machine->receipt.facts.os_version);
    (void)json_push_kv_str(&self_reported, "arch", machine->receipt.facts.arch);
    (void)json_push_kv_int(&self_reported, "cores",
                           (int64_t)machine->receipt.facts.cores);
    (void)json_push_kv_int(&self_reported, "ram_mb",
                           (int64_t)machine->receipt.facts.ram_mb);
    (void)json_push_kv_int(&self_reported, "disk_free_mb",
                           (int64_t)machine->receipt.facts.disk_free_mb);
    (void)json_push_kv_str(&self_reported, "toolchain",
                           machine->receipt.facts.toolchain);
    (void)json_push_kv_str(&self_reported, "git_head",
                           machine->receipt.facts.git_head);

    json_set_object(out);
    (void)json_push_kv(out, "verified", &verified);
    (void)json_push_kv(out, "self_reported", &self_reported);
    json_free(&verified);
    json_free(&self_reported);
}

/* ── the ssh bridge ─────────────────────────────────────────────────────── */

bool fleet_bridge_line(const char *ssh_pubkey, uint16_t port, const char *name,
                       char *out, size_t cap)
{
    int n;
    if (!ssh_pubkey || !ssh_pubkey[0] || !fleet_enrol_name_valid(name) ||
        port < FLEET_ENROL_PORT_FIRST || port > FLEET_ENROL_PORT_LAST)
        return false;
    /* `restrict` denies everything sshd knows how to deny — no shell, no
     * command, no agent forwarding, no X11, no pty, no user rc — and is
     * FORWARD-COMPATIBLE: a future sshd restriction is denied by default
     * rather than silently permitted. The single re-grant is one loopback
     * listen port, so the key cannot forward to anything else, cannot
     * listen on a public address, and cannot run anything. */
    n = snprintf(out, cap,
                 "restrict,port-forwarding,permitlisten=\"127.0.0.1:%u\" %s "
                 "z23-fleet-%s",
                 (unsigned)port, ssh_pubkey, name);
    return n > 0 && (size_t)n < cap;
}

/* Is a line for this box already present? The match is on the comment tag
 * alone, so re-admitting a box whose port or key changed replaces nothing
 * and adds nothing — the operator is told the tag is already there and
 * decides. Silently rewriting an authorized_keys line the owner may have
 * edited is not this command's business. */
static bool fe_bridge_present(const char *body, const char *name)
{
    char tag[FLEET_ENROL_NAME_MAX + 16];
    if (snprintf(tag, sizeof(tag), "z23-fleet-%s", name) <= 0) return false;
    return strstr(body, tag) != NULL;
}

/* Read the measured store before any string search or append. */
static bool fe_bridge_read(struct platform_private_file *file, char **body,
                           uint64_t *size)
{
    *body = NULL;
    *size = 0;
    if (!platform_private_file_size(file, size) ||
        *size >= FLEET_BRIDGE_MAX_BYTES) return false;
    *body = zcl_malloc((size_t)*size + 1u, "fleet-authorized-keys");
    if (!*body) return false;
    if (!platform_private_file_read_at(file, *body, (size_t)*size, 0))
        return false;
    if (memchr(*body, '\0', (size_t)*size)) return false;
    (*body)[(size_t)*size] = '\0';
    return true;
}

bool fleet_bridge_authorize(const char *line, const char *name, bool *added,
                            const char **why)
{
    struct platform_private_file file;
    char *body = NULL;
    char path[FLEET_ENROL_PATH_MAX];
    char buffer[FLEET_ENROL_SSH_MAX + 256];
    const char *home = NULL;
    uint64_t size = 0;
    int n;
    fe_why(why, NULL);
    *added = false;
#if defined(_WIN32)
    home = getenv("USERPROFILE");
#else
    home = getenv("HOME");
#endif
    if (!home || !home[0] || !fleet_enrol_name_valid(name)) {
        fe_why(why, FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        return false;
    }
    n = snprintf(path, sizeof(path), "%s/.ssh/authorized_keys", home);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        fe_why(why, FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        return false;
    }
    n = snprintf(buffer, sizeof(buffer), "%s\n", line);
    if (n <= 0 || (size_t)n >= sizeof(buffer)) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    platform_private_file_init(&file);
    /* ~/.ssh must already exist with the mode sshd insists on. Creating it
     * here would mean guessing an owner's ssh layout from a fleet command;
     * refusing by name is the honest answer. */
    if (!platform_private_file_open_locked_create_wait(path, &file)) {
        fe_why(why, FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        LOG_WARN(FLEET_DOMAIN,
                 "cannot open the operator authorized_keys file; the bridge "
                 "needs ~/.ssh to exist already");
        return false;
    }
    bool ok = fe_bridge_read(&file, &body, &size);
    if (ok) {
        if (fe_bridge_present(body, name)) {
            platform_private_file_close(&file);
            free(body);
            return true; /* already granted; adding a second is a widening */
        }
        ok = platform_private_file_write_at(&file, buffer, (size_t)n, size) &&
             platform_private_file_authority_flush(&file);
    }
    platform_private_file_close(&file);
    free(body);
    if (!ok) {
        fe_why(why, FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        LOG_WARN(FLEET_DOMAIN, "cannot append the restricted bridge line");
        return false;
    }
    *added = true;
    return true;
}
