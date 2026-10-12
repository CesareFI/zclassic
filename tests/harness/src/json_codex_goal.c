/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Local goal write-ahead, exact readback and no-replay witnesses. */
#include "test/test_core.h"
#include "command/native_devagent_codex_goal.h"
#include "json/json.h"
#include <stddef.h>
#include <string.h>

struct cgat_fixture {
    struct cga_record saved;
    struct cga_observation observed;
    struct cga_command sent;
    struct cga_command *caller;
    struct cga_record *record;
    unsigned sends, reads, saves, fail_save, mutate_read;
    enum cga_goal_status post_status;
    bool fail_read, lost_ack, wrong_ack, change_goal, corrupt_binding, erase_fact;
    bool mutate_save, poison_send, poison_save;
    bool forge_effect, erase_record, wrong_thread, wrong_turn;
};
static bool cgat_save(void *ctx, const struct cga_record *record)
{
    struct cgat_fixture *f = ctx;
    ++f->saves;
    if (f->saves == f->fail_save) {
        if (f->poison_save && f->record) memset(f->record, 0, sizeof(*f->record));
        return false;
    }
    f->saved = *record;
    if (f->mutate_save && f->caller) memcpy(f->caller->goal, "evil", 4);
    return true;
}
static void cgat_poison(struct cgat_fixture *f)
{
    if (f->caller) memcpy(f->caller->goal, "evil", 4);
    if (!f->record) return;
    if (f->erase_record) { memset(f->record, 0, sizeof(*f->record)); return; }
    if (f->forge_effect) {
        f->record->accepted = true; f->record->applied = true;
        return;
    }
    if (f->erase_fact) { f->record->uncertain = false; return; }
    if (f->corrupt_binding) memset(f->record->command.thread_id, 'x', CGA_ID_CAP);
    else {
        memcpy(f->record->command.goal, "evil", 4);
        memcpy(f->observed.goal, "evil", 4);
    }
}
static bool cgat_read(void *ctx, struct cga_observation *out)
{
    struct cgat_fixture *f = ctx;
    ++f->reads;
    if (f->reads == f->mutate_read) cgat_poison(f);
    *out = f->observed;
    if (f->reads == 2 && f->post_status) out->status = f->post_status;
    if (f->reads >= 3 && f->change_goal) memcpy(out->goal, "evil", 4);
    return !f->fail_read;
}
static enum cga_send_result cgat_send(void *ctx, const struct cga_command *command,
    struct cga_ack *ack)
{
    struct cgat_fixture *f = ctx;
    ++f->sends; f->sent = *command;
    if (f->poison_send && f->record) memset(f->record, 0, sizeof(*f->record));
    memcpy(ack->command_id, command->id, sizeof(ack->command_id));
    memcpy(ack->thread_id, command->thread_id, sizeof(ack->thread_id));
    memcpy(ack->turn_id, command->turn_id, sizeof(ack->turn_id));
    if (f->wrong_ack) ack->command_id[0] = 'x';
    if (f->wrong_thread) ack->thread_id[0] = 'x';
    if (f->wrong_turn) ack->turn_id[0] = 'x';
    return f->lost_ack ? CGA_SEND_UNCERTAIN : CGA_SEND_APPLIED;
}
static void cgat_init(struct cgat_fixture *f, struct cga_command *command,
    struct cga_io *io)
{
    memset(f, 0, sizeof(*f));
    *command = (struct cga_command){.id = "review-command", .operation = CGA_SET,
        .thread_id = "review-thread", .expected_revision = "revision",
        .workspace = "/fixture", .job_id = "review-job", .executable = "/fixture/inert",
        .model = "fixture-model", .effort = "medium", .effective_model = "fixture-model",
        .effective_effort = "medium", .goal = "goal", .goal_len = 4, .token_budget = 100};
    memset(command->executable_sha256, 'a', 64);
    memset(command->environment_sha256, 'b', 64);
    f->observed = (struct cga_observation){.thread_id = "review-thread",
        .revision = "revision", .effective_model = "fixture-model",
        .effective_effort = "medium", .goal_present = true, .goal = "goal",
        .goal_len = 4, .token_budget = 100, .status = CGA_ACTIVE};
    *io = (struct cga_io){.ctx = f, .caps = {"0.160.0", true, true, true},
        .save = cgat_save, .read = cgat_read, .send = cgat_send};
}
static void cgat_fact(struct cga_record *record, unsigned fact)
{
    switch (fact) {
    case 0: record->uncertain = true; break;
    case 1: record->applied = true; break;
    case 2: record->readback = true; break;
    case 3: record->terminal = true; break;
    case 4: record->quiescent = true; break;
    default: record->admission_refused = true; break;
    }
}
static int cgat_recovered_fact(unsigned fact, bool accepted, bool unavailable)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command command; struct cga_io io;
    struct cga_record record; char why[160];
    cgat_init(&f, &command, &io);
    record = (struct cga_record){.command = command, .accepted = accepted};
    cgat_fact(&record, fact); f.fail_read = unavailable;
    enum cga_result expected = !accepted ? CGA_INVALID : fact == 5 ? CGA_LIMIT :
        unavailable ? CGA_UNCERTAIN : CGA_OK;
    TEST("D1: independent recovered effect facts never permit another send") {
        for (unsigned retry = 0; retry < 2; ++retry) {
            ASSERT_EQ(cga_execute(&io, &command, &record, why, sizeof(why)), expected);
            ASSERT_EQ(f.sends, 0);
            ASSERT_EQ(record.accepted, accepted);
            ASSERT_EQ(record.terminal, fact == 3);
            ASSERT_EQ(record.quiescent, fact == 4);
            ASSERT_EQ(record.admission_refused, fact == 5);
            ASSERT(!memcmp(&record.command, &command, sizeof(command)));
        }
        ASSERT_EQ(f.reads, accepted && fact != 5 ? 2 : 0);
        ASSERT_EQ(f.saves, accepted && fact != 5 && !unavailable ? 2 : 0);
        PASS();
    }
_test_next:;
    if (failures) fprintf(stderr, "D1 fact=%u accepted=%d unavailable=%d\n", fact, accepted, unavailable);
    return failures;
}
static int cgat_recovery(void)
{
    int failures = 0;
    for (unsigned fact = 0; fact < 6; ++fact) {
        failures += cgat_recovered_fact(fact, true, false);
        failures += cgat_recovered_fact(fact, true, true);
        failures += cgat_recovered_fact(fact, false, false);
    }
    return failures;
}
static int cgat_success(void)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io);
    TEST("goal execute: durable intent, applied ACK and readback are separate from quiescence") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_OK);
        ASSERT_EQ(f.saves, 4); ASSERT_EQ(f.reads, 3); ASSERT_EQ(f.sends, 1);
        ASSERT(r.accepted && r.applied && r.readback && !r.uncertain);
        ASSERT(!r.terminal && !r.quiescent);
        ASSERT(!memcmp(&f.sent, &c, sizeof(c)));
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_OK);
        ASSERT_EQ(f.sends, 1);
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_storage(unsigned save)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io); f.fail_save = save;
    TEST("goal write-ahead: failed save prevents effect or retains durable recovery") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_STORAGE);
        ASSERT_EQ(f.sends, save >= 3 ? 1 : 0);
        ASSERT_EQ(f.saves, save);
        ASSERT_EQ(r.accepted, save != 1);
        ASSERT_EQ(r.uncertain, save == 3);
        ASSERT_EQ(r.applied, save == 4);
        ASSERT(!r.readback);
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_ack(unsigned mode)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io);
    f.lost_ack = mode == 0; f.wrong_ack = mode == 1; f.change_goal = mode == 2;
    f.wrong_thread = mode == 3; f.wrong_turn = mode == 4;
    if (mode == 4) {
        c.operation = CGA_INTERRUPT; c.goal_len = 0;
        memcpy(c.turn_id, "turn", 5); memcpy(f.observed.turn_id, "turn", 5);
    }
    TEST("goal ACK: lost reply, wrong correlation and changed readback never authorize replay") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT_EQ(f.sends, 1); ASSERT(!r.readback);
        ASSERT_EQ(r.applied, mode == 2); ASSERT_EQ(r.uncertain, mode != 2);
        f.fail_read = true;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT_EQ(f.sends, 1);
        f.fail_read = false; f.change_goal = false;
        if (mode == 4) f.observed.turn_terminal = true;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_OK);
        ASSERT(r.readback); ASSERT_EQ(f.sends, 1);
        ASSERT_EQ(r.applied, mode == 2); ASSERT_EQ(r.uncertain, mode != 2);
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_post_state(enum cga_goal_status status)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io); f.post_status = status;
    TEST("goal submit: blocked or exhausted after write-ahead stays uncertain without refusal") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT(r.accepted && r.uncertain && !r.admission_refused);
        ASSERT_EQ(f.saves, 2); ASSERT_EQ(f.sends, 0);
        f.fail_read = true;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT_EQ(f.sends, 0);
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_prepare_alias(unsigned mutation, unsigned observation, bool accepted)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}, before; char why[160];
    cgat_init(&f, &c, &io);
    if (accepted) { r.command = c; r.accepted = true; }
    memcpy(&before, &r, sizeof(before));
    f.record = &r; f.mutate_read = 1; f.fail_save = 1;
    f.corrupt_binding = mutation == 1;
    f.forge_effect = mutation == 2; f.erase_record = mutation == 3;
    f.fail_read = observation == 0;
    if (observation == 2) f.observed.goal_len = CGA_GOAL_CAP + 1;
    if (observation == 3) f.observed.revision[0] = 'x';
    if (observation == 4) f.observed.status = CGA_BLOCKED;
    TEST("goal prepare: aliased read preserves fresh and accepted-only records before any refusal or save") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT(!memcmp(&r, &before, sizeof(r)));
        ASSERT_EQ(f.reads, 1); ASSERT_EQ(f.sends, 0); ASSERT_EQ(f.saves, 0);
        f.mutate_read = 0; f.fail_read = true;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT(!memcmp(&r, &before, sizeof(r)));
        ASSERT_EQ(f.sends, 0); ASSERT_EQ(f.saves, 0);
        PASS();
    }
_test_next:;
    if (failures) fprintf(stderr, "prepare alias mutation=%u observation=%u accepted=%d\n",
        mutation, observation, accepted);
    return failures;
}

static int cgat_submit_mutation(unsigned stage)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io); f.caller = &c;
    f.mutate_save = stage == 0; f.mutate_read = stage == 0 ? 0 : stage == 1 ? 2 : 1;
    TEST("goal submit: callback caller mutation cannot change saved intent or reach send") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT_EQ(f.sends, 0); ASSERT(r.accepted && r.uncertain);
        ASSERT(!memcmp(r.command.goal, "goal", 4));
        ASSERT(!memcmp(f.saved.command.goal, "goal", 4));
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_reconcile_mutation(unsigned mode, bool recovered)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r; char why[160];
    cgat_init(&f, &c, &io);
    r = (struct cga_record){.command = c, .accepted = true, .uncertain = true};
    f.saved = r; f.record = &r; f.mutate_read = 1;
    f.corrupt_binding = mode == 1; f.erase_fact = mode == 2;
    TEST("goal reconcile: callback binding or state mutation refuses without saving new evidence") {
        enum cga_result result = recovered ? cga_execute(&io, &c, &r, why, sizeof(why)) :
            cga_reconcile(&io, &r, why, sizeof(why));
        ASSERT_EQ(result, CGA_UNCERTAIN);
        ASSERT_EQ(f.saves, 0); ASSERT_EQ(f.sends, 0);
        ASSERT(!memcmp(f.saved.command.goal, "goal", 4));
        ASSERT(f.saved.uncertain && !f.saved.readback);
        ASSERT(!memcmp(&r.command, &c, sizeof(c)));
        ASSERT(r.uncertain && !r.readback);
        f.mutate_read = 0; f.fail_read = true;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT_EQ(f.sends, 0); ASSERT_EQ(f.saves, 0);
        ASSERT(r.uncertain);
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_admission(enum cga_goal_status status)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io); f.observed.status = status;
    bool blocked = status == CGA_BLOCKED;
    TEST("goal prepare: pre-intent blocked refuses; exhausted admission is sticky") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), blocked ? CGA_UNSUPPORTED : CGA_LIMIT);
        ASSERT_EQ(f.sends, 0); ASSERT_EQ(f.saves, blocked ? 0 : 1);
        ASSERT_EQ(r.admission_refused, !blocked);
        if (!blocked) {
            f.observed.status = CGA_ACTIVE;
            ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_LIMIT);
            ASSERT_EQ(f.sends, 0); ASSERT_EQ(f.saves, 1);
        }
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_guards(void)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io);
    TEST("goal validation: unqualified capabilities, stale target and conflicting binding cannot send") {
        io.caps.exclusive_thread = false;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_AUTHORITY);
        io.caps.exclusive_thread = true; io.caps.runtime_qualified = false;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNSUPPORTED);
        io.caps.runtime_qualified = true; c.goal[0] = 0;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_INVALID);
        c.goal[0] = 'g'; f.observed.revision[0] = 'x';
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_STALE);
        r = (struct cga_record){.command = c, .accepted = true, .uncertain = true};
        r.command.job_id[0] = 'x';
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_CONFLICT);
        ASSERT_EQ(f.sends, 0); ASSERT_EQ(f.saves, 0);
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_terminal(enum cga_operation op)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io); c.operation = op;
    if (op != CGA_SET) c.goal_len = 0;
    if (op == CGA_CLEAR) { f.observed.goal_present = false; f.observed.status = CGA_ABSENT; }
    if (op == CGA_INTERRUPT) {
        memcpy(c.turn_id, "turn", 5); memcpy(f.observed.turn_id, "turn", 5);
        f.observed.turn_terminal = true;
    }
    if (op == CGA_SET) f.observed.status = CGA_COMPLETE;
    TEST("goal readback: SET completion and INTERRUPT terminal preserve independent quiescence") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_OK);
        ASSERT_EQ(r.terminal, op != CGA_CLEAR); ASSERT(!r.quiescent);
        ASSERT(r.readback && r.applied); ASSERT_EQ(f.sends, 1);
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_wire_envelope(enum cga_operation op)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    char out[1024], why[160];
    cgat_init(&f, &c, &io); c.operation = op;
    if (op != CGA_SET) c.goal_len = 0;
    if (op == CGA_INTERRUPT) memcpy(c.turn_id, "turn", 5);
    const char *expected = op == CGA_SET ?
        "{\"jsonrpc\":\"2.0\",\"id\":\"review-command\",\"method\":\"thread/goal/set\",\"params\":{\"threadId\":\"review-thread\",\"objective\":\"goal\",\"status\":\"active\",\"tokenBudget\":100}}\n" :
        op == CGA_CLEAR ?
        "{\"jsonrpc\":\"2.0\",\"id\":\"review-command\",\"method\":\"thread/goal/clear\",\"params\":{\"threadId\":\"review-thread\"}}\n" :
        "{\"jsonrpc\":\"2.0\",\"id\":\"review-command\",\"method\":\"turn/interrupt\",\"params\":{\"threadId\":\"review-thread\",\"turnId\":\"turn\"}}\n";
    TEST("goal wire: every operation uses the exact versioned request envelope") {
        ASSERT_EQ(cga_wire_request(&c, out, sizeof(out), why, sizeof(why)), CGA_OK);
        ASSERT_STR_EQ(out, expected);
        PASS();
    }
_test_next:;
    if (failures) fprintf(stderr, "wire envelope operation=%d\n", op);
    return failures;
}

static int cgat_wire(void)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    char out[4096], why[160]; struct json_value parsed;
    cgat_init(&f, &c, &io);
    memcpy(c.goal, "\"\\\n\001\xc3\xa9", 6); c.goal_len = 6;
    TEST("goal wire: exact UTF-8 and escaped objective, budget and bounded refusal") {
        ASSERT_EQ(cga_wire_request(&c, out, sizeof(out), why, sizeof(why)), CGA_OK);
        ASSERT_STR_EQ(out, "{\"jsonrpc\":\"2.0\",\"id\":\"review-command\",\"method\":\"thread/goal/set\",\"params\":{\"threadId\":\"review-thread\",\"objective\":\"\\\"\\\\\\n\\u0001\xc3\xa9\",\"status\":\"active\",\"tokenBudget\":100}}\n");
        ASSERT(json_read(&parsed, out, strlen(out))); json_free(&parsed);
        ASSERT_EQ(cga_wire_request(&c, out, 4, why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(out[0], 0);
        c.operation = CGA_CLEAR; c.goal_len = 0;
        ASSERT_EQ(cga_wire_request(&c, out, sizeof(out), why, sizeof(why)), CGA_OK);
        ASSERT_STR_EQ(out, "{\"jsonrpc\":\"2.0\",\"id\":\"review-command\",\"method\":\"thread/goal/clear\",\"params\":{\"threadId\":\"review-thread\"}}\n");
        c.operation = CGA_INTERRUPT; memcpy(c.turn_id, "turn", 5);
        ASSERT_EQ(cga_wire_request(&c, out, sizeof(out), why, sizeof(why)), CGA_OK);
        ASSERT_STR_EQ(out, "{\"jsonrpc\":\"2.0\",\"id\":\"review-command\",\"method\":\"turn/interrupt\",\"params\":{\"threadId\":\"review-thread\",\"turnId\":\"turn\"}}\n");
        PASS();
    }
_test_next:;
    return failures;
}
static int cgat_callback_failure(unsigned mode)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    struct cga_record r = {0}; char why[160];
    cgat_init(&f, &c, &io); f.record = &r;
    f.poison_send = mode == 0; f.lost_ack = mode == 0;
    f.poison_save = mode != 0; f.fail_save = mode == 1 ? 3 : mode == 2 ? 4 : 0;
    TEST("goal callbacks: uncertain send or failed save cannot erase the no-replay record") {
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), mode == 0 ? CGA_UNCERTAIN : CGA_STORAGE);
        ASSERT(r.accepted); ASSERT_EQ(r.uncertain, mode != 2);
        ASSERT_EQ(r.applied, mode == 2); ASSERT(!r.readback);
        ASSERT(!memcmp(&r.command, &c, sizeof(c))); ASSERT_EQ(f.sends, 1);
        f.poison_send = false; f.poison_save = false; f.fail_read = true;
        ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_UNCERTAIN);
        ASSERT_EQ(f.sends, 1);
        PASS();
    }
_test_next:;
    return failures;
}

static int cgat_readback_state(enum cga_goal_status status, bool fenced)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    char why[160];
    cgat_init(&f, &c, &io);
    struct cga_record r = {.command = c, .accepted = true, .uncertain = fenced};
    f.observed.status = status;
    if (status == CGA_ABSENT) {
        f.observed.goal_present = false; f.observed.goal_len = 0;
    }
    TEST("goal readback: matching observation never proves applied or clears uncertainty") {
        ASSERT_EQ(cga_reconcile(&io, &r, why, sizeof(why)),
            status == CGA_ABSENT ? CGA_UNCERTAIN : CGA_OK);
        ASSERT(r.accepted && !r.applied && !r.quiescent);
        ASSERT_EQ(r.uncertain, fenced); ASSERT_EQ(f.sends, 0);
        ASSERT_EQ(r.readback, status != CGA_ABSENT);
        ASSERT_EQ(r.terminal, status == CGA_COMPLETE);
        ASSERT_EQ(f.saves, status != CGA_ABSENT);
        if (status != CGA_ABSENT) {
            ASSERT_EQ(r.observation.status, status);
            ASSERT_EQ(cga_execute(&io, &c, &r, why, sizeof(why)), CGA_OK);
            ASSERT_EQ(f.sends, 0); ASSERT(!r.applied);
            ASSERT_EQ(r.uncertain, fenced);
        }
        PASS();
    }
_test_next:;
    if (failures) fprintf(stderr, "readback status=%d fenced=%d\n", status, fenced);
    return failures;
}
static int cgat_wire_invalid(unsigned mode)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    /* Must fit a CAP+1 objective; a 1KiB buffer fails as writer overflow. */
    char out[CGA_GOAL_CAP + 1024] = "previous", why[160] = {0};
    cgat_init(&f, &c, &io);
    switch (mode) {
    case 0: {
        /* Adjacent alignment padding must not supply an independent NUL refusal. */
        size_t span = offsetof(struct cga_command, goal_len) -
            offsetof(struct cga_command, goal);
        memset((unsigned char *)&c + offsetof(struct cga_command, goal),
            'a', span);
        c.goal_len = CGA_GOAL_CAP + 1; break;
    }
    case 1: c.goal_len = 0; break;
    case 2: c.token_budget = 0; break;
    case 3: c.token_budget = -1; break;
    case 4: memset(c.id, 'x', sizeof(c.id)); break;
    case 5: memset(c.thread_id, 'x', sizeof(c.thread_id)); break;
    case 6: c.operation = CGA_INTERRUPT; c.goal_len = 0;
        memset(c.turn_id, 'x', sizeof(c.turn_id)); break;
    case 7: c.id[0] = (char)0xff; break;
    case 8: c.thread_id[0] = (char)0xff; break;
    case 9: c.operation = CGA_INTERRUPT; c.goal_len = 0; c.turn_id[0] = (char)0xff; break;
    case 10: c.goal[0] = 0xff; break;
    default: memset(c.expected_revision, 'x', sizeof(c.expected_revision)); break;
    }
    TEST("goal wire: invalid bounds, native identifiers and SET budgets refuse an envelope") {
        ASSERT_EQ(cga_wire_request(&c, out, sizeof(out), why, sizeof(why)), CGA_INVALID);
        ASSERT_EQ(out[0], 0); ASSERT(why[0] != 0);
        PASS();
    }
_test_next:;
    if (failures) fprintf(stderr, "wire invalid case=%u\n", mode);
    return failures;
}
static int cgat_wire_maximum(void)
{
    int failures = 0;
    struct cgat_fixture f; struct cga_command c; struct cga_io io;
    char out[CGA_GOAL_CAP + 1024], why[160]; struct json_value parsed;
    cgat_init(&f, &c, &io); memset(c.goal, 'a', sizeof(c.goal));
    c.goal_len = sizeof(c.goal);
    TEST("goal wire: maximum bounded objective round trips without truncation") {
        ASSERT_EQ(cga_wire_request(&c, out, sizeof(out), why, sizeof(why)), CGA_OK);
        ASSERT(json_read(&parsed, out, strlen(out)));
        const struct json_value *params = json_get(&parsed, "params");
        const struct json_value *objective = params ? json_get(params, "objective") : NULL;
        const char *text = objective ? json_get_str(objective) : NULL;
        bool exact = text && strlen(text) == c.goal_len &&
            memcmp(text, c.goal, c.goal_len) == 0;
        json_free(&parsed);
        ASSERT(exact); ASSERT_EQ(out[strlen(out) - 1], '\n');
        PASS();
    }
_test_next:;
    return failures;
}

int cga_goal_tests(void);
int cga_goal_tests(void)
{
    int failures = cgat_recovery() + cgat_success() + cgat_guards() + cgat_wire();
    for (unsigned mutation = 0; mutation < 4; ++mutation)
        for (unsigned observation = 0; observation < 5; ++observation) {
            if (mutation != 3)
                failures += cgat_prepare_alias(mutation, observation, false);
            failures += cgat_prepare_alias(mutation, observation, true);
        }
    for (unsigned i = 1; i <= 4; i++) failures += cgat_storage(i);
    for (unsigned i = 0; i < 5; i++) failures += cgat_ack(i);
    for (unsigned i = 0; i < 3; i++) failures += cgat_callback_failure(i);
    for (unsigned i = 0; i < 12; i++) failures += cgat_wire_invalid(i);
    failures += cgat_wire_maximum();
    for (unsigned i = CGA_ABSENT; i <= CGA_COMPLETE; i++) {
        failures += cgat_readback_state((enum cga_goal_status)i, false);
        failures += cgat_readback_state((enum cga_goal_status)i, true);
    }
    for (unsigned i = 0; i < 3; i++) {
        failures += cgat_reconcile_mutation(i, false);
        failures += cgat_reconcile_mutation(i, true);
    }
    failures += cgat_submit_mutation(0) + cgat_submit_mutation(1) + cgat_submit_mutation(2);
    const enum cga_goal_status states[] = {CGA_BLOCKED, CGA_USAGE_LIMITED, CGA_BUDGET_LIMITED};
    for (unsigned i = 0; i < 3; i++) {
        failures += cgat_post_state(states[i]); failures += cgat_admission(states[i]);
        failures += cgat_terminal((enum cga_operation)(i + 1));
        failures += cgat_wire_envelope((enum cga_operation)(i + 1));
    }
    return failures;
}
