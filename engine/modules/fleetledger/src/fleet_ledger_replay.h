/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: private verified-replay collector and row verification seams. */
#ifndef ZCL_FLEET_LEDGER_REPLAY_H
#define ZCL_FLEET_LEDGER_REPLAY_H
#include "fleetledger/fleet_ledger.h"

struct history_collect {
    const uint8_t *box;
    int subject;
    uint64_t after;
    size_t limit;
    size_t scanned;
    struct zcl_fleet_vitals_history page;
};

void fleet_replay_history_begin(struct history_collect *history, const uint8_t *box);
void fleet_replay_history_row(struct history_collect *history,
    const struct zcl_fleet_row *row, const uint8_t *hash);
enum zcl_fleet_status fleet_replay_verify_row(const uint8_t *bytes, size_t len,
    uint64_t seq, const uint8_t *box, const uint8_t *previous,
    struct zcl_fleet_row *row);
/* Same full verified replay as open_readonly; the collector is unpublished
 * scratch owned by the caller until this open has succeeded in its entirety. */
struct zcl_fleet_ledger *fleet_replay_open_readonly(const char *dir,
    const uint8_t *self_box, const uint8_t *self_signer,
    struct zcl_fleet_report *report, struct history_collect *history);
#endif
