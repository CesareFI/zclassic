/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: verify replay links and collect a bounded historical page. */
#include "fleet_ledger_replay.h"
#include <string.h>

void fleet_replay_history_begin(struct history_collect *h, const uint8_t *box)
{
    if (h && memcmp(h->box, box, ZCL_FLEET_ID_BYTES) == 0)
        h->page.found = true;
}

void fleet_replay_history_row(struct history_collect *h,
                        const struct zcl_fleet_row *row, const uint8_t *hash)
{
    if (!h || memcmp(h->box, row->box_id, ZCL_FLEET_ID_BYTES) != 0)
        return;
    h->page.found = true;
    h->page.snapshot_head = row->seq;
    memcpy(h->page.snapshot_hash, hash, ZCL_FLEET_HASH_BYTES);
    if (row->seq <= h->after || h->scanned == ZCL_FLEET_BATCH_MAX ||
        h->page.count == h->limit)
        return;
    h->scanned++;
    h->page.next_seq = row->seq;
    if (row->kind == ZCL_FLEET_KIND_VITALS &&
        (h->subject < 0 || row->subject == (uint16_t)h->subject))
        h->page.rows[h->page.count++] = *row;
}


enum zcl_fleet_status fleet_replay_verify_row(const uint8_t *buf, size_t len,
    uint64_t seq, const uint8_t *box, const uint8_t *expect,
    struct zcl_fleet_row *row)
{
    enum zcl_fleet_status status = zcl_fleet_row_decode(buf, len, row, NULL);
    if (status == ZCL_FLEET_OK && row->seq != seq)
        status = ZCL_FLEET_SEQUENCE;
    if (status == ZCL_FLEET_OK &&
        memcmp(row->box_id, box, ZCL_FLEET_ID_BYTES) != 0)
        status = ZCL_FLEET_NOT_OWNER;
    if (status == ZCL_FLEET_OK &&
        memcmp(row->prev_hash, expect, ZCL_FLEET_HASH_BYTES) != 0)
        status = ZCL_FLEET_CHAIN_BROKEN;
    if (status == ZCL_FLEET_OK)
        status = zcl_fleet_row_verify(row);
    return status;
}

enum zcl_fleet_status zcl_fleet_ledger_vitals_history_readonly(
    const char *dir, const uint8_t *self_box, const uint8_t *self_signer,
    const uint8_t *box, int subject, uint64_t after_seq, size_t limit,
    struct zcl_fleet_vitals_history *page, struct zcl_fleet_report *report)
{
    if (page) memset(page, 0, sizeof *page);
    if (!report) return ZCL_FLEET_ARGUMENT;
    memset(report, 0, sizeof *report);
    if (!page || !box || subject < -1 ||
        subject >= (int)zcl_fleet_vital_count() || !limit ||
        limit > ZCL_FLEET_BATCH_MAX || after_seq == UINT64_MAX) {
        report->status = ZCL_FLEET_ARGUMENT;
        return report->status;
    }
    struct history_collect h = {
        .box = box, .subject = subject, .after = after_seq, .limit = limit
    };
    h.page.next_seq = after_seq;
    struct zcl_fleet_ledger *l = fleet_replay_open_readonly(
        dir, self_box, self_signer, report, &h);
    if (!l) return report->status;
    h.page.more = h.page.snapshot_head > h.page.next_seq;
    *page = h.page;
    zcl_fleet_ledger_close(l);
    return ZCL_FLEET_OK;
}
