/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_stream.h"
#include "zcl_tx_review.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t wire[256];
    size_t length, input_count_at, script_length_at, output_count_at;
    size_t first_script_at, balance_at, shielded_at;
} fixture;

typedef struct {
    unsigned inputs, outputs;
    uint64_t total;
    bool reject;
} observed;

static void put_u32(fixture *item, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        item->wire[item->length++] = (uint8_t)(value >> (8 * i));
}

static void put_u64(fixture *item, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        item->wire[item->length++] = (uint8_t)(value >> (8 * i));
}

static fixture make_fixture(void) {
    fixture item = {0};
    put_u32(&item, 0x80000004);
    put_u32(&item, 0x892f2085);
    item.input_count_at = item.length;
    item.wire[item.length++] = 1;
    memset(item.wire + item.length, 0xaa, 32);
    item.length += 32;
    put_u32(&item, 0);
    item.script_length_at = item.length;
    item.wire[item.length++] = 0;
    put_u32(&item, UINT32_MAX - 1);
    item.output_count_at = item.length;
    item.wire[item.length++] = 2;
    put_u64(&item, 100000000);
    item.wire[item.length++] = 25;
    item.first_script_at = item.length;
    item.wire[item.length++] = 0x76;
    item.wire[item.length++] = 0xa9;
    item.wire[item.length++] = 0x14;
    memset(item.wire + item.length, 0x11, 20);
    item.length += 20;
    item.wire[item.length++] = 0x88;
    item.wire[item.length++] = 0xac;
    put_u64(&item, 200000000);
    item.wire[item.length++] = 23;
    item.wire[item.length++] = 0xa9;
    item.wire[item.length++] = 0x14;
    memset(item.wire + item.length, 0x22, 20);
    item.length += 20;
    item.wire[item.length++] = 0x87;
    put_u32(&item, 100);
    put_u32(&item, 200);
    item.balance_at = item.length;
    put_u64(&item, 0);
    item.shielded_at = item.length;
    item.wire[item.length++] = 0;
    item.wire[item.length++] = 0;
    item.wire[item.length++] = 0;
    return item;
}

static bool input_seen(void *context, uint32_t index,
                       const uint8_t outpoint[36], uint32_t sequence) {
    observed *seen = context;
    if (seen->reject) return false;
    assert(index == seen->inputs++ && sequence == UINT32_MAX - 1);
    for (size_t i = 0; i < 32; ++i) assert(outpoint[i] == 0xaa);
    for (size_t i = 32; i < 36; ++i) assert(outpoint[i] == 0);
    return true;
}

static bool output_seen(void *context, uint32_t index, uint64_t amount,
                        zcl_tx_stream_output_type type,
                        const uint8_t hash160[20]) {
    observed *seen = context;
    if (seen->reject) return false;
    assert(index == seen->outputs++);
    assert(amount == (uint64_t)(index + 1) * 100000000);
    assert(type == (index ? ZCL_TX_STREAM_P2SH : ZCL_TX_STREAM_P2PKH));
    for (size_t i = 0; i < 20; ++i)
        assert(hash160[i] == (index ? 0x22 : 0x11));
    seen->total += amount;
    return true;
}

static bool parse_chunks(const uint8_t *wire, size_t length, size_t chunk,
                         observed *seen, zcl_tx_stream_facts *facts) {
    zcl_tx_stream stream;
    if (!zcl_tx_stream_begin(&stream, (uint32_t)length)) return false;
    for (size_t offset = 0; offset < length;) {
        size_t n = length - offset < chunk ? length - offset : chunk;
        if (!zcl_tx_stream_feed(&stream, wire + offset, n,
                                input_seen, output_seen, seen)) return false;
        offset += n;
    }
    return zcl_tx_stream_finish(&stream, facts);
}

static void test_valid(const fixture *item) {
    zcl_tx_review full;
    assert(zcl_tx_review_parse(item->wire, item->length, &full) == 0);
    for (size_t chunk = 1; chunk <= item->length; ++chunk) {
        observed seen = {0};
        zcl_tx_stream_facts facts = {0};
        assert(parse_chunks(item->wire, item->length, chunk, &seen, &facts));
        assert(seen.inputs == 1 && seen.outputs == 2);
        assert(facts.inputs == full.transparent_inputs);
        assert(facts.outputs == full.transparent_outputs);
        assert(facts.output_zat == full.transparent_output_zat);
        assert(seen.total == facts.output_zat);
        assert(facts.lock_time == full.lock_time);
        assert(facts.expiry_height == full.expiry_height);
    }
    assert(sizeof(zcl_tx_stream) <= 160);
}

static void test_failures(const fixture *item) {
    uint8_t changed[sizeof item->wire];
    zcl_tx_stream_facts facts;
    observed seen;
    const size_t bad_offsets[] = {0, item->input_count_at,
        item->script_length_at, item->first_script_at, item->balance_at,
        item->shielded_at};
    const uint8_t bad_values[] = {5, 17, 1, 0x75, 1, 1};
    for (size_t i = 0; i < sizeof bad_offsets / sizeof *bad_offsets; ++i) {
        memcpy(changed, item->wire, item->length);
        changed[bad_offsets[i]] = bad_values[i];
        seen = (observed){0};
        assert(!parse_chunks(changed, item->length, 7, &seen, &facts));
    }
    memcpy(changed, item->wire, item->output_count_at);
    changed[item->output_count_at] = 0xfd;
    changed[item->output_count_at + 1] = 2;
    changed[item->output_count_at + 2] = 0;
    memcpy(changed + item->output_count_at + 3,
           item->wire + item->output_count_at + 1,
           item->length - item->output_count_at - 1);
    seen = (observed){0};
    assert(!parse_chunks(changed, item->length + 2, 1, &seen, &facts));
    for (size_t cut = 0; cut < item->length; ++cut) {
        zcl_tx_stream stream;
        seen = (observed){0};
        assert(zcl_tx_stream_begin(&stream, (uint32_t)item->length));
        if (cut && !zcl_tx_stream_feed(&stream, item->wire, cut,
                                       input_seen, output_seen, &seen)) continue;
        assert(!zcl_tx_stream_finish(&stream, &facts));
    }
    zcl_tx_stream stream;
    assert(zcl_tx_stream_begin(&stream, (uint32_t)item->length + 1));
    seen = (observed){0};
    assert(zcl_tx_stream_feed(&stream, item->wire, item->length,
                              input_seen, output_seen, &seen));
    assert(!zcl_tx_stream_feed(&stream, (const uint8_t[]){0}, 1,
                               input_seen, output_seen, &seen));
    assert(!zcl_tx_stream_finish(&stream, &facts));
    assert(zcl_tx_stream_begin(&stream, (uint32_t)item->length));
    assert(!zcl_tx_stream_feed(&stream, item->wire, 0,
                               input_seen, output_seen, &seen));
    assert(zcl_tx_stream_begin(&stream, (uint32_t)item->length));
    seen = (observed){.reject = true};
    assert(!zcl_tx_stream_feed(&stream, item->wire, item->length,
                               input_seen, output_seen, &seen));
    assert(zcl_tx_stream_begin(&stream, (uint32_t)item->length));
    seen = (observed){0};
    assert(zcl_tx_stream_feed(&stream, item->wire, item->length,
                              input_seen, output_seen, &seen));
    assert(zcl_tx_stream_finish(&stream, &facts));
    assert(!zcl_tx_stream_finish(&stream, &facts));
}

static void test_mutations(const fixture *item) {
    uint32_t random = 0x23c2026u;
    unsigned accepted = 0, rejected = 0;
    for (unsigned run = 0; run < 20000; ++run) {
        uint8_t changed[sizeof item->wire];
        memcpy(changed, item->wire, item->length);
        random = random * 1664525u + 1013904223u;
        size_t length = run % 5 == 0 ? random % item->length : item->length;
        random = random * 1664525u + 1013904223u;
        size_t offset = random % item->length;
        changed[offset] ^= (uint8_t)(1u << (random & 7u));
        zcl_tx_stream stream;
        bool valid = zcl_tx_stream_begin(&stream, (uint32_t)length);
        for (size_t pos = 0; valid && pos < length;) {
            random = random * 1664525u + 1013904223u;
            size_t chunk = 1 + random % 64;
            if (chunk > length - pos) chunk = length - pos;
            valid = zcl_tx_stream_feed(&stream, changed + pos, chunk,
                                        NULL, NULL, NULL);
            pos += chunk;
        }
        zcl_tx_stream_facts facts;
        valid = valid && zcl_tx_stream_finish(&stream, &facts);
        if (!valid) { ++rejected; continue; }
        zcl_tx_review complete;
        assert(zcl_tx_review_parse(changed, length, &complete) == 0);
        assert(facts.inputs == complete.transparent_inputs);
        assert(facts.outputs == complete.transparent_outputs);
        assert(facts.output_zat == complete.transparent_output_zat);
        assert(facts.lock_time == complete.lock_time);
        assert(facts.expiry_height == complete.expiry_height);
        assert(!complete.sapling_spends && !complete.sapling_outputs &&
               !complete.sprout_joinsplits && !complete.value_balance_zat);
        ++accepted;
    }
    assert(accepted && rejected);
}

int main(int argc, char **argv) {
    fixture item = make_fixture();
    if (argc == 2) {
        FILE *seed = fopen(argv[1], "wb");
        assert(seed);
        assert(fwrite(item.wire, 1, item.length, seed) == item.length);
        assert(fclose(seed) == 0);
    } else assert(argc == 1);
    test_valid(&item);
    test_failures(&item);
    test_mutations(&item);
    return 0;
}
