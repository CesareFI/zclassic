/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * test_difficulty_adjustment_adversarial: adversarial coverage of the
 * Digishield-style DAA and nBits compact encoding, driving the full
 * GetNextWorkRequired() over a synthetic block_index chain against an
 * independent scalar reference:
 *
 *   1. RETARGET CLAMPS: fast timestamps cannot raise difficulty past the
 *      max-up clamp, slow ones cannot drop past max-down; each case also
 *      asserts the unclamped value differs, so the clamp is load-bearing.
 *   2. powLimit FLOOR: difficulty never eases below powLimit, including via
 *      IncreaseDifficultyBy() with a too-easy nBits.
 *   3. nBits COMPACT ENCODING: SetCompact/GetCompact round-trips; a
 *      non-canonical nBits normalizes; negative-flagged and overflow nBits
 *      are rejected by CheckProofOfWork().
 *   4. TIMESTAMP-MANIPULATION RESISTANCE: the retarget uses median-time-past,
 *      so shoving the tip timestamp to +/- extremes changes nothing.
 *   5. MIN-DIFFICULTY RULE NOT ON MAINNET: a wildly-late block takes the
 *      averaging path, not powLimit.
 *
 * Pure and deterministic; selects mainnet params and restores the prior
 * network on exit. Extends test_domain_consensus_pow,
 * test_domain_consensus_pow_seal and test_pow_diffadj_precedence. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"  /* enum chain_network */
#include "chain/pow.h"
#include "consensus/params.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "primitives/block.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DAA_CHECK(name, expr) do {                              \
    printf("difficulty_adjustment_adversarial: %s... ", (name)); \
    if ((expr)) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                       \
} while (0)

/* Long enough that the tip and the window-start (17 hops back) both have a
 * full 11-deep median-time-past window: LEN >= 28, with margin. */
#define DAA_CHAIN_LEN 40

/* Small target so the retarget math fits in 64 bits: 0x0700ffff decodes to
 * 0xffff << 32 (~2^48), far below powLimit (~2^243), so the powLimit clamp
 * never fires in the clamp-boundary cases. */
#define DAA_SMALL_NBITS 0x0700ffffu

static enum chain_network daa_current_net(void)
{
    const char *id = chain_params_get()->strNetworkID;
    if (strcmp(id, "test") == 0)    return CHAIN_TESTNET;
    if (strcmp(id, "regtest") == 0) return CHAIN_REGTEST;
    return CHAIN_MAIN;
}

/* Build DAA_CHAIN_LEN linked nodes ending at `tip_height`, `spacing` seconds
 * apart, all nBits == DAA_SMALL_NBITS; chain[LEN-1] is pindexLast. Endpoint
 * median-time-past differs by nPowAveragingWindow*spacing. */
static void daa_build_chain(struct block_index chain[DAA_CHAIN_LEN],
                            int tip_height, int64_t spacing, int64_t base_time)
{
    for (int i = 0; i < DAA_CHAIN_LEN; i++) {
        block_index_init(&chain[i]);
        int back = (DAA_CHAIN_LEN - 1) - i;   /* 0 at the tip */
        chain[i].nHeight = tip_height - back;
        chain[i].nBits = DAA_SMALL_NBITS;
        chain[i].nTime = (uint32_t)(base_time + (int64_t)i * spacing);
        chain[i].pprev = (i == 0) ? NULL : &chain[i - 1];
    }
}

/* Independent scalar reference for a 64-bit-fits target: damp toward avg by
 * /4, clamp the timespan to [min,max] (unless `clamp` is false), then
 * bnNew = target/avgTs*actTs, encoded with arith_uint256_get_compact.
 * `raw_timespan` is last-first before damping. Returns the expected nBits;
 * out_actts receives the timespan used. */
static uint32_t daa_ref_retarget(uint64_t target, int64_t raw_timespan,
                                 int64_t avgTs, int64_t minTs, int64_t maxTs,
                                 bool clamp, int64_t *out_actts)
{
    int64_t act = avgTs + (raw_timespan - avgTs) / 4;   /* same /4 damping */
    if (clamp) {
        if (act < minTs) act = minTs;
        if (act > maxTs) act = maxTs;
    }
    if (out_actts) *out_actts = act;
    uint64_t bnNew = (target / (uint64_t)avgTs) * (uint64_t)act;  /* div THEN mul */
    struct arith_uint256 a;
    arith_uint256_set_u64(&a, bnNew);
    return arith_uint256_get_compact(&a, false);
}

int test_difficulty_adjustment_adversarial(void);
int test_difficulty_adjustment_adversarial(void)
{
    printf("\n=== difficulty-adjustment adversarial (clamps / floor / "
           "timestamp / encoding) ===\n");
    int failures = 0;

    enum chain_network saved_net = daa_current_net();
    chain_params_select(CHAIN_MAIN);
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *params = &cp->consensus;

    /* Pin the premise so a chainparams edit that changes these fails HERE. */
    DAA_CHECK("mainnet: nPowAveragingWindow==17",
              params->nPowAveragingWindow == 17);
    DAA_CHECK("mainnet: nPowMaxAdjustUp==16",  params->nPowMaxAdjustUp == 16);
    DAA_CHECK("mainnet: nPowMaxAdjustDown==32", params->nPowMaxAdjustDown == 32);

    struct arith_uint256 pow_limit_arith;
    uint256_to_arith(&pow_limit_arith, &params->powLimit);
    const uint32_t powlimit_bits = arith_uint256_get_compact(&pow_limit_arith, false);

    /* Decode DAA_SMALL_NBITS to its 64-bit target for the scalar reference. */
    struct arith_uint256 small_target_a;
    arith_uint256_set_compact(&small_target_a, DAA_SMALL_NBITS, NULL, NULL);
    const uint64_t small_target = arith_uint256_get_low64(&small_target_a);
    DAA_CHECK("small nBits is canonical (round-trips)",
              arith_uint256_get_compact(&small_target_a, false) == DAA_SMALL_NBITS);
    DAA_CHECK("small target far below powLimit (isolates timespan clamp)",
              arith_uint256_compare(&small_target_a, &pow_limit_arith) < 0);

    /* Height 100000: pre-Buttercup (150s spacing), avgTs=2550, min=2142,
     * max=3366; outside every upgrade window, so the pure averaging path. */
    const int tip_height = 100000;
    const int next_height = tip_height + 1;
    const int64_t spacing = consensus_pow_target_spacing(params, next_height);
    const int64_t avgTs = consensus_averaging_window_timespan(params, next_height);
    const int64_t minTs = consensus_min_actual_timespan(params, next_height);
    const int64_t maxTs = consensus_max_actual_timespan(params, next_height);
    DAA_CHECK("mainnet@100001: spacing==150", spacing == 150);
    DAA_CHECK("mainnet@100001: avgTs==2550", avgTs == 2550);
    DAA_CHECK("mainnet@100001: minTs==2142 (avg*84/100)", minTs == 2142);
    DAA_CHECK("mainnet@100001: maxTs==3366 (avg*132/100)", maxTs == 3366);

    /* ─── 1a. FAST run: max-UP clamp. Blocks 1s apart, raw 17s; damped
     * 2550+(17-2550)/4 = 1917 < minTs, clamped to 2142. ───────────────── */
    {
        struct block_index chain[DAA_CHAIN_LEN];
        daa_build_chain(chain, tip_height, /*spacing=*/1, 1500000000LL);
        struct block_index *pindexLast = &chain[DAA_CHAIN_LEN - 1];

        /* pblock time irrelevant here (no fork-window / min-diff branch at this
         * height); give it a benign value. */
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nBits = DAA_SMALL_NBITS;
        hdr.nTime = (uint32_t)(block_index_get_time(pindexLast) + spacing);

        unsigned int got = GetNextWorkRequired(pindexLast, &hdr, params);

        int64_t raw = 17 * 1;              /* MTP(last)-MTP(first) under uniform spacing */
        int64_t used = 0;
        uint32_t ref_clamped   = daa_ref_retarget(small_target, raw, avgTs, minTs, maxTs, true,  &used);
        uint32_t ref_unclamped = daa_ref_retarget(small_target, raw, avgTs, minTs, maxTs, false, NULL);

        DAA_CHECK("FAST: damped timespan clamps UP to minTs (2142)", used == minTs);
        DAA_CHECK("FAST: GetNextWorkRequired == clamped scalar reference",
                  got == ref_clamped);
        DAA_CHECK("FAST: clamp is load-bearing (clamped != unclamped)",
                  ref_clamped != ref_unclamped);
    }

    /* ─── 1b. SLOW run: max-DOWN clamp. Blocks 400s apart, raw 6800s; damped
     * 2550+(6800-2550)/4 = 3612 > maxTs, clamped to 3366. ─────────────── */
    {
        struct block_index chain[DAA_CHAIN_LEN];
        daa_build_chain(chain, tip_height, /*spacing=*/400, 1500000000LL);
        struct block_index *pindexLast = &chain[DAA_CHAIN_LEN - 1];

        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nBits = DAA_SMALL_NBITS;
        hdr.nTime = (uint32_t)(block_index_get_time(pindexLast) + spacing);

        unsigned int got = GetNextWorkRequired(pindexLast, &hdr, params);

        int64_t raw = 17 * 400;
        int64_t used = 0;
        uint32_t ref_clamped   = daa_ref_retarget(small_target, raw, avgTs, minTs, maxTs, true,  &used);
        uint32_t ref_unclamped = daa_ref_retarget(small_target, raw, avgTs, minTs, maxTs, false, NULL);

        DAA_CHECK("SLOW: damped timespan clamps DOWN to maxTs (3366)", used == maxTs);
        DAA_CHECK("SLOW: GetNextWorkRequired == clamped scalar reference",
                  got == ref_clamped);
        DAA_CHECK("SLOW: clamp is load-bearing (clamped != unclamped)",
                  ref_clamped != ref_unclamped);
    }

    /* ─── 2. powLimit FLOOR. bnAvg == powLimit: a slow window (maxTs) would
     * exceed powLimit and must clamp to it; a fast window (minTs) stays
     * un-clamped. Reference = get_compact(powLimit). ─────────────────── */
    {
        int64_t slow_last = 1000000 + 100 * avgTs;   /* wildly slow -> clamps to maxTs */
        uint32_t got_slow = CalculateNextWorkRequired(
            pow_limit_arith, slow_last, 1000000, params, next_height);
        DAA_CHECK("FLOOR: over-limit retarget clamps to powLimit",
                  got_slow == powlimit_bits);

        int64_t fast_last = 1000000 + 1;             /* wildly fast -> clamps to minTs */
        uint32_t got_fast = CalculateNextWorkRequired(
            pow_limit_arith, fast_last, 1000000, params, next_height);
        DAA_CHECK("FLOOR: under-limit retarget NOT clamped (harder than powLimit)",
                  got_fast != powlimit_bits);

        /* IncreaseDifficultyBy: a too-EASY nBits (0x2000ffff, ~2^248 >
         * powLimit ~2^243) is clamped to the floor. */
        struct arith_uint256 easy_a;
        arith_uint256_set_compact(&easy_a, 0x2000ffffu, NULL, NULL);
        DAA_CHECK("FLOOR: crafted easy nBits really exceeds powLimit",
                  arith_uint256_compare(&easy_a, &pow_limit_arith) > 0);
        unsigned int clamped = IncreaseDifficultyBy(0x2000ffffu, 1, params);
        DAA_CHECK("FLOOR: IncreaseDifficultyBy clamps too-easy nBits to powLimit",
                  clamped == powlimit_bits);
    }

    /* ─── 3. nBits COMPACT ENCODING. ─────────────────────────────────────── */
    {
        /* 3a. Canonical round-trips. */
        uint32_t canon[] = {
            0x1d00ffffu, 0x1b0404cbu, 0x1e00ffffu, 0x0700ffffu, 0x03123456u,
        };
        bool rt_ok = true;
        for (size_t i = 0; i < sizeof(canon)/sizeof(canon[0]); i++) {
            struct arith_uint256 t;
            arith_uint256_set_compact(&t, canon[i], NULL, NULL);
            if (arith_uint256_get_compact(&t, false) != canon[i]) {
                printf("\n  round-trip MISMATCH 0x%08x -> 0x%08x\n",
                       canon[i], arith_uint256_get_compact(&t, false));
                rt_ok = false;
            }
        }
        DAA_CHECK("ENC: canonical nBits round-trip through set/get compact", rt_ok);

        /* 3b. Non-canonical normalizes. 0x05001234 decodes to 0x1234<<16 ==
         * 0x12340000, which re-encodes canonically as 0x04123400. */
        {
            struct arith_uint256 t;
            bool neg = true, ovf = true;
            arith_uint256_set_compact(&t, 0x05001234u, &neg, &ovf);
            uint32_t re = arith_uint256_get_compact(&t, false);
            DAA_CHECK("ENC: non-canonical 0x05001234 normalizes to 0x04123400",
                      re == 0x04123400u && re != 0x05001234u && !neg && !ovf);
        }

        /* 3c. Negative-flagged nBits: set_compact flags it and
         * CheckProofOfWork rejects it regardless of the hash. */
        {
            struct arith_uint256 t;
            bool neg = false, ovf = false;
            arith_uint256_set_compact(&t, 0x05800001u, &neg, &ovf);
            DAA_CHECK("ENC: 0x05800001 flagged negative (non-zero target)",
                      neg && !ovf && !arith_uint256_is_zero(&t));
            struct uint256 h;
            memset(&h, 0, sizeof(h));   /* hash 0: as easy as possible */
            DAA_CHECK("ENC: negative nBits rejected by CheckProofOfWork",
                      CheckProofOfWork(h, 0x05800001u, params) == false);
        }

        /* 3d. Overflow nBits: size 0x23==35 (>34) with non-zero word overflows;
         * rejected by CheckProofOfWork. */
        {
            struct arith_uint256 t;
            bool neg = false, ovf = false;
            arith_uint256_set_compact(&t, 0x23000001u, &neg, &ovf);
            DAA_CHECK("ENC: 0x23000001 flagged overflow", ovf);
            struct uint256 h;
            memset(&h, 0, sizeof(h));
            DAA_CHECK("ENC: overflow nBits rejected by CheckProofOfWork",
                      CheckProofOfWork(h, 0x23000001u, params) == false);
        }
    }

    /* ─── 4. TIMESTAMP-MANIPULATION RESISTANCE. The retarget uses
     * median-time-past of the window endpoints, so a manipulated tip
     * timestamp leaves the result byte-identical to the baseline. ─────── */
    {
        struct block_index chain[DAA_CHAIN_LEN];
        daa_build_chain(chain, tip_height, /*spacing=*/spacing, 1500000000LL);
        struct block_index *pindexLast = &chain[DAA_CHAIN_LEN - 1];

        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nBits = DAA_SMALL_NBITS;
        hdr.nTime = (uint32_t)(block_index_get_time(pindexLast) + spacing);

        unsigned int baseline = GetNextWorkRequired(pindexLast, &hdr, params);

        /* A far-future tip timestamp only becomes the max of the 11-value
         * median window; the median is unchanged. */
        uint32_t honest_tip = chain[DAA_CHAIN_LEN - 1].nTime;
        chain[DAA_CHAIN_LEN - 1].nTime = 0xfffffff0u;   /* year ~2106, extreme */
        unsigned int got_future = GetNextWorkRequired(pindexLast, &hdr, params);
        DAA_CHECK("TS: far-future tip timestamp does not change the retarget",
                  got_future == baseline);

        /* Attacker back-dates the tip below its neighbours (out-of-order). The
         * median still ignores a single low outlier. */
        chain[DAA_CHAIN_LEN - 1].nTime = honest_tip - 5;
        unsigned int got_past = GetNextWorkRequired(pindexLast, &hdr, params);
        DAA_CHECK("TS: back-dated tip timestamp does not change the retarget",
                  got_past == baseline);

        chain[DAA_CHAIN_LEN - 1].nTime = honest_tip;    /* restore */

        /* And the baseline itself is the honest averaging result, not powLimit. */
        DAA_CHECK("TS: baseline retarget is a real target, not powLimit",
                  baseline != powlimit_bits);
    }

    /* ─── 5. MIN-DIFFICULTY RULE IS NOT ACTIVE ON MAINNET: a wildly-late
     * block at a normal height takes the averaging path, not powLimit. ─── */
    {
        DAA_CHECK("MINDIFF: mainnet nPowAllowMinDifficultyEnabled == false",
                  params->nPowAllowMinDifficultyEnabled == false);
        DAA_CHECK("MINDIFF: mainnet nPowAllowMinDifficultyBlocksAfterHeight == -1",
                  params->nPowAllowMinDifficultyBlocksAfterHeight == -1);

        /* Height 1,000,000 is past the DIFFADJ [585322,585339) and BUTTERCUP
         * [707000,707017) windows, so the fork-window min-diff ramp is
         * skipped. */
        const int md_tip = 1000000;
        const int md_next = md_tip + 1;
        const int64_t md_spacing = consensus_pow_target_spacing(params, md_next);

        struct block_index chain[DAA_CHAIN_LEN];
        daa_build_chain(chain, md_tip, md_spacing, 1500000000LL);
        struct block_index *pindexLast = &chain[DAA_CHAIN_LEN - 1];

        /* A block absurdly late (> spacing*12 after the tip): on testnet this
         * would trip the min-diff escape to powLimit; on mainnet it must NOT. */
        struct block_header late;
        block_header_init(&late);
        late.nBits = DAA_SMALL_NBITS;
        late.nTime = (uint32_t)(block_index_get_time(pindexLast) + md_spacing * 100);

        unsigned int got = GetNextWorkRequired(pindexLast, &late, params);
        DAA_CHECK("MINDIFF: wildly-late mainnet block does NOT ease to powLimit",
                  got != powlimit_bits);

        /* It equals the averaging result (uniform-nBits window, actual==avgTs
         * -> no timespan clamp). Independent scalar reference. */
        int64_t md_avgTs = consensus_averaging_window_timespan(params, md_next);
        int64_t md_minTs = consensus_min_actual_timespan(params, md_next);
        int64_t md_maxTs = consensus_max_actual_timespan(params, md_next);
        uint32_t ref = daa_ref_retarget(small_target, 17 * md_spacing,
                                        md_avgTs, md_minTs, md_maxTs, true, NULL);
        DAA_CHECK("MINDIFF: mainnet late block returns the averaging result",
                  got == ref);
    }

    /* Contrast (read-only): the escape hatch IS enabled on testnet params, so
     * the mainnet-off assertion above is meaningful, not vacuous. */
    {
        chain_params_select(CHAIN_TESTNET);
        const struct consensus_params *tp = &chain_params_get()->consensus;
        DAA_CHECK("MINDIFF: testnet nPowAllowMinDifficultyEnabled == true (contrast)",
                  tp->nPowAllowMinDifficultyEnabled == true);
        chain_params_select(CHAIN_MAIN);
    }

    chain_params_select(saved_net);
    printf("=== difficulty-adjustment adversarial: %d failures ===\n", failures);
    return failures;
}
