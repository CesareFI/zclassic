/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Pedantic unit tests for domain_consensus_verify_equihash_solution().
 * Separate from test_domain_consensus_equihash.c: this file uses the project
 * TEST_CASE/TEST_END harness with exactly ONE TEST_CASE per entrypoint
 * (TEST_END defines `_test_next`). It pins:
 *
 *   1. Null-pointer contracts: NULL header -> ERR_NULL_HEADER, NULL out_valid
 *      -> ERR_NULL_OUT, and the error path leaves *out untouched.
 *   2. Solution-size demux: unrecognised sizes (2, 256, 0xffffffff) map to
 *      ERR_BAD_SOL_SIZE; the consensus sizes (36/68/400/1344) return ZCL_OK
 *      (valid=false for a zero solution).
 *   3. BLAKE2b state: the ZcashPoW personalised state and canonical
 *      little-endian header feed are rebuilt independently and pinned against
 *      constants captured from the crypto primitive.
 *   4. Regression seal: over real-shape headers (and a known-good (96,5)
 *      witness) `valid` equals both a direct equihash_is_valid_solution() on
 *      an independently rebuilt state and the legacy
 *      check_equihash_solution() wrapper.
 */

#include "test/test_core.h"

#include "chain/equihash.h"            /* check_equihash_solution (legacy seal) */
#include "chain/chainparams.h"         /* chain_params_get */
#include "crypto/blake2b.h"
#include "crypto/equihash.h"
#include "domain/consensus/equihash.h"
#include "primitives/block.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ── shared fixtures ──────────────────────────────────────────────────── */

/* Little-endian u32 writer (Equihash challenge serialization is LE by
 * consensus); kept local so a module regression cannot mask itself. */
static void seal_le32(uint8_t b[4], uint32_t v)
{
    b[0] = (uint8_t)(v        & 0xff);
    b[1] = (uint8_t)((v >>  8) & 0xff);
    b[2] = (uint8_t)((v >> 16) & 0xff);
    b[3] = (uint8_t)((v >> 24) & 0xff);
}

/* Hand-rolled "legacy stream" feed of the header pre-nonce bytes + nonce,
 * independent of the module; the byte order is consensus-frozen. */
static void seal_feed_header(struct blake2b_ctx *st, const struct block_header *h)
{
    uint8_t b4[4];

    seal_le32(b4, (uint32_t)h->nVersion);
    blake2b_update(st, b4, 4);

    blake2b_update(st, h->hashPrevBlock.data,        32);
    blake2b_update(st, h->hashMerkleRoot.data,       32);
    blake2b_update(st, h->hashFinalSaplingRoot.data, 32);

    seal_le32(b4, h->nTime);
    blake2b_update(st, b4, 4);
    seal_le32(b4, h->nBits);
    blake2b_update(st, b4, 4);

    blake2b_update(st, h->nNonce.data, 32);
}

/* A known-valid (N=96, K=5) Equihash witness from the Zcash reference
 * suite (canonical input string + nonce {1,0,...}), proving the verifier
 * still accepts a real positive. */
static const eh_index kValidIndices_96_5[32] = {
    2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041,
    32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026,
    15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
    23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568
};

/* ── 1. Null-pointer contracts ────────────────────────────────────────── */

int test_equihash_null_guards(void)
{
    int failures = 0;
    TEST_CASE("equihash verify: null header/out map to typed errors, *out untouched")
    {
        /* NULL header -> ERR_NULL_HEADER. Sentinel proves *out is NOT
         * written on the error path. */
        bool out = true;
        struct zcl_result r1 =
            domain_consensus_verify_equihash_solution(NULL, NULL, &out);
        ASSERT(!r1.ok);
        ASSERT(r1.code == DOMAIN_CONSENSUS_EQUIHASH_ERR_NULL_HEADER);
        ASSERT(out == true);  /* untouched */

        /* NULL out_valid -> ERR_NULL_OUT (valid solution size, so it is the
         * out-guard that fires). */
        struct block_header h;
        block_header_init(&h);
        h.nSolutionSize = 1344;
        struct zcl_result r2 =
            domain_consensus_verify_equihash_solution(&h, NULL, NULL);
        ASSERT(!r2.ok);
        ASSERT(r2.code == DOMAIN_CONSENSUS_EQUIHASH_ERR_NULL_OUT);

        /* The header guard is checked BEFORE the out guard: NULL header +
         * NULL out reports the header error, not the out error. */
        struct zcl_result r3 =
            domain_consensus_verify_equihash_solution(NULL, NULL, NULL);
        ASSERT(!r3.ok);
        ASSERT(r3.code == DOMAIN_CONSENSUS_EQUIHASH_ERR_NULL_HEADER);
    }
    TEST_END
    return failures;
}

/* ── 2. Solution-size demux ───────────────────────────────────────────── */

int test_equihash_solution_size_demux(void)
{
    int failures = 0;
    TEST_CASE("equihash verify: unrecognised sizes -> ERR_BAD_SOL_SIZE; 4 real sizes -> ok")
    {
        /* Unrecognised sizes (just below, just above, at the SIZE_MAX edge)
         * all collapse to ERR_BAD_SOL_SIZE without invoking the verifier. */
        const size_t bad[] = { 0, 1, 2, 35, 37, 67, 69, 256, 401, 1343,
                               1345, (size_t)0xffffffffu };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            struct block_header h;
            block_header_init(&h);
            h.nSolutionSize = bad[i];
            bool out = true;  /* sentinel: must remain untouched on error */
            struct zcl_result r =
                domain_consensus_verify_equihash_solution(&h, NULL, &out);
            ASSERT(!r.ok);
            ASSERT(r.code == DOMAIN_CONSENSUS_EQUIHASH_ERR_BAD_SOL_SIZE);
            ASSERT(out == true);
        }

        /* The four consensus sizes demux into the verifier and return
         * ZCL_OK; an all-zero solution writes *out false, proving the call
         * reached the crypto check. */
        const size_t good[] = { 36, 68, 400, 1344 };
        for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
            struct block_header h;
            block_header_init(&h);
            h.nSolutionSize = good[i];
            memset(h.nSolution, 0, sizeof(h.nSolution));
            bool out = true;
            struct zcl_result r =
                domain_consensus_verify_equihash_solution(&h, NULL, &out);
            ASSERT(r.ok);
            ASSERT(out == false);
        }
    }
    TEST_END
    return failures;
}

/* ── 3. BLAKE2b state correctness ─────────────────────────────────────── */

int test_equihash_blake2b_state_seal(void)
{
    int failures = 0;
    TEST_CASE("equihash verify: ZcashPoW BLAKE2b state matches precomputed constants")
    {
        /* (a) The (N,K) param set selects the ZcashPoW personalisation and
         * digest length; the low byte of h[0] and outlen are pinned per set
         * from equihash_initialise_state(). */
        struct { unsigned N, K; uint8_t outlen; uint64_t h0, h7; } cfg[] = {
            { 200, 9, 50, 0x6a09e667f2bdc93aULL, 0x5be0cd10137e21b1ULL },
            { 192, 7, 48, 0x6a09e667f2bdc938ULL, 0x5be0cd1e137e21b9ULL },
            {  96, 5, 60, 0x6a09e667f2bdc934ULL, 0x5be0cd1c137e2119ULL },
            {  48, 5, 60, 0x6a09e667f2bdc934ULL, 0x5be0cd1c137e2149ULL },
        };
        for (size_t i = 0; i < sizeof(cfg) / sizeof(cfg[0]); i++) {
            struct equihash_params ep;
            equihash_params_init(&ep, cfg[i].N, cfg[i].K);
            struct blake2b_ctx st;
            equihash_initialise_state(&ep, &st);
            ASSERT(st.outlen == cfg[i].outlen);
            ASSERT((size_t)st.outlen == ep.hash_output);
            /* h[0] low byte encodes digest_length; h[0] and h[7] both fold in
             * the ZcashPoW "N,K" personalisation — both differ per param set. */
            ASSERT(st.h[0] == cfg[i].h0);
            ASSERT(st.h[7] == cfg[i].h7);
            ASSERT(st.h[6] == 0x48ec89c38820de31ULL); /* IV[6], personalisation-free */
        }

        /* (b) A fixed header through the canonical LE serialization: pin the
         * streaming counters and finalized digest. 140 bytes = one 128-byte
         * BLAKE2b block (t[0]=128) plus 12 buffered. */
        struct block_header h;
        block_header_init(&h);
        h.nVersion = 4;
        memset(h.hashPrevBlock.data,        0x11, 32);
        memset(h.hashMerkleRoot.data,       0x22, 32);
        memset(h.hashFinalSaplingRoot.data, 0x33, 32);
        h.nTime = 1234567890u;
        h.nBits = 0x1d00ffff;
        memset(h.nNonce.data, 0x44, 32);

        struct equihash_params ep96;
        equihash_params_init(&ep96, 96, 5);
        struct blake2b_ctx st;
        equihash_initialise_state(&ep96, &st);
        seal_feed_header(&st, &h);

        ASSERT(st.t[0] == 128);    /* one full block absorbed */
        ASSERT(st.buflen == 12);   /* 140 - 128 buffered */

        static const unsigned char kExpectDigest[60] = {
            0x0f,0xf0,0x85,0xbc,0x19,0xe1,0xf8,0xd4,0xab,0xb1,
            0x10,0x2f,0x89,0x8f,0x54,0x87,0xa3,0x7d,0x28,0x2c,
            0xa7,0xb9,0x1f,0x73,0x41,0x4d,0xfa,0xbc,0xcb,0xc1,
            0xf3,0x15,0xe1,0xf0,0x9d,0xf0,0x5d,0xc3,0xb5,0x12,
            0x0d,0x1b,0x84,0x60,0x5c,0xa3,0x82,0x60,0x49,0xaa,
            0x9f,0xb6,0x54,0x22,0x21,0x39,0xa5,0x4d,0x48,0x5e
        };
        unsigned char digest[64];
        struct blake2b_ctx fin = st;  /* finalize a copy; verifier uses by-value */
        blake2b_final(&fin, digest, ep96.hash_output);
        ASSERT(memcmp(digest, kExpectDigest, ep96.hash_output) == 0);

        /* (c) Swapping prev<->merkle changes the digest, so the pin above is
         * load-bearing. */
        struct block_header swapped = h;
        memcpy(swapped.hashPrevBlock.data,  h.hashMerkleRoot.data, 32);
        memcpy(swapped.hashMerkleRoot.data, h.hashPrevBlock.data,  32);
        struct blake2b_ctx st2;
        equihash_initialise_state(&ep96, &st2);
        seal_feed_header(&st2, &swapped);
        unsigned char digest2[64];
        struct blake2b_ctx fin2 = st2;
        blake2b_final(&fin2, digest2, ep96.hash_output);
        ASSERT(memcmp(digest2, kExpectDigest, ep96.hash_output) != 0);
    }
    TEST_END
    return failures;
}

/* ── 4a. Regression seal: domain serialization == independent rebuild ─── */

int test_equihash_serialization_matches_independent_rebuild(void)
{
    int failures = 0;
    TEST_CASE("equihash verify: domain valid == independent state rebuild over header matrix")
    {
        struct equihash_params ep;
        equihash_params_init(&ep, 96, 5);

        /* Real-shape headers perturbing each challenge field independently:
         * the domain `valid` must match a state rebuilt here and handed to
         * the primitive. */
        for (int trial = 0; trial < 16; trial++) {
            struct block_header h;
            block_header_init(&h);
            h.nVersion = 4 + trial;
            memset(h.hashPrevBlock.data,        (uint8_t)(0x10 + trial), 32);
            memset(h.hashMerkleRoot.data,       (uint8_t)(0x20 + trial), 32);
            memset(h.hashFinalSaplingRoot.data, (uint8_t)(0x30 + trial), 32);
            h.nTime = 0x600D0000u + (uint32_t)(trial * 7919);
            h.nBits = 0x1d00ffffu - (uint32_t)trial;
            memset(h.nNonce.data, (uint8_t)(0xA0 + trial), 32);

            /* 68-byte (96,5)-shaped solution: arbitrary noise, almost surely
             * invalid, but both paths must agree on the verdict. */
            h.nSolutionSize = 68;
            for (size_t b = 0; b < 68; b++)
                h.nSolution[b] = (uint8_t)((trial * 31 + (int)b) & 0xff);

            bool domain_valid = true;
            struct zcl_result r =
                domain_consensus_verify_equihash_solution(&h, NULL, &domain_valid);
            ASSERT(r.ok);

            struct blake2b_ctx st;
            equihash_initialise_state(&ep, &st);
            seal_feed_header(&st, &h);
            bool indep_valid =
                equihash_is_valid_solution(&ep, &st, h.nSolution, h.nSolutionSize);

            ASSERT(domain_valid == indep_valid);
        }
    }
    TEST_END
    return failures;
}

/* ── 4b. Regression seal: domain valid == legacy wrapper, incl. a positive ─ */

int test_equihash_legacy_wrapper_regression_seal(void)
{
    int failures = 0;
    TEST_CASE("equihash verify: domain valid == legacy check_equihash_solution, true positive accepted")
    {
        const struct chain_params *cp = chain_params_get();

        /* (a) Matrix of invalid-noise headers: domain `valid` must equal the
         * legacy wrapper's bool for every one. */
        for (int trial = 0; trial < 12; trial++) {
            struct block_header h;
            block_header_init(&h);
            h.nVersion = 4;
            memset(h.hashPrevBlock.data,        (uint8_t)(0x01 + trial), 32);
            memset(h.hashMerkleRoot.data,       (uint8_t)(0x40 + trial), 32);
            memset(h.hashFinalSaplingRoot.data, (uint8_t)(0x80 + trial), 32);
            h.nTime = 1500000000u + (uint32_t)trial;
            h.nBits = 0x1d00ffff;
            memset(h.nNonce.data, (uint8_t)(0xC0 + trial), 32);
            h.nSolutionSize = 68;
            for (size_t b = 0; b < 68; b++)
                h.nSolution[b] = (uint8_t)((b * 7 + trial) & 0xff);

            bool domain_valid = true;
            struct zcl_result r =
                domain_consensus_verify_equihash_solution(&h, NULL, &domain_valid);
            ASSERT(r.ok);
            bool legacy_valid = check_equihash_solution(&h, cp);
            ASSERT(domain_valid == legacy_valid);
        }

        /* (b) True positive: the canonical (96,5) reference state's minimal
         * solution is accepted by the primitive (guards against
         * false-rejecting everything). */
        struct equihash_params ep;
        equihash_params_init(&ep, 96, 5);
        struct blake2b_ctx ref;
        equihash_initialise_state(&ep, &ref);
        const char *input = "Equihash is an asymmetric PoW based on the "
                            "Generalised Birthday problem.";
        blake2b_update(&ref, (const unsigned char *)input, strlen(input));
        unsigned char nonce[32] = {0};
        nonce[0] = 1;
        blake2b_update(&ref, nonce, 32);

        unsigned char soln[68];
        size_t soln_len = eh_get_minimal_from_indices(
                kValidIndices_96_5, 32, ep.collision_bit_length,
                soln, sizeof(soln));
        ASSERT(soln_len == 68);
        ASSERT(equihash_is_valid_solution(&ep, &ref, soln, soln_len) == true);

        /* (c) Perturbing one witness index must make the primitive reject,
         * so (b) is a real positive. */
        eh_index bad[32];
        memcpy(bad, kValidIndices_96_5, sizeof(bad));
        bad[0] ^= 1u;
        unsigned char soln_bad[68];
        size_t bad_len = eh_get_minimal_from_indices(
                bad, 32, ep.collision_bit_length, soln_bad, sizeof(soln_bad));
        ASSERT(bad_len == 68);
        ASSERT(equihash_is_valid_solution(&ep, &ref, soln_bad, bad_len) == false);
    }
    TEST_END
    return failures;
}
