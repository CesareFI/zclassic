/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_generators.h"

/* Fixed group-hash points for the empty tag under Zcash_G_ and Zcash_H_.
 * The host and Cortex-M3 fixtures verify their compressed encodings. */
const struct jub_point blue_spending_key_generator = {
    .x = {.d = {0x9fea675eb63e8cf6ULL, 0x15ba8508eb7f13c5ULL,
                0x87a02da79c8b7ef8ULL, 0x0af4897169c1851eULL}},
    .y = {.d = {0xfb63146264e65a56ULL, 0x77f3f8c6fd45d5e5ULL,
                0x8770a243986a6eb9ULL, 0x6dde055ca112d037ULL}},
    .z = {.d = {0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
                0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL}},
    .t = {.d = {0x1c78341b5c609fc6ULL, 0xbb8cd2689521ecaeULL,
                0xb1768e136106271aULL, 0x16f2498b4757e919ULL}}
};

const struct jub_point blue_proof_generation_generator = {
    .x = {.d = {0xa4e8d4b1980bd94fULL, 0x6a724da8827983abULL,
                0xa6b51a46c1c2196aULL, 0x329b2187754475beULL}},
    .y = {.d = {0x66f612d1a98bb469ULL, 0xc129c0527cdad63eULL,
                0x21bb76b83609b54fULL, 0x7054400a940fda47ULL}},
    .z = {.d = {0x502541e94d3c87d6ULL, 0x31784011f1384103ULL,
                0xe30ed01cabb04dfaULL, 0x1d4d0f776079a5beULL}},
    .t = {.d = {0xdd9d5eb20a3da546ULL, 0xbb940601762c9974ULL,
                0xd01e550ecf80d2ceULL, 0x5ede38b638d28a85ULL}}
};
