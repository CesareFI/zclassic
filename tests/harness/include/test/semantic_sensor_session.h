/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Live cases of the semantic sensor's warm session, run inside the semantic_sensor group. */
#ifndef ZCL_TEST_SEMANTIC_SENSOR_SESSION_H
#define ZCL_TEST_SEMANTIC_SENSOR_SESSION_H

/* The warm session (`z23-clang-manifest session`) against the cold oracle:
 * byte-identical manifests after body, macro, header-layout, shadowing-header
 * and flag edits, each with the TU reuse the contract requires, and a forced
 * mismatch that disables reuse without ever writing the warm bytes. Needs
 * the built sensor; the caller skips when it is absent. Returns failures. */
int semantic_sensor_session_cases(void);

/* Bits set when one cold `z23-clang-manifest emit` of a tiny TU accepts
 * that syntax. A raw-string, #embed, or __has_embed case skips only when
 * its bit is clear. Returns -1 when the emit could not be started. */
enum {
    SEMANTIC_SENSOR_FEAT_RAW = 1,
    SEMANTIC_SENSOR_FEAT_EMBED = 2,
    SEMANTIC_SENSOR_FEAT_HAS_EMBED = 4
};
int semantic_sensor_front_end_features(void);

#endif /* ZCL_TEST_SEMANTIC_SENSOR_SESSION_H */
