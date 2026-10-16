<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Source-bound context capsule qualification

Date: 2026-10-16. Host: r1, AMD Ryzen 9 7950X3D.
Compiler: GCC 14.2.0 (Ubuntu 14.2.0-4ubuntu2~24.04.1).
Base: `0e48534231a8b5dc379f5393df3dd720ac88d37c`.

## User outcome

A code capsule identifies the source and dependency generation from the same
opened index used for its symbol and relationship queries. Both found and
not-found replies include `source_root_sha3` and `dep_root_sha3`. Unavailable
generation metadata produces `CODEINDEX_GENERATION`. The result remains
bounded to 4 KiB, with existing evidence labels and section-drop ordering.

Full freshness checks reuse a settled source snapshot while retaining active
depfile metadata, source generation, store format and schema checks. Missing or
changed inventories take the existing full refresh path. This is a filesystem
observation, not an atomic snapshot against concurrent source edits.

## Executed evidence

The registered `codeindex,code_capsule,code_impact` gate ran three groups with
zero failures, zero self-skips and zero cached groups. Retained log:
`build/scratch/semantic-capsule/combined-gate.log`.

Coverage includes exact generation roots for found and missing symbols,
independent source and depfile changes, added source inventory,
restored-mtime source and depfile changes, absent schema metadata, and bounded
serialized output.

Independent source review accepted the four-file diff with SHA-256
`e041c0563154bec97adfdbf4319fe38155d934ec80c8eea17153e8b30d9bd74a`.
That review is separate from runtime qualification.

## Performance limits

One existing full-open fixture sample measured baseline wall time 19,480 us
and thread CPU 1,845 us; the candidate measured wall time 21,067 us and thread
CPU 1,895 us. Both reread zero exact source bytes. These isolated samples
establish no speed improvement or latency distribution. Baseline log:
`build/scratch/semantic-capsule/codeindex-baseline.log`.

Before claiming improved performance, alternate exact baseline and candidate
runs on identical fixtures, retain every observation and environmental load,
and separately measure full-open, freshness-only and capsule latency.
Token usage and accepted-work cost remain unmeasured.

## Remaining qualification

Release lint initially refused increased complexity in the existing platform
fixture. Focused helpers repaired it without raising its baseline. The affected
registered codeindex group passed again, with zero failures and zero self-skips;
release lint then printed `lint-land: OK`. Logs: `repaired-gate.log` and
`lint-final.log` under the same retained evidence directory. Independent review
accepted the repaired test diff SHA-256
`d968c62e31aed1d275832512e54b425997b9c3e3c0d248b0bea9edbc2c06a5b5`.
Unavailable-generation fault injection and concurrent-publication tests were
not added. Publication and deployment are separate acceptance steps.
