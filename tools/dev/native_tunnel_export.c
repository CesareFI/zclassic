/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Export exact inert optional tunnel source through retained file handles.
 * No child, execution, signing or secrets.
 */
#include "base/safe_alloc.h"
#include "base/hex.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "zsha256/zsha256.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef TUNNEL_EXPORT_TESTING
#include "native_tunnel_export_binding.h"
#endif
struct ex_map {
  const char *source, *target;
};
#define ZCL_TUNNEL_SOURCE(s, t) {s, t},
#define ZCL_TUNNEL_HEADER(s, t) {s, t},
#define ZCL_TUNNEL_INTERNAL(s, t) {s, t},
#define ZCL_TUNNEL_PROGRAM(s, t) {s, t},
#define ZCL_TUNNEL_COPY(s, t) {s, t},
static const struct ex_map ex_map[] = {
#ifdef TUNNEL_EXPORT_TESTING
#ifdef TUNNEL_EXPORT_OFFSOURCE
#include "native_tunnel_export_fixture.def"
#else
#include "../../tests/harness/fixtures/native_tunnel_export_fixture.def"
#endif
#else
#include "native_tunnel_sources.def"
#endif
};
#undef ZCL_TUNNEL_SOURCE
#undef ZCL_TUNNEL_HEADER
#undef ZCL_TUNNEL_INTERNAL
#undef ZCL_TUNNEL_PROGRAM
#undef ZCL_TUNNEL_COPY
#define EX_COUNT (sizeof ex_map / sizeof ex_map[0])
enum { EX_PATH = 1024, EX_DEPTH = 16, EX_MAX_ROWS = 512, EX_CHUNK = 8192 };
#define EX_FILE_MAX (UINT64_C(64) * 1024 * 1024)
#define EX_TOTAL_MAX (UINT64_C(256) * 1024 * 1024)
#define EX_META_MAX (UINT64_C(2) * 1024 * 1024)
struct ex_record {
  struct platform_positioned_file_snapshot before;
  uint8_t digest[32];
  struct platform_directory_child_info copied;
};
struct ex_parent {
  struct platform_directory_transaction chain[EX_DEPTH];
  size_t used;
  struct platform_directory_transaction *value;
  char leaf[256];
};
static const char ex_metadata[] =
    "{\"schema\":1,\"name\":\"zclassic23/"
    "tunnel\",\"semver\":\"0.1.0\",\"language\":\"c23\",\"license\":\"Apache-2."
    "0\",\"include_dir\":\"include\",\"source_dir\":\"src\",\"dependencies\":[]"
    ",\"programs\":[\"app/tunnel.c\"]}\n";
static const char *const ex_generated[] = {
    "EXPORT-PENDING", "SOURCE-MAP.txt", "SOURCE-CANONICAL.sha256",
    "SOURCE.sha256",  "PROVENANCE.txt", "zcode-package.json"};
enum {
  EX_INITIAL = 1,
  EX_COPY_BEGIN,
  EX_COPY_CHUNK,
  EX_AFTER_COPY,
  EX_FINAL,
  EX_BEFORE_UNLINK,
  EX_AFTER_UNLINK,
  EX_PENDING_FLUSH
};
#ifdef TUNNEL_EXPORT_TESTING
int native_tunnel_export_test_hook(unsigned stage, size_t row, const char *root,
                                   const char *out);
#define EX_FAULT(stage, row, root, out)                                        \
  native_tunnel_export_test_hook(stage, row, root, out)
#else
/* Keep test-only scalar/pointer parameters used without evaluating operands. */
#define EX_FAULT(stage, row, root, out) \
  ((void)sizeof(stage), (void)sizeof(row), (void)sizeof(root), (void)sizeof(out), 0)
#endif
static unsigned char ex_lower(unsigned char c) {
  return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}
static bool ex_equal_ci(const char *a, const char *b) {
  while (*a && *b) {
    if (ex_lower((unsigned char)*a++) != ex_lower((unsigned char)*b++))
      return false;
  }
  return *a == *b;
}
static bool ex_prefix(const char *a, const char *b) {
  size_t n = strlen(a);
  if (strlen(b) <= n || b[n] != '/')
    return false;
  for (size_t i = 0; i < n; i++)
    if (ex_lower((unsigned char)a[i]) != ex_lower((unsigned char)b[i]))
      return false;
  return true;
}
static bool ex_device(const char *s, size_t n) {
  char stem[16];
  size_t k = 0;
  while (k < n && s[k] != '.' && k < sizeof stem - 1) {
    stem[k] = (char)ex_lower((unsigned char)s[k]);
    ++k;
  }
  stem[k] = 0;
  return !strcmp(stem, "con") || !strcmp(stem, "prn") || !strcmp(stem, "aux") ||
         !strcmp(stem, "nul") ||
         (k == 4 && (!memcmp(stem, "com", 3) || !memcmp(stem, "lpt", 3)) &&
          stem[3] >= '1' && stem[3] <= '9');
}
static bool ex_character(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}
static bool ex_segment(const char *start, size_t length) {
  return length && length <= 255 && !(length == 1 && start[0] == '.') &&
         !(length == 2 && !memcmp(start, "..", 2)) &&
         start[length - 1] != '.' && !ex_device(start, length);
}
static bool ex_path(const char *s) {
  if (!s || !*s || strlen(s) >= EX_PATH) return false;
  size_t depth = 0;
  const char *p = s;
  while (*p) {
    const char *start = p;
    while (*p && *p != '/') {
      if (!ex_character((unsigned char)*p)) return false;
      ++p;
    }
    if (!ex_segment(start, (size_t)(p - start)) || ++depth > EX_DEPTH) return false;
    if (*p && !*++p) return false;
  }
  return true;
}
static bool ex_oid(const char *s) {
  if (!s || (strlen(s) != 40 && strlen(s) != 64))
    return false;
  bool positive = false;
  for (const char *p = s; *p; p++) {
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
      return false;
    positive |= *p != '0';
  }
  return positive;
}
static bool ex_target_reserved(const char *target) {
  for (size_t j = 0; j < sizeof ex_generated / sizeof ex_generated[0]; ++j)
    if (ex_equal_ci(target, ex_generated[j]) || ex_prefix(ex_generated[j], target) ||
        ex_prefix(target, ex_generated[j])) return true;
  return false;
}
static bool ex_map_pair(const struct ex_map *a, const struct ex_map *b) {
  return !ex_equal_ci(a->source, b->source) && !ex_equal_ci(a->target, b->target) &&
         !ex_prefix(a->target, b->target) && !ex_prefix(b->target, a->target);
}
static bool ex_map_valid(const struct ex_map *map, size_t count) {
  if (!map || !count || count > EX_MAX_ROWS) return false;
  for (size_t i = 0; i < count; ++i) {
    if (!ex_path(map[i].source) || !ex_path(map[i].target) ||
        ex_target_reserved(map[i].target)) return false;
    for (size_t j = 0; j < i; ++j)
      if (!ex_map_pair(&map[i], &map[j])) return false;
  }
  return true;
}
static bool ex_regular_hash(struct platform_positioned_file *f, uint64_t size,
                            uint8_t digest[32]) {
  if (size > EX_FILE_MAX)
    return false;
  zsha256_ctx h;
  zsha256_init(&h);
  uint8_t bytes[EX_CHUNK];
  uint64_t at = 0;
  while (at < size) {
    size_t want = size - at < sizeof bytes ? (size_t)(size - at) : sizeof bytes;
    int64_t got = platform_positioned_file_read(f, bytes, want, at);
    if (got <= 0 || (uint64_t)got > want)
      return false;
    zsha256_update(&h, bytes, (size_t)got);
    at += (uint64_t)got;
  }
  uint8_t extra;
  if (platform_positioned_file_read(f, &extra, 1, at) != 0)
    return false;
  zsha256_final(&h, digest);
  return true;
}
static bool ex_source(const char *root, const char *path,
                      struct platform_positioned_file_snapshot *before,
                      uint8_t digest[32]) {
  struct platform_positioned_file f;
  platform_positioned_file_init(&f);
  struct platform_positioned_file_snapshot after;
  bool ok = platform_positioned_file_open_beneath(&f, root, path) &&
            platform_positioned_file_snapshot(&f, before) &&
            ex_regular_hash(&f, before->size, digest) &&
            platform_positioned_file_snapshot(&f, &after) &&
            platform_positioned_file_snapshot_equal(before, &after);
  platform_positioned_file_close(&f);
  return ok;
}
static bool ex_child_same(const struct platform_directory_child_info *before,
                          const struct platform_directory_child_info *after) {
  return before->size == after->size && before->volume == after->volume &&
         before->file_low == after->file_low && before->file_high == after->file_high &&
         before->modified_seconds == after->modified_seconds &&
         before->modified_nanoseconds == after->modified_nanoseconds &&
         before->changed_seconds == after->changed_seconds &&
         before->changed_nanoseconds == after->changed_nanoseconds && after->link_count == 1;
}
static bool ex_child_hash(struct platform_directory_child *f, uint8_t digest[32],
                          struct platform_directory_child_info *info) {
  struct platform_directory_child_info after;
  if (!platform_directory_child_info(f, info) || info->size > EX_FILE_MAX ||
      info->link_count != 1) return false;
  zsha256_ctx h; zsha256_init(&h);
  uint8_t bytes[EX_CHUNK]; uint64_t at = 0;
  while (at < info->size) {
    size_t want = info->size - at < sizeof bytes ? (size_t)(info->size - at) : sizeof bytes;
    int64_t got = platform_directory_child_read(f, bytes, want, at);
    if (got <= 0 || (uint64_t)got > want) return false;
    zsha256_update(&h, bytes, (size_t)got); at += (uint64_t)got;
  }
  uint8_t extra;
  if (platform_directory_child_read(f, &extra, 1, at) != 0 ||
      !platform_directory_child_info(f, &after) || !ex_child_same(info, &after)) return false;
  zsha256_final(&h, digest); return true;
}
static bool ex_line(struct platform_directory_child *f, uint64_t *at,
                    zsha256_ctx *expected, const char *fmt, ...) {
  char line[EX_PATH * 2 + 128];
  va_list a;
  va_start(a, fmt);
  int n = vsnprintf(line, sizeof line, fmt, a);
  va_end(a);
  if (n < 0 || (size_t)n >= sizeof line || (uint64_t)n > EX_META_MAX - *at)
    return false;
  if (!platform_directory_child_write_exact(f, line, (size_t)n, *at))
    return false;
  zsha256_update(expected, line, (size_t)n);
  *at += (uint64_t)n;
  return true;
}
static void ex_parent_close(struct ex_parent *p) {
  while (p->used)
    platform_directory_transaction_close(&p->chain[--p->used]);
}
static bool ex_parent_open(struct ex_parent *p,
                           struct platform_directory_transaction *root,
                           const char *path, bool create) {
  memset(p, 0, sizeof *p);
  for (size_t i = 0; i < EX_DEPTH; i++)
    platform_directory_transaction_init(&p->chain[i]);
  p->value = root;
  char text[EX_PATH];
  int n = snprintf(text, sizeof text, "%s", path);
  if (n < 0 || (size_t)n >= sizeof text)
    return false;
  char *segment = text;
  char *slash;
  while ((slash = strchr(segment, '/'))) {
    *slash = 0;
    if (p->used == EX_DEPTH ||
        platform_directory_transaction_open_child(p->value, segment, create,
                                                  &p->chain[p->used]) !=
            PLATFORM_DIRECTORY_OK) {
      ex_parent_close(p);
      return false;
    }
    if (create && !platform_directory_transaction_flush(p->value)) {
      ++p->used;
      ex_parent_close(p);
      return false;
    }
    p->value = &p->chain[p->used++];
    segment = slash + 1;
  }
  n = snprintf(p->leaf, sizeof p->leaf, "%s", segment);
  return n > 0 && (size_t)n < sizeof p->leaf;
}
static bool
ex_named_output(const char *out, const char *path,
                const struct platform_directory_child_info *expected,
                const uint8_t digest[32]) {
  struct platform_positioned_file_snapshot snap;
  uint8_t seen[32];
  return ex_source(out, path, &snap, seen) && snap.volume == expected->volume &&
         snap.file_low == expected->file_low &&
         snap.file_high == expected->file_high && snap.size == expected->size &&
         !memcmp(seen, digest, 32);
}
static bool ex_copy_stream(struct platform_positioned_file *source,
    struct platform_directory_child *dest, uint64_t size, uint8_t digest[32],
    size_t row, const char *root, const char *out) {
  zsha256_ctx h; zsha256_init(&h);
  uint8_t bytes[EX_CHUNK]; uint64_t at = 0;
  while (at < size) {
    size_t want = size - at < sizeof bytes ? (size_t)(size - at) : sizeof bytes;
    int64_t got = platform_positioned_file_read(source, bytes, want, at);
    if (got <= 0 || (uint64_t)got > want ||
        !platform_directory_child_write_exact(dest, bytes, (size_t)got, at)) return false;
    zsha256_update(&h, bytes, (size_t)got); at += (uint64_t)got;
    if (EX_FAULT(EX_COPY_CHUNK, row, root, out)) return false;
  }
  uint8_t extra;
  if (platform_positioned_file_read(source, &extra, 1, at) != 0) return false;
  zsha256_final(&h, digest); return true;
}
static bool ex_copy_admit(struct platform_positioned_file *source, struct ex_parent *parent,
    struct platform_directory_child *dest, struct platform_directory_transaction *output,
    const char *root, const char *out, size_t row, const struct ex_record *record,
    struct platform_positioned_file_snapshot *before) {
  return !EX_FAULT(EX_COPY_BEGIN, row, root, out) &&
         platform_positioned_file_open_beneath(source, root, ex_map[row].source) &&
         platform_positioned_file_snapshot(source, before) &&
         platform_positioned_file_snapshot_equal(before, &record->before) &&
         ex_parent_open(parent, output, ex_map[row].target, true) &&
         platform_directory_child_create(parent->value, parent->leaf, dest);
}
static bool ex_copy_verify(struct platform_directory_child *dest,
    const char *root, const char *out, size_t row, struct ex_record *record,
    uint8_t digest[32]) {
  struct platform_directory_child_info copied;
  if (memcmp(digest, record->digest, 32) || !platform_directory_child_flush(dest) ||
      EX_FAULT(EX_AFTER_COPY, row, root, out) || !ex_child_hash(dest, digest, &copied) ||
      memcmp(digest, record->digest, 32) || !ex_named_output(out, ex_map[row].target, &copied, digest))
    return false;
  record->copied = copied; return true;
}
static bool ex_copy(struct platform_directory_transaction *output, const char *root,
    const char *out, size_t row, struct ex_record *record) {
  struct platform_positioned_file source; platform_positioned_file_init(&source);
  struct platform_directory_child dest; platform_directory_child_init(&dest);
  struct ex_parent parent = {0};
  struct platform_positioned_file_snapshot before, after; uint8_t digest[32];
  bool ok = ex_copy_admit(&source, &parent, &dest, output, root, out, row, record, &before) &&
            ex_copy_stream(&source, &dest, before.size, digest, row, root, out) &&
            platform_positioned_file_snapshot(&source, &after) &&
            platform_positioned_file_snapshot_equal(&before, &after) &&
            ex_copy_verify(&dest, root, out, row, record, digest);
  platform_positioned_file_close(&source); platform_directory_child_close(&dest);
  ex_parent_close(&parent); return ok;
}
static bool ex_root_real(const char *root) {
  char probe[EX_PATH], resolved[EX_PATH], parent[EX_PATH];
  int n = snprintf(probe, sizeof probe, "%s/.tunnel-export-root-probe", root);
  return n > 0 && (size_t)n < sizeof probe &&
         platform_private_path_resolve(probe, resolved, sizeof resolved, parent,
                                       sizeof parent) &&
         !strcmp(parent, root);
}
struct ex_job {
  const char *root, *out, *head, *phase, *item;
  int result; bool made;
  struct ex_record *record;
  struct platform_directory_transaction output;
  struct platform_directory_child meta[6];
  uint64_t offset[6]; zsha256_ctx expected_meta[6];
  struct platform_positioned_file_snapshot descriptor;
  char parent[EX_PATH];
};
static void ex_job_init(struct ex_job *job, const char *root, const char *out, const char *head) {
  *job = (struct ex_job){.root = root, .out = out, .head = head,
                        .phase = "input", .item = "", .result = 1};
  platform_directory_transaction_init(&job->output);
  for (size_t j = 0; j < 6; ++j) {
    platform_directory_child_init(&job->meta[j]); zsha256_init(&job->expected_meta[j]);
  }
}
static bool ex_input_arguments(const struct ex_job *job) {
  return job->root && job->out && ex_oid(job->head) && EX_COUNT > 0 &&
         EX_COUNT <= EX_MAX_ROWS && strlen(job->root) < EX_PATH && strlen(job->out) < EX_PATH;
}
static bool ex_input_paths(struct ex_job *job) {
  char resolved[EX_PATH];
  return ex_root_real(job->root) &&
         platform_private_path_resolve(job->out, resolved, sizeof resolved,
                                       job->parent, sizeof job->parent) &&
         !strcmp(resolved, job->out) && platform_private_path_absent(job->out);
}
static bool ex_descriptor_initial(struct ex_job *job) {
  uint8_t hash[32]; char text[65];
  if (!ex_source(job->root, "tools/native_tunnel_sources.def", &job->descriptor, hash))
    return false;
  zcl_hex_encode(hash, 32, text);
  return strlen(TUNNEL_DESCRIPTOR_SHA256) == 64 && !strcmp(text, TUNNEL_DESCRIPTOR_SHA256);
}
static bool ex_preflight(struct ex_job *job) {
  if (!ex_input_arguments(job) || !ex_input_paths(job)) {
    job->result = 2; return false;
  }
  job->phase = "map";
  if (!ex_map_valid(ex_map, EX_COUNT)) return false;
  job->phase = "descriptor-binding";
  return ex_descriptor_initial(job);
}
static bool ex_initial_sources(struct ex_job *job) {
  job->record = zcl_calloc(EX_COUNT, sizeof *job->record, "native.tunnel.export.snapshot");
  if (!job->record) { job->phase = "allocation"; return false; }
  job->phase = "initial-source"; uint64_t total = 0;
  for (size_t i = 0; i < EX_COUNT; ++i) {
    job->item = ex_map[i].source;
    struct ex_record *record = &job->record[i];
    if (!ex_source(job->root, job->item, &record->before, record->digest) ||
        record->before.size > EX_TOTAL_MAX - total ||
        EX_FAULT(EX_INITIAL, i, job->root, job->out)) return false;
    total += record->before.size;
  }
  return true;
}
static bool ex_create_output(struct ex_job *job) {
  job->phase = "destination";
  if (!platform_private_directory_create(job->out)) return false;
  job->made = true;
  if (!platform_private_parent_flush(job->parent) ||
      !platform_directory_transaction_open(&job->output, job->out)) return false;
  job->phase = "pending";
  return platform_directory_child_create(&job->output, ex_generated[0], &job->meta[0]) &&
         ex_line(&job->meta[0], &job->offset[0], &job->expected_meta[0],
                 "incomplete public source export; inspect before use\n") &&
         !EX_FAULT(EX_PENDING_FLUSH, 0, job->root, job->out) &&
         platform_directory_child_flush(&job->meta[0]) &&
         platform_directory_transaction_flush(&job->output);
}
static bool ex_metadata_create(struct ex_job *job) {
  job->phase = "metadata-create";
  for (size_t j = 1; j < 6; ++j)
    if (!platform_directory_child_create(&job->output, ex_generated[j], &job->meta[j]))
      return false;
  return true;
}
static bool ex_copy_all(struct ex_job *job) {
  job->phase = "copy";
  for (size_t i = 0; i < EX_COUNT; ++i) {
    job->item = ex_map[i].source; char text[65];
    zcl_hex_encode(job->record[i].digest, 32, text);
    if (!ex_line(&job->meta[1], &job->offset[1], &job->expected_meta[1], "%s %s\n",
                 ex_map[i].source, ex_map[i].target) ||
        !ex_line(&job->meta[2], &job->offset[2], &job->expected_meta[2], "%s  %s\n",
                 text, ex_map[i].source) ||
        !ex_copy(&job->output, job->root, job->out, i, &job->record[i]) ||
        !ex_line(&job->meta[3], &job->offset[3], &job->expected_meta[3], "%s  %s\n",
                 text, ex_map[i].target)) return false;
  }
  return true;
}
static bool ex_metadata_checksum(struct ex_job *job, size_t index) {
  uint8_t hash[32], expected_hash[32]; char text[65];
  struct platform_directory_child_info info;
  if (!platform_directory_child_flush(&job->meta[index]) ||
      !ex_child_hash(&job->meta[index], hash, &info)) return false;
  zsha256_ctx expected = job->expected_meta[index]; zsha256_final(&expected, expected_hash);
  if (memcmp(hash, expected_hash, 32)) return false;
  zcl_hex_encode(hash, 32, text);
  return ex_line(&job->meta[3], &job->offset[3], &job->expected_meta[3],
                 "%s  %s\n", text, ex_generated[index]);
}
static bool ex_metadata_write(struct ex_job *job) {
  job->phase = "metadata-write";
  if (!ex_line(&job->meta[4], &job->offset[4], &job->expected_meta[4],
               "source_head=%s\nsource_model=exact_exported_bytes_not_commit_only\n", job->head) ||
      !ex_line(&job->meta[5], &job->offset[5], &job->expected_meta[5], "%s", ex_metadata))
    return false;
  static const size_t included[] = {1, 2, 4, 5};
  for (size_t j = 0; j < sizeof included / sizeof included[0]; ++j)
    if (!ex_metadata_checksum(job, included[j])) return false;
  return platform_directory_child_flush(&job->meta[3]);
}
static bool ex_verify_copy(struct ex_job *job, size_t row) {
  struct ex_parent parent; struct platform_directory_child file;
  platform_directory_child_init(&file);
  bool opened = ex_parent_open(&parent, &job->output, ex_map[row].target, false);
  struct platform_directory_child_info info; uint8_t hash[32];
  const struct ex_record *record = &job->record[row];
  bool ok = opened && platform_directory_child_open(parent.value, parent.leaf, &file) &&
            ex_child_hash(&file, hash, &info) && info.volume == record->copied.volume &&
            info.file_low == record->copied.file_low && info.file_high == record->copied.file_high &&
            !memcmp(hash, record->digest, 32) &&
            ex_named_output(job->out, ex_map[row].target, &info, hash);
  platform_directory_child_close(&file); ex_parent_close(&parent); return ok;
}
static bool ex_final_sources(struct ex_job *job) {
  job->phase = "final-source";
  for (size_t i = 0; i < EX_COUNT; ++i) {
    job->item = ex_map[i].source;
    struct platform_positioned_file_snapshot current; uint8_t hash[32];
    if (EX_FAULT(EX_FINAL, i, job->root, job->out) ||
        !ex_source(job->root, job->item, &current, hash) ||
        !platform_positioned_file_snapshot_equal(&job->record[i].before, &current) ||
        memcmp(hash, job->record[i].digest, 32) || !ex_verify_copy(job, i)) return false;
  }
  return true;
}
static bool ex_final_descriptor(struct ex_job *job) {
  job->phase = "final-descriptor";
  struct platform_positioned_file_snapshot current; uint8_t hash[32]; char text[65];
  if (!ex_source(job->root, "tools/native_tunnel_sources.def", &current, hash) ||
      !platform_positioned_file_snapshot_equal(&job->descriptor, &current)) return false;
  zcl_hex_encode(hash, 32, text); return !strcmp(text, TUNNEL_DESCRIPTOR_SHA256);
}
static bool ex_final_metadata(struct ex_job *job) {
  job->phase = "final-metadata";
  for (size_t j = 0; j < 6; ++j) {
    struct platform_directory_child_info info; uint8_t hash[32], expected_hash[32];
    zsha256_ctx expected = job->expected_meta[j]; zsha256_final(&expected, expected_hash);
    if (!ex_child_hash(&job->meta[j], hash, &info) || memcmp(hash, expected_hash, 32) ||
        !ex_named_output(job->out, ex_generated[j], &info, hash)) return false;
  }
  return true;
}
static bool ex_complete(struct ex_job *job) {
  if (!platform_directory_transaction_flush(&job->output) ||
      EX_FAULT(EX_BEFORE_UNLINK, 0, job->root, job->out)) return false;
  job->phase = "completion-unconfirmed";
  enum platform_directory_result retired =
      platform_directory_child_unlink_result(&job->output, ex_generated[0]);
  if (retired != PLATFORM_DIRECTORY_OK) {
    fprintf(stderr, "export namespace_result=%u; marker may be absent, completion unconfirmed\n",
            (unsigned)retired);
    job->result = 3; return false;
  }
  if (EX_FAULT(EX_AFTER_UNLINK, 0, job->root, job->out) ||
      !platform_directory_transaction_flush(&job->output)) {
    job->result = 3; return false;
  }
  job->result = 0; return true;
}
static int ex_run(const char *root, const char *out, const char *head) {
  struct ex_job job; ex_job_init(&job, root, out, head);
  if (!ex_preflight(&job)) goto done;
  if (!ex_initial_sources(&job) || !ex_create_output(&job) || !ex_metadata_create(&job) ||
      !ex_copy_all(&job) || !ex_metadata_write(&job) || !ex_final_sources(&job) ||
      !ex_final_descriptor(&job) || !ex_final_metadata(&job) || !ex_complete(&job)) goto done;
done:
  for (size_t j = 0; j < 6; ++j) platform_directory_child_close(&job.meta[j]);
  platform_directory_transaction_close(&job.output); free(job.record);
  if (job.result)
    fprintf(stderr, "error=TUNNEL_EXPORT_FAILED phase=%s item=%s destination_created=%u result=%d\n",
            job.phase, job.item, (unsigned)job.made, job.result);
  return job.result;
}
int main(int argc, char **argv) {
  if (argc != 7 || strcmp(argv[1], "--root") || strcmp(argv[3], "--out") ||
      strcmp(argv[5], "--source-head")) {
    fprintf(stderr, "usage: native-tunnel-export --root ABS_REAL_ROOT --out "
                    "ABS_ABSENT_DEST --source-head OBSERVED_FULL_OID\n");
    return 2;
  }
  return ex_run(argv[2], argv[4], argv[6]);
}
