/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Verify bounded canonical exporter snapshots, completion and refusal fixtures. */
#include "test/test_core.h"
#define TUNNEL_EXPORT_TESTING
#define TUNNEL_DESCRIPTOR_SHA256                                               \
  "fd29dfd7f269f64cfb769233a6244fd99c5143e220c3c6ac0e5b8e9cc90ac958"
#define main native_tunnel_export_test_entry
int native_tunnel_export_test_entry(int argc, char **argv);
#ifdef TUNNEL_EXPORT_OFFSOURCE
#include "native_tunnel_export.c"
#else
#include "../../../tools/dev/native_tunnel_export.c"
#endif
#undef main
static unsigned fault;
static bool fired;
static const char fixture_descriptor[] =
    "/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */\n"
    "ZCL_TUNNEL_PROGRAM(\"src/main.c\",\"app/tunnel.c\")\n"
    "ZCL_TUNNEL_HEADER(\"include/demo.h\",\"include/demo.h\")\n"
    "ZCL_TUNNEL_COPY(\"tools/"
    "native_tunnel_sources.def\",\"SOURCE-DESCRIPTOR.def\")\n";
static bool fixture_write(const char *path, const void *data, size_t size) {
  FILE *f = fopen(path, "wb");
  if (!f)
    return false;
  bool ok = fwrite(data, 1, size, f) == size;
  if (fclose(f))
    ok = false;
  return ok;
}
static bool fixture_paths(const char *base, char root[1024], char out[1024]) {
  int a = snprintf(root, 1024, "%s/root", base),
      b = snprintf(out, 1024, "%s/out", base);
  return a > 0 && a < 1024 && b > 0 && b < 1024;
}
static bool fixture_root(const char *root) {
  if (!platform_private_directory_create(root))
    return false;
  char path[1200];
  const char *dirs[] = {"src", "include", "tools"};
  for (size_t i = 0; i < 3; i++) {
    snprintf(path, sizeof path, "%s/%s", root, dirs[i]);
    if (!platform_private_directory_create(path))
      return false;
  }
  char source[16384];
  memset(source, 'a', sizeof source);
  static const char prefix[] = "int main(void){return 0;}\n/*";
  memcpy(source, prefix, sizeof prefix - 1);
  memcpy(source + sizeof source - 3, "*/\n", 3);
  snprintf(path, sizeof path, "%s/src/main.c", root);
  if (!fixture_write(path, source, sizeof source))
    return false;
  snprintf(path, sizeof path, "%s/include/demo.h", root);
  if (!fixture_write(path, "/* public fixture */\n", 21))
    return false;
  snprintf(path, sizeof path, "%s/tools/native_tunnel_sources.def", root);
  return fixture_write(path, fixture_descriptor, sizeof fixture_descriptor - 1);
}
static int fixture_change_source(const char *root, const char *out) {
  (void)out; char path[1200];
  snprintf(path, sizeof path, "%s/src/main.c", root);
  return fixture_write(path, "changed", 7) ? 0 : 1;
}
static int fixture_stage_error(const char *root, const char *out) {
  (void)root; (void)out; return 1;
}
static int fixture_tamper_output(const char *root, const char *out) {
  (void)root; char path[1200];
  snprintf(path, sizeof path, "%s/app/tunnel.c", out);
  return fixture_write(path, "tampered", 8) ? 0 : 1;
}
static int fixture_tamper_metadata(const char *root, const char *out) {
  (void)root; char path[1200];
  snprintf(path, sizeof path, "%s/zcode-package.json", out);
  return fixture_write(path, "tampered", 8) ? 0 : 1;
}
static int fixture_source_aba(const char *root, const char *out) {
  (void)out; char path[1200], old[1200];
  snprintf(path, sizeof path, "%s/src/main.c", root);
  snprintf(old, sizeof old, "%s/src/old.c", root);
  if (rename(path, old)) return 1;
  FILE *file = fopen(old, "rb");
  if (!file) return 1;
  char original[16384];
  bool ok = fread(original, 1, sizeof original, file) == sizeof original && fgetc(file) == EOF;
  if (fclose(file)) ok = false;
  return ok && fixture_write(path, original, sizeof original) ? 0 : 1;
}
static int fixture_namespace_swap(const char *root, const char *out) {
  (void)root; char moved[1200];
  snprintf(moved, sizeof moved, "%s-moved", out);
  return rename(out, moved) == 0 && platform_private_directory_create(out) ? 0 : 1;
}
struct fixture_fault {
  unsigned kind, stage;
  int (*apply)(const char *, const char *);
};
int native_tunnel_export_test_hook(unsigned stage, size_t row, const char *root, const char *out) {
  static const struct fixture_fault faults[] = {
    {1, EX_COPY_BEGIN, fixture_change_source}, {2, EX_COPY_CHUNK, fixture_stage_error},
    {3, EX_AFTER_COPY, fixture_tamper_output}, {4, EX_FINAL, fixture_tamper_metadata},
    {5, EX_BEFORE_UNLINK, fixture_stage_error}, {6, EX_AFTER_UNLINK, fixture_stage_error},
    {12, EX_COPY_BEGIN, fixture_source_aba}, {13, EX_FINAL, fixture_namespace_swap},
    {14, EX_PENDING_FLUSH, fixture_stage_error}
  };
  if (fired || row != 0) return 0;
  for (size_t i = 0; i < sizeof faults / sizeof faults[0]; ++i) {
    if (fault != faults[i].kind || stage != faults[i].stage) continue;
    fired = true; return faults[i].apply(root, out);
  }
  return 0;
}
#if !defined(_WIN32)
static bool fixture_link_source(const char *root, unsigned kind) {
  char path[1200];
  snprintf(path, sizeof path, "%s/src/main.c", root);
  if (kind == 9) return unlink(path) == 0 && symlink("../include/demo.h", path) == 0;
  snprintf(path, sizeof path, "%s/include/main.c", root);
  if (!fixture_write(path, "public link target", 18)) return false;
  snprintf(path, sizeof path, "%s/src/main.c", root);
  if (unlink(path) != 0) return false;
  snprintf(path, sizeof path, "%s/src", root);
  return rmdir(path) == 0 && symlink("include", path) == 0;
}
#endif
static bool fixture_prepare_fault(const char *root, const char *out, unsigned kind) {
  char path[1200];
  if (kind == 7) {
    snprintf(path, sizeof path, "%s/tools/native_tunnel_sources.def", root);
    return fixture_write(path, "stale", 5);
  }
  if (kind == 8) return platform_private_directory_create(out);
#if !defined(_WIN32)
  if (kind == 9 || kind == 10) return fixture_link_source(root, kind);
#endif
  if (kind == 11) zcl_alloc_fault_fail_next("native.tunnel.export.snapshot");
  return true;
}
static bool fixture_success(const char *base, const char *root, const char *out) {
  char other[1024];
  snprintf(other, sizeof other, "%s/other", base);
  if (ex_run(root, other, "1111111111111111111111111111111111111111") != 0) return false;
  for (size_t j = 1; j < 6; ++j) {
    uint8_t a[32], b[32]; struct platform_positioned_file_snapshot x, y;
    if (!ex_source(out, ex_generated[j], &x, a) || !ex_source(other, ex_generated[j], &y, b) ||
        memcmp(a, b, 32)) return false;
  }
  struct platform_positioned_file file; platform_positioned_file_init(&file);
  uint8_t metadata[sizeof ex_metadata];
  bool ok = platform_positioned_file_open_beneath(&file, out, "zcode-package.json") &&
            platform_positioned_file_read(&file, metadata, sizeof ex_metadata - 1, 0) ==
              (int64_t)(sizeof ex_metadata - 1) &&
            !memcmp(metadata, ex_metadata, sizeof ex_metadata - 1);
  platform_positioned_file_close(&file); return ok;
}
static bool fixture_failure(unsigned kind, int result, bool pending, const char *out) {
  if (kind <= 5 || kind == 12 || kind == 14) return result == 1 && pending && fired;
  if (kind == 6) return result == 3 && !pending && fired;
  if (kind == 8) return result == 2 && !pending;
  if (kind == 13) {
    char path[1200]; snprintf(path, sizeof path, "%s-moved/EXPORT-PENDING", out);
    return result == 1 && fired && !platform_private_path_absent(path);
  }
  return result != 0 && platform_private_path_absent(out);
}
static bool fixture_case(unsigned kind) {
  char base[768] = {0}, root[1024], out[1024], path[1200];
  if (!test_mkdtemp(base, sizeof base, "tunnel-export")) return false;
  bool ok = fixture_paths(base, root, out) && fixture_root(root);
  fault = kind; fired = false;
  if (ok) ok = fixture_prepare_fault(root, out, kind);
  int result = ok ? ex_run(root, out, "1111111111111111111111111111111111111111") : -99;
  bool allocation_consumed = zcl_alloc_fault_armed_label() == NULL;
  zcl_alloc_fault_clear();
  if (kind == 11 && !allocation_consumed) ok = false;
  snprintf(path, sizeof path, "%s/EXPORT-PENDING", out);
  bool pending = !platform_private_path_absent(path);
  if (kind == 0) ok = ok && result == 0 && !pending && fixture_success(base, root, out);
  else ok = ok && fixture_failure(kind, result, pending, out);
  fault = 0;
  bool cleaned = test_rm_rf_recursive(base) == 0;
  return ok && cleaned;
}
static int fixture_stable(void) {
  int failures = 0;
  TEST_CASE("native tunnel export: stable exact metadata/hash manifests and "
            "existing output refusal") {
    ASSERT(fixture_case(0));
    ASSERT(fixture_case(8));
  }
  TEST_END
  return failures;
}
static int fixture_preflight(void) {
  int failures = 0;
  TEST_CASE("native tunnel export: stale descriptor, linked source paths and "
            "allocation refuse before output effects") {
    ASSERT(fixture_case(7));
    ASSERT(fixture_case(11));
#if !defined(_WIN32)
    ASSERT(fixture_case(9));
    ASSERT(fixture_case(10));
#endif
  }
  TEST_END
  return failures;
}
static int fixture_interruption(void) {
  int failures = 0;
  TEST_CASE("native tunnel export: source/output/metadata tamper and "
            "partial-copy failures retain pending") {
    for (unsigned i = 1; i <= 5; i++)
      ASSERT(fixture_case(i));
    ASSERT(fixture_case(12));
    ASSERT(fixture_case(13));
    ASSERT(fixture_case(14));
  }
  TEST_END
  return failures;
}
static int fixture_completion_unknown(void) {
  int failures = 0;
  TEST_CASE("native tunnel export: last namespace confirmation failure is "
            "unconfirmed, not complete") {
    ASSERT(fixture_case(6));
  }
  TEST_END
  return failures;
}
static int fixture_ambiguous_map(void) {
  int failures = 0;
  TEST_CASE("native tunnel export: ambiguous paths, duplicate targets and "
            "reserved metadata rejected") {
    struct ex_map bad[2] = {{"src/a.c", "include/a.h"},
                            {"src/b.c", "include/a.h"}};
    ASSERT(!ex_map_valid(bad, 2));
    bad[1].target = "include/a.h/child";
    ASSERT(!ex_map_valid(bad, 2));
    bad[1].target = "SOURCE.sha256";
    ASSERT(!ex_map_valid(bad, 2));
    bad[1].target = "../escape";
    ASSERT(!ex_map_valid(bad, 2));
    bad[1].target = "include/CON.h";
    ASSERT(!ex_map_valid(bad, 2));
  }
  TEST_END
  return failures;
}
int test_native_tunnel_export(void);
int test_native_tunnel_export(void) {
  return fixture_stable() + fixture_preflight() + fixture_interruption() + fixture_completion_unknown() + fixture_ambiguous_map();
}
