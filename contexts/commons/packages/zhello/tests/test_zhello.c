/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic known-answer test for the zhello painter. */
#include "zhello/zhello.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int io_failure_mode;
static int io_getc(FILE *stream)
{
	return io_failure_mode == 1 ? EOF : fgetc(stream);
}
static int io_error(FILE *stream)
{
	return io_failure_mode == 1 ? 1 : ferror(stream);
}
static int io_close(FILE *stream)
{
	const int result = fclose(stream);
	return io_failure_mode == 2 ? EOF : result;
}
#define zhello_world_init probe_init
#define zhello_world_step probe_step
#define zhello_render probe_render
#define zhello_canvas_digest probe_digest
#define zhello_world_save probe_save
#define zhello_world_load probe_load
#define fgetc io_getc
#define ferror io_error
#define fclose io_close
#include "../src/zhello.c"
#undef fclose
#undef ferror
#undef fgetc
#undef zhello_world_load
#undef zhello_world_save
#undef zhello_canvas_digest
#undef zhello_render
#undef zhello_world_step
#undef zhello_world_init

enum { TEST_WIDTH = 96, TEST_HEIGHT = 96 };

#define CHECK(cond) do { \
	if (!(cond)) { \
		(void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		return 1; \
	} \
} while (0)

int main(void)
{
	(void)io_error;
	const struct zhello_canvas empty_canvas = {NULL, 0, 0};
	uint8_t zero_pixel[4] = {0};
	const struct zhello_canvas one_pixel = {zero_pixel, 1, 1};
	CHECK(zhello_canvas_digest(&empty_canvas) == UINT64_C(14695981039346656037));
	CHECK(zhello_canvas_digest(&one_pixel) == UINT64_C(5558979605539197941));
	static uint8_t pixels_a[TEST_WIDTH * TEST_HEIGHT * ZHELLO_PIXEL_BYTES];
	static uint8_t pixels_b[TEST_WIDTH * TEST_HEIGHT * ZHELLO_PIXEL_BYTES];
	struct zhello_world world_a;
	struct zhello_world world_b;
	const struct zhello_canvas canvas_a = { pixels_a, TEST_WIDTH, TEST_HEIGHT };
	const struct zhello_canvas canvas_b = { pixels_b, TEST_WIDTH, TEST_HEIGHT };

	zhello_world_init(&world_a, TEST_WIDTH, TEST_HEIGHT);
	zhello_world_init(&world_b, TEST_WIDTH, TEST_HEIGHT);
	zhello_world_step(&world_a, TEST_WIDTH, TEST_HEIGHT, ZHELLO_TEST_DT_SECONDS);
	zhello_world_step(&world_b, TEST_WIDTH, TEST_HEIGHT, ZHELLO_TEST_DT_SECONDS);
	zhello_render(&world_a, &canvas_a, 16u);
	zhello_render(&world_b, &canvas_b, 16u);

	CHECK(world_a.frames == 1u);
	CHECK(memcmp(pixels_a, pixels_b, sizeof pixels_a) == 0);
	for (size_t i = 3u; i < sizeof pixels_a; i += ZHELLO_PIXEL_BYTES)
		CHECK(pixels_a[i] == 0xffu);
	const uint64_t digest = zhello_canvas_digest(&canvas_a);
	if (digest != UINT64_C(7127855221134341213)) {
		(void)fprintf(stderr, "zhello KAT digest=%llu\n",
			      (unsigned long long)digest);
		return 1;
	}
	/* ── close and reopen ────────────────────────────────────────────
	 *
	 * The claim is not "a file was written". It is that stopping and
	 * starting again lands in the same place as never having stopped,
	 * so it is stated as an equality between two runs. */
	const char *const state_path = "zhello-state.test.tmp";
	(void)remove(state_path);

	/* A first run has no file, and that is not a failure. */
	struct zhello_world fresh;
	bool missing = false;
	CHECK(!zhello_world_load(&fresh, state_path, &missing));
	CHECK(missing);

	/* Run A: thirty steps, then close. */
	struct zhello_world closed;
	zhello_world_init(&closed, TEST_WIDTH, TEST_HEIGHT);
	for (int i = 0; i < 30; i++)
		zhello_world_step(&closed, TEST_WIDTH, TEST_HEIGHT,
				  ZHELLO_TEST_DT_SECONDS);
	CHECK(zhello_world_save(&closed, state_path));

	/* Reopen: every field comes back exactly, bit for bit. A position is
	 * carried as its binary64 pattern precisely so this can be memcmp and
	 * not "close enough". */
	struct zhello_world reopened;
	missing = true;
	CHECK(zhello_world_load(&reopened, state_path, &missing));
	CHECK(!missing);
	CHECK(memcmp(&reopened, &closed, sizeof reopened) == 0);

	/* Thirty more steps after reopening == sixty steps in one sitting. */
	struct zhello_world uninterrupted;
	zhello_world_init(&uninterrupted, TEST_WIDTH, TEST_HEIGHT);
	for (int i = 0; i < 60; i++)
		zhello_world_step(&uninterrupted, TEST_WIDTH, TEST_HEIGHT,
				  ZHELLO_TEST_DT_SECONDS);
	for (int i = 0; i < 30; i++)
		zhello_world_step(&reopened, TEST_WIDTH, TEST_HEIGHT,
				  ZHELLO_TEST_DT_SECONDS);
	CHECK(reopened.frames == 60u);
	CHECK(memcmp(&reopened, &uninterrupted, sizeof reopened) == 0);

	/* A damaged file is refused, never folded into "start over": that is
	 * how a person's state disappears with nobody told. `missing` stays
	 * false, so the caller can tell the two apart. */
	bool io_failed = false;
	for (int mode = 1; mode <= 2; mode++) {
		struct zhello_world failed_io = closed;
		failed_io.x += 7.0;
		failed_io.frames += 9u;
		const struct zhello_world previous = failed_io;
		missing = true;
		io_failure_mode = mode;
		if (probe_load(&failed_io, state_path, &missing) || missing ||
		    memcmp(&failed_io, &previous, sizeof failed_io) != 0) {
			(void)fprintf(stderr, "FAIL saved-state I/O refusal mode=%d\n", mode);
			io_failed = true;
		}
	}
	io_failure_mode = 0;
	CHECK(!io_failed);
	/* A valid header must not turn nonfinite saved coordinates into a
	 * world that the painter cannot convert to integer pixel positions. */
	FILE *nonfinite = fopen(state_path, "r+b");
	CHECK(nonfinite != NULL);
	const uint8_t quiet_nan[8] = {0, 0, 0, 0, 0, 0, 0xf8, 0x7f};
	CHECK(fseek(nonfinite, 10, SEEK_SET) == 0);
	CHECK(fwrite(quiet_nan, 1, sizeof quiet_nan, nonfinite) == sizeof quiet_nan);
	CHECK(fclose(nonfinite) == 0);
	struct zhello_world refused = closed;
	missing = true;
	CHECK(!zhello_world_load(&refused, state_path, &missing));
	CHECK(!missing);
	CHECK(memcmp(&refused, &closed, sizeof refused) == 0);
	CHECK(zhello_world_save(&closed, state_path));
	FILE *bad = fopen(state_path, "r+b");
	CHECK(bad != NULL);
	CHECK(fseek(bad, 3, SEEK_SET) == 0);
	CHECK(fputc('X', bad) != EOF);
	CHECK(fclose(bad) == 0);
	struct zhello_world damaged;
	missing = true;
	CHECK(!zhello_world_load(&damaged, state_path, &missing));
	CHECK(!missing);

	/* A file of the right shape but the wrong length is refused too — a
	 * truncated write must not read back as a shorter, valid world. */
	FILE *cut = fopen(state_path, "wb");
	CHECK(cut != NULL);
	CHECK(fwrite(&closed, 1, 4, cut) == 4);
	CHECK(fclose(cut) == 0);
	missing = true;
	CHECK(!zhello_world_load(&damaged, state_path, &missing));
	CHECK(!missing);
	CHECK(remove(state_path) == 0);

	(void)printf("zhello package test PASS digest=%llu\n",
		     (unsigned long long)digest);
	return 0;
}
