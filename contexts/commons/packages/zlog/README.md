# zlog

Small leveled logging sink for C23.

- Six levels (trace..error, plus off) with per-sink thresholds.
- Caller-injected `emit` callback — no stdio dependency in the core.
- Bounded line assembly: "LEVEL tag message\n", long messages and tags
  truncated, never overrun.
- Optional subsystem tag per sink.

## API

```c
#include <zlog/zlog.h>

static void emit(void *ctx, const char *line) { fputs(line, stderr); }

zlog_sink log = { emit, NULL, ZLOG_INFO, true, "net" };
zlog_info(&log, "peer connected");
zlog_warn(&log, "retrying");
```

## CLI

```sh
zlog -t net -l debug info "peer connected"
zlog warn "low disk"
```

## License

Apache-2.0. See LICENSE.

## Tests

Compile `src/zlog.c` and `tests/test_zlog.c` with `-Iinclude`, C23 and
ASan/UBSan. The registered suite includes plain, tagged, threshold and filtered
CLI cases with writable, buffered refusing and unbuffered refusing streams.
An emitted log whose stream fails returns 1; a filtered log with no stream
error returns 0. Diagnostics on failed stderr may not be delivered. The POSIX
fixture reports unavailable required coverage and exits 1 on `_WIN32`.
Close-only delivery failures are not qualified by these tests.

`tests/test_zlog.c:191` registers these CLI rows, including usage and unknown
level diagnostics with writable and refusing stderr. The final stream check
is in `app/main.c:17`.
