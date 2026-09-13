# C3 lock benchmark recipe

Use identical loaded fixture bytes, peer set, binary build profile, CPU
governor, and 600-second window before and after the repair.

```bash
devbuild --wait env VENDOR_CC=gcc make t-fast-exact ONLY=download_contention
devbuild --wait env VENDOR_CC=gcc make t-fast-exact ONLY=download_enqueue_profile
ZCL_BIN=ABS_BINARY ZCL_PEER=DECLARED_PEER ZCL_FILE_PEER=DECLARED_FILE_PEER \
  devbuild --wait make mvp-coldstart-to-tip-stopwatch
```

At a fixed cadence, capture the existing `download_stats`, `body_history`,
`reducer_frontier`, `body_persist`, and `sync_monitor` projections. Record:

- duplicate-lock and first-useful-history enqueue p50/p95/max;
- durable history bodies per second from first/last counters and monotonic time;
- foreground request-to-first-response p50/p95/max and timeout count;
- queued/in-flight history, received, timed out, accounting drift, and
  monotonically advancing coverage/lowest-missing state;
- CPU governor and `scaling_cur_freq` for every policy before and after.

Read CPU policy without changing it:

```bash
for p in /sys/devices/system/cpu/cpufreq/policy*; do
  printf '%s ' "$p"
  cat "$p/scaling_governor" "$p/scaling_cur_freq"
done
```
