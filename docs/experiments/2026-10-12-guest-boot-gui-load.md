<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Headless z23-dev loads the wallet GUI only for an explicit launch

Recorded 2026-10-12T16:46:37Z (local 2026-10-12T12:46:37-0400).
Host `t14`, clang 22.1.6, AMD Ryzen 7 PRO 8840U.
The timed command is `z23-dev dev app machine boot` of
`tests/fixtures/rvmachine/tiny.bin` with `max_instr` 100000.
`-datadir` named an empty temporary directory. The public chain node
was not restarted.

On Linux the dev executable's `DT_NEEDED` entries are `libstdc++.so.6`,
`libm.so.6`, and `libc.so.6`. GTK and WebKit are `DT_NEEDED` by
`build/bin/libz23walletgui.so` and are mapped when `-gui`, `--gui`, or
`--self-test` calls `wallet_gui_main`. A headless start does not reach
that loader. The wallet GUI is still the WebKit window. With
`GDK_BACKEND=x11` and `DISPLAY` unset, `-gui` exits 1 and prints
`Cannot open display` after `libwebkit` is mapped, before any wallet
datadir open. The SSH launcher option string and the onion fail-closed
dial are unchanged.

Eight boots at 2026-10-12T16:47Z were wall 0.011 s each. The last
sample reported handler `elapsed_us` 168. Every sample reported retired
279, firmware calls 62, device work 0, skip 999, fetch hits 274, fetch
misses 67, guest time 1026, and console 60 bytes. Guest work is
279 + 62 + 0 = 341. The console marker is
`tiny: hello from S-mode\nprobe putchar=1\ntiny: timer fired\nU\n`,
sha256 `3cbce45f847a34606550eca184e332ce43b5370b3b597ef7f5a6aebf48e9cd4c`.
The measured executable is sha256
`70a94d887ae8b96916a3875f62416e7c748eddf05ee65c2b1524e016011cf332`.
The GUI library is sha256
`fba1f50e6d6882553e0216fe4f26fc020b115947dfb87c27e7937b6a1927abc9`.

An earlier eight-boot sample on this host, recorded 2026-10-12T12:58:25Z
against the published tree that still linked the toolkit into
`z23-dev`, was wall 0.041–0.044 s with the same guest pins. These are
separate samples, not one paired rebuild.

`make -j8 t-fast-exact ONLY=test_wallet_gui_load,test_dev_machine_boot,test_guest_ssh_fixture,test_rom_fetch_onion,test_tor,test_onion_stream`
at 2026-10-12T16:46:03Z reported `groups_failed=0`, `groups_ran=6`,
`groups_total=1305`, mode=cold, wall 1.9 s. That run and the
cyclomatic scan below were on base
`47efb7f70aad9ad03abb49bd254e308dec418022`. The boot group printed
`fetch_hits=274 fetch_misses=67`. The SSH group asserted
`KexAlgorithms=mlkem768x25519-sha256`. The onion groups refused a
malformed onion without resolution and refused a Tor dial while Tor
was down. Cyclomatic ratchet: 77329 functions, 3921 pins exact.
Capability closure printed `OK — closed`.

The same patch replayed onto `1b98ebaf1bd079c5ef46c8462eb6552a7b2441fe`
was measured again at 2026-10-12T16:59Z. Eight boots were wall
0.010–0.012 s. The last sample reported handler `elapsed_us` 164 and
the same guest pins, console length, and marker hash. That executable
is sha256
`ce4374af5797b7f0fb6f720d3c93ca69464681ca20ae82e7aada5f38f8ac24fd`.
`make -j8 t-fast-exact` of the same six groups reported
`groups_failed=0`, `groups_ran=6`, `groups_total=1306`, mode=cold,
wall 2.2 s. Cyclomatic ratchet on that tree: 77834 functions, 3921
pins exact. The headless `DT_NEEDED` set was still `libstdc++.so.6`,
`libm.so.6`, and `libc.so.6`.

Rhett land sequence 661 failed prebuild lint on that tip:
`check-proc-self-shim` and `check-hotswap-dev-only`. The loader now
resolves its executable with `os_proc_exe_path` and opens
`libz23walletgui.so` through `zcl_dev_library_open`. That open sits in
`engine/modules/hotswap/src/dev_library.c` inside `#ifdef ZCL_DEV_BUILD`.
A release build compiles the refusal stub. On `t14` at
2026-10-12T17:29Z the rebuilt executable sha256
`f00fadc53d33e1becc186d8d02621507b95fb247aa7fea64d689b0c261ade333`
booted `tiny.bin` once: retired 279, firmware calls 62, device work 0,
skip 999, fetch 274/67, guest time 1026, handler `elapsed_us` 184, and
the same console marker. Headless `DT_NEEDED` stayed `libstdc++.so.6`,
`libm.so.6`, and `libc.so.6`. The same six groups reported
`groups_failed=0`, `groups_ran=6`, `groups_total=1306`. The SSH group
still asserted `KexAlgorithms=mlkem768x25519-sha256`. Cyclomatic
ratchet: 77837 functions, 3921 pins exact. Capability closure passed.

Rhett land sequence 664 failed the test dimension on successor
`cd053c2ba30e`. `test_wallet_gui_load` required `libgtk` and `libwebkit`
in `libz23walletgui.so`, then `Cannot open display`. That host has the
GTK runtime and no `gtk+-3.0` or `webkit2gtk-4.1` pkg-config file, so
the companion is the built-without-toolkit stub. The registered test
now requires toolkit linkage only when the companion lists those
libraries. Otherwise `-gui` must exit 1 with the closed-library text
and must not map `libgtk` or `libwebkit`. On `t14` at 2026-10-12T18:20Z
the toolkit shape and the moved-aside companion both reported
`groups_failed=0` for `test_wallet_gui_load`, including the headless
pins and, on the toolkit shape, `Cannot open display`.
