#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_wallclock_assertion.sh — refuse NEW test assertions whose PASS/FAIL
# verdict is decided by a reading of a real clock. Mode: shrink-only ratchet
# with a closed allowlist (ZCL_LINT_MODE: FAIL default | WARN | UPDATE — same
# shape as check_pipefail_status_pipe.sh).
#
# ── WHY THIS EXISTS ────────────────────────────────────────────────────────
# A test graded on wall-clock duration reports on the MACHINE, not on the
# code. Measured on this tree, same commit and same binary:
# test_make_lint_gates_heavy_02 FAILED at 48 s inside a 32-worker suite run
# and PASSED at 64.0 s run standalone immediately afterwards. Load was the
# only variable, and the failure carried no diagnostic beyond the timeout
# expression. A sibling, test_binary_ab_fallback, graded three checks on
# `elapsed < 250 ms`; on this 32-cpu box at loadavg 44 one of those calls was
# measured at 66.3 ms — a quarter of the bound already, with nothing wrong.
#
# The cost is not the red build. It is that everybody learns to read a red
# result as "probably just the flake", and that is how a real failure gets
# waved through. A test that cries wolf is worse than no test.
#
# It is also the same defect this project already refuses to commit against
# PEERS. The standing rule is that reachability and speed must never collapse
# into one pass/fail scalar, because a timeout encodes an economic assumption:
# an SSD-shaped budget grades an honest slow machine as broken, and that is
# how a network centralises. This project's own fleet includes 7200rpm boxes
# measured under 2 MB/s, and keeps them ON PURPOSE — a slow box is the only
# instrument that reveals where the code assumes fast storage. A fleet of fast
# machines hides those assumptions. Grading a CONTRIBUTOR's box the way we
# refuse to grade a peer's is the same mistake pointed inward.
#
# ── WHAT IS COUNTED ────────────────────────────────────────────────────────
# One rule, chosen because it is precise rather than broad: an assertion whose
# expression depends on a MEASURED INTERVAL — the difference between two
# readings of a real clock. Bare timestamps are not intervals. An explicit
# virtual clock shared by fixture and subject makes offset checks independent
# of scheduling. A captured real timestamp alone does not: a subject that
# samples the clock again can cross its expiry boundary while the test waits.
# This bounded detector conservatively flags clock-derived subtraction; it
# does not prove which called functions sample a clock. Counting bare
# timestamps too was tried and measured: 31 files, ~350
# sites, almost all of them the good idiom. A gate that noisy gets silenced,
# which is the same failure as the flake it is trying to stop.
#
# A "clock reader" is one of clock_now_monotonic_ns / clock_now_wall_ms /
# clock_gettime / gettimeofday / platform_time_monotonic_timespec /
# platform_time_wall_time_t / difftime / time(NULL), plus — computed per file,
# to a fixpoint — any local helper whose body calls one, and any variable that
# receives one's value, whether by assignment (`int64_t t = clock_...()`) or
# by out-parameter (`clock_gettime(CLOCK_MONOTONIC, &t0)`). Taint propagates
# through arithmetic, so `elapsed = t1 - t0` is tainted and
# `ASSERT(elapsed < 2.0)` is a violation.
#
# An "assertion" is any macro invocation whose name is ASSERT*, EXPECT*,
# REQUIRE*, or ends in _CHECK / CHECK — which covers ASSERT, ASSERT_EQ,
# AB_CHECK, MBX_CHECK, CLK_CHECK, TAPE_CHECK and the rest of the per-file
# check macros in this tree. Invocations are joined across lines by counting
# parentheses, so reindenting or wrapping an assertion does not dodge the
# gate; --selftest proves that with a wrapped copy of a planted violation.
#
# By construction, these are NOT violations:
#   * VIRTUAL TIME. The dominant correct idiom in this tree is a test that
#     passes an explicit `now` into the subject —
#     `ASSERT(dl_check_timeouts(&dm, now + DL_REQUEST_TIMEOUT_SECS + 1) == 1)`.
#     No clock is read, the verdict is deterministic on any box, and the gate
#     must not push anybody away from it. There are dozens of these and none
#     are counted.
#   * CPU TIME. CLOCK_THREAD_CPUTIME_ID does not accrue while a thread is
#     descheduled, so it is not a wall clock and a benchmark budget built on
#     it is not load-graded. Only the wall/monotonic readers above count.
#   * REPORTING. `printf("took %.3f ms", elapsed)` is not an assertion, and
#     reporting a measured duration next to a load average is exactly the
#     treatment this gate wants — measure it, print it, grade something else.
#   * COMMENTS AND STRING LITERALS are stripped before matching, so prose
#     about elapsed time, and an assertion MESSAGE containing the word
#     "elapsed", are not violations.
#
# ── WHAT THIS GATE CANNOT DO ───────────────────────────────────────────────
# Stated plainly so nobody mistakes a pass here for "the suite is now
# load-independent":
#   * It does not see SLEEP-AND-CHECK races. `sleep_ms(50); ASSERT(done)` has
#     no clock read in the assertion and is invisible here. Those are ordinary
#     bugs and need review, not a pattern matcher.
#   * It does not see SHELL. The confirmed instance that started this work was
#     a shell fixture publishing state on a wall clock; no C rule could have
#     caught it. That one is pinned instead by its own hermetic assertion (a
#     run with an already-expired window must still pass).
#   * It does not see a bound handed to an external tool (`timeout 180 foo`).
#   * It does not see a duration compared inside a HELPER the assertion calls.
#     Taint is intra-file and intra-function-set, not interprocedural.
#   * IT DOES NOT SEE A FIXED-ITERATION RETRY LOOP, and this is the blind spot
#     that matters most, because the third confirmed instance of this bug had
#     exactly that shape. test_onion_bootstrap.c polled
#     `for (i = 0; i < 90; i++) { if (ready) break; sleep(1); }` and then wrote
#     `failures++` by hand — no assertion macro, no clock arithmetic, nothing
#     this detector can match. Measured: it FAILED with "not ready after 90s
#     ceiling" inside a full gate run and PASSED standalone in 14.1 s on the
#     same commit and binary. Note what that ratio says: a 90 s bound on a 14 s
#     operation LOOKS like a comfortable hang detector and still flipped. Do
#     not treat "bound >> typical" as evidence that something is
#     load-independent — for anything involving I/O or network round trips it
#     is not, and on a genuinely slow box that test fails PERMANENTLY rather
#     than intermittently, which means that machine can never run the suite.
#   * It does not see a hand-rolled `if (...) { failures++; }` verdict at all;
#     only macro-shaped assertions. Extending it there is the obvious next
#     step and is the reason the assertion-name pattern is one regex.
#   * Proven local/formal declarations are scoped to their function and their
#     visible lines. Same-name locals in distinct blocks still share a summary;
#     unsupported declarators retain a conservative file-wide summary. Helper summaries remain
#     conservative: reading a clock can classify unrelated return values and
#     output arguments as clock-derived within the calling function. This
#     gate is a bounded source heuristic, not a complete data-flow proof.
#
# ── PRODUCTION, AND WHY THE SCAN SET IS A PARAMETER ────────────────────────
# The shape this detects is not test-specific. A systemd watchdog that
# SIGABRTs a healthy node because concurrent builds saturated the box is the
# same defect in production: a clock read, minus a start, compared against a
# constant, deciding a verdict. ZCL_WALLCLOCK_GATE_SCAN_GLOB points this same
# detector at any tree, and running it over lib/ and app/ does report those
# sites. It is deliberately NOT gating there yet: in production a clock-vs-
# constant comparison is also how every legitimate protocol timeout and
# backoff is written, so the honest production rule is narrower (a duration
# deciding a HEALTH verdict, not a duration deciding a retry) and needs a
# reviewed baseline of its own. The detector is ready for it; the policy is
# not written. Do not wire it up without that narrowing.
#
# ── THE ALLOWLIST IS CLOSED ────────────────────────────────────────────────
# There is NO per-line allow-comment, on purpose: an unbounded, never-reviewed
# escape hatch would be used for exactly the cases that need a human. The
# baseline file is the only route, it is shrink-only, and RATCHET_CEILING
# below caps its total sum so raising the ceiling is a visible source diff
# rather than a quiet data-file edit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh
# Pipeline-free substring predicates. This gate must not report a violation as
# clean: under `set -o pipefail` a `printf | grep -q` returns 141 on a MATCH,
# which reads as "no match" and inverts the decision. Nothing below decides
# anything on a pipeline's exit status.
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh || {
    echo "check_no_wallclock_assertion: cannot source tools/scripts/sh_str.sh" >&2
    exit 2
}

GATE=check_no_wallclock_assertion
MODE="${ZCL_LINT_MODE:-FAIL}"
# Total clock-graded assertions tolerated across the whole allowlist. This is
# the count measured when the gate was introduced; it may only go DOWN.
RATCHET_CEILING=15

# ── the detector ─────────────────────────────────────────────────────────
# Emits: path<TAB>count<TAB>first-line-number
scan_counts() {
    awk '
        function reset_file() {
            delete taint; delete readers; delete stamp; delete ambiguous
            delete line_scope
            delete local_binding
            readers["clock_now_monotonic_ns"] = 1
            readers["clock_now_wall_ms"] = 1
            readers["clock_gettime"] = 1
            readers["gettimeofday"] = 1
            readers["platform_time_monotonic_timespec"] = 1
            readers["platform_time_wall_time_t"] = 1
            readers["difftime"] = 1
            nlines = 0
        }
        # Strip //-comments, block comments and string/char literals so that
        # prose and assertion MESSAGES cannot match. Block-comment state is
        # carried across lines in `inblk`.
        function strip(s,   out, i, n, c, two) {
            out = ""; n = length(s); i = 1
            while (i <= n) {
                two = substr(s, i, 2)
                if (inblk) {
                    if (two == "*/") { inblk = 0; i += 2 } else { i++ }
                    continue
                }
                if (two == "/*") { inblk = 1; i += 2; continue }
                if (two == "//") break
                c = substr(s, i, 1)
                if (c == "\"" || c == "\047") {
                    q = c; i++
                    while (i <= n) {
                        d = substr(s, i, 1)
                        if (d == "\\") { i += 2; continue }
                        i++
                        if (d == q) break
                    }
                    out = out " "        # literal becomes whitespace
                    continue
                }
                out = out c; i++
            }
            return out
        }
        # ── TWO INDEXES PER LINE, NOT ONE REGEX PER KNOWN SYMBOL ───────────
        # Every predicate below asks a line the same two questions: is
        # identifier X mentioned here, and is X CALLED here. Asking them by
        # building one dynamic regex per accumulated symbol costs
        # O(symbols) regex matches per line per fixpoint pass, and the symbol
        # sets grow as the fixpoint runs, so the scan degrades as it learns.
        # Measured on this tree that was 97 percent of the whole `make lint`
        # wall time. Both questions are answered instead from two strings
        # built once from the text being asked about:
        #   tokstr(s)  -> " tok tok tok "   every maximal [A-Za-z0-9_] run
        #   callstr(s) -> " name name "     every such run that is immediately
        #                                   followed by optional blanks and `(`
        # Membership in those sets is EXACTLY what the old regexes tested:
        #   `(^|[^A-Za-z0-9_])id([^A-Za-z0-9_]|$)` matches iff id is one of the
        #   maximal word runs of s, because a word run cannot carry a word
        #   boundary inside itself;
        #   `(^|[^A-Za-z0-9_])id[ \t]*\(` matches iff id is the maximal word
        #   run immediately preceding a `(`.
        # Every identifier in play is [A-Za-z_][A-Za-z0-9_]*, so no name can
        # smuggle a regex metacharacter into either string.
        function tokstr(s) {
            gsub(/[^A-Za-z0-9_]+/, " ", s)
            return " " s " "
        }
        function callstr(s,   n, i, t, out, A) {
            if (index(s, "(") == 0) return " "
            gsub(/[ \t]+\(/, "(", s)
            n = split(s, A, /\(/)
            out = " "
            for (i = 1; i < n; i++) {
                t = A[i]
                if (match(t, /[A-Za-z0-9_]+$/))
                    out = out substr(t, RSTART, RLENGTH) " "
            }
            return out
        }
        # Scope proven locals/formals only where their declarations are
        # visible. Unresolved names retain the original conservative file-wide
        # summary, including globals passed through a capture/getter pair.
        function binding(id) {
            if ((current_line SUBSEP id) in local_binding) return curfn SUBSEP id
            return "@file" SUBSEP id
        }
        function declaration(s,   head) {
            if (s ~ /^[ \t]*(return|goto|break|continue|case|else)[ \t]/) return ""
            # Arbitrary identifiers may be expression operands, not types:
            # other * stamp; must not hide a global clock observation.
            # Unknown pointer typedefs remain file-wide; a type/name pair
            # without an intervening star cannot be multiplication.
            if (!match(s, /^[ \t]*(static[ \t]+|extern[ \t]+|const[ \t]+|volatile[ \t]+|register[ \t]+)*(((struct|union|enum)[ \t]+[A-Za-z_][A-Za-z0-9_]*|(unsigned|signed)[ \t]+long[ \t]+long|(unsigned|signed)[ \t]+(long|short|int|char)|long[ \t]+long|void|char|short|int|long|float|double|signed|unsigned|_Bool|bool)[ \t*]+|[A-Za-z_][A-Za-z0-9_]*[ \t]+)[A-Za-z_][A-Za-z0-9_]*[ \t]*(=|;|\[|,)/)) return ""
            head = substr(s, RSTART, RLENGTH)
            sub(/[ \t]*(=|;|\[|,)$/, "", head)
            match(head, /[A-Za-z_][A-Za-z0-9_]*$/)
            return substr(head, RSTART, RLENGTH)
        }
        function index_bindings(   i, id, before, depth, header, key, parts,
                                   shadow, params, n, p) {
            curfn = ""; body_depth = 0; pending_header = ""
            for (i = 0; i < nlines; i++) {
                before = body_depth
                if (!note_funcdef(line[i])) continue
                if (before == 0) {
                    delete shadow
                    header = entry_header
                    sub(/^[^(]*\(/, "", header)
                    sub(/\)[^{]*\{.*$/, "", header)
                    n = split(header, params, ",")
                    for (p = 1; p <= n; p++) {
                        id = declaration(params[p] ";")
                        if (id != "") shadow[id, 1] = 1
                    }
                }
                depth = before > 0 ? before : 1
                id = declaration(scan_line)
                if (id != "" && scan_line !~ /^[ \t]*extern[ \t]/)
                    shadow[id, depth] = 1
                for (key in shadow) {
                    split(key, parts, SUBSEP)
                    local_binding[i, parts[1]] = 1
                    if (parts[2] > body_depth) delete shadow[key]
                }
            }
        }
        # Does this text READ a clock (call a reader, or name a variable
        # holding a single reading)?
        # `toks`/`calls` are the caller-supplied indexes for `s`; empty means
        # "not computed yet", and neither index is ever legitimately empty
        # because both are blank-padded.
        function is_clocky(s, toks, calls,   n, i, p, A) {
            if (calls == "") calls = callstr(s)
            n = split(calls, A, " ")
            for (i = 1; i <= n; i++)
                if (A[i] in readers) return 1
            # time(NULL) only — bare `time` is too common a word.
            if (index(calls, " time ") > 0 &&
                s ~ /(^|[^A-Za-z0-9_])time[ \t]*\([ \t]*(NULL|0)[ \t]*\)/) return 1
            if (toks == "") toks = tokstr(s)
            n = split(toks, A, " ")
            for (i = 1; i <= n; i++) {
                p = A[i]
                if (binding(p) in ambiguous) continue
                if (binding(p) in stamp) return 1
                if (binding(p) in taint) return 1
            }
            return 0
        }
        # ── The load-sensitive shape is an INTERVAL, not a timestamp ────────
        # Bare timestamps are not measured durations. Subtraction may compare
        # two observations, including one obtained inside a called helper.
        # Keep this conservative when the source heuristic cannot prove the
        # operands: a numeric offset does not by itself prove a deterministic
        # assertion. Inject a fixed clock into fixture and subject instead.
        # (Measured:
        # counting bare timestamps too reported 31 files / ~350 sites, almost
        # all of them the good idiom — precision is the whole point of a gate
        # nobody is allowed to silence.)
        function is_interval(s, toks, calls,   n, i, p, A) {
            if (toks == "") toks = tokstr(s)
            n = split(toks, A, " ")
            for (i = 1; i <= n; i++) {
                p = A[i]
                if (!(binding(p) in ambiguous) &&
                    (binding(p) in taint)) return 1
            }
            if (calls == "") calls = callstr(s)
            if (index(calls, " difftime ") > 0) return 1
            gsub(/-[>]/, " ", s)
            if (index(s, "-") == 0) return 0
            return is_clocky(s, toks, calls)
        }
        # Record every identifier this line binds from a clocky expression:
        #   TYPE name = <clocky>;          -> name
        #   name = <clocky>;               -> name
        #   reader(..., &name)             -> name  (out-parameter form)
        # Returns 1 if anything new was added.
        function harvest(s, toks, calls,   added, lhs, rhs, k, m, rest, id,
                         n, i, A, seen, rtoks, rcalls, clocky) {
            added = 0
            # out-parameter form: any reader call taking &ident. The pattern
            # needs a literal `&` AND a call of the reader, so a line missing
            # either cannot match it — checked first, so the common line pays
            # one index() and builds no regex at all.
            if (index(s, "&") > 0) {
                if (calls == "") calls = callstr(s)
                n = split(calls, A, " ")
                for (i = 1; i <= n; i++) {
                    k = A[i]
                    if (!(k in readers) || (k in seen)) continue
                    seen[k] = 1
                    rest = s
                    while (match(rest, ("(^|[^A-Za-z0-9_])" k "[ \t]*\\([^)]*&[ \t]*[A-Za-z_][A-Za-z0-9_]*"))) {
                        m = substr(rest, RSTART, RLENGTH)
                        if (match(m, /&[ \t]*[A-Za-z_][A-Za-z0-9_]*$/)) {
                            id = substr(m, RSTART + 1, RLENGTH - 1)
                            gsub(/[ \t]/, "", id)
                            # A single reading -> a STAMP, not yet an interval.
                            if (id != "" && !(binding(id) in stamp)) {
                                stamp[binding(id)] = 1; added = 1
                            }
                        }
                        rest = substr(rest, RSTART + RLENGTH)
                    }
                }
            }
            # DECLARATION form only: `int64_t elapsed = <clocky>;`. Deliberately
            # NOT plain assignment. A bare `row.expires_at = wall_time() + 600`
            # binds a STRUCT FIELD, and taking "the last identifier before the
            # ="  would taint the bare name `expires_at` for the whole file —
            # measured on this tree, that one line alone produced 100 false
            # violations in test_transaction_intent.c. Precision matters more
            # than recall here: a gate that cries wolf is the very thing this
            # gate exists to stop.
            if (match(s, /^[ \t]*(static[ \t]+)?(const[ \t]+)?(unsigned[ \t]+)?(int64_t|uint64_t|int32_t|uint32_t|long long|long|int|double|float|time_t|clock_t|suseconds_t)[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*=/)) {
                lhs = substr(s, RSTART, RLENGTH)
                rhs = substr(s, RSTART + RLENGTH)
                # The right-hand side is a SUBSTRING of the line, so it needs
                # indexes of its own; they are built only for the ~2 percent of
                # lines that are declarations at all.
                clocky = 0
                if (substr(rhs, 1, 1) != "=") {
                    rtoks = tokstr(rhs); rcalls = callstr(rhs)
                    clocky = is_clocky(rhs, rtoks, rcalls)
                }
                if (clocky) {
                    if (match(lhs, /[A-Za-z_][A-Za-z0-9_]*[ \t]*=$/)) {
                        id = substr(lhs, RSTART, RLENGTH)
                        sub(/[ \t]*=$/, "", id)
                        if (id != "") {
                            # An INTERVAL initializer taints; a bare reading is
                            # only a stamp. See is_interval().
                            if (is_interval(rhs, rtoks, rcalls)) {
                                if (!(binding(id) in taint)) {
                                    taint[binding(id)] = 1; added = 1
                                }
                            } else if (!(binding(id) in stamp)) {
                                stamp[binding(id)] = 1; added = 1
                            }
                        }
                    }
                } else if (match(lhs, /[A-Za-z_][A-Za-z0-9_]*[ \t]*=$/)) {
                    # AMBIGUOUS NAME GUARD. Names are scoped to their function,
                    # but separate blocks may still reuse short names. Before
                    # function scoping, measured on
                    # this tree, one `int64_t now = wall_time();` in one
                    # function made every `const int64_t now = 1800000000;`
                    # fixture in the SAME FILE look clock-derived, and
                    # test_onion_directory.c alone reported 18 false
                    # violations. If a name is ALSO declared from a
                    # non-clock expression anywhere in the file, we cannot
                    # tell separate blocks apart, so we give up that name
                    # within this function only.
                    # This trades recall for precision on purpose: a gate that
                    # cries wolf is the exact failure this whole change exists
                    # to stop, and nobody is allowed to silence this one
                    # per-line.
                    id = substr(lhs, RSTART, RLENGTH)
                    sub(/[ \t]*=$/, "", id)
                    if (id != "") ambiguous[binding(id)] = 1
                }
            }
            return added
        }
        # A local helper whose BODY reads a clock becomes a reader itself, so
        # `static int64_t mono_us(void) { clock_gettime(...); }` taints every
        # `x = mono_us()`. Detected by remembering the most recent function
        # definition header and promoting it when its body turns out clocky.
        # A function DEFINITION in this tree starts in COLUMN 0 and its header
        # ends on the closing paren. Anchoring there is what keeps an indented
        # `TEST("name") {` or `if (cond) {` from being mistaken for one — the
        # earlier unanchored version promoted the TEST macro itself to a clock
        # reader and the false-positive count exploded.
        function note_funcdef(s,   id, header, opens, closes) {
            scan_line = s
            if (body_depth == 0) {
                curfn = ""
                if (pending_header != "") pending_header = pending_header " " s
                else if (s ~ /^[A-Za-z_]/) pending_header = s
                if (index(pending_header, ";") > 0 &&
                    (index(pending_header, "{") == 0 ||
                     index(pending_header, ";") < index(pending_header, "{"))) pending_header = ""
                if (index(pending_header, "{") > 0) {
                    entry_header = pending_header
                    header = pending_header
                    if (match(header, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
                        id = substr(header, RSTART, RLENGTH)
                        sub(/[ \t]*\($/, "", id)
                        if (id !~ /^(if|for|while|switch|return|sizeof)$/ && id ~ /[a-z]/) curfn = id
                    }
                    pending_header = ""
                    if (curfn == "") return 0
                    scan_line = substr(s, index(s, "{") + 1)
                    header = scan_line
                    opens = gsub(/\{/, "", header)
                    header = scan_line
                    closes = gsub(/\}/, "", header)
                    body_depth = 1 + opens - closes
                    return 1
                }
                return 0
            }
            header = s
            opens = gsub(/\{/, "", header)
            header = s
            closes = gsub(/\}/, "", header)
            body_depth += opens - closes
            if (body_depth < 0) body_depth = 0
            return 1
        }
        FNR == 1 {
            if (NR > 1) emit()
            path = FILENAME; count = 0; first_line = 0
            inblk = 0; curfn = ""
            reset_file()
        }
        {
            line[nlines] = strip($0); lineno[nlines] = FNR; nlines++
        }
        function emit() {
            index_bindings()
            fixpoint()
            find_assertions()
            if (path != "" && count > 0)
                printf "%s\t%d\t%d\n", path, count, first_line
        }
        function fixpoint(   pass, i, changed) {
            for (pass = 0; pass < 6; pass++) {
                changed = 0
                curfn = ""; body_depth = 0; pending_header = ""
                for (i = 0; i < nlines; i++) {
                    current_line = i
                    in_body = note_funcdef(line[i])
                    line_scope[i] = in_body ? curfn : ""
                    # `curfn in readers` is tested BEFORE is_clocky() rather
                    # than after: is_clocky() has no side effects, so the
                    # promotion decision is unchanged, and an already-promoted
                    # helper stops being re-examined on every later pass.
                    if (in_body && curfn != "" && !(curfn in readers) &&
                        is_clocky(scan_line)) {
                        readers[curfn] = 1; changed = 1
                    }
                    if (in_body && harvest(scan_line)) changed = 1
                }
                if (!changed) break
            }
        }
        # Join an assertion invocation across lines by balancing parentheses,
        # so wrapping/reindenting cannot hide the expression.
        function find_assertions(   i, s, j, depth, buf, k, startln, pos, name) {
            for (i = 0; i < nlines; i++) {
                current_line = i
                curfn = line_scope[i]
                s = line[i]
                pos = 1
                while (match(substr(s, pos), /(^|[^A-Za-z0-9_])(ASSERT[A-Za-z0-9_]*|EXPECT[A-Za-z0-9_]*|REQUIRE[A-Za-z0-9_]*|[A-Za-z0-9_]*CHECK)[ \t]*\(/)) {
                    startln = lineno[i]
                    k = pos + RSTART - 1
                    name = substr(s, k, RLENGTH)
                    pos = k + RLENGTH
                    # accumulate from the opening paren until balanced
                    buf = ""; depth = 0; j = i
                    idx = pos - 1
                    while (j < nlines) {
                        t = (j == i) ? substr(line[j], idx) : line[j]
                        for (c = 1; c <= length(t); c++) {
                            ch = substr(t, c, 1)
                            if (ch == "(") depth++
                            else if (ch == ")") {
                                depth--
                                if (depth == 0) { c = length(t) + 1; break }
                            }
                            buf = buf ch
                        }
                        if (depth <= 0) break
                        buf = buf " "
                        j++
                    }
                    if (is_interval(buf)) {
                        count++
                        if (first_line == 0) first_line = startln
                    }
                    if (pos > length(s)) break
                }
            }
        }
        END { emit() }
    ' "$@"
}

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/src"

    # A violation written the way the two real ones in this tree were.
    plain="$(cat <<'FIXTURE'
#include "test/test_core.h"
#include "platform/clock.h"
int t_probe(void)
{
    int failures = 0;
    int64_t started = clock_now_monotonic_ns();
    do_the_thing();
    int64_t elapsed = clock_now_monotonic_ns() - started;
    ASSERT(elapsed < 250000000LL);
    return failures;
}
FIXTURE
)"
    # The SAME violation, wrapped across lines, reindented, and behind an
    # out-parameter clock read plus a local helper — the three shapes a
    # line-anchored matcher misses.
    wrapped="$(cat <<'FIXTURE'
#include "test/test_core.h"
static int64_t probe_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}
int t_probe(void)
{
    int failures = 0;
    int64_t t0 = probe_now_us();
    do_the_thing();
    int64_t spent = probe_now_us() - t0;
    PROBE_CHECK("finished promptly",
                spent
                    <
                        250000);
    return failures;
}
FIXTURE
)"
    # Clean, and every line of it is an idiom this tree uses and must keep:
    # virtual time passed into the subject, CPU time, a reported duration, an
    # assertion MESSAGE mentioning elapsed, and a comment about wall clocks.
    clean="$(cat <<'FIXTURE'
#include "test/test_core.h"
/* elapsed wall-clock time is deliberately not asserted on here. */
int t_probe(void)
{
    int failures = 0;
    int64_t now = 1000;                       /* virtual time, injected */
    ASSERT(check_timeouts(&dm, now + DL_REQUEST_TIMEOUT_SECS + 1) == 1);
    ASSERT(dl_get_request_timeout_secs() == DL_REQUEST_TIMEOUT_SECS);
    struct timespec cpu;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu);
    int64_t started = clock_now_monotonic_ns();
    int ops = do_the_thing();
    printf("took %.3f ms\n", (double)(clock_now_monotonic_ns() - started) / 1e6);
    ASSERT(ops == 2);
    ASSERT_EQ(strcmp(msg, "elapsed"), 0);
    return failures;
}
FIXTURE
)"

    # ── HOLLOWNESS GUARDS on the fixtures themselves ─────────────────────
    # A fixture that quietly stopped carrying the shape it claims turns every
    # assertion below into a tautology.
    if [ "$wrapped" = "$plain" ]; then
        echo "$GATE: SELFTEST FAILED — the wrapped fixture is byte-identical to the plain one; the wrap-dodge assertion is hollow" >&2
        exit 2
    fi
    for pair in "plain:$plain" "wrapped:$wrapped"; do
        nm="${pair%%:*}"; body="${pair#*:}"
        if str_lacks "$body" 'clock_'; then
            echo "$GATE: SELFTEST FAILED — the $nm fixture no longer reads a clock; it cannot carry the violation it claims" >&2
            exit 2
        fi
    done
    if str_lacks "$wrapped" 'clock_gettime(CLOCK_MONOTONIC, &ts)'; then
        echo "$GATE: SELFTEST FAILED — the wrapped fixture lost its out-parameter clock read; it is not testing that shape" >&2
        exit 2
    fi
    if str_lacks "$clean" 'CLOCK_THREAD_CPUTIME_ID'; then
        echo "$GATE: SELFTEST FAILED — the clean fixture lost its CPU-time line; the 'CPU time is not wall time' exemption is untested" >&2
        exit 2
    fi
    if str_lacks "$clean" 'clock_now_monotonic_ns'; then
        echo "$GATE: SELFTEST FAILED — the clean fixture no longer READS a clock at all, so proving it clean proves nothing about reporting-vs-asserting" >&2
        exit 2
    fi
    if str_lacks "$clean" 'ASSERT_EQ(strcmp(msg, "elapsed"), 0)'; then
        echo "$GATE: SELFTEST FAILED — the clean fixture lost the assertion whose MESSAGE says 'elapsed'; the string-stripping exemption is untested" >&2
        exit 2
    fi

    plant() { printf '%s\n' "$1" > "$tmp/src/sandbox_probe.c"; }
    self="$PWD/tools/lint/$GATE.sh"
    : > "$tmp/empty_allowlist.txt"

    run_sandbox() {
        ZCL_WALLCLOCK_GATE_SCAN_GLOB="$tmp/src/*.c" \
        ZCL_WALLCLOCK_GATE_ALLOWLIST="$tmp/empty_allowlist.txt" \
        ZCL_WALLCLOCK_GATE_CEILING=0 \
        ZCL_WALLCLOCK_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }

    expect() { # $1 = pass|fail, $2 = message, $3 = fixture body
        local want="$1" msg="$2" body="$3" rc=0
        plant "$body"
        run_sandbox || rc=$?
        if [ "$want" = fail ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
    }

    expect fail "a plain 'elapsed < literal' assertion was reported CLEAN" "$plain"
    expect fail "the same violation wrapped across lines, behind a local helper and an out-parameter clock read, escaped the gate" "$wrapped"
    expect pass "a clean file (virtual time, CPU time, a REPORTED duration, an 'elapsed' message) was reported as a violation" "$clean"

    expect pass "a multiline clock reader contaminated the preceding helper or a member arrow became subtraction" "$(cat <<'FIXTURE'
static int ordinary_result(void) { return 7; }
static int64_t actual_clock(
    void)
{
    return clock_now_monotonic_ns();
}
int probe(struct row *row)
{
    int value = ordinary_result();
    ASSERT(value - 1 == 6);
    int64_t base = actual_clock();
    ASSERT(row->ready && base > 0);
}
FIXTURE
)"
    expect pass "a clock output name leaked into another function body" "$(cat <<'FIXTURE'
static void report_clock(void)
{
    struct timespec out;
    clock_gettime(CLOCK_MONOTONIC, &out);
}
static int ordinary_result(int out)
{
    return out;
}
int probe(void)
{
    int value = ordinary_result(7);
    ASSERT(value - 1 == 6);
}
FIXTURE
)"
    expect fail "another function's constant shadowed a genuine multiline-reader interval" "$(cat <<'FIXTURE'
static void virtual_fixture(void)
{
    int64_t elapsed = 7;
    ASSERT(elapsed == 7);
}
static int64_t actual_clock(
    void)
{
    return clock_now_monotonic_ns();
}
int probe(void)
{
    int64_t start = actual_clock();
    int64_t elapsed = actual_clock() - start;
    ASSERT(elapsed < 250000000);
}
FIXTURE
)"
    expect fail "a genuine clock-output wrapper interval escaped function scoping" "$(cat <<'FIXTURE'
static int observed_clock(struct timespec *output)
{
    return clock_gettime(CLOCK_MONOTONIC, output);
}
int probe(void)
{
    struct timespec start, finish;
    observed_clock(&start);
    observed_clock(&finish);
    int64_t elapsed = finish.tv_sec - start.tv_sec;
    ASSERT(elapsed < 2);
}
FIXTURE
)"

    expect fail "a formal timestamp escaped interval detection" "$(cat <<'FIXTURE'
int probe(int64_t started)
{
    ASSERT(clock_now_monotonic_ns() - started < 250000000);
}
FIXTURE
)"
    expect fail "a global timestamp escaped interval detection" "$(cat <<'FIXTURE'
static int64_t started;
int probe(void)
{
    ASSERT(clock_now_monotonic_ns() - started < 250000000);
}
FIXTURE
)"
    expect fail "a member timestamp escaped interval detection" "$(cat <<'FIXTURE'
int probe(struct record *record)
{
    ASSERT(clock_now_monotonic_ns() - record->started < 250000000);
}
FIXTURE
)"
    expect fail "two clock readings in the same aggregate escaped detection" "$(cat <<'FIXTURE'
int probe(void)
{
    struct record record;
    clock_gettime(CLOCK_MONOTONIC, &record.started);
    clock_gettime(CLOCK_MONOTONIC, &record.finished);
    ASSERT(record.finished.tv_sec - record.started.tv_sec < 2);
}
FIXTURE
)"
    expect fail "a numeric prefix hid an unknown timestamp operand" "$(cat <<'FIXTURE'
int probe(int64_t started)
{
    ASSERT(clock_now_monotonic_ns() - (1 * started) < 250000000);
}
FIXTURE
)"
    expect fail "a fixed offset hid a comparison of two real timestamps" "$(cat <<'FIXTURE'
int probe(void)
{
    int64_t started = clock_now_monotonic_ns();
    int64_t finished = clock_now_monotonic_ns();
    ASSERT(started < finished - 10);
}
FIXTURE
)"
    expect fail "a fixed offset hid two timestamps in the same aggregate" "$(cat <<'FIXTURE'
int probe(void)
{
    struct record record;
    clock_gettime(CLOCK_MONOTONIC, &record.started);
    clock_gettime(CLOCK_MONOTONIC, &record.finished);
    ASSERT(record.started.tv_sec < record.finished.tv_sec - 10);
}
FIXTURE
)"

    expect fail "a declared global timestamp lost its capture-to-getter flow" "$(cat <<'FIXTURE'
static struct timespec shared;
static void capture(void)
{
    clock_gettime(CLOCK_MONOTONIC, &shared);
}
static long getter(void)
{
    return shared.tv_sec;
}
int probe(void)
{
    capture();
    long first = getter();
    capture();
    long second = getter();
    ASSERT(second - first < 2);
}
FIXTURE
)"
    expect pass "a declared global timestamp contaminated a local or formal shadow" "$(cat <<'FIXTURE'
static struct timespec shared;
static void capture(void)
{
    clock_gettime(CLOCK_MONOTONIC, &shared);
}
static void parameter(struct timespec shared)
{
    ASSERT(shared.tv_sec - 1 == 6);
}
int probe(void)
{
    struct timespec shared = {7, 0};
    ASSERT(shared.tv_sec - 1 == 6);
}
FIXTURE
)"
    expect fail "an unresolved global declarator lost cross-helper flow" "$(cat <<'FIXTURE'
static struct timespec unused, shared;
static void capture(void)
{
    clock_gettime(CLOCK_MONOTONIC, &shared);
}
static long getter(struct shared *other)
{
    return shared.tv_sec;
}
int probe(void)
{
    capture();
    long first = getter(NULL);
    capture();
    long second = getter(NULL);
    ASSERT(second - first < 2);
}
FIXTURE
)"
    expect fail "a later local declaration hid an earlier global timestamp" "$(cat <<'FIXTURE'
static struct timespec shared;
static void capture(void)
{
    clock_gettime(CLOCK_MONOTONIC, &shared);
}
int probe(void)
{
    ASSERT(shared.tv_sec - 1 < 2);
    struct timespec shared = {7, 0};
    ASSERT(shared.tv_sec - 1 == 6);
}
FIXTURE
)"
    expect fail "a closed nested shadow hid a subsequent global timestamp" "$(cat <<'FIXTURE'
static struct timespec shared;
static void capture(void)
{
    clock_gettime(CLOCK_MONOTONIC, &shared);
}
int probe(void)
{
    {
        struct timespec shared = {7, 0};
        ASSERT(shared.tv_sec - 1 == 6);
    }
    ASSERT(shared.tv_sec - 1 < 2);
}
FIXTURE
)"

    expect fail "a multiplication expression hid a global clock observation" "$(cat <<'FIXTURE'
static long multiplier, other;
static void observed_clock(long *output)
{
    struct timespec stamp;
    clock_gettime(CLOCK_MONOTONIC, &stamp);
    *output = stamp.tv_sec;
}
static void capture(void)
{
    observed_clock(&multiplier);
}
static long getter(void)
{
    other * multiplier;
    return multiplier;
}
int probe(void)
{
    capture();
    long first = getter();
    capture();
    long second = getter();
    ASSERT(second - first < 2);
}
FIXTURE
)"

    # A hollow scan must be LOUD, not a quiet pass: point the gate at a glob
    # that matches nothing and require exit 2, not 0.
    plant "$clean"
    hollow_rc=0
    ZCL_WALLCLOCK_GATE_SCAN_GLOB="$tmp/src/nothing-matches-this-*.c" \
        ZCL_WALLCLOCK_GATE_ALLOWLIST="$tmp/empty_allowlist.txt" \
        ZCL_WALLCLOCK_GATE_CEILING=0 \
        ZCL_WALLCLOCK_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1 || hollow_rc=$?
    if [ "$hollow_rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — an EMPTY scan set exited $hollow_rc, not 2; the gate can pass by scanning nothing" >&2
        exit 2
    fi

    # An allowlist row must actually tolerate the violation it names...
    plant "$plain"
    printf '%s 1\n' "$tmp/src/sandbox_probe.c" > "$tmp/allow1.txt"
    allow_rc=0
    ZCL_WALLCLOCK_GATE_SCAN_GLOB="$tmp/src/*.c" \
        ZCL_WALLCLOCK_GATE_ALLOWLIST="$tmp/allow1.txt" \
        ZCL_WALLCLOCK_GATE_CEILING=1 \
        ZCL_WALLCLOCK_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1 || allow_rc=$?
    if [ "$allow_rc" -ne 0 ]; then
        echo "$GATE: SELFTEST FAILED — an allowlisted file at its recorded count was still reported as a violation (rc=$allow_rc)" >&2
        exit 2
    fi
    # ...and must NOT tolerate a second one appearing in the same file.
    plant "$plain
int t_probe2(void)
{
    int failures = 0;
    int64_t s2 = clock_now_monotonic_ns();
    do_the_thing();
    ASSERT(clock_now_monotonic_ns() - s2 < 250000000LL);
    return failures;
}"
    grew_rc=0
    ZCL_WALLCLOCK_GATE_SCAN_GLOB="$tmp/src/*.c" \
        ZCL_WALLCLOCK_GATE_ALLOWLIST="$tmp/allow1.txt" \
        ZCL_WALLCLOCK_GATE_CEILING=1 \
        ZCL_WALLCLOCK_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1 || grew_rc=$?
    if [ "$grew_rc" -eq 0 ]; then
        echo "$GATE: SELFTEST FAILED — an allowlisted file that GREW a new clock-graded assertion still passed; the ratchet does not ratchet" >&2
        exit 2
    fi
    # A stale allowlist row (file now clean) must be reported, so the ratchet
    # cannot rust shut at a number nobody can lower.
    plant "$clean"
    stale_rc=0
    ZCL_WALLCLOCK_GATE_SCAN_GLOB="$tmp/src/*.c" \
        ZCL_WALLCLOCK_GATE_ALLOWLIST="$tmp/allow1.txt" \
        ZCL_WALLCLOCK_GATE_CEILING=1 \
        ZCL_WALLCLOCK_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1 || stale_rc=$?
    if [ "$stale_rc" -eq 0 ]; then
        echo "$GATE: SELFTEST FAILED — a STALE allowlist row (file now clean) was accepted" >&2
        exit 2
    fi

    echo "[$GATE] SELFTEST PASSED (plain/wrapped/helper/out-param violations, function boundaries and local names, member arrows, clean idioms, hollow scan, allowlist honoured, growth and stale rows refused)"
    exit 0
fi

# ── the scan set ─────────────────────────────────────────────────────────
ALLOWLIST="${ZCL_WALLCLOCK_GATE_ALLOWLIST:-tools/lint/wallclock_assertion_allowlist.txt}"
CEILING="${ZCL_WALLCLOCK_GATE_CEILING:-$RATCHET_CEILING}"

if [ -n "${ZCL_WALLCLOCK_GATE_SCAN_GLOB:-}" ]; then
    # shellcheck disable=SC2086
    mapfile -t scan_files < <(ls -1 ${ZCL_WALLCLOCK_GATE_SCAN_GLOB} 2>/dev/null || true)
    FILE_FLOOR="${ZCL_WALLCLOCK_GATE_FILE_FLOOR:-1}"
else
    # Every tracked C test source: the monolithic suite plus every package's
    # own tests/ directory.
    mapfile -t scan_files < <(git ls-files | grep -E '(^|/)(tests?)/.*\.(c|h)$|^tests/harness/src/.*\.(c|h)$' || true)
    # Floor, not a guess: the tree carried 1079 such files when this gate was
    # written. Anything under 800 means the producer broke, and a "clean"
    # verdict off a collapsed scan set is exactly the hollow pass gate_lib.sh
    # exists to refuse.
    FILE_FLOOR="${ZCL_WALLCLOCK_GATE_FILE_FLOOR:-800}"
fi

gate_require_scanned "${#scan_files[@]}" "$FILE_FLOOR" "$GATE" \
    "Expected the tracked C test sources (tests/harness/src/**, **/tests/**)."

# The detector's exit status is CHECKED. `mapfile < <(...)` swallows it, and a
# broken awk program then produces zero rows — which reads as "nothing is
# clock-graded" and is exactly the hollow pass gate_lib.sh exists to refuse.
# This is not hypothetical: an unbalanced brace introduced while tightening
# the detector made it report the whole tree clean, and only the --selftest
# caught it.
set +e
scan_out="$(scan_counts "${scan_files[@]}")"
scan_rc=$?
set -e
if [ "$scan_rc" -ne 0 ]; then
    echo "$GATE: FATAL — the detector exited $scan_rc. Refusing to report" >&2
    echo "  'clean' off a scan that did not run." >&2
    exit 2
fi
COUNT_ROWS=()
if [ -n "$scan_out" ]; then
    while IFS= read -r _row; do
        [ -n "$_row" ] && COUNT_ROWS+=("$_row")
    done <<< "$scan_out"
fi

declare -A ALLOWED
gate_load_kv_file "$ALLOWLIST" ALLOWED

declare -A HIT
violations=()
tolerated=()
total_sites=0
for row in "${COUNT_ROWS[@]}"; do
    IFS=$'\t' read -r path found line <<< "$row"
    HIT["$path"]=$found
    total_sites=$((total_sites + found))
    allowed="${ALLOWED[$path]:-0}"
    if [ "$found" -gt "$allowed" ]; then
        violations+=("$path:$line — $found clock-graded assertion(s), allowlist tolerates $allowed")
    else
        tolerated+=("$path ($found/$allowed)")
    fi
done

stale=()
allow_sum=0
allow_count=0
for path in "${!ALLOWED[@]}"; do
    allow_sum=$((allow_sum + ALLOWED[$path]))
    allow_count=$((allow_count + 1))
    if [ -z "${HIT[$path]+x}" ]; then
        stale+=("$path (allowlist says ${ALLOWED[$path]}, actual 0)")
    fi
done

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE allowlist — the reviewed set of test assertions still"
        echo "# graded on a reading of a real clock. Format: <path> <count>."
        echo "# COUNTS MAY ONLY SHRINK. Adding a row for a NEW file is not a fix:"
        echo "# a file with no row may carry ZERO."
        echo "#"
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for row in "${COUNT_ROWS[@]}"; do
            IFS=$'\t' read -r path found line <<< "$row"
            echo "$path $found"
        done | sort
    } > "$ALLOWLIST"
    echo "[$GATE] allowlist UPDATED: $ALLOWLIST"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} violation(s) — a NEW or GROWN test assertion"
    echo "        graded on a reading of a real clock:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  A verdict that a busy box can flip is measuring the box, not the code."
    echo "  Do not widen the bound: a bigger magic number is the same defect with a"
    echo "  longer fuse, and it makes a genuine hang take longer to surface."
    echo "  Pick the treatment that matches what the bound is actually for:"
    echo "    * hang detector (the bound is NOT the property) — assert the OUTCOME,"
    echo "      and let a progress watchdog catch a true wedge. See"
    echo "      run_gate_script_watched() in tests/harness/src/lint_gate_helpers.c and"
    echo "      group_watchdog_expired() in tests/harness/src/test_parallel.c: both bound"
    echo "      SILENCE, not runtime, so a slow box keeps passing."
    echo "    * the speed IS the property — assert a load-independent proxy"
    echo "      (operation counts, bytes written, syscalls, iterations, progress"
    echo "      across N samples) and REPORT the wall-clock figure beside it."
    echo "    * a sleep-and-check race — fix the race; wait on the EVENT, not the"
    echo "      clock."
    echo "  Whatever you keep, make the failure message say what was measured, what"
    echo "  the bound was and what the load looked like, so the next reader can tell"
    echo "  a regression from a busy box in one glance."
    echo "  Raising a number in $ALLOWLIST is NOT a fix; counts may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE allowlist row(s) — the file no longer carries"
    echo "        the shape. Delete them from $ALLOWLIST:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$allow_sum" -gt "$CEILING" ]; then
    echo ""
    echo "[$GATE] allowlist sum ($allow_sum) exceeds the ratchet ceiling ($CEILING)"
    echo "        in $ALLOWLIST — the allowlist was edited upward. Lower it back, or"
    echo "        lower RATCHET_CEILING in this script if the tolerated set has"
    echo "        genuinely shrunk (a change that belongs in code review, not a"
    echo "        quiet data-file edit)."
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} test source file(s) scanned, ${#COUNT_ROWS[@]} carrying a clock-graded assertion, $total_sites total site(s), $allow_count allowlisted file(s) summing to $allow_sum/$CEILING, no allow-comment mechanism exists)"
