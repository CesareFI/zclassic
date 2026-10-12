#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# An adversarial wrapper can ignore ZCC_VERIFIED and serve old code. This is
# an executed RED witness, not an admitted proof reuse path.
set -euo pipefail

fixture=$1
mkdir -p "$fixture/src"
cp platform/modules/base/src/result.c "$fixture/src/result.c"
cat > "$fixture/driver.c" <<'C'
#include "base/result.h"
#include <stdio.h>
int main(void)
{
    struct zcl_result r = zcl_result_make(7, "fixture", 1, NULL);
    puts(r.message);
    return 0;
}
C

include=platform/modules/base/include
cc -std=c23 -O3 -I"$include" -c "$fixture/src/result.c" \
    -o "$fixture/baseline.o"
cc -std=c23 -I"$include" "$fixture/driver.c" "$fixture/baseline.o" \
    -o "$fixture/baseline-run"
baseline=$("$fixture/baseline-run")

sed 's/<zcl_result: missing format>/<zcl_result: missing format v2>/' \
    "$fixture/src/result.c" > "$fixture/result.changed.c"
mv "$fixture/result.changed.c" "$fixture/src/result.c"
cat > "$fixture/candidate-zcc" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
test "${ZCC_VERIFIED:-}" = 1
out=
dep=
source=
while (($#)); do
    case $1 in
        -o) out=$2; shift 2 ;;
        -MF) dep=$2; shift 2 ;;
        *.c) source=$1; shift ;;
        *) shift ;;
    esac
done
test -n "$out" && test -n "$dep" && test -n "$source"
cp "$ZCC_RED_DIR/baseline.o" "$out"
printf '%s: %s\n' "$out" "$source" > "$dep"
SH
chmod 700 "$fixture/candidate-zcc"

ZCC_VERIFIED=1 ZCC_RED_DIR="$fixture" "$fixture/candidate-zcc" cc \
    -std=c23 -O3 -I"$include" -MMD -MF "$fixture/stale.d" \
    -MT "$fixture/stale.o" -c "$fixture/src/result.c" \
    -o "$fixture/stale.o"
cc -std=c23 -I"$include" "$fixture/driver.c" "$fixture/stale.o" \
    -o "$fixture/stale-run"
stale=$("$fixture/stale-run")

cc -std=c23 -O3 -I"$include" -MMD -MF "$fixture/fresh.d" \
    -MT "$fixture/fresh.o" -c "$fixture/src/result.c" \
    -o "$fixture/fresh.o"
cc -std=c23 -I"$include" "$fixture/driver.c" "$fixture/fresh.o" \
    -o "$fixture/fresh-run"
fresh=$("$fixture/fresh-run")

# A later object-byte check can also see fresh bytes even though the link
# already consumed stale bytes. Only link-time provenance connects the object
# to the image that actually ran.
cp "$fixture/stale.o" "$fixture/current.o"
cc -std=c23 -I"$include" "$fixture/driver.c" "$fixture/current.o" \
    -o "$fixture/transient-run"
cp "$fixture/fresh.o" "$fixture/current.o"
transient=$("$fixture/transient-run")

test "$baseline" = '<zcl_result: missing format>'
test "$stale" = "$baseline"
test "$fresh" = '<zcl_result: missing format v2>'
test "$transient" = "$baseline"
cmp -s "$fixture/baseline.o" "$fixture/stale.o"
cmp -s "$fixture/current.o" "$fixture/fresh.o"
if cmp -s "$fixture/stale.o" "$fixture/fresh.o"; then
    printf 'stale_candidate_zcc: changed source built identical object\n' >&2
    exit 1
fi
if cmp -s "$fixture/transient-run" "$fixture/fresh-run"; then
    printf 'stale_candidate_zcc: transient stale link matched fresh image\n' >&2
    exit 1
fi
printf 'RED stale candidate wrapper: baseline=%s stale=%s fresh=%s\n' \
    "$baseline" "$stale" "$fresh"
printf 'RED transient link swap: final_object=fresh executed=%s fresh=%s\n' \
    "$transient" "$fresh"
printf 'launches baseline_compile=1 stale_compile=0 fresh_compile=1 links=4 executions=4\n'
