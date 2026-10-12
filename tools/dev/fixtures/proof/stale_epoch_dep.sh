#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# An object can cross epoch target names, but its -MT depfile cannot. This
# executes the stale and fresh outcomes; it does not authorize proof reuse.
set -euo pipefail

fixture=$1
mkdir -p "$fixture"
cat > "$fixture/epoch.mk" <<'MAKE'
.PHONY: z23-fixture-fast-epoch
z23-fixture-fast-epoch:
	@printf '%s\n' '$(TEST_FAST_COMPILE_EPOCH)'
MAKE
epoch=$(make --no-print-directory -s -f Makefile -f "$fixture/epoch.mk" \
    ZCL_EPOCH_PROFILES=test-fast z23-fixture-fast-epoch | tail -n 1)
[[ $epoch =~ ^[0-9a-f]{64}$ ]]
donor_epoch=0000000000000000000000000000000000000000000000000000000000000000
if [[ $epoch == "$donor_epoch" ]]; then
    donor_epoch=1111111111111111111111111111111111111111111111111111111111111111
fi

source_dir=$fixture/src
donor_dir=$fixture/build/test-obj/epochs/$donor_epoch
current_dir=$fixture/build/test-obj/epochs/$epoch
mkdir -p "$source_dir" "$donor_dir" "$current_dir"
cat > "$source_dir/value.h" <<'C'
#define VALUE 7
C
cat > "$source_dir/unit.c" <<'C'
#include "value.h"
int fixture_value(void) { return VALUE; }
C
cat > "$source_dir/driver.c" <<'C'
#include <stdio.h>
int fixture_value(void);
int main(void) { printf("%d\n", fixture_value()); return 0; }
C

donor_obj=$donor_dir/fixture.o
donor_dep=$donor_dir/fixture.d
current_obj=$current_dir/fixture.o
current_dep=$current_dir/fixture.d
cat > "$fixture/count-cc" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
kind=other
for arg in "$@"; do
    case $arg in
        -c) kind=compile ;;
        -E) kind=preprocess ;;
    esac
done
printf '%s\n' "$kind" >> "$COUNT_CC_LOG"
exec cc "$@"
SH
chmod 700 "$fixture/count-cc"
export COUNT_CC_LOG=$fixture/cc.log

"$fixture/count-cc" -std=c2x -O1 -MMD -MP -MF "$donor_dep" \
    -MT "$donor_obj" -c "$source_dir/unit.c" -o "$donor_obj"
cp "$donor_obj" "$current_obj"
cp "$donor_dep" "$current_dep"
case $(head -n 1 "$current_dep") in
    "$donor_obj":*) ;;
    *) printf 'donor dep lost its -MT target\n' >&2; exit 1 ;;
esac

cat > "$fixture/Makefile" <<'MAKE'
.DEFAULT_GOAL := all
all: $(TARGET)
$(TARGET): $(SOURCE)
	$(CC) -std=c2x -O1 -MMD -MP -MF $(DEP) -MT $(TARGET) -c $(SOURCE) -o $(TARGET)
-include $(DEP)
MAKE
make_fixture() {
    make --no-print-directory -s -f "$fixture/Makefile" \
        TARGET="$current_obj" SOURCE="$source_dir/unit.c" \
        DEP="$current_dep" CC="$fixture/count-cc" all
}

sleep 1
printf '#define VALUE 9\n' > "$source_dir/value.h"
make_fixture
stale_compiles=$(grep -c '^compile$' "$COUNT_CC_LOG")
test "$stale_compiles" -eq 1
cc -std=c2x "$source_dir/driver.c" "$current_obj" -o "$fixture/stale-run"
stale=$("$fixture/stale-run")
test "$stale" = 7

"$fixture/count-cc" -std=c2x -O1 -E -MMD -MP -MF "$current_dep" \
    -MT "$current_obj" "$source_dir/unit.c" -o /dev/null
case $(head -n 1 "$current_dep") in
    "$current_obj":*) ;;
    *) printf 'current dep kept donor -MT target\n' >&2; exit 1 ;;
esac
make_fixture
fresh_compiles=$(grep -c '^compile$' "$COUNT_CC_LOG")
test "$fresh_compiles" -eq 2
cc -std=c2x "$source_dir/driver.c" "$current_obj" -o "$fixture/fresh-run"
fresh=$("$fixture/fresh-run")
test "$fresh" = 9

printf 'RED donor dep substitution: epoch=%s donor=%s stale=%s fresh=%s\n' \
    "$epoch" "$donor_epoch" "$stale" "$fresh"
printf 'launches donor_compile=1 stale_compile=0 current_preprocess=1 fresh_compile=1 links=2 executions=2\n'
