#!/bin/sh
# Soft-BR engine host unit tests: gcc C11, -Wall -Wextra -Werror, ASan + UBSan.
set -e
D=$(cd "$(dirname "$0")/.." && pwd)
B=${TMPDIR:-/tmp}/br_ll_test
mkdir -p "$B"
CFLAGS="-std=c11 -O1 -g -Wall -Wextra -Werror -Wshadow -Wconversion -Wno-sign-conversion -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -I$D"
SRC="$D/br_proto.c $D/br_hop.c $D/br_air.c $D/br_crypto.c $D/br_engine.c"
rc=0
for t in test_air_hop test_crypto test_engine test_fast_paths; do
	[ -f "$D/test/$t.c" ] || continue
	gcc $CFLAGS -o "$B/$t" "$D/test/$t.c" $SRC || { echo "BUILD FAIL $t"; exit 2; }
	if ! "$B/$t"; then rc=1; fi
done
if [ $rc -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi
exit $rc
