#!/bin/sh
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
BTC="$DIR/../.."
BR="$BTC/../br_ll"
BUILD="$DIR/build"
mkdir -p "$BUILD"

CC="${CC:-gcc}"
CXX="${CXX:-g++}"
SAN="-fsanitize=address,undefined"

$CC -std=c11 -O2 -g -Wall -Wextra -Werror $SAN \
    -I"$BR" -I"$BTC/include" -I"$BTC/src" \
    -c "$BR/br_proto.c" -o "$BUILD/br_proto.o"

$CC -std=c11 -O2 -g -Wall -Wextra -Werror $SAN \
    -I"$BR" -I"$BTC/include" -I"$BTC/src" \
    -c "$BR/br_crypto.c" -o "$BUILD/br_crypto.o"

$CC -std=c11 -O2 -g -Wall -Wextra -Werror $SAN \
    -I"$BR" -I"$BTC/include" -I"$BTC/src" \
    -c "$BTC/src/sbc_enc.c" -o "$BUILD/sbc_enc.o"

$CXX -std=c++17 -O2 -g -Wall -Wextra -Werror $SAN \
    -I"$BR" -I"$BTC/include" -I"$BTC/src" \
    "$BTC/src/btc_lmp.cpp" \
    "$BTC/src/btc_l2cap_avdtp.cpp" \
    "$DIR/test_bt_classic.cpp" \
    "$BUILD/br_proto.o" "$BUILD/br_crypto.o" "$BUILD/sbc_enc.o" \
    -lm -o "$BUILD/test_bt_classic"

"$BUILD/test_bt_classic"
