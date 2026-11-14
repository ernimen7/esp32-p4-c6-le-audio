#!/bin/sh
# Host test of the player's device list (no ESP-IDF needed: g++ only).
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN="$DIR/../../main"
BUILD="${TMPDIR:-/tmp}/tab5_player_host"
mkdir -p "$BUILD"
CXX="${CXX:-g++}"
$CXX -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I"$MAIN" "$MAIN/bt_list_model.cpp" "$DIR/test_bt_list.cpp" -o "$BUILD/test_bt_list"
"$BUILD/test_bt_list"
