#!/bin/sh
# Compile check of p4_bt_classic for ESP32-P4 in the pinned ESP-IDF container (nothing is flashed).
set -e
IDF_IMAGE="espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
case "$(uname -s)" in
    MINGW*|MSYS*)
        ROOT="$(cd "$ROOT" && pwd -W)"
        export MSYS_NO_PATHCONV=1
        ;;
esac
docker run --rm -v "$ROOT:/src" -w /src/p4_bt_classic/test/compile_check \
    "$IDF_IMAGE" bash -c "git config --global --add safe.directory '*' && idf.py ${*:-build}"
