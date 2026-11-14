#!/bin/sh
# Discrete-event Bluetooth Classic over-the-air simulator (Inquiry -> Page -> ACL -> E0 -> AFH -> DH3 Audio).
set -e
SIM_DIR=$(cd "$(dirname "$0")" && pwd)
BR_DIR=$(cd "$SIM_DIR/.." && pwd)
OUT=${TMPDIR:-/tmp}/br_ll_sim
mkdir -p "$OUT"
CFLAGS="-std=c11 -O1 -g -Wall -Wextra -Werror -Wshadow -Wconversion -Wno-sign-conversion -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -I$BR_DIR"
SRC="$BR_DIR/br_proto.c $BR_DIR/br_hop.c $BR_DIR/br_air.c $BR_DIR/br_crypto.c $BR_DIR/br_engine.c $SIM_DIR/sim_br.c"
gcc $CFLAGS -o "$OUT/sim_br" $SRC
"$OUT/sim_br"
"$OUT/sim_br" no-3-slot
"$OUT/sim_br" no-3-slot-poll-ack
"$OUT/sim_br" outage
"$OUT/sim_br" busy-radio
"$OUT/sim_br" slices
"$OUT/sim_br" 3-slot-fade
"$OUT/sim_br" no-3-slot-long
