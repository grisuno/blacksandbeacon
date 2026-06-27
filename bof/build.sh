#!/bin/bash
#
# bof/build.sh - Build a single BOF and copy it to the C2 upload dir.
#
# Usage:   ./bof/build.sh <bof-name> [destination-dir]
# Example: ./bof/build.sh whoami sessions/uploads
#
# The Makefile target `make bof-<name>` does the same thing in a
# more discoverable way; this script is kept for users who prefer
# the old workflow.
#
# Requires: gcc, and the headers in bof/include/.

set -e

NAME="${1:?usage: build.sh <bof-name> [destination-dir]}"
DEST="${2:-sessions/uploads}"

SRC="bof/${NAME}/bof.c"
OUT="build/bof/${NAME}.x64.o"

if [ ! -f "$SRC" ]; then
    echo "build.sh: no BOF named '$NAME' (looking for $SRC)"
    exit 1
fi

mkdir -p "$(dirname "$OUT")" "$DEST"

gcc -c -fPIC -nostdlib -m64 -O2 -Wall -Wextra \
    -I bof/include "$SRC" -o "$OUT"

cp "$OUT" "$DEST/"

echo "built $OUT -> $DEST/$(basename "$OUT")"
