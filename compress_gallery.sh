#!/usr/bin/env bash

set -euo pipefail

SRC="./gallery"
DST="./assets/gallery"

mkdir -p "$DST"

find "$SRC" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' \) -print0 |

while IFS= read -r -d '' src; do
    relative="${src#"$SRC"/}"
    dst="$DST/$relative"

    mkdir -p "$(dirname "$dst")"

    echo "$src -> $dst"

    magick "$src" -auto-orient -resize '2000x2000>' -quality 82 "$dst"
done