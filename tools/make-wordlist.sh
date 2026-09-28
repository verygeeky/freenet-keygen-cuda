#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Rebuild words-b58.txt from SCOWL (Spell Checker Oriented Word Lists).
#
# Takes the two most common SCOWL size levels (10 and 20) of the "english" and
# "american" word lists, keeps plain lowercase words, and drops any word that
# cannot appear in a base58 string (base58 has no 0, O, I or l).
#
# SCOWL is Copyright 2000-2018 Kevin Atkinson and distributed under a
# permissive license; see THIRD_PARTY_NOTICES.md and wordlists/SCOWL-Copyright.
#
# Usage: tools/make-wordlist.sh [output-file]
set -eu

VERSION=2020.12.07
URL="https://downloads.sourceforge.net/wordlist/scowl-$VERSION.tar.gz"
SHA256=5587667caa20c4891390c2d42dbb4d5c4c3f41bee77af1457ece3ba23fb859cc
OUT=${1:-words-b58.txt}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/scowl.tar.gz" "$URL"
echo "$SHA256  $tmp/scowl.tar.gz" | sha256sum -c - >/dev/null
tar -xzf "$tmp/scowl.tar.gz" -C "$tmp"

final="$tmp/scowl-$VERSION/final"
cat "$final/english-words.10" "$final/american-words.10" \
    "$final/english-words.20" "$final/american-words.20" \
  | iconv -f latin1 -t utf-8 \
  | LC_ALL=C grep -E '^[a-z]+$' \
  | grep -v 'l' \
  | LC_ALL=C sort -u > "$OUT"

echo "wrote $(wc -l < "$OUT") words to $OUT"
