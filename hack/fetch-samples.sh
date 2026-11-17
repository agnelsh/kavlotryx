#!/usr/bin/env bash
# Download third-party sample scanner outputs from DefectDojo's test suite
# (BSD-3-Clause) at a pinned commit, and verify each file's SHA-256.
# Files land in examples/samples/defectdojo/ (git-ignored); they are not
# redistributed with Kavlotryx.
set -euo pipefail
cd "$(dirname "$0")/.."
SHA=bb64f7aa1c2f722d88f02cfd3f4b5bb015ee3e43   # django-DefectDojo master, 2026-11-16
BASE="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/$SHA/unittests/scans"
OUT=examples/samples/defectdojo
SUMS="$PWD/examples/samples/SHA256SUMS"
mkdir -p "$OUT"
cd "$OUT"
while read -r sum path; do
  [ -z "$path" ] && continue
  if [ -f "$path" ] && echo "$sum  $path" | shasum -a 256 -c --status; then
    continue
  fi
  mkdir -p "$(dirname "$path")"
  curl -sSfL --proto '=https' -o "$path.tmp" "$BASE/$path"
  mv "$path.tmp" "$path"
done < "$SUMS"
shasum -a 256 -c "$SUMS" --quiet
cat > NOTICE.md <<NOTE
These files come from the DefectDojo project test suite, commit $SHA:
https://github.com/DefectDojo/django-DefectDojo/tree/$SHA/unittests/scans

DefectDojo is licensed under the BSD 3-Clause License, Copyright (c) DefectDojo Inc.
The wiz/ files are sample exports from Wiz's public demo tenant as published there.
They are downloaded for local demos and tests only and are not part of Kavlotryx.
NOTE
echo "samples ready in $OUT ($(wc -l < "$SUMS" | tr -d ' ') files, checksums OK)"
