#!/usr/bin/env bash
# The snapshots of `tuf/v1` that the `snapshot` job of pages.yml signed, handed to the jobs
# `timestamp` and `build` as a job output (`docs/design/publishers.md`, "Онлайн-снимок"): the
# new one, and the published one it extends when the tree does not have it. One line per
# file, `<N>.snapshot.json <base64>`; the timestamp hashes these bytes, so they go as they are.
#
#   snapshot-files.sh pack <tree metadata> <copy metadata>
#       prints the lines of the files the copy has and the tree has not;
#   SNAPSHOTS=<lines> snapshot-files.sh unpack <metadata>
#       writes them into <metadata>.
#
# Only `<N>.snapshot.json`, one or two of them, each at most 128 KiB (what the client reads),
# none that is there already: anything else is refused before a file is written.
set -euo pipefail

MAX=131072
NAME='^[0-9]{1,20}\.snapshot\.json$'

fail() {
  echo "::error::snapshot-files.sh: $1" >&2
  exit 1
}

case "${1:-}" in
  pack)
    [ "$#" -eq 3 ] || fail "usage: pack <tree metadata> <copy metadata>"
    count=0
    shopt -s nullglob dotglob
    for file in "$3"/*; do
      name="${file##*/}"
      if [ -e "$2/$name" ] || [ -L "$2/$name" ]; then
        continue
      fi
      [[ "$name" =~ $NAME ]] || fail "the copy has a new file that is not <N>.snapshot.json"
      { [ -f "$file" ] && [ ! -L "$file" ]; } || fail "$name is not a regular file"
      size=$(stat -c %s -- "$file")
      [ "$size" -le "$MAX" ] || fail "$name is $size bytes, more than $MAX"
      printf '%s %s\n' "$name" "$(base64 -w0 -- "$file")"
      count=$((count + 1))
    done
    { [ "$count" -ge 1 ] && [ "$count" -le 2 ]; } || fail "$count new snapshots, not one or two"
    ;;
  unpack)
    [ "$#" -eq 2 ] || fail "usage: unpack <metadata>"
    [ -d "$2" ] || fail "$2 is not a directory"
    [ -n "${SNAPSHOTS:-}" ] || fail "no snapshot was handed over"
    mapfile -t lines <<< "$SNAPSHOTS"
    { [ "${#lines[@]}" -ge 1 ] && [ "${#lines[@]}" -le 2 ]; } || fail "${#lines[@]} lines, not one or two"
    staged=$(mktemp -d)
    trap 'rm -rf -- "$staged"' EXIT
    names=()
    for line in "${lines[@]}"; do
      name="${line%% *}"
      data="${line#* }"
      { [[ "$name" =~ $NAME ]] && [[ "$data" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; } \
        || fail "a line is not <N>.snapshot.json <base64>"
      # The base64 of MAX bytes, checked before anything is decoded.
      [ "${#data}" -le $(((MAX + 2) / 3 * 4)) ] || fail "$name is more than $MAX bytes"
      { [ ! -e "$2/$name" ] && [ ! -L "$2/$name" ] && [ ! -e "$staged/$name" ]; } || fail "$name is there already"
      printf '%s' "$data" | base64 -d > "$staged/$name" || fail "$name is not base64"
      size=$(stat -c %s -- "$staged/$name")
      [ "$size" -le "$MAX" ] || fail "$name is $size bytes, more than $MAX"
      names+=("$name")
    done
    for name in "${names[@]}"; do
      mv -n -- "$staged/$name" "$2/$name"
      [ ! -e "$staged/$name" ] || fail "$name could not be written"
    done
    ;;
  *)
    fail "usage: snapshot-files.sh pack <tree metadata> <copy metadata> | unpack <metadata>"
    ;;
esac
