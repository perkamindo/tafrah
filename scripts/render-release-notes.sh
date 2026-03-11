#!/bin/sh

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "usage: sh ./scripts/render-release-notes.sh <tag> [output-file] [changelog]" >&2
  exit 1
fi

tag="$1"
output_file="${2:-}"
script_dir="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "${script_dir}/.." && pwd)"
changelog="${3:-${repo_root}/CHANGELOG.md}"
version="${tag#v}"

tmp_output="$(mktemp)"
cleanup() {
  rm -f "$tmp_output"
}
trap cleanup EXIT

if ! awk -v version="$version" '
  BEGIN {
    capture = 0;
    found = 0;
  }

  {
    target = ("^## \\[" version "\\] - ");
    legacy = ("^## " version " - ");

    if ($0 ~ target || $0 ~ legacy) {
      capture = 1;
      found = 1;
    } else if (capture && $0 ~ /^## /) {
      exit 0;
    }

    if (capture) {
      print;
    }
  }

  END {
    if (!found) {
      exit 2;
    }
  }
' "$changelog" > "$tmp_output"; then
  echo "failed to render release notes for ${tag} from ${changelog}" >&2
  exit 1
fi

if [ -n "$output_file" ]; then
  cp "$tmp_output" "$output_file"
else
  cat "$tmp_output"
fi
