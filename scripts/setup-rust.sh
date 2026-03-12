#!/bin/sh
set -eu

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required on the GitHub runner" >&2
  exit 1
fi

rustup toolchain install stable --profile minimal --no-self-update
rustup default stable

rustc --version
cargo --version
