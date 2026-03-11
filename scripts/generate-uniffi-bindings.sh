#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LANGUAGE=${1:-python}
OUT_DIR=${2:-"$ROOT_DIR/target/uniffi/$LANGUAGE"}

case "$(uname -s)" in
  Darwin) LIB_NAME=libtafrah_uniffi.dylib ;;
  Linux) LIB_NAME=libtafrah_uniffi.so ;;
  MINGW*|MSYS*|CYGWIN*) LIB_NAME=tafrah_uniffi.dll ;;
  *)
    echo "Unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

cd "$ROOT_DIR"
cargo build -p tafrah-uniffi --release
cargo run -p uniffi-bindgen -- generate \
  --library "target/release/$LIB_NAME" \
  --language "$LANGUAGE" \
  --out-dir "$OUT_DIR"
