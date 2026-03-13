#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
PREFIX=${1:-"$SCRIPT_DIR/target/install"}

cd "$SCRIPT_DIR/.."
cargo build -p tafrah-abi --release

case "$(uname -s)" in
  Darwin)
    LIB_NAME=libtafrah_abi.dylib
    STATIC_LIB_NAME=libtafrah_abi.a
    LEGACY_LIB_NAME=libtafrah_ffi.dylib
    ;;
  Linux)
    LIB_NAME=libtafrah_abi.so
    STATIC_LIB_NAME=libtafrah_abi.a
    LEGACY_LIB_NAME=libtafrah_ffi.so
    ;;
  MINGW*|MSYS*|CYGWIN*)
    LIB_NAME=tafrah_abi.dll
    STATIC_LIB_NAME=tafrah_abi.lib
    LEGACY_LIB_NAME=tafrah_ffi.dll
    ;;
  *)
    echo "Unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

mkdir -p "$PREFIX/lib" "$PREFIX/include/tafrah" "$PREFIX/lib/pkgconfig"

cp "$SCRIPT_DIR/include/tafrah_abi.h" "$PREFIX/include/tafrah_abi.h"
cp "$SCRIPT_DIR/include/tafrah_ffi.h" "$PREFIX/include/tafrah_ffi.h"
cp "$SCRIPT_DIR/include/tafrah/tafrah.h" "$PREFIX/include/tafrah/tafrah.h"
cp "$SCRIPT_DIR/include/tafrah/tafrah.hpp" "$PREFIX/include/tafrah/tafrah.hpp"
cp "$SCRIPT_DIR/../target/release/$LIB_NAME" "$PREFIX/lib/$LIB_NAME"
cp "$SCRIPT_DIR/../target/release/$STATIC_LIB_NAME" "$PREFIX/lib/$STATIC_LIB_NAME"
cp "$SCRIPT_DIR/../target/release/$LIB_NAME" "$PREFIX/lib/$LEGACY_LIB_NAME"

sed \
  -e "s#@PREFIX@#$PREFIX#g" \
  -e "s#@VERSION@#0.1.7#g" \
  "$SCRIPT_DIR/pkgconfig/tafrah.pc.in" > "$PREFIX/lib/pkgconfig/tafrah.pc"

printf 'Installed tafrah-abi to %s\n' "$PREFIX"
