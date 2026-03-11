#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
WORKSPACE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

cd "$WORKSPACE_ROOT"
make build-abi

case "$(uname -s)" in
  Darwin) LIB_NAME=libtafrah_abi.dylib ;;
  Linux) LIB_NAME=libtafrah_abi.so ;;
  MINGW*|MSYS*|CYGWIN*) LIB_NAME=tafrah_abi.dll ;;
  *)
    echo "Unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

echo "Built: $WORKSPACE_ROOT/target/release/$LIB_NAME"
