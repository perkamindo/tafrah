#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
WORKSPACE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BUILD_DIR="$SCRIPT_DIR/build"
RESULTS_DIR="$SCRIPT_DIR/results"
INSTALL_PREFIX="$BUILD_DIR/prefix"

mkdir -p "$BUILD_DIR/cpp" "$BUILD_DIR/go" "$BUILD_DIR/java/classes" "$BUILD_DIR/js" "$BUILD_DIR/kotlin" "$BUILD_DIR/rust-target" "$RESULTS_DIR"
mkdir -p "$BUILD_DIR/go/cache"

sh "$WORKSPACE_ROOT/tafrah-abi/install.sh" "$INSTALL_PREFIX"

ABI_INCLUDE_DIR="$INSTALL_PREFIX/include"
ABI_LIB_DIR="$INSTALL_PREFIX/lib"
PKG_CONFIG_PATH="$INSTALL_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export PKG_CONFIG_PATH

TAFRAH_CFLAGS=$(pkg-config --cflags tafrah)
TAFRAH_LIBS=$(pkg-config --libs tafrah)

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

detect_java_home() {
  if [ -n "${JAVA_HOME:-}" ]; then
    printf '%s\n' "$JAVA_HOME"
    return
  fi
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    /usr/libexec/java_home
    return
  fi
  if command -v javac >/dev/null 2>&1; then
    dirname "$(dirname "$(readlink -f "$(command -v javac)")")"
    return
  fi
  echo "Unable to determine JAVA_HOME" >&2
  exit 1
}

detect_node_include() {
  for candidate in \
    /opt/homebrew/include/node \
    /usr/local/include/node \
    /usr/include/node \
    /usr/include/nodejs/src \
    /usr/include/nodejs
  do
    if [ -d "$candidate" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "Unable to locate Node.js headers" >&2
  exit 1
}

require_cmd python3
require_cmd clang++
require_cmd javac
require_cmd java
require_cmd kotlinc
require_cmd kotlin
require_cmd go
require_cmd node
require_cmd pkg-config

JAVA_HOME=$(detect_java_home)
NODE_INCLUDE_DIR=$(detect_node_include)

OS_NAME=$(uname -s)
SHARED_EXT=so
JAVA_SHARED_FLAGS="-shared -fPIC"
NODE_SHARED_FLAGS="-shared -fPIC"
case "$OS_NAME" in
  Darwin)
    SHARED_EXT=dylib
    JAVA_SHARED_FLAGS="-shared -fPIC -undefined dynamic_lookup"
    NODE_SHARED_FLAGS="-shared -fPIC -undefined dynamic_lookup"
    ;;
esac

clang++ -std=c++17 -O2 \
  $TAFRAH_CFLAGS \
  "$SCRIPT_DIR/cpp/main.cpp" \
  $TAFRAH_LIBS \
  -o "$BUILD_DIR/cpp/tafrah_cpp_demo"

clang++ -std=c++17 -O2 $JAVA_SHARED_FLAGS \
  -I"$JAVA_HOME/include" \
  -I"$JAVA_HOME/include/$([ "$OS_NAME" = Darwin ] && printf darwin || printf linux)" \
  $TAFRAH_CFLAGS \
  -I"$SCRIPT_DIR/native" \
  "$SCRIPT_DIR/native/demo_core.cpp" \
  "$SCRIPT_DIR/java/native/tafrah_jni.cpp" \
  $TAFRAH_LIBS \
  -o "$BUILD_DIR/java/libtafrah_jni.$SHARED_EXT"

javac -d "$BUILD_DIR/java/classes" \
  "$SCRIPT_DIR/java/src/io/tafrah/demo/Tafrah.java" \
  "$SCRIPT_DIR/java/src/io/tafrah/demo/TafrahJni.java" \
  "$SCRIPT_DIR/java/src/io/tafrah/demo/Main.java"

kotlinc \
  -cp "$BUILD_DIR/java/classes" \
  "$SCRIPT_DIR/kotlin/Main.kt" \
  -d "$BUILD_DIR/kotlin"

(
  cd "$SCRIPT_DIR/go"
  GOCACHE="$BUILD_DIR/go/cache" CGO_ENABLED=1 go build -o "$BUILD_DIR/go/tafrah_go_demo" ./cmd/demo
)

clang++ -std=c++17 -O2 $NODE_SHARED_FLAGS \
  -I"$NODE_INCLUDE_DIR" \
  $TAFRAH_CFLAGS \
  -I"$SCRIPT_DIR/native" \
  "$SCRIPT_DIR/native/demo_core.cpp" \
  "$SCRIPT_DIR/js/tafrah_node.cc" \
  $TAFRAH_LIBS \
  -o "$BUILD_DIR/js/tafrah_node.node"

if [ "$OS_NAME" = Darwin ]; then
  export DYLD_LIBRARY_PATH="$ABI_LIB_DIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
else
  export LD_LIBRARY_PATH="$ABI_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
export TAFRAH_INSTALL_PREFIX="$INSTALL_PREFIX"

python3 "$SCRIPT_DIR/python/example.py" > "$RESULTS_DIR/python.json"
"$BUILD_DIR/cpp/tafrah_cpp_demo" > "$RESULTS_DIR/cpp.json"
java \
  -Dtafrah.jni.path="$BUILD_DIR/java/libtafrah_jni.$SHARED_EXT" \
  -cp "$BUILD_DIR/java/classes" \
  io.tafrah.demo.Main > "$RESULTS_DIR/java.json"
kotlin \
  -J-Dtafrah.jni.path="$BUILD_DIR/java/libtafrah_jni.$SHARED_EXT" \
  -cp "$BUILD_DIR/kotlin:$BUILD_DIR/java/classes" \
  io.tafrah.demo.MainKt > "$RESULTS_DIR/kotlin.json"
"$BUILD_DIR/go/tafrah_go_demo" > "$RESULTS_DIR/go.json"
node "$SCRIPT_DIR/js/example.mjs" "$BUILD_DIR/js/tafrah_node.node" > "$RESULTS_DIR/js.json"
(
  cd "$SCRIPT_DIR/rust"
  CARGO_TARGET_DIR="$BUILD_DIR/rust-target" cargo run --quiet --offline > "$RESULTS_DIR/rust.json"
)

for language in python cpp java kotlin go js rust; do
  printf '%s: ' "$language"
  cat "$RESULTS_DIR/$language.json"
done
