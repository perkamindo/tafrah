# Java Guide

The Java example uses a small JNI bridge over the installed C ABI.

## Quick Start

```sh
make install PREFIX="$PWD/dist/install"
sh examples/auth-demo/run_language_examples.sh
```

Relevant files:

- `examples/auth-demo/java/src/io/tafrah/demo/Tafrah.java`
- `examples/auth-demo/java/src/io/tafrah/demo/TafrahJni.java`
- `examples/auth-demo/java/native/tafrah_jni.cpp`
