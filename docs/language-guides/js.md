# JavaScript Guide

The JavaScript example uses a native Node addon that forwards to the C ABI.

## Quick Start

```sh
make install PREFIX="$PWD/dist/install"
sh examples/auth-demo/run_language_examples.sh
```

Relevant files:

- `examples/auth-demo/js/tafrah_node.cc`
- `examples/auth-demo/js/tafrah.mjs`
- `examples/auth-demo/js/example.mjs`
