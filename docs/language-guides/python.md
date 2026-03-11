# Python Guide

The smallest Python path today is `ctypes` over the installed C ABI.

## Quick Start

```sh
make install PREFIX="$PWD/dist/install"
python3 examples/auth-demo/python/example.py
```

For the richer proof:

```sh
python3 examples/auth-demo/proof_demo.py
```

Relevant files:

- `examples/auth-demo/tafrah_ctypes.py`
- `examples/auth-demo/python/tafrah/__init__.py`
- `examples/auth-demo/python/example.py`
