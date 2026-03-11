# Examples

This directory contains usage examples for the Tafrah ecosystem.

## Recommended Starting Point

Start with [auth-demo/README.md](auth-demo/README.md).

That example bundle is organized to help new users answer three questions quickly:

1. How do I use Tafrah directly from Rust?
2. How do I install the C ABI and call it from another language?
3. How do I verify that key generation, encapsulation, signing, verification, and shared-library loading actually work end to end?

## Example Categories

- `auth-demo/`: cross-language, install-style examples for Rust, Python, C++, Go, Java, Kotlin, and JavaScript.

## Typical Workflow

From the repository root:

```sh
make install PREFIX="$PWD/dist/install"
make examples
```

For a richer Python-only proof:

```sh
make demo-python
```
