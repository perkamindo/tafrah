# Tafrah Auth Demo

This example bundle demonstrates that the native Rust `tafrah` library can be consumed from other languages through the installed C ABI, while Rust applications can continue to use the native crates directly.

The examples focus on proof of use, not on packaging or framework integration.

## What This Demo Covers

- FIPS 203 with `ML-KEM-768` for key exchange and file-encryption key derivation
- FIPS 204 with `ML-DSA-65` for signatures
- FIPS 205 with `SLH-DSA-SHAKE-128f` for signatures
- FIPS 206 with `Falcon-512` for signatures
- FIPS 207 with `HQC-128` for KEM smoke coverage across language examples

## Directory Layout

- `python/`: Python wrapper package and simple example
- `cpp/`: C++ example using the installed header
- `go/`: Go wrapper package and example binary
- `java/`: JNI wrapper and Java example
- `kotlin/`: Kotlin entrypoint using the JNI bridge
- `js/`: Node.js wrapper over a native addon
- `rust/`: direct native-crate example without the ABI layer
- `native/`: shared native example logic used by C++, Java, Kotlin, and JavaScript
- `tafrah_ctypes.py`: minimal Python `ctypes` wrapper
- `proof_demo.py`: richer end-to-end proof and small benchmark script
- `run_language_examples.sh`: compiles and runs all examples
- `build_native.sh`: builds the release `tafrah-abi` shared library

## Quick Start

From the repository root:

```sh
make install PREFIX="$PWD/dist/install"
make examples
```

Or from this directory:

```sh
sh build_native.sh
python3 proof_demo.py
sh run_language_examples.sh
```

## What the Scripts Do

`build_native.sh`

- builds `tafrah-abi` in release mode

`proof_demo.py`

- performs ML-KEM key exchange
- derives proof-only symmetric keys in Python
- simulates a small client/server chat exchange
- encrypts and recovers a sample file
- signs and verifies with ML-DSA, SLH-DSA, and Falcon
- prints small latency measurements

`run_language_examples.sh`

- installs `tafrah-abi` into a local prefix under `build/prefix`
- compiles or prepares the Python, C++, Java, Kotlin, Go, JavaScript, and Rust examples
- runs each example and writes JSON results under `results/`

Generated directories such as `build/`, `results/`, `artifacts/`, and `__pycache__/` are ignored and can be deleted safely between runs.

## Beginner Notes

- Start with `rust/` if you are writing a Rust application.
- Start with `python/` or `tafrah_ctypes.py` if you want the smallest possible foreign-language example.
- Use `run_language_examples.sh` when you want one command that validates the install layout end to end.

## Scope and Limits

- The Python symmetric encryption layer is proof-only. It is intentionally simple and is not presented as a production transport or file format.
- The proof scripts now use HMAC-SHA3-256 based derivation and explicit framing, but they are still demonstrations rather than finalized protocol or file-format guidance.
- The shared-library wrappers are thin by design. Their job is to prove ABI usability, not to replace a polished SDK yet.
- The Rust example is the recommended path for Rust applications because it avoids the ABI layer entirely.
