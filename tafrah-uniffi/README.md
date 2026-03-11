# Tafrah UniFFI

Host-side UniFFI surface for Tafrah PQC primitives. This crate wraps the stable
Rust implementations from `tafrah-ml-kem`, `tafrah-ml-dsa`, `tafrah-slh-dsa`,
`tafrah-falcon`, and `tafrah-hqc` with a byte-oriented API that is easier to consume from
Swift, Kotlin, and Python.

Current scope:

- `ML-KEM-768`
- `ML-DSA-65`
- `SLH-DSA-SHAKE-128f`
- `Falcon-512`
- `Falcon-1024`
- `HQC-128`
- `HQC-192`
- `HQC-256`

Typical local flow on the current host:

```bash
cargo build -p tafrah-uniffi --release
cargo run -p uniffi-bindgen -- generate \
  --library target/release/libtafrah_uniffi.dylib \
  --language python \
  --out-dir target/uniffi/python
```
