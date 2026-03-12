# Performance Notes

Tafrah currently prioritizes correctness, specification parity, portability, and
`no_std`-friendly native Rust implementations over architecture-specific
acceleration.

## Current Baseline

- Production code paths are scalar and portable.
- Experimental SIMD backends now exist behind explicit features:
  - `tafrah-math/avx2` for x86_64 hosts with runtime AVX2 detection
  - `tafrah-math/neon` for AArch64 hosts
- The shipped default remains scalar unless the build opts into one of those
  features.
- The current baseline is the same code that is validated by the workspace
  KAT, reference-oracle, ABI, and cross-language example suites.
- A native benchmark suite is available through `make bench` and
  `make bench-json`, with AVX2 opt-in through `make bench-avx2` and
  `make bench-avx2-json`, plus AArch64 Neon through `make bench-neon` and
  `make bench-neon-json`.

## Benchmark Suite

The benchmark harness lives in the non-published `tafrah-bench` crate and
covers two levels:

- math hotspots:
  - ML-KEM NTT
  - ML-KEM inverse NTT
  - ML-KEM pointwise/base multiplication
  - ML-DSA NTT
  - ML-DSA inverse NTT
  - ML-DSA pointwise multiplication
- scheme operations:
  - ML-KEM-768 keygen, encapsulation, decapsulation
  - ML-DSA-65 keygen, sign, verify
  - SLH-DSA-SHAKE-128f keygen, sign, verify
  - Falcon-512 keygen, sign, verify
  - HQC-128 keygen, encapsulation, decapsulation

The suite also reports host architecture, detected CPU features, and which math
backend is active for ML-KEM and ML-DSA.

## Current AVX2 Scope

The first AVX2 landing is intentionally narrow:

- ML-KEM forward NTT
- ML-KEM inverse NTT
- ML-KEM base multiplication in the NTT domain
- ML-DSA forward NTT
- ML-DSA inverse NTT
- ML-DSA pointwise Montgomery multiplication

The first Neon landing mirrors that scope for AArch64 hosts.

## Validation Status

- AVX2:
  - implemented for x86/x86_64
  - runtime detection keeps scalar fallback active when AVX2 is unavailable
  - CI now runs a dedicated x64 benchmark job with the `avx2` feature enabled
- Neon:
  - implemented for AArch64
  - verified on local Apple Silicon by executing the benchmark suite and
    observing `math_backends: {"ml_kem":"neon","ml_dsa":"neon"}`
- SVE:
  - not implemented yet
  - Apple Silicon does not expose SVE, so this repository cannot validate an
    SVE path on the current development host

The implementation keeps the scalar algorithms as the authoritative path and
uses AVX2 only for the coefficient-multiplication heavy portions of those
kernels. This keeps review risk manageable while still giving a real SIMD
backend to measure.

## Why AVX2 Is Still Limited

SIMD can materially improve throughput, but it also raises the review burden:

- architecture-specific code paths must preserve bit-for-bit behavior
- constant-time properties need to be re-reviewed on each backend
- `no_std` portability becomes harder
- CI and release validation need separate parity coverage per backend

For this repository, that tradeoff is not acceptable until the scalar baseline
is fully hardened and continuously validated.

## Expected Hotspots

The most likely areas to benefit from future SIMD work are:

- ML-KEM NTT-heavy polynomial arithmetic
- ML-KEM base multiplication in the NTT domain
- ML-DSA rejection sampling and decomposition helpers
- Falcon FFT, sampler, and floating-point heavy paths
- HQC vector arithmetic and code-based decoding primitives
- SLH-DSA hash-heavy batching on host platforms

## Safe Path For Future SIMD

SVE is not implemented at this point. Apple Silicon does not expose SVE, so the
current ARM SIMD work targets Neon, which is the portable AArch64 baseline.

Any future AVX2, NEON, or SVE backend should be introduced behind explicit
feature flags or runtime/target-feature gating, with the following requirements:

- identical public API
- deterministic parity against the scalar path
- KAT and reference-oracle parity on every optimized backend
- ABI and language-wrapper smoke tests against optimized builds
- clear fallback to the scalar implementation

Until that work is finished, the scalar Rust path remains the authoritative
implementation.
