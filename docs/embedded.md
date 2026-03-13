# Embedded Support

Tafrah's core algorithm crates are written as `no_std` Rust crates, but that
does not automatically mean every embedded target is ready today.

## Current Status

- `tafrah`, `tafrah-ml-kem`, `tafrah-ml-dsa`, `tafrah-slh-dsa`,
  `tafrah-falcon`, `tafrah-hqc`, `tafrah-math`, and `tafrah-traits` are
  `no_std`
- several crates currently depend on `alloc`
- `tafrah-abi` and `tafrah-uniffi` are host-side integration layers and should
  not be treated as embedded targets

In practice, that means:

- alloc-capable embedded Linux and similar environments are realistic targets
- richer embedded systems with a global allocator can be explored now
- very small bare-metal microcontrollers without allocator support are not yet a
  first-class target

## Constraints To Keep In Mind

- many carrier types currently own heap-backed byte buffers
- Falcon uses floating-point heavy paths that are not a natural fit for small
  MCU-class devices
- HQC and SLH-DSA can have substantial memory pressure depending on parameter
  set and integration style
- the release examples and the ABI layer assume a host operating system

## Recommended Embedded-Oriented Stack

If embedded support becomes a product goal, the most useful stack is likely:

- [`embassy`](https://embassy.dev/) for async embedded Rust systems
- [`heapless`](https://docs.rs/heapless/latest/heapless/) for fixed-capacity
  data structures
- [`embedded-alloc`](https://docs.rs/embedded-alloc/latest/embedded_alloc/) for
  allocator-backed `alloc` environments
- [`probe-rs`](https://probe.rs/) or `cargo-embed` for flashing and debugging
- target-specific benchmarking and memory profiling early in the port

## Practical Assessment

Today, Tafrah is best described as:

- ready for host platforms through Rust crates, ABI, and UniFFI
- promising for larger `alloc`-capable embedded environments
- not yet validated as a small bare-metal MCU library

If embedded becomes a near-term requirement, the next engineering step should be
to benchmark and profile the concrete target first, then identify which crates
need `Vec`-free or heap-free alternatives.
