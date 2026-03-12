//! Deterministic math primitives shared across Tafrah scheme crates.
//!
//! `tafrah-math` intentionally does not depend on `rand`. Sampling helpers in
//! this crate consume caller-supplied seeds or pre-expanded byte strings so the
//! entropy policy stays at the scheme layer, not in the low-level arithmetic
//! layer.
//!
//! In practice:
//!
//! - `tafrah-math` owns arithmetic, transforms, compression, and deterministic
//!   sampling kernels
//! - scheme crates own RNG-backed key generation and randomized signing flows
//! - host bindings and applications decide how randomness is sourced
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod compress;
pub mod field;
pub mod matrix;
pub mod ntt;
pub mod poly;
pub mod sampling;
