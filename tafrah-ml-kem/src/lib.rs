//! Native Rust ML-KEM implementation for FIPS 203.
//!
//! The fixed-parameter convenience modules are:
//!
//! - `ml_kem_512`
//! - `ml_kem_768`
//! - `ml_kem_1024`
//!
//! Generic entry points live in `keygen`, `encaps`, and `decaps`.
#![no_std]

extern crate alloc;

pub mod decaps;
pub mod encaps;
pub mod encode;
pub mod keygen;
pub mod params;
pub mod types;

pub mod ml_kem_1024;
pub mod ml_kem_512;
pub mod ml_kem_768;
