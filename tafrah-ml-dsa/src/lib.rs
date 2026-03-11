//! Native Rust ML-DSA implementation for FIPS 204.
//!
//! The fixed-parameter convenience modules are:
//!
//! - `ml_dsa_44`
//! - `ml_dsa_65`
//! - `ml_dsa_87`
//!
//! Generic entry points live in `keygen`, `sign`, and `verify`.
#![no_std]

extern crate alloc;

pub mod context;
pub mod encode;
pub mod hint;
pub mod keygen;
pub mod ntt_dsa;
pub mod params;
pub mod sign;
pub mod types;
pub mod verify;

pub mod ml_dsa_44;
pub mod ml_dsa_65;
pub mod ml_dsa_87;
