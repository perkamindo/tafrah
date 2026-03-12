//! Native Rust ML-DSA implementation for FIPS 204.
//!
//! The fixed-parameter convenience modules are:
//!
//! - `ml_dsa_44`
//! - `ml_dsa_65`
//! - `ml_dsa_87`
//!
//! Generic entry points live in `keygen`, `sign`, `prehash`, and `verify`.
//!
//! The public ML-DSA surface covers:
//!
//! - randomized and deterministic detached signatures
//! - caller-supplied `mu` signing and verification
//! - HashML-DSA pre-hash signing and verification
//! - internal deterministic key generation from a 32-byte seed
//! - signed-message `signature || message` helpers
//!
//! For the most direct FIPS 204 entry points, start with the fixed-parameter
//! modules. Use the generic modules when the parameter set or message framing
//! is selected dynamically by the caller.
#![no_std]

extern crate alloc;

pub mod context;
pub mod encode;
pub mod hint;
pub mod keygen;
pub mod ntt_dsa;
pub mod params;
pub mod prehash;
pub mod sign;
pub mod types;
pub mod verify;

pub mod ml_dsa_44;
pub mod ml_dsa_65;
pub mod ml_dsa_87;
