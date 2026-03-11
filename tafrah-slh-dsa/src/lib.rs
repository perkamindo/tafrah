//! Native Rust SLH-DSA implementation for FIPS 205.
//!
//! SLH-DSA exposes generic entry points plus the public parameter bundles in
//! `params`, such as `SLH_DSA_SHAKE_128F`.
#![no_std]

extern crate alloc;

pub mod address;
pub mod fors;
pub mod hash_functions;
pub mod hypertree;
pub mod keygen;
pub mod params;
pub mod sign;
pub mod types;
pub mod verify;
pub mod wots;
pub mod xmss;
