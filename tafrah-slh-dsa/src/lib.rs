//! Native Rust SLH-DSA implementation for FIPS 205.
//!
//! This crate exposes the full public FIPS 205 surface for the standardized
//! twelve parameter sets:
//!
//! - internal APIs in [`keygen`], [`sign`], and [`verify`]
//! - pure SLH-DSA APIs with context strings in [`sign::slh_sign`] and
//!   [`verify::slh_verify`]
//! - HashSLH-DSA pre-hash APIs in [`prehash`]
//!
//! The public parameter bundles live in [`params`], for example
//! [`params::SLH_DSA_SHAKE_128F`].
#![no_std]

extern crate alloc;

pub mod address;
pub mod fors;
pub mod hash_functions;
pub mod hypertree;
pub mod keygen;
pub mod params;
pub mod prehash;
pub mod sign;
pub mod types;
pub mod verify;
pub mod wots;
pub mod xmss;
