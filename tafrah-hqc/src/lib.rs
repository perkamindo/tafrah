//! Native Rust HQC implementation for FIPS 207.
//!
//! The fixed-parameter convenience modules are:
//!
//! - `hqc_128`
//! - `hqc_192`
//! - `hqc_256`
//!
//! Generic entry points live in `keygen`, `encaps`, and `decaps`.
#![no_std]

extern crate alloc;

pub mod arithmetic;
mod code;
pub mod decaps;
pub mod encaps;
mod fft;
mod gf;
mod hash;
pub mod hqc_128;
pub mod hqc_192;
pub mod hqc_256;
pub mod keygen;
pub mod params;
pub mod parse;
mod pke;
mod reed_muller;
mod reed_solomon;
pub mod sampling;
pub mod types;
