//! Native Rust Falcon implementation for FIPS 206.
//!
//! The fixed-parameter convenience modules are:
//!
//! - `falcon_512`
//! - `falcon_1024`
//!
//! Generic entry points live in `keygen`, `sign`, `verify`, and `derive`.
#![no_std]

extern crate alloc;

mod codec;
mod common;
pub mod derive;
mod expanded;
pub mod falcon_1024;
pub mod falcon_512;
mod fft;
mod fpr;
mod fpr_tables;
mod key_material;
pub mod keygen;
mod mq;
mod modp;
mod ntru;
pub mod params;
mod prng;
mod reduction;
pub mod sign;
pub mod types;
pub mod verify;
mod zint;
