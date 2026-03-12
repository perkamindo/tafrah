//! Tafrah umbrella crate.
//!
//! This crate re-exports the scheme crates and shared traits used by the
//! workspace:
//!
//! - `ml_kem` for FIPS 203
//! - `ml_dsa` for FIPS 204
//! - `slh_dsa` for FIPS 205
//! - `falcon` for FIPS 206
//! - `hqc` for FIPS 207
//! - `traits` for shared traits and errors
//!
//! Rust applications should prefer this native surface over the C ABI layer.
//!
//! Feature flags:
//!
//! - `std`
//! - `alloc`
//! - `ml-kem`
//! - `ml-dsa`
//! - `slh-dsa`
//! - `falcon`
//! - `hqc`
//!
//! See the repository `docs/` directory and `examples/auth-demo/rust/` for
//! fuller usage examples.
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub use tafrah_traits as traits;

#[cfg(feature = "ml-kem")]
pub use tafrah_ml_kem as ml_kem;

#[cfg(feature = "ml-dsa")]
pub use tafrah_ml_dsa as ml_dsa;

#[cfg(feature = "slh-dsa")]
pub use tafrah_slh_dsa as slh_dsa;

#[cfg(feature = "falcon")]
pub use tafrah_falcon as falcon;

#[cfg(feature = "hqc")]
pub use tafrah_hqc as hqc;
