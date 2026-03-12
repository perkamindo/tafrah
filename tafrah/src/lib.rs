//! Native Rust umbrella crate for the Tafrah post-quantum cryptography
//! workspace.
//!
//! `tafrah` re-exports the scheme crates and common traits used throughout the
//! workspace so Rust applications can depend on a single crate and then opt
//! into the algorithms they need.
//!
//! ## Standards and re-exports
//!
//! | Standard | Primitive class | Re-export | Fixed-parameter entry points |
//! | --- | --- | --- | --- |
//! | FIPS 203 | KEM | `ml_kem` | `ml_kem_512`, `ml_kem_768`, `ml_kem_1024` |
//! | FIPS 204 | Signature | `ml_dsa` | `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87` |
//! | FIPS 205 | Hash-based signature | `slh_dsa` | parameter bundles in `slh_dsa::params` |
//! | FIPS 206 | Signature | `falcon` | `falcon_512`, `falcon_1024` |
//! | FIPS 207 | KEM | `hqc` | `hqc_128`, `hqc_192`, `hqc_256` |
//! | Shared surface | Traits and errors | `traits` | `traits::kem`, `traits::dsa`, `traits::serdes` |
//!
//! The umbrella crate is the right entry point when:
//!
//! - your application wants a single dependency for multiple PQC schemes
//! - you want ergonomic fixed-parameter modules
//! - you want to share trait bounds across KEM and signature code
//!
//! If you only need one scheme crate, depending on that crate directly is also
//! supported.
//!
//! ## Choosing an API surface
//!
//! Tafrah exposes two styles of native Rust API:
//!
//! - Fixed-parameter modules such as `ml_kem::ml_kem_768` or `falcon::falcon_512`
//!   provide the most direct way to call a specific standardized parameter set.
//! - Generic scheme modules such as `ml_kem::keygen`, `ml_dsa::sign`,
//!   `slh_dsa::verify`, `falcon::verify`, and `hqc::encaps` are useful when the
//!   parameter set is selected dynamically.
//!
//! The shared trait layer in `traits` provides common vocabulary for generic
//! consumers:
//!
//! - [`Encapsulate`](../tafrah_traits/kem/trait.Encapsulate.html) and
//!   [`Decapsulate`](../tafrah_traits/kem/trait.Decapsulate.html) for KEMs
//! - [`SigningKey`](../tafrah_traits/dsa/trait.SigningKey.html) and
//!   [`VerifyingKey`](../tafrah_traits/dsa/trait.VerifyingKey.html) for
//!   signatures
//!
//! ## Feature flags
//!
//! Default features enable the most common surface:
//!
//! - `std`
//! - `ml-kem`
//! - `ml-dsa`
//! - `slh-dsa`
//!
//! Additional optional features are:
//!
//! - `alloc` for heap-backed types without requiring full `std`
//! - `falcon` to re-export FIPS 206 Falcon
//! - `hqc` to re-export FIPS 207 HQC
//!
//! For example:
//!
//! ```toml
//! tafrah = { version = "0.1.2", features = ["falcon", "hqc"] }
//! ```
//!
//! ## Quick start: ML-KEM
//!
//! ```no_run
//! use rand::rngs::OsRng;
//! use tafrah::ml_kem::ml_kem_768;
//!
//! let mut rng = OsRng;
//! let (ek, dk) = ml_kem_768::keygen(&mut rng);
//! let (ct, client_ss) = ml_kem_768::encapsulate(&ek, &mut rng).expect("encapsulate");
//! let server_ss = ml_kem_768::decapsulate(&dk, &ct).expect("decapsulate");
//!
//! assert_eq!(client_ss.as_bytes(), server_ss.as_bytes());
//! ```
//!
//! ## Quick start: ML-DSA
//!
//! ```no_run
//! use rand::rngs::OsRng;
//! use tafrah::ml_dsa::ml_dsa_65;
//!
//! let mut rng = OsRng;
//! let (vk, sk) = ml_dsa_65::keygen(&mut rng);
//! let msg = b"tafrah-docs";
//! let sig = ml_dsa_65::sign_with_context(&sk, msg, &[], &mut rng).expect("sign");
//!
//! ml_dsa_65::verify_with_context(&vk, msg, &sig, &[]).expect("verify");
//! ```
//!
//! ## Optional schemes
//!
//! Falcon and HQC are intentionally feature-gated because not every consumer
//! needs them. They become part of the umbrella crate when the `falcon` and
//! `hqc` features are enabled.
//!
//! ```no_run
//! # #[cfg(feature = "falcon")] {
//! use rand::rngs::OsRng;
//! use tafrah::falcon::falcon_512;
//!
//! let mut rng = OsRng;
//! let (vk, sk) = falcon_512::keygen(&mut rng).expect("keygen");
//! let sig = falcon_512::sign(&sk, b"tafrah-docs", &mut rng).expect("sign");
//!
//! falcon_512::verify(&vk, b"tafrah-docs", &sig).expect("verify");
//! # }
//! ```
//!
//! ## no_std and allocation model
//!
//! The umbrella crate is `#![no_std]`. The core algorithm crates are also
//! written to remain usable in constrained environments, while `std` and
//! `alloc` remain opt-in at the crate feature level.
//!
//! In practice:
//!
//! - use the default feature set for ordinary desktop, server, and CLI
//!   applications
//! - disable default features and opt into `alloc` selectively for embedded or
//!   freestanding environments
//!
//! ## Errors, serialization, and malformed inputs
//!
//! Public operations return `Result` and use
//! [`traits::Error`](../tafrah_traits/enum.Error.html) or a scheme-local
//! equivalent to report malformed serialized keys, ciphertexts, signatures, RNG
//! failures, or unsupported parameter bundles.
//!
//! Serialized carrier types and parameter bundles live in the scheme crates:
//!
//! - `types` modules hold serialized key, ciphertext, shared secret, or
//!   signature carriers
//! - `params` modules expose the standardized parameter bundles used by the
//!   generic entry points
//!
//! ## Ecosystem layers
//!
//! This crate is the native Rust surface. The repository also contains:
//!
//! - `tafrah-abi` for the installable C ABI used by non-Rust host languages
//! - `tafrah-uniffi` for UniFFI-generated bindings
//! - `examples/auth-demo` for cross-language integration examples and proof
//!   scripts
//!
//! Rust applications should prefer this native surface when possible and only
//! move to the ABI layer when another language or runtime boundary requires it.
#![no_std]

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
