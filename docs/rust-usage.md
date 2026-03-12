# Rust Usage

Rust applications should use the native crates directly instead of going through the C ABI layer.

## Umbrella Crate

Add the umbrella crate with the features you need:

```toml
[dependencies]
tafrah = { version = "0.1", features = ["std", "ml-kem", "ml-dsa", "slh-dsa", "falcon", "hqc"] }
```

## Example

```rust
use rand::thread_rng;
use tafrah::falcon::falcon_512;
use tafrah::ml_dsa::ml_dsa_65;
use tafrah::ml_kem::ml_kem_768;
use tafrah::slh_dsa::params::SLH_DSA_SHAKE_128F;
use tafrah::slh_dsa::sign::slh_sign;
use tafrah::slh_dsa::verify::slh_verify;

let mut rng = thread_rng();

let (ek, dk) = ml_kem_768::keygen(&mut rng);
let (ct, sender_ss) = ml_kem_768::encapsulate(&ek, &mut rng)?;
let recipient_ss = ml_kem_768::decapsulate(&dk, &ct)?;
assert_eq!(sender_ss.bytes, recipient_ss.bytes);

let (vk, sk) = ml_dsa_65::keygen(&mut rng);
let message = b"tafrah";
let sig = ml_dsa_65::sign(&sk, message, &mut rng);
ml_dsa_65::verify(&vk, message, &sig)?;

let (slh_vk, slh_sk) = tafrah::slh_dsa::keygen::slh_dsa_keygen(&mut rng, &SLH_DSA_SHAKE_128F)?;
let slh_sig = slh_sign(&slh_sk, message, b"docs", None, &SLH_DSA_SHAKE_128F)?;
slh_verify(&slh_vk, message, &slh_sig, b"docs", &SLH_DSA_SHAKE_128F)?;

let (falcon_vk, falcon_sk) = falcon_512::keygen(&mut rng)?;
let falcon_sig = falcon_512::sign(&falcon_sk, message, &mut rng)?;
falcon_512::verify(&falcon_vk, message, &falcon_sig)?;
# Ok::<(), tafrah::traits::Error>(())
```

See [../examples/auth-demo/rust/src/main.rs](../examples/auth-demo/rust/src/main.rs) for a fuller example.
