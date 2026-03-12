use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use tafrah_ml_kem::ml_kem_512;
use tafrah_ml_kem::params::{Params, ML_KEM_512};
use tafrah_ml_kem::types::{Ciphertext, DecapsulationKey, EncapsulationKey};
use tafrah_ml_kem::{encaps, keygen};
use tafrah_traits::Error;

#[test]
fn test_ml_kem_encapsulate_rejects_short_public_key() {
    let mut rng = rand::rng();
    let (ek, _) = ml_kem_512::keygen(&mut rng);

    let truncated_ek =
        EncapsulationKey::from_bytes(ek.as_bytes()[..ek.as_bytes().len() - 1].to_vec());

    assert!(matches!(
        ml_kem_512::encapsulate(&truncated_ek, &mut rng),
        Err(Error::InvalidKeyLength),
    ));
}

#[test]
fn test_ml_kem_decapsulate_implicit_rejects_short_ciphertext() {
    let mut rng = rand::rng();
    let (ek, dk) = ml_kem_512::keygen(&mut rng);
    let (ct, _) = ml_kem_512::encapsulate(&ek, &mut rng).unwrap();

    let truncated_ct = Ciphertext::from_bytes(ct.as_bytes()[..ct.as_bytes().len() - 1].to_vec());

    let z = &dk.as_bytes()[dk.as_bytes().len() - 32..];
    let mut j = Shake256::default();
    j.update(z);
    j.update(truncated_ct.as_bytes());
    let mut reader = j.finalize_xof();
    let mut expected = [0u8; 32];
    reader.read(&mut expected);

    let ss = ml_kem_512::decapsulate(&dk, &truncated_ct).unwrap();
    assert_eq!(ss.as_bytes(), expected);
}

#[test]
fn test_ml_kem_decapsulate_rejects_short_secret_key() {
    let mut rng = rand::rng();
    let (ek, dk) = ml_kem_512::keygen(&mut rng);
    let (ct, _) = ml_kem_512::encapsulate(&ek, &mut rng).unwrap();

    let truncated_dk =
        DecapsulationKey::from_bytes(dk.as_bytes()[..dk.as_bytes().len() - 1].to_vec());

    assert!(matches!(
        ml_kem_512::decapsulate(&truncated_dk, &ct),
        Err(Error::InvalidKeyLength),
    ));
}

#[test]
fn test_ml_kem_generic_api_rejects_invalid_params() {
    let mut rng = rand::rng();
    let invalid = Params {
        eta2: 3,
        eta2_bytes: 192,
        ..ML_KEM_512
    };
    let seed = [9u8; 32];

    assert!(matches!(
        keygen::k_pke_keygen(&seed, &invalid),
        Err(Error::InvalidParameter),
    ));
    assert!(matches!(
        keygen::ml_kem_keygen(&mut rng, &invalid),
        Err(Error::InvalidParameter),
    ));

    let (ek, dk) = ml_kem_512::keygen(&mut rng);
    let (ct, _) = ml_kem_512::encapsulate(&ek, &mut rng).unwrap();

    assert!(matches!(
        encaps::ml_kem_encaps(&ek, &mut rng, &invalid),
        Err(Error::InvalidParameter),
    ));
    assert!(matches!(
        tafrah_ml_kem::decaps::ml_kem_decaps(&dk, &ct, &invalid),
        Err(Error::InvalidParameter),
    ));
}
