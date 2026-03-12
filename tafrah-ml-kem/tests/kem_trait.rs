use rand::SeedableRng;
use tafrah_ml_kem::ml_kem_768::MlKem768Kem;
use tafrah_traits::kem::Kem;

#[test]
fn test_ml_kem_kem_trait_roundtrip() {
    let mut rng = rand::rngs::StdRng::from_seed([21u8; 32]);
    let (ek, dk) = MlKem768Kem::keygen(&mut rng).expect("keygen");
    let (ct, ss_enc) = MlKem768Kem::encapsulate(&ek, &mut rng).expect("encapsulate");
    let ss_dec = MlKem768Kem::decapsulate(&dk, &ct).expect("decapsulate");

    assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
}
