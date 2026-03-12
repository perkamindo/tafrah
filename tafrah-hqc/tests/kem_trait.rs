use rand::SeedableRng;
use tafrah_hqc::hqc_128::Hqc128Kem;
use tafrah_traits::kem::Kem;

#[test]
fn test_hqc_kem_trait_roundtrip() {
    let mut rng = rand::rngs::StdRng::from_seed([22u8; 32]);
    let (ek, dk) = Hqc128Kem::keygen(&mut rng).expect("keygen");
    let (ct, ss_enc) = Hqc128Kem::encapsulate(&ek, &mut rng).expect("encapsulate");
    let ss_dec = Hqc128Kem::decapsulate(&dk, &ct).expect("decapsulate");

    assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
}
