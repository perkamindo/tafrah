/// ML-KEM round-trip tests

#[test]
fn test_ml_kem_512_roundtrip() {
    let mut rng = rand::rng();
    let (ek, dk) = tafrah_ml_kem::ml_kem_512::keygen(&mut rng);
    let (ct, ss1) = tafrah_ml_kem::ml_kem_512::encapsulate(&ek, &mut rng).unwrap();
    let ss2 = tafrah_ml_kem::ml_kem_512::decapsulate(&dk, &ct).unwrap();
    assert_eq!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "ML-KEM-512: shared secrets must match"
    );
}

#[test]
fn test_ml_kem_768_roundtrip() {
    let mut rng = rand::rng();
    let (ek, dk) = tafrah_ml_kem::ml_kem_768::keygen(&mut rng);
    let (ct, ss1) = tafrah_ml_kem::ml_kem_768::encapsulate(&ek, &mut rng).unwrap();
    let ss2 = tafrah_ml_kem::ml_kem_768::decapsulate(&dk, &ct).unwrap();
    assert_eq!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "ML-KEM-768: shared secrets must match"
    );
}

#[test]
fn test_ml_kem_1024_roundtrip() {
    let mut rng = rand::rng();
    let (ek, dk) = tafrah_ml_kem::ml_kem_1024::keygen(&mut rng);
    let (ct, ss1) = tafrah_ml_kem::ml_kem_1024::encapsulate(&ek, &mut rng).unwrap();
    let ss2 = tafrah_ml_kem::ml_kem_1024::decapsulate(&dk, &ct).unwrap();
    assert_eq!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "ML-KEM-1024: shared secrets must match"
    );
}

#[test]
fn test_ml_kem_512_multiple_roundtrips() {
    let mut rng = rand::rng();
    let (ek, dk) = tafrah_ml_kem::ml_kem_512::keygen(&mut rng);

    for _ in 0..5 {
        let (ct, ss1) = tafrah_ml_kem::ml_kem_512::encapsulate(&ek, &mut rng).unwrap();
        let ss2 = tafrah_ml_kem::ml_kem_512::decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
