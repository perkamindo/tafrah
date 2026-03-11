/// ML-DSA round-trip tests
use rand::rngs::OsRng;

#[test]
fn test_ml_dsa_44_roundtrip() {
    let mut rng = OsRng;
    let (vk, sk) = tafrah_ml_dsa::ml_dsa_44::keygen(&mut rng);

    let msg = b"test message for ML-DSA-44";
    let sig = tafrah_ml_dsa::ml_dsa_44::sign(&sk, msg, &mut rng);
    let result = tafrah_ml_dsa::ml_dsa_44::verify(&vk, msg, &sig);
    assert!(result.is_ok(), "ML-DSA-44: signature should verify");
}

#[test]
fn test_ml_dsa_44_context_roundtrip() {
    let mut rng = OsRng;
    let (vk, sk) = tafrah_ml_dsa::ml_dsa_44::keygen(&mut rng);

    let msg = b"test message for ML-DSA-44 with context";
    let ctx = b"tafrah-reference";
    let sig = tafrah_ml_dsa::ml_dsa_44::sign_with_context(&sk, msg, ctx, &mut rng)
        .expect("context-bounded ML-DSA-44 signing should succeed");
    let result = tafrah_ml_dsa::ml_dsa_44::verify_with_context(&vk, msg, &sig, ctx);
    assert!(
        result.is_ok(),
        "ML-DSA-44: contextual signature should verify"
    );
}

#[test]
fn test_ml_dsa_44_wrong_message() {
    let mut rng = OsRng;
    let (vk, sk) = tafrah_ml_dsa::ml_dsa_44::keygen(&mut rng);

    let msg = b"correct message";
    let sig = tafrah_ml_dsa::ml_dsa_44::sign(&sk, msg, &mut rng);

    let wrong_msg = b"wrong message";
    let result = tafrah_ml_dsa::ml_dsa_44::verify(&vk, wrong_msg, &sig);
    assert!(
        result.is_err(),
        "ML-DSA-44: wrong message should not verify"
    );
}

#[test]
fn test_ml_dsa_65_roundtrip() {
    let mut rng = OsRng;
    let (vk, sk) = tafrah_ml_dsa::ml_dsa_65::keygen(&mut rng);

    let msg = b"test message for ML-DSA-65";
    let sig = tafrah_ml_dsa::ml_dsa_65::sign(&sk, msg, &mut rng);
    let result = tafrah_ml_dsa::ml_dsa_65::verify(&vk, msg, &sig);
    assert!(result.is_ok(), "ML-DSA-65: signature should verify");
}

#[test]
fn test_ml_dsa_87_roundtrip() {
    let mut rng = OsRng;
    let (vk, sk) = tafrah_ml_dsa::ml_dsa_87::keygen(&mut rng);

    let msg = b"test message for ML-DSA-87";
    let sig = tafrah_ml_dsa::ml_dsa_87::sign(&sk, msg, &mut rng);
    let result = tafrah_ml_dsa::ml_dsa_87::verify(&vk, msg, &sig);
    assert!(result.is_ok(), "ML-DSA-87: signature should verify");
}
