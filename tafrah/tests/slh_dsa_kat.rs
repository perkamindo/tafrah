/// SLH-DSA round-trip tests
/// NOTE: SLH-DSA keygen and signing are computationally expensive,
/// especially for the "s" (small) parameter sets. Only testing "f" (fast) variants.

#[test]
fn test_slh_dsa_shake_128f_roundtrip() {
    let mut rng = rand::rng();
    let params = tafrah_slh_dsa::params::SLH_DSA_SHAKE_128F;
    let (vk, sk) = tafrah_slh_dsa::keygen::slh_dsa_keygen(&mut rng, &params).unwrap();

    let msg = b"test message for SLH-DSA-SHAKE-128f";
    let sig = tafrah_slh_dsa::sign::slh_dsa_sign(&sk, msg, &mut rng, &params).unwrap();
    let result = tafrah_slh_dsa::verify::slh_dsa_verify(&vk, msg, &sig, &params);
    assert!(
        result.is_ok(),
        "SLH-DSA-SHAKE-128f: signature should verify"
    );
}

#[test]
fn test_slh_dsa_shake_128f_wrong_message() {
    let mut rng = rand::rng();
    let params = tafrah_slh_dsa::params::SLH_DSA_SHAKE_128F;
    let (vk, sk) = tafrah_slh_dsa::keygen::slh_dsa_keygen(&mut rng, &params).unwrap();

    let msg = b"correct message";
    let sig = tafrah_slh_dsa::sign::slh_dsa_sign(&sk, msg, &mut rng, &params).unwrap();

    let wrong_msg = b"wrong message";
    let result = tafrah_slh_dsa::verify::slh_dsa_verify(&vk, wrong_msg, &sig, &params);
    assert!(result.is_err(), "SLH-DSA: wrong message should not verify");
}
