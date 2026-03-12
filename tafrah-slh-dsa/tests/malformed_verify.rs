use tafrah_slh_dsa::params::SLH_DSA_SHAKE_128F;
use tafrah_slh_dsa::types::{Signature, SigningKey, VerifyingKey};
use tafrah_traits::Error;

#[test]
fn test_slh_dsa_verify_rejects_malformed_serialized_inputs() {
    let mut rng = rand::rng();
    let params = SLH_DSA_SHAKE_128F;
    let (vk, sk) = tafrah_slh_dsa::keygen::slh_dsa_keygen(&mut rng, &params).unwrap();
    let msg = b"malformed input regression";
    let sig = tafrah_slh_dsa::sign::slh_dsa_sign(&sk, msg, &mut rng, &params).unwrap();

    let truncated_sig = Signature {
        bytes: sig.bytes[..sig.bytes.len() - 1].to_vec(),
    };
    assert_eq!(
        tafrah_slh_dsa::verify::slh_dsa_verify(&vk, msg, &truncated_sig, &params),
        Err(Error::InvalidSignatureLength),
    );

    let truncated_vk = VerifyingKey {
        bytes: vk.bytes[..vk.bytes.len() - 1].to_vec(),
    };
    assert_eq!(
        tafrah_slh_dsa::verify::slh_dsa_verify(&truncated_vk, msg, &sig, &params),
        Err(Error::InvalidKeyLength),
    );
}

#[test]
fn test_slh_dsa_sign_rejects_malformed_inputs() {
    let mut rng = rand::rng();
    let params = SLH_DSA_SHAKE_128F;
    let malformed_sk = SigningKey {
        bytes: vec![0u8; params.sk_bytes - 1],
    };

    assert!(
        matches!(
            tafrah_slh_dsa::sign::slh_dsa_sign(
                &malformed_sk,
                b"malformed sign regression",
                &mut rng,
                &params,
            ),
            Err(Error::InvalidKeyLength)
        ),
        "malformed SLH-DSA signing key must be rejected",
    );
}

#[test]
fn test_slh_dsa_generic_api_rejects_invalid_params() {
    let mut rng = rand::rng();
    let mut invalid = SLH_DSA_SHAKE_128F;
    invalid.sig_bytes -= 1;

    assert!(
        matches!(
            tafrah_slh_dsa::keygen::slh_dsa_keygen(&mut rng, &invalid),
            Err(Error::InvalidParameter)
        ),
        "invalid SLH-DSA params must be rejected at keygen",
    );

    let sk = SigningKey {
        bytes: vec![0u8; SLH_DSA_SHAKE_128F.sk_bytes],
    };
    assert!(
        matches!(
            tafrah_slh_dsa::sign::slh_dsa_sign(&sk, b"msg", &mut rng, &invalid),
            Err(Error::InvalidParameter)
        ),
        "invalid SLH-DSA params must be rejected at sign",
    );
}
