use tafrah_ml_dsa::keygen;
use tafrah_ml_dsa::ml_dsa_44;
use tafrah_ml_dsa::params::{Params, ML_DSA_44};
use tafrah_ml_dsa::sign;
use tafrah_ml_dsa::types::{Signature, VerifyingKey};
use tafrah_ml_dsa::verify;
use tafrah_traits::Error;

#[test]
fn test_ml_dsa_verify_rejects_malformed_serialized_inputs() {
    let mut rng = rand::rng();
    let (vk, sk) = ml_dsa_44::keygen(&mut rng);
    let msg = b"malformed input regression";
    let sig = ml_dsa_44::sign(&sk, msg, &mut rng);

    let truncated_sig = Signature {
        bytes: sig.bytes[..sig.bytes.len() - 1].to_vec(),
    };
    assert_eq!(
        ml_dsa_44::verify(&vk, msg, &truncated_sig),
        Err(Error::InvalidSignatureLength),
    );

    let truncated_vk = VerifyingKey {
        bytes: vk.bytes[..vk.bytes.len() - 1].to_vec(),
    };
    assert_eq!(
        ml_dsa_44::verify(&truncated_vk, msg, &sig),
        Err(Error::InvalidKeyLength),
    );
}

#[test]
fn test_ml_dsa_context_is_bounded_to_one_byte() {
    let mut rng = rand::rng();
    let (vk, sk) = ml_dsa_44::keygen(&mut rng);
    let msg = b"context length regression";
    let oversized_ctx = [7u8; 256];

    assert!(matches!(
        ml_dsa_44::sign_with_context(&sk, msg, &oversized_ctx, &mut rng),
        Err(Error::InvalidParameter),
    ));

    let sig = ml_dsa_44::sign(&sk, msg, &mut rng);
    assert_eq!(
        ml_dsa_44::verify_with_context(&vk, msg, &sig, &oversized_ctx),
        Err(Error::InvalidParameter),
    );
}

#[test]
fn test_ml_dsa_generic_api_rejects_invalid_params() {
    let mut rng = rand::rng();
    let msg = b"invalid params";
    let invalid = Params {
        gamma2: 12345,
        ..ML_DSA_44
    };

    assert!(matches!(
        keygen::ml_dsa_keygen(&mut rng, &invalid),
        Err(Error::InvalidParameter),
    ));

    let (vk, sk) = ml_dsa_44::keygen(&mut rng);
    let sig = ml_dsa_44::sign(&sk, msg, &mut rng);

    assert!(matches!(
        sign::ml_dsa_sign(&sk, msg, &mut rng, &invalid),
        Err(Error::InvalidParameter),
    ));
    assert!(matches!(
        sign::ml_dsa_sign_with_context(&sk, msg, &[], &mut rng, &invalid),
        Err(Error::InvalidParameter),
    ));
    assert!(matches!(
        verify::ml_dsa_verify(&vk, msg, &sig, &invalid),
        Err(Error::InvalidParameter),
    ));
}
