use rand::rngs::OsRng;
use tafrah_falcon::params::{FALCON_1024, FALCON_512};
use tafrah_falcon::types::{
    Signature as FalconSignature, SigningKey as FalconSigningKey,
    VerifyingKey as FalconVerifyingKey,
};
use tafrah_hqc::types::{
    Ciphertext as HqcCiphertext, DecapsulationKey as HqcDecapsulationKey,
    EncapsulationKey as HqcEncapsulationKey,
};
use tafrah_ml_dsa::params::ML_DSA_65;
use tafrah_ml_dsa::types::{
    Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use tafrah_ml_kem::params::ML_KEM_768;
use tafrah_ml_kem::types::{
    Ciphertext as MlKemCiphertext, DecapsulationKey as MlKemDecapsulationKey,
    EncapsulationKey as MlKemEncapsulationKey,
};
use tafrah_slh_dsa::params::SLH_DSA_SHAKE_128F;
use tafrah_slh_dsa::types::{
    Signature as SlhDsaSignature, SigningKey as SlhDsaSigningKey,
    VerifyingKey as SlhDsaVerifyingKey,
};
use tafrah_traits::Error;

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, uniffi::Record)]
pub struct KemKeypair {
    pub encapsulation_key: Vec<u8>,
    pub decapsulation_key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignatureKeypair {
    pub verifying_key: Vec<u8>,
    pub signing_key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EncapsulationResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct SchemeSizes {
    pub public_key_bytes: u64,
    pub secret_key_bytes: u64,
    pub ciphertext_or_signature_bytes: u64,
    pub shared_secret_bytes: u64,
}

#[derive(Debug, Clone, uniffi::Error)]
#[uniffi(flat_error)]
pub enum UniFfiError {
    InvalidKeyLength,
    InvalidCiphertextLength,
    InvalidSignatureLength,
    InvalidParameter,
    InternalError(String),
    NotImplemented,
}

impl core::fmt::Display for UniFfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength => f.write_str("invalid key length"),
            Self::InvalidCiphertextLength => f.write_str("invalid ciphertext length"),
            Self::InvalidSignatureLength => f.write_str("invalid signature length"),
            Self::InvalidParameter => f.write_str("invalid parameter"),
            Self::InternalError(message) => f.write_str(message),
            Self::NotImplemented => f.write_str("not implemented"),
        }
    }
}

impl std::error::Error for UniFfiError {}

impl From<Error> for UniFfiError {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidKeyLength => Self::InvalidKeyLength,
            Error::InvalidCiphertextLength => Self::InvalidCiphertextLength,
            Error::InvalidSignatureLength => Self::InvalidSignatureLength,
            Error::InvalidParameter => Self::InvalidParameter,
            Error::VerificationFailed => Self::InternalError("verification failed".to_owned()),
            Error::DecodingError => Self::InternalError("decoding error".to_owned()),
            Error::RngError => Self::InternalError("rng error".to_owned()),
            Error::NotImplemented => Self::NotImplemented,
        }
    }
}

fn ml_kem_keypair() -> KemKeypair {
    let mut rng = OsRng;
    let (ek, dk) = tafrah_ml_kem::ml_kem_768::keygen(&mut rng);
    KemKeypair {
        encapsulation_key: ek.as_bytes().to_vec(),
        decapsulation_key: dk.as_bytes().to_vec(),
    }
}

fn hqc_keypair(
    keygen: impl FnOnce(&mut OsRng) -> Result<(HqcEncapsulationKey, HqcDecapsulationKey), Error>,
) -> Result<KemKeypair, UniFfiError> {
    let mut rng = OsRng;
    let (ek, dk) = keygen(&mut rng)?;
    Ok(KemKeypair {
        encapsulation_key: ek.as_bytes().to_vec(),
        decapsulation_key: dk.as_bytes().to_vec(),
    })
}

fn hqc_encapsulation(
    ek: Vec<u8>,
    encapsulate: impl FnOnce(
        &HqcEncapsulationKey,
        &mut OsRng,
    ) -> Result<(HqcCiphertext, tafrah_hqc::types::SharedSecret), Error>,
) -> Result<EncapsulationResult, UniFfiError> {
    let ek = HqcEncapsulationKey { bytes: ek };
    let mut rng = OsRng;
    let (ct, ss) = encapsulate(&ek, &mut rng)?;
    Ok(EncapsulationResult {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

fn hqc_decapsulation(
    dk: Vec<u8>,
    ct: Vec<u8>,
    decapsulate: impl FnOnce(
        &HqcDecapsulationKey,
        &HqcCiphertext,
    ) -> Result<tafrah_hqc::types::SharedSecret, Error>,
) -> Result<Vec<u8>, UniFfiError> {
    let dk = HqcDecapsulationKey { bytes: dk };
    let ct = HqcCiphertext { bytes: ct };
    let ss = decapsulate(&dk, &ct)?;
    Ok(ss.as_bytes().to_vec())
}

fn ml_dsa_keypair() -> SignatureKeypair {
    let mut rng = OsRng;
    let (vk, sk) = tafrah_ml_dsa::ml_dsa_65::keygen(&mut rng);
    SignatureKeypair {
        verifying_key: vk.as_bytes().to_vec(),
        signing_key: sk.as_bytes().to_vec(),
    }
}

fn slh_dsa_keypair() -> SignatureKeypair {
    let mut rng = OsRng;
    let (vk, sk) = tafrah_slh_dsa::keygen::slh_dsa_keygen(&mut rng, &SLH_DSA_SHAKE_128F)
        .expect("fixed SLH-DSA parameter set must remain valid");
    SignatureKeypair {
        verifying_key: vk.as_bytes().to_vec(),
        signing_key: sk.as_bytes().to_vec(),
    }
}

fn falcon_keypair(
    keygen: impl FnOnce(&mut OsRng) -> Result<(FalconVerifyingKey, FalconSigningKey), Error>,
) -> Result<SignatureKeypair, UniFfiError> {
    let mut rng = OsRng;
    let (vk, sk) = keygen(&mut rng)?;
    Ok(SignatureKeypair {
        verifying_key: vk.as_bytes().to_vec(),
        signing_key: sk.as_bytes().to_vec(),
    })
}

#[uniffi::export]
pub fn version() -> String {
    "tafrah-uniffi/0.1.0".to_owned()
}

#[uniffi::export]
pub fn supported_algorithms() -> Vec<String> {
    vec![
        "ML-KEM-768".to_owned(),
        "ML-DSA-65".to_owned(),
        "SLH-DSA-SHAKE-128f".to_owned(),
        "Falcon-512".to_owned(),
        "Falcon-1024".to_owned(),
        "HQC-128".to_owned(),
        "HQC-192".to_owned(),
        "HQC-256".to_owned(),
    ]
}

#[uniffi::export]
pub fn ml_kem_768_sizes() -> SchemeSizes {
    SchemeSizes {
        public_key_bytes: ML_KEM_768.ek_size() as u64,
        secret_key_bytes: ML_KEM_768.dk_size() as u64,
        ciphertext_or_signature_bytes: ML_KEM_768.ct_size() as u64,
        shared_secret_bytes: 32,
    }
}

#[uniffi::export]
pub fn ml_kem_768_keygen() -> KemKeypair {
    ml_kem_keypair()
}

#[uniffi::export]
pub fn ml_kem_768_encapsulate(ek: Vec<u8>) -> Result<EncapsulationResult, UniFfiError> {
    let ek = MlKemEncapsulationKey { bytes: ek };
    let mut rng = OsRng;
    let (ct, ss) = tafrah_ml_kem::ml_kem_768::encapsulate(&ek, &mut rng)?;
    Ok(EncapsulationResult {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

#[uniffi::export]
pub fn ml_kem_768_decapsulate(dk: Vec<u8>, ct: Vec<u8>) -> Result<Vec<u8>, UniFfiError> {
    let dk = MlKemDecapsulationKey { bytes: dk };
    let ct = MlKemCiphertext { bytes: ct };
    let ss = tafrah_ml_kem::ml_kem_768::decapsulate(&dk, &ct)?;
    Ok(ss.as_bytes().to_vec())
}

#[uniffi::export]
pub fn ml_dsa_65_sizes() -> SchemeSizes {
    SchemeSizes {
        public_key_bytes: ML_DSA_65.vk_size() as u64,
        secret_key_bytes: ML_DSA_65.sk_size() as u64,
        ciphertext_or_signature_bytes: ML_DSA_65.sig_size() as u64,
        shared_secret_bytes: 0,
    }
}

#[uniffi::export]
pub fn ml_dsa_65_keygen() -> SignatureKeypair {
    ml_dsa_keypair()
}

#[uniffi::export]
pub fn ml_dsa_65_sign(sk: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, UniFfiError> {
    let sk = MlDsaSigningKey { bytes: sk };
    let mut rng = OsRng;
    let sig = tafrah_ml_dsa::ml_dsa_65::sign_with_context(&sk, &message, &[], &mut rng)?;
    Ok(sig.as_bytes().to_vec())
}

#[uniffi::export]
pub fn ml_dsa_65_verify(vk: Vec<u8>, message: Vec<u8>, sig: Vec<u8>) -> Result<bool, UniFfiError> {
    let vk = MlDsaVerifyingKey { bytes: vk };
    let sig = MlDsaSignature { bytes: sig };
    match tafrah_ml_dsa::ml_dsa_65::verify_with_context(&vk, &message, &sig, &[]) {
        Ok(()) => Ok(true),
        Err(Error::VerificationFailed) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

#[uniffi::export]
pub fn slh_dsa_shake_128f_sizes() -> SchemeSizes {
    SchemeSizes {
        public_key_bytes: SLH_DSA_SHAKE_128F.pk_bytes as u64,
        secret_key_bytes: SLH_DSA_SHAKE_128F.sk_bytes as u64,
        ciphertext_or_signature_bytes: SLH_DSA_SHAKE_128F.sig_bytes as u64,
        shared_secret_bytes: 0,
    }
}

#[uniffi::export]
pub fn slh_dsa_shake_128f_keygen() -> SignatureKeypair {
    slh_dsa_keypair()
}

#[uniffi::export]
pub fn slh_dsa_shake_128f_sign(sk: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, UniFfiError> {
    let sk = SlhDsaSigningKey { bytes: sk };
    let mut rng = OsRng;
    let sig = tafrah_slh_dsa::sign::slh_dsa_sign(&sk, &message, &mut rng, &SLH_DSA_SHAKE_128F)?;
    Ok(sig.as_bytes().to_vec())
}

#[uniffi::export]
pub fn slh_dsa_shake_128f_verify(
    vk: Vec<u8>,
    message: Vec<u8>,
    sig: Vec<u8>,
) -> Result<bool, UniFfiError> {
    let vk = SlhDsaVerifyingKey { bytes: vk };
    let sig = SlhDsaSignature { bytes: sig };
    match tafrah_slh_dsa::verify::slh_dsa_verify(&vk, &message, &sig, &SLH_DSA_SHAKE_128F) {
        Ok(()) => Ok(true),
        Err(Error::VerificationFailed) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

#[uniffi::export]
pub fn falcon_512_sizes() -> SchemeSizes {
    SchemeSizes {
        public_key_bytes: FALCON_512.pk_bytes as u64,
        secret_key_bytes: FALCON_512.sk_bytes as u64,
        ciphertext_or_signature_bytes: FALCON_512.sig_max_bytes as u64,
        shared_secret_bytes: 0,
    }
}

#[uniffi::export]
pub fn falcon_512_keygen() -> Result<SignatureKeypair, UniFfiError> {
    falcon_keypair(tafrah_falcon::falcon_512::keygen)
}

#[uniffi::export]
pub fn falcon_512_sign(sk: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, UniFfiError> {
    let sk = FalconSigningKey { bytes: sk };
    let mut rng = OsRng;
    let sig = tafrah_falcon::falcon_512::sign(&sk, &message, &mut rng)?;
    Ok(sig.as_bytes().to_vec())
}

#[uniffi::export]
pub fn falcon_512_verify(vk: Vec<u8>, message: Vec<u8>, sig: Vec<u8>) -> Result<bool, UniFfiError> {
    let vk = FalconVerifyingKey { bytes: vk };
    let sig = FalconSignature { bytes: sig };
    match tafrah_falcon::falcon_512::verify(&vk, &message, &sig) {
        Ok(()) => Ok(true),
        Err(Error::VerificationFailed) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

#[uniffi::export]
pub fn falcon_1024_sizes() -> SchemeSizes {
    SchemeSizes {
        public_key_bytes: FALCON_1024.pk_bytes as u64,
        secret_key_bytes: FALCON_1024.sk_bytes as u64,
        ciphertext_or_signature_bytes: FALCON_1024.sig_max_bytes as u64,
        shared_secret_bytes: 0,
    }
}

#[uniffi::export]
pub fn falcon_1024_keygen() -> Result<SignatureKeypair, UniFfiError> {
    falcon_keypair(tafrah_falcon::falcon_1024::keygen)
}

#[uniffi::export]
pub fn falcon_1024_sign(sk: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, UniFfiError> {
    let sk = FalconSigningKey { bytes: sk };
    let mut rng = OsRng;
    let sig = tafrah_falcon::falcon_1024::sign(&sk, &message, &mut rng)?;
    Ok(sig.as_bytes().to_vec())
}

#[uniffi::export]
pub fn falcon_1024_verify(
    vk: Vec<u8>,
    message: Vec<u8>,
    sig: Vec<u8>,
) -> Result<bool, UniFfiError> {
    let vk = FalconVerifyingKey { bytes: vk };
    let sig = FalconSignature { bytes: sig };
    match tafrah_falcon::falcon_1024::verify(&vk, &message, &sig) {
        Ok(()) => Ok(true),
        Err(Error::VerificationFailed) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

#[uniffi::export]
pub fn hqc_128_sizes() -> SchemeSizes {
    SchemeSizes {
        public_key_bytes: tafrah_hqc::params::HQC_128.pk_bytes as u64,
        secret_key_bytes: tafrah_hqc::params::HQC_128.sk_bytes as u64,
        ciphertext_or_signature_bytes: tafrah_hqc::params::HQC_128.ct_bytes as u64,
        shared_secret_bytes: tafrah_hqc::params::HQC_128.ss_bytes as u64,
    }
}

#[uniffi::export]
pub fn hqc_128_keygen() -> Result<KemKeypair, UniFfiError> {
    hqc_keypair(tafrah_hqc::hqc_128::keygen)
}

#[uniffi::export]
pub fn hqc_128_encapsulate(ek: Vec<u8>) -> Result<EncapsulationResult, UniFfiError> {
    hqc_encapsulation(ek, tafrah_hqc::hqc_128::encapsulate)
}

#[uniffi::export]
pub fn hqc_128_decapsulate(dk: Vec<u8>, ct: Vec<u8>) -> Result<Vec<u8>, UniFfiError> {
    hqc_decapsulation(dk, ct, tafrah_hqc::hqc_128::decapsulate)
}

#[uniffi::export]
pub fn hqc_192_sizes() -> SchemeSizes {
    SchemeSizes {
        public_key_bytes: tafrah_hqc::params::HQC_192.pk_bytes as u64,
        secret_key_bytes: tafrah_hqc::params::HQC_192.sk_bytes as u64,
        ciphertext_or_signature_bytes: tafrah_hqc::params::HQC_192.ct_bytes as u64,
        shared_secret_bytes: tafrah_hqc::params::HQC_192.ss_bytes as u64,
    }
}

#[uniffi::export]
pub fn hqc_192_keygen() -> Result<KemKeypair, UniFfiError> {
    hqc_keypair(tafrah_hqc::hqc_192::keygen)
}

#[uniffi::export]
pub fn hqc_192_encapsulate(ek: Vec<u8>) -> Result<EncapsulationResult, UniFfiError> {
    hqc_encapsulation(ek, tafrah_hqc::hqc_192::encapsulate)
}

#[uniffi::export]
pub fn hqc_192_decapsulate(dk: Vec<u8>, ct: Vec<u8>) -> Result<Vec<u8>, UniFfiError> {
    hqc_decapsulation(dk, ct, tafrah_hqc::hqc_192::decapsulate)
}

#[uniffi::export]
pub fn hqc_256_sizes() -> SchemeSizes {
    SchemeSizes {
        public_key_bytes: tafrah_hqc::params::HQC_256.pk_bytes as u64,
        secret_key_bytes: tafrah_hqc::params::HQC_256.sk_bytes as u64,
        ciphertext_or_signature_bytes: tafrah_hqc::params::HQC_256.ct_bytes as u64,
        shared_secret_bytes: tafrah_hqc::params::HQC_256.ss_bytes as u64,
    }
}

#[uniffi::export]
pub fn hqc_256_keygen() -> Result<KemKeypair, UniFfiError> {
    hqc_keypair(tafrah_hqc::hqc_256::keygen)
}

#[uniffi::export]
pub fn hqc_256_encapsulate(ek: Vec<u8>) -> Result<EncapsulationResult, UniFfiError> {
    hqc_encapsulation(ek, tafrah_hqc::hqc_256::encapsulate)
}

#[uniffi::export]
pub fn hqc_256_decapsulate(dk: Vec<u8>, ct: Vec<u8>) -> Result<Vec<u8>, UniFfiError> {
    hqc_decapsulation(dk, ct, tafrah_hqc::hqc_256::decapsulate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_uniffi_surface_roundtrip() {
        let keypair = ml_kem_768_keygen();
        let enc = ml_kem_768_encapsulate(keypair.encapsulation_key).expect("encaps");
        let dec =
            ml_kem_768_decapsulate(keypair.decapsulation_key, enc.ciphertext).expect("decaps");
        assert_eq!(enc.shared_secret, dec);
    }

    #[test]
    fn test_ml_dsa_uniffi_surface_sign_verify() {
        let keypair = ml_dsa_65_keygen();
        let message = b"uniffi ml-dsa proof".to_vec();
        let sig = ml_dsa_65_sign(keypair.signing_key, message.clone()).expect("sign");
        assert!(ml_dsa_65_verify(keypair.verifying_key, message, sig).expect("verify"));
    }

    #[test]
    fn test_slh_dsa_uniffi_surface_sign_verify() {
        let keypair = slh_dsa_shake_128f_keygen();
        let message = b"uniffi slh-dsa proof".to_vec();
        let sig = slh_dsa_shake_128f_sign(keypair.signing_key, message.clone()).expect("sign");
        assert!(slh_dsa_shake_128f_verify(keypair.verifying_key, message, sig).expect("verify"));
    }

    #[test]
    fn test_hqc_uniffi_surface_roundtrip() {
        let keypair = hqc_128_keygen().expect("keygen");
        let enc = hqc_128_encapsulate(keypair.encapsulation_key).expect("encaps");
        let dec = hqc_128_decapsulate(keypair.decapsulation_key, enc.ciphertext).expect("decaps");
        assert_eq!(enc.shared_secret, dec);
    }

    #[test]
    fn test_falcon_uniffi_surface_sign_verify() {
        let keypair = falcon_512_keygen().expect("keygen");
        let message = b"uniffi falcon proof".to_vec();
        let sig = falcon_512_sign(keypair.signing_key, message.clone()).expect("sign");
        assert!(falcon_512_verify(keypair.verifying_key, message, sig).expect("verify"));
    }
}
