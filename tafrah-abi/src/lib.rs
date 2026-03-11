//! Installable C ABI for Tafrah PQC primitives.
//!
//! This crate is the universal host boundary for consumers that cannot link to
//! the native Rust crates directly.

use core::ffi::{c_char, c_int};

use rand::rngs::OsRng;
use tafrah_falcon::params::{Params as FalconParams, FALCON_1024, FALCON_512};
use tafrah_falcon::types::{
    Signature as FalconSignature, SigningKey as FalconSigningKey,
    VerifyingKey as FalconVerifyingKey,
};
use tafrah_hqc::params::{Params as HqcParams, HQC_128, HQC_192, HQC_256};
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

pub const TAFRAH_STATUS_OK: c_int = 0;
pub const TAFRAH_STATUS_NULL_POINTER: c_int = 1;
pub const TAFRAH_STATUS_INVALID_LENGTH: c_int = 2;
pub const TAFRAH_STATUS_INVALID_PARAMETER: c_int = 3;
pub const TAFRAH_STATUS_VERIFICATION_FAILED: c_int = 4;
pub const TAFRAH_STATUS_INTERNAL_ERROR: c_int = 5;
pub const TAFRAH_STATUS_NOT_IMPLEMENTED: c_int = 6;

const VERSION: &[u8] = b"tafrah-abi/0.1.0\0";
const STATUS_OK: &[u8] = b"ok\0";
const STATUS_NULL_POINTER: &[u8] = b"null pointer\0";
const STATUS_INVALID_LENGTH: &[u8] = b"invalid length\0";
const STATUS_INVALID_PARAMETER: &[u8] = b"invalid parameter\0";
const STATUS_VERIFICATION_FAILED: &[u8] = b"verification failed\0";
const STATUS_INTERNAL_ERROR: &[u8] = b"internal error\0";
const STATUS_NOT_IMPLEMENTED: &[u8] = b"not implemented\0";
const STATUS_UNKNOWN: &[u8] = b"unknown status\0";

fn status_from_error(err: Error) -> c_int {
    match err {
        Error::InvalidKeyLength
        | Error::InvalidCiphertextLength
        | Error::InvalidSignatureLength => TAFRAH_STATUS_INVALID_LENGTH,
        Error::InvalidParameter => TAFRAH_STATUS_INVALID_PARAMETER,
        Error::VerificationFailed => TAFRAH_STATUS_VERIFICATION_FAILED,
        Error::DecodingError | Error::RngError => TAFRAH_STATUS_INTERNAL_ERROR,
        Error::NotImplemented => TAFRAH_STATUS_NOT_IMPLEMENTED,
    }
}

unsafe fn input_bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], c_int> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(TAFRAH_STATUS_NULL_POINTER);
    }
    Ok(core::slice::from_raw_parts(ptr, len))
}

unsafe fn input_bytes_exact<'a>(
    ptr: *const u8,
    len: usize,
    expected: usize,
) -> Result<&'a [u8], c_int> {
    if len != expected {
        return Err(TAFRAH_STATUS_INVALID_LENGTH);
    }
    input_bytes(ptr, len)
}

unsafe fn output_bytes_exact<'a>(
    ptr: *mut u8,
    len: usize,
    expected: usize,
) -> Result<&'a mut [u8], c_int> {
    if ptr.is_null() {
        return Err(TAFRAH_STATUS_NULL_POINTER);
    }
    if len != expected {
        return Err(TAFRAH_STATUS_INVALID_LENGTH);
    }
    Ok(core::slice::from_raw_parts_mut(ptr, len))
}

unsafe fn output_bytes_capacity<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], c_int> {
    if ptr.is_null() {
        return Err(TAFRAH_STATUS_NULL_POINTER);
    }
    Ok(core::slice::from_raw_parts_mut(ptr, len))
}

fn copy_result(src: &[u8], dst: &mut [u8]) -> c_int {
    dst.copy_from_slice(src);
    TAFRAH_STATUS_OK
}

fn falcon_keygen_inner<F>(
    vk_out: *mut u8,
    vk_len: usize,
    sk_out: *mut u8,
    sk_len: usize,
    params: &FalconParams,
    keygen: F,
) -> c_int
where
    F: FnOnce(&mut OsRng) -> Result<(FalconVerifyingKey, FalconSigningKey), Error>,
{
    let vk_out = match unsafe { output_bytes_exact(vk_out, vk_len, params.pk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let sk_out = match unsafe { output_bytes_exact(sk_out, sk_len, params.sk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let mut rng = OsRng;
    match keygen(&mut rng) {
        Ok((vk, sk)) => {
            vk_out.copy_from_slice(vk.as_bytes());
            sk_out.copy_from_slice(sk.as_bytes());
            TAFRAH_STATUS_OK
        }
        Err(err) => status_from_error(err),
    }
}

fn falcon_sign_inner<F>(
    sk_ptr: *const u8,
    sk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_capacity: usize,
    sig_written: *mut usize,
    params: &FalconParams,
    sign: F,
) -> c_int
where
    F: FnOnce(&FalconSigningKey, &[u8], &mut OsRng) -> Result<FalconSignature, Error>,
{
    let sk_bytes = match unsafe { input_bytes_exact(sk_ptr, sk_len, params.sk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let msg_bytes = match unsafe { input_bytes(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    if sig_written.is_null() {
        return TAFRAH_STATUS_NULL_POINTER;
    }
    let sig_out = match unsafe { output_bytes_capacity(sig_out, sig_capacity) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let sk = FalconSigningKey {
        bytes: sk_bytes.to_vec(),
    };
    let mut rng = OsRng;
    match sign(&sk, msg_bytes, &mut rng) {
        Ok(sig) => {
            if sig.as_bytes().len() > params.sig_max_bytes || sig.as_bytes().len() > sig_out.len() {
                return TAFRAH_STATUS_INVALID_LENGTH;
            }
            let written = sig.as_bytes().len();
            sig_out[..written].copy_from_slice(sig.as_bytes());
            unsafe {
                *sig_written = written;
            }
            TAFRAH_STATUS_OK
        }
        Err(err) => status_from_error(err),
    }
}

fn falcon_verify_inner<F>(
    vk_ptr: *const u8,
    vk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    params: &FalconParams,
    verify: F,
) -> c_int
where
    F: FnOnce(&FalconVerifyingKey, &[u8], &FalconSignature) -> Result<(), Error>,
{
    let vk_bytes = match unsafe { input_bytes_exact(vk_ptr, vk_len, params.pk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let msg_bytes = match unsafe { input_bytes(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    if sig_len == 0 || sig_len > params.sig_max_bytes {
        return TAFRAH_STATUS_INVALID_LENGTH;
    }
    let sig_bytes = match unsafe { input_bytes(sig_ptr, sig_len) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let vk = FalconVerifyingKey {
        bytes: vk_bytes.to_vec(),
    };
    let sig = FalconSignature {
        bytes: sig_bytes.to_vec(),
    };
    match verify(&vk, msg_bytes, &sig) {
        Ok(()) => TAFRAH_STATUS_OK,
        Err(err) => status_from_error(err),
    }
}

fn hqc_keygen_inner<F>(
    ek_out: *mut u8,
    ek_len: usize,
    dk_out: *mut u8,
    dk_len: usize,
    params: &HqcParams,
    keygen: F,
) -> c_int
where
    F: FnOnce(&mut OsRng) -> Result<(HqcEncapsulationKey, HqcDecapsulationKey), Error>,
{
    let ek_out = match unsafe { output_bytes_exact(ek_out, ek_len, params.pk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let dk_out = match unsafe { output_bytes_exact(dk_out, dk_len, params.sk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let mut rng = OsRng;
    match keygen(&mut rng) {
        Ok((ek, dk)) => {
            ek_out.copy_from_slice(ek.as_bytes());
            dk_out.copy_from_slice(dk.as_bytes());
            TAFRAH_STATUS_OK
        }
        Err(err) => status_from_error(err),
    }
}

fn hqc_encapsulate_inner<F>(
    ek_ptr: *const u8,
    ek_len: usize,
    ct_out: *mut u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
    params: &HqcParams,
    encapsulate: F,
) -> c_int
where
    F: FnOnce(
        &HqcEncapsulationKey,
        &mut OsRng,
    ) -> Result<(HqcCiphertext, tafrah_hqc::types::SharedSecret), Error>,
{
    let ek_bytes = match unsafe { input_bytes_exact(ek_ptr, ek_len, params.pk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let ct_out = match unsafe { output_bytes_exact(ct_out, ct_len, params.ct_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let ss_out = match unsafe { output_bytes_exact(ss_out, ss_len, params.ss_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let ek = HqcEncapsulationKey {
        bytes: ek_bytes.to_vec(),
    };
    let mut rng = OsRng;
    match encapsulate(&ek, &mut rng) {
        Ok((ct, ss)) => {
            ct_out.copy_from_slice(ct.as_bytes());
            ss_out.copy_from_slice(ss.as_bytes());
            TAFRAH_STATUS_OK
        }
        Err(err) => status_from_error(err),
    }
}

fn hqc_decapsulate_inner<F>(
    dk_ptr: *const u8,
    dk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
    params: &HqcParams,
    decapsulate: F,
) -> c_int
where
    F: FnOnce(
        &HqcDecapsulationKey,
        &HqcCiphertext,
    ) -> Result<tafrah_hqc::types::SharedSecret, Error>,
{
    let dk_bytes = match unsafe { input_bytes_exact(dk_ptr, dk_len, params.sk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let ct_bytes = match unsafe { input_bytes_exact(ct_ptr, ct_len, params.ct_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let ss_out = match unsafe { output_bytes_exact(ss_out, ss_len, params.ss_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let dk = HqcDecapsulationKey {
        bytes: dk_bytes.to_vec(),
    };
    let ct = HqcCiphertext {
        bytes: ct_bytes.to_vec(),
    };
    match decapsulate(&dk, &ct) {
        Ok(ss) => copy_result(ss.as_bytes(), ss_out),
        Err(err) => status_from_error(err),
    }
}

#[no_mangle]
pub extern "C" fn tafrah_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn tafrah_status_string(status: c_int) -> *const c_char {
    let bytes = match status {
        TAFRAH_STATUS_OK => STATUS_OK,
        TAFRAH_STATUS_NULL_POINTER => STATUS_NULL_POINTER,
        TAFRAH_STATUS_INVALID_LENGTH => STATUS_INVALID_LENGTH,
        TAFRAH_STATUS_INVALID_PARAMETER => STATUS_INVALID_PARAMETER,
        TAFRAH_STATUS_VERIFICATION_FAILED => STATUS_VERIFICATION_FAILED,
        TAFRAH_STATUS_INTERNAL_ERROR => STATUS_INTERNAL_ERROR,
        TAFRAH_STATUS_NOT_IMPLEMENTED => STATUS_NOT_IMPLEMENTED,
        _ => STATUS_UNKNOWN,
    };
    bytes.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn tafrah_ml_kem_768_ek_size() -> usize {
    ML_KEM_768.ek_size()
}

#[no_mangle]
pub extern "C" fn tafrah_ml_kem_768_dk_size() -> usize {
    ML_KEM_768.dk_size()
}

#[no_mangle]
pub extern "C" fn tafrah_ml_kem_768_ct_size() -> usize {
    ML_KEM_768.ct_size()
}

#[no_mangle]
pub extern "C" fn tafrah_shared_secret_size() -> usize {
    32
}

#[no_mangle]
pub extern "C" fn tafrah_ml_dsa_65_vk_size() -> usize {
    ML_DSA_65.vk_size()
}

#[no_mangle]
pub extern "C" fn tafrah_ml_dsa_65_sk_size() -> usize {
    ML_DSA_65.sk_size()
}

#[no_mangle]
pub extern "C" fn tafrah_ml_dsa_65_sig_size() -> usize {
    ML_DSA_65.sig_size()
}

#[no_mangle]
pub extern "C" fn tafrah_slh_dsa_shake_128f_vk_size() -> usize {
    SLH_DSA_SHAKE_128F.pk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_slh_dsa_shake_128f_sk_size() -> usize {
    SLH_DSA_SHAKE_128F.sk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_slh_dsa_shake_128f_sig_size() -> usize {
    SLH_DSA_SHAKE_128F.sig_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_512_vk_size() -> usize {
    FALCON_512.pk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_512_sk_size() -> usize {
    FALCON_512.sk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_512_sig_size() -> usize {
    FALCON_512.sig_max_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_1024_vk_size() -> usize {
    FALCON_1024.pk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_1024_sk_size() -> usize {
    FALCON_1024.sk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_1024_sig_size() -> usize {
    FALCON_1024.sig_max_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_128_ek_size() -> usize {
    HQC_128.pk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_128_dk_size() -> usize {
    HQC_128.sk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_128_ct_size() -> usize {
    HQC_128.ct_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_128_ss_size() -> usize {
    HQC_128.ss_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_192_ek_size() -> usize {
    HQC_192.pk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_192_dk_size() -> usize {
    HQC_192.sk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_192_ct_size() -> usize {
    HQC_192.ct_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_192_ss_size() -> usize {
    HQC_192.ss_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_256_ek_size() -> usize {
    HQC_256.pk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_256_dk_size() -> usize {
    HQC_256.sk_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_256_ct_size() -> usize {
    HQC_256.ct_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_256_ss_size() -> usize {
    HQC_256.ss_bytes
}

#[no_mangle]
pub extern "C" fn tafrah_ml_kem_768_keygen(
    ek_out: *mut u8,
    ek_len: usize,
    dk_out: *mut u8,
    dk_len: usize,
) -> c_int {
    let ek_out = match unsafe { output_bytes_exact(ek_out, ek_len, ML_KEM_768.ek_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let dk_out = match unsafe { output_bytes_exact(dk_out, dk_len, ML_KEM_768.dk_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let mut rng = OsRng;
    let (ek, dk) = tafrah_ml_kem::ml_kem_768::keygen(&mut rng);
    ek_out.copy_from_slice(ek.as_bytes());
    dk_out.copy_from_slice(dk.as_bytes());
    TAFRAH_STATUS_OK
}

#[no_mangle]
pub extern "C" fn tafrah_ml_kem_768_encapsulate(
    ek_ptr: *const u8,
    ek_len: usize,
    ct_out: *mut u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> c_int {
    let ek_bytes = match unsafe { input_bytes_exact(ek_ptr, ek_len, ML_KEM_768.ek_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let ct_out = match unsafe { output_bytes_exact(ct_out, ct_len, ML_KEM_768.ct_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let ss_out = match unsafe { output_bytes_exact(ss_out, ss_len, 32) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let ek = MlKemEncapsulationKey {
        bytes: ek_bytes.to_vec(),
    };
    let mut rng = OsRng;
    match tafrah_ml_kem::ml_kem_768::encapsulate(&ek, &mut rng) {
        Ok((ct, ss)) => {
            ct_out.copy_from_slice(ct.as_bytes());
            ss_out.copy_from_slice(ss.as_bytes());
            TAFRAH_STATUS_OK
        }
        Err(err) => status_from_error(err),
    }
}

#[no_mangle]
pub extern "C" fn tafrah_ml_kem_768_decapsulate(
    dk_ptr: *const u8,
    dk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> c_int {
    let dk_bytes = match unsafe { input_bytes_exact(dk_ptr, dk_len, ML_KEM_768.dk_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let ct_bytes = match unsafe { input_bytes_exact(ct_ptr, ct_len, ML_KEM_768.ct_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let ss_out = match unsafe { output_bytes_exact(ss_out, ss_len, 32) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let dk = MlKemDecapsulationKey {
        bytes: dk_bytes.to_vec(),
    };
    let ct = MlKemCiphertext {
        bytes: ct_bytes.to_vec(),
    };
    match tafrah_ml_kem::ml_kem_768::decapsulate(&dk, &ct) {
        Ok(ss) => copy_result(ss.as_bytes(), ss_out),
        Err(err) => status_from_error(err),
    }
}

#[no_mangle]
pub extern "C" fn tafrah_ml_dsa_65_keygen(
    vk_out: *mut u8,
    vk_len: usize,
    sk_out: *mut u8,
    sk_len: usize,
) -> c_int {
    let vk_out = match unsafe { output_bytes_exact(vk_out, vk_len, ML_DSA_65.vk_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let sk_out = match unsafe { output_bytes_exact(sk_out, sk_len, ML_DSA_65.sk_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let mut rng = OsRng;
    let (vk, sk) = tafrah_ml_dsa::ml_dsa_65::keygen(&mut rng);
    vk_out.copy_from_slice(vk.as_bytes());
    sk_out.copy_from_slice(sk.as_bytes());
    TAFRAH_STATUS_OK
}

#[no_mangle]
pub extern "C" fn tafrah_ml_dsa_65_sign(
    sk_ptr: *const u8,
    sk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> c_int {
    let sk_bytes = match unsafe { input_bytes_exact(sk_ptr, sk_len, ML_DSA_65.sk_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let msg_bytes = match unsafe { input_bytes(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let sig_out = match unsafe { output_bytes_exact(sig_out, sig_len, ML_DSA_65.sig_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let sk = MlDsaSigningKey {
        bytes: sk_bytes.to_vec(),
    };
    let mut rng = OsRng;
    match tafrah_ml_dsa::ml_dsa_65::sign_with_context(&sk, msg_bytes, &[], &mut rng) {
        Ok(sig) => copy_result(sig.as_bytes(), sig_out),
        Err(err) => status_from_error(err),
    }
}

#[no_mangle]
pub extern "C" fn tafrah_ml_dsa_65_verify(
    vk_ptr: *const u8,
    vk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> c_int {
    let vk_bytes = match unsafe { input_bytes_exact(vk_ptr, vk_len, ML_DSA_65.vk_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let msg_bytes = match unsafe { input_bytes(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let sig_bytes = match unsafe { input_bytes_exact(sig_ptr, sig_len, ML_DSA_65.sig_size()) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let vk = MlDsaVerifyingKey {
        bytes: vk_bytes.to_vec(),
    };
    let sig = MlDsaSignature {
        bytes: sig_bytes.to_vec(),
    };
    match tafrah_ml_dsa::ml_dsa_65::verify_with_context(&vk, msg_bytes, &sig, &[]) {
        Ok(()) => TAFRAH_STATUS_OK,
        Err(err) => status_from_error(err),
    }
}

#[no_mangle]
pub extern "C" fn tafrah_slh_dsa_shake_128f_keygen(
    vk_out: *mut u8,
    vk_len: usize,
    sk_out: *mut u8,
    sk_len: usize,
) -> c_int {
    let vk_out = match unsafe { output_bytes_exact(vk_out, vk_len, SLH_DSA_SHAKE_128F.pk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let sk_out = match unsafe { output_bytes_exact(sk_out, sk_len, SLH_DSA_SHAKE_128F.sk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let mut rng = OsRng;
    let (vk, sk) = match tafrah_slh_dsa::keygen::slh_dsa_keygen(&mut rng, &SLH_DSA_SHAKE_128F) {
        Ok(pair) => pair,
        Err(err) => return status_from_error(err),
    };
    vk_out.copy_from_slice(vk.as_bytes());
    sk_out.copy_from_slice(sk.as_bytes());
    TAFRAH_STATUS_OK
}

#[no_mangle]
pub extern "C" fn tafrah_slh_dsa_shake_128f_sign(
    sk_ptr: *const u8,
    sk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> c_int {
    let sk_bytes = match unsafe { input_bytes_exact(sk_ptr, sk_len, SLH_DSA_SHAKE_128F.sk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let msg_bytes = match unsafe { input_bytes(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let sig_out =
        match unsafe { output_bytes_exact(sig_out, sig_len, SLH_DSA_SHAKE_128F.sig_bytes) } {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };

    let sk = SlhDsaSigningKey {
        bytes: sk_bytes.to_vec(),
    };
    let mut rng = OsRng;
    match tafrah_slh_dsa::sign::slh_dsa_sign(&sk, msg_bytes, &mut rng, &SLH_DSA_SHAKE_128F) {
        Ok(sig) => copy_result(sig.as_bytes(), sig_out),
        Err(err) => status_from_error(err),
    }
}

#[no_mangle]
pub extern "C" fn tafrah_slh_dsa_shake_128f_verify(
    vk_ptr: *const u8,
    vk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> c_int {
    let vk_bytes = match unsafe { input_bytes_exact(vk_ptr, vk_len, SLH_DSA_SHAKE_128F.pk_bytes) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let msg_bytes = match unsafe { input_bytes(msg_ptr, msg_len) } {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let sig_bytes =
        match unsafe { input_bytes_exact(sig_ptr, sig_len, SLH_DSA_SHAKE_128F.sig_bytes) } {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };

    let vk = SlhDsaVerifyingKey {
        bytes: vk_bytes.to_vec(),
    };
    let sig = SlhDsaSignature {
        bytes: sig_bytes.to_vec(),
    };
    match tafrah_slh_dsa::verify::slh_dsa_verify(&vk, msg_bytes, &sig, &SLH_DSA_SHAKE_128F) {
        Ok(()) => TAFRAH_STATUS_OK,
        Err(err) => status_from_error(err),
    }
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_512_keygen(
    vk_out: *mut u8,
    vk_len: usize,
    sk_out: *mut u8,
    sk_len: usize,
) -> c_int {
    falcon_keygen_inner(vk_out, vk_len, sk_out, sk_len, &FALCON_512, |rng| {
        tafrah_falcon::falcon_512::keygen(rng)
    })
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_512_sign(
    sk_ptr: *const u8,
    sk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_capacity: usize,
    sig_written: *mut usize,
) -> c_int {
    falcon_sign_inner(
        sk_ptr,
        sk_len,
        msg_ptr,
        msg_len,
        sig_out,
        sig_capacity,
        sig_written,
        &FALCON_512,
        |sk, msg, rng| tafrah_falcon::falcon_512::sign(sk, msg, rng),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_512_verify(
    vk_ptr: *const u8,
    vk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> c_int {
    falcon_verify_inner(
        vk_ptr,
        vk_len,
        msg_ptr,
        msg_len,
        sig_ptr,
        sig_len,
        &FALCON_512,
        |vk, msg, sig| tafrah_falcon::falcon_512::verify(vk, msg, sig),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_1024_keygen(
    vk_out: *mut u8,
    vk_len: usize,
    sk_out: *mut u8,
    sk_len: usize,
) -> c_int {
    falcon_keygen_inner(vk_out, vk_len, sk_out, sk_len, &FALCON_1024, |rng| {
        tafrah_falcon::falcon_1024::keygen(rng)
    })
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_1024_sign(
    sk_ptr: *const u8,
    sk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_capacity: usize,
    sig_written: *mut usize,
) -> c_int {
    falcon_sign_inner(
        sk_ptr,
        sk_len,
        msg_ptr,
        msg_len,
        sig_out,
        sig_capacity,
        sig_written,
        &FALCON_1024,
        |sk, msg, rng| tafrah_falcon::falcon_1024::sign(sk, msg, rng),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_falcon_1024_verify(
    vk_ptr: *const u8,
    vk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> c_int {
    falcon_verify_inner(
        vk_ptr,
        vk_len,
        msg_ptr,
        msg_len,
        sig_ptr,
        sig_len,
        &FALCON_1024,
        |vk, msg, sig| tafrah_falcon::falcon_1024::verify(vk, msg, sig),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_128_keygen(
    ek_out: *mut u8,
    ek_len: usize,
    dk_out: *mut u8,
    dk_len: usize,
) -> c_int {
    hqc_keygen_inner(ek_out, ek_len, dk_out, dk_len, &HQC_128, |rng| {
        tafrah_hqc::hqc_128::keygen(rng)
    })
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_128_encapsulate(
    ek_ptr: *const u8,
    ek_len: usize,
    ct_out: *mut u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> c_int {
    hqc_encapsulate_inner(
        ek_ptr,
        ek_len,
        ct_out,
        ct_len,
        ss_out,
        ss_len,
        &HQC_128,
        |ek, rng| tafrah_hqc::hqc_128::encapsulate(ek, rng),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_128_decapsulate(
    dk_ptr: *const u8,
    dk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> c_int {
    hqc_decapsulate_inner(
        dk_ptr,
        dk_len,
        ct_ptr,
        ct_len,
        ss_out,
        ss_len,
        &HQC_128,
        |dk, ct| tafrah_hqc::hqc_128::decapsulate(dk, ct),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_192_keygen(
    ek_out: *mut u8,
    ek_len: usize,
    dk_out: *mut u8,
    dk_len: usize,
) -> c_int {
    hqc_keygen_inner(ek_out, ek_len, dk_out, dk_len, &HQC_192, |rng| {
        tafrah_hqc::hqc_192::keygen(rng)
    })
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_192_encapsulate(
    ek_ptr: *const u8,
    ek_len: usize,
    ct_out: *mut u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> c_int {
    hqc_encapsulate_inner(
        ek_ptr,
        ek_len,
        ct_out,
        ct_len,
        ss_out,
        ss_len,
        &HQC_192,
        |ek, rng| tafrah_hqc::hqc_192::encapsulate(ek, rng),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_192_decapsulate(
    dk_ptr: *const u8,
    dk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> c_int {
    hqc_decapsulate_inner(
        dk_ptr,
        dk_len,
        ct_ptr,
        ct_len,
        ss_out,
        ss_len,
        &HQC_192,
        |dk, ct| tafrah_hqc::hqc_192::decapsulate(dk, ct),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_256_keygen(
    ek_out: *mut u8,
    ek_len: usize,
    dk_out: *mut u8,
    dk_len: usize,
) -> c_int {
    hqc_keygen_inner(ek_out, ek_len, dk_out, dk_len, &HQC_256, |rng| {
        tafrah_hqc::hqc_256::keygen(rng)
    })
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_256_encapsulate(
    ek_ptr: *const u8,
    ek_len: usize,
    ct_out: *mut u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> c_int {
    hqc_encapsulate_inner(
        ek_ptr,
        ek_len,
        ct_out,
        ct_len,
        ss_out,
        ss_len,
        &HQC_256,
        |ek, rng| tafrah_hqc::hqc_256::encapsulate(ek, rng),
    )
}

#[no_mangle]
pub extern "C" fn tafrah_hqc_256_decapsulate(
    dk_ptr: *const u8,
    dk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> c_int {
    hqc_decapsulate_inner(
        dk_ptr,
        dk_len,
        ct_ptr,
        ct_len,
        ss_out,
        ss_len,
        &HQC_256,
        |dk, ct| tafrah_hqc::hqc_256::decapsulate(dk, ct),
    )
}
