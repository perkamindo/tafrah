use tafrah_abi::{
    tafrah_falcon_512_keygen, tafrah_falcon_512_sig_size, tafrah_falcon_512_sign,
    tafrah_falcon_512_sk_size, tafrah_falcon_512_verify, tafrah_falcon_512_vk_size,
    tafrah_hqc_128_ct_size, tafrah_hqc_128_decapsulate, tafrah_hqc_128_dk_size,
    tafrah_hqc_128_ek_size, tafrah_hqc_128_encapsulate, tafrah_hqc_128_keygen,
    tafrah_hqc_128_ss_size, tafrah_hqc_192_ct_size, tafrah_hqc_192_decapsulate,
    tafrah_hqc_192_dk_size, tafrah_hqc_192_ek_size, tafrah_hqc_192_encapsulate,
    tafrah_hqc_192_keygen, tafrah_hqc_192_ss_size, tafrah_hqc_256_ct_size,
    tafrah_hqc_256_decapsulate, tafrah_hqc_256_dk_size, tafrah_hqc_256_ek_size,
    tafrah_hqc_256_encapsulate, tafrah_hqc_256_keygen, tafrah_hqc_256_ss_size,
    tafrah_ml_dsa_44_keygen, tafrah_ml_dsa_44_sig_size, tafrah_ml_dsa_44_sign,
    tafrah_ml_dsa_44_sk_size, tafrah_ml_dsa_44_verify, tafrah_ml_dsa_44_vk_size,
    tafrah_ml_dsa_65_keygen, tafrah_ml_dsa_65_sig_size, tafrah_ml_dsa_65_sign,
    tafrah_ml_dsa_65_sk_size, tafrah_ml_dsa_65_verify, tafrah_ml_dsa_65_vk_size,
    tafrah_ml_dsa_87_keygen, tafrah_ml_dsa_87_sig_size, tafrah_ml_dsa_87_sign,
    tafrah_ml_dsa_87_sk_size, tafrah_ml_dsa_87_verify, tafrah_ml_dsa_87_vk_size,
    tafrah_ml_kem_1024_ct_size, tafrah_ml_kem_1024_decapsulate, tafrah_ml_kem_1024_dk_size,
    tafrah_ml_kem_1024_ek_size, tafrah_ml_kem_1024_encapsulate, tafrah_ml_kem_1024_keygen,
    tafrah_ml_kem_512_ct_size, tafrah_ml_kem_512_decapsulate, tafrah_ml_kem_512_dk_size,
    tafrah_ml_kem_512_ek_size, tafrah_ml_kem_512_encapsulate, tafrah_ml_kem_512_keygen,
    tafrah_ml_kem_768_ct_size, tafrah_ml_kem_768_decapsulate, tafrah_ml_kem_768_dk_size,
    tafrah_ml_kem_768_ek_size, tafrah_ml_kem_768_encapsulate, tafrah_ml_kem_768_keygen,
    tafrah_shared_secret_size, tafrah_slh_dsa_sha2_128f_sig_size, tafrah_slh_dsa_sha2_128f_sk_size,
    tafrah_slh_dsa_sha2_128f_vk_size, tafrah_slh_dsa_sha2_128s_keygen,
    tafrah_slh_dsa_sha2_128s_sig_size, tafrah_slh_dsa_sha2_128s_sign,
    tafrah_slh_dsa_sha2_128s_sk_size, tafrah_slh_dsa_sha2_128s_verify,
    tafrah_slh_dsa_sha2_128s_vk_size, tafrah_slh_dsa_sha2_192f_sig_size,
    tafrah_slh_dsa_sha2_192f_sk_size, tafrah_slh_dsa_sha2_192f_vk_size,
    tafrah_slh_dsa_sha2_192s_sig_size, tafrah_slh_dsa_sha2_192s_sk_size,
    tafrah_slh_dsa_sha2_192s_vk_size, tafrah_slh_dsa_sha2_256f_sig_size,
    tafrah_slh_dsa_sha2_256f_sk_size, tafrah_slh_dsa_sha2_256f_vk_size,
    tafrah_slh_dsa_sha2_256s_sig_size, tafrah_slh_dsa_sha2_256s_sk_size,
    tafrah_slh_dsa_sha2_256s_vk_size, tafrah_slh_dsa_shake_128f_keygen,
    tafrah_slh_dsa_shake_128f_hash_sha2_256_sign,
    tafrah_slh_dsa_shake_128f_hash_sha2_256_verify,
    tafrah_slh_dsa_shake_128f_sig_size, tafrah_slh_dsa_shake_128f_sign,
    tafrah_slh_dsa_shake_128f_sk_size, tafrah_slh_dsa_shake_128f_verify,
    tafrah_slh_dsa_shake_128f_vk_size, tafrah_slh_dsa_shake_128s_sig_size,
    tafrah_slh_dsa_shake_128s_sk_size, tafrah_slh_dsa_shake_128s_vk_size,
    tafrah_slh_dsa_shake_192f_sig_size, tafrah_slh_dsa_shake_192f_sk_size,
    tafrah_slh_dsa_shake_192f_vk_size, tafrah_slh_dsa_shake_192s_sig_size,
    tafrah_slh_dsa_shake_192s_sk_size, tafrah_slh_dsa_shake_192s_vk_size,
    tafrah_slh_dsa_shake_256f_sig_size, tafrah_slh_dsa_shake_256f_sk_size,
    tafrah_slh_dsa_shake_256f_vk_size, tafrah_slh_dsa_shake_256s_sig_size,
    tafrah_slh_dsa_shake_256s_sk_size, tafrah_slh_dsa_shake_256s_vk_size, TAFRAH_STATUS_OK,
    TAFRAH_STATUS_VERIFICATION_FAILED,
};

type MlKemKeygenFn = extern "C" fn(*mut u8, usize, *mut u8, usize) -> i32;
type MlKemEncapsulateFn = extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> i32;
type MlKemDecapsulateFn = extern "C" fn(*const u8, usize, *const u8, usize, *mut u8, usize) -> i32;

type MlDsaKeygenFn = extern "C" fn(*mut u8, usize, *mut u8, usize) -> i32;
type MlDsaSignFn = extern "C" fn(*const u8, usize, *const u8, usize, *mut u8, usize) -> i32;
type MlDsaVerifyFn = extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> i32;

type SlhKeygenFn = extern "C" fn(*mut u8, usize, *mut u8, usize) -> i32;
type SlhSignFn = extern "C" fn(*const u8, usize, *const u8, usize, *mut u8, usize) -> i32;
type SlhVerifyFn = extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> i32;

fn run_ml_kem_roundtrip(
    ek_size: usize,
    dk_size: usize,
    ct_size: usize,
    keygen: MlKemKeygenFn,
    encapsulate: MlKemEncapsulateFn,
    decapsulate: MlKemDecapsulateFn,
) {
    let mut ek = vec![0u8; ek_size];
    let mut dk = vec![0u8; dk_size];
    let mut ct = vec![0u8; ct_size];
    let mut ss_client = vec![0u8; tafrah_shared_secret_size()];
    let mut ss_server = vec![0u8; tafrah_shared_secret_size()];

    assert_eq!(
        keygen(ek.as_mut_ptr(), ek.len(), dk.as_mut_ptr(), dk.len()),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        encapsulate(
            ek.as_ptr(),
            ek.len(),
            ct.as_mut_ptr(),
            ct.len(),
            ss_client.as_mut_ptr(),
            ss_client.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        decapsulate(
            dk.as_ptr(),
            dk.len(),
            ct.as_ptr(),
            ct.len(),
            ss_server.as_mut_ptr(),
            ss_server.len(),
        ),
        TAFRAH_STATUS_OK
    );

    assert_eq!(ss_client, ss_server);
}

fn run_ml_dsa_sign_verify(
    vk_size: usize,
    sk_size: usize,
    sig_size: usize,
    keygen: MlDsaKeygenFn,
    sign: MlDsaSignFn,
    verify: MlDsaVerifyFn,
) {
    let mut vk = vec![0u8; vk_size];
    let mut sk = vec![0u8; sk_size];
    let mut sig = vec![0u8; sig_size];
    let msg = b"abi proof message";

    assert_eq!(
        keygen(vk.as_mut_ptr(), vk.len(), sk.as_mut_ptr(), sk.len()),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        sign(
            sk.as_ptr(),
            sk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        verify(
            vk.as_ptr(),
            vk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_OK
    );

    let wrong_msg = b"abi proof message tampered";
    assert_eq!(
        verify(
            vk.as_ptr(),
            vk.len(),
            wrong_msg.as_ptr(),
            wrong_msg.len(),
            sig.as_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_VERIFICATION_FAILED
    );
}

fn run_slh_sign_verify(
    vk_size: usize,
    sk_size: usize,
    sig_size: usize,
    keygen: SlhKeygenFn,
    sign: SlhSignFn,
    verify: SlhVerifyFn,
) {
    let mut vk = vec![0u8; vk_size];
    let mut sk = vec![0u8; sk_size];
    let mut sig = vec![0u8; sig_size];
    let msg = b"slh abi proof message";

    assert_eq!(
        keygen(vk.as_mut_ptr(), vk.len(), sk.as_mut_ptr(), sk.len()),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        sign(
            sk.as_ptr(),
            sk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        verify(
            vk.as_ptr(),
            vk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_OK
    );
}

fn run_slh_prehash_sign_verify(
    vk_size: usize,
    sk_size: usize,
    sig_size: usize,
    keygen: SlhKeygenFn,
    sign: SlhSignFn,
    verify: SlhVerifyFn,
) {
    let mut vk = vec![0u8; vk_size];
    let mut sk = vec![0u8; sk_size];
    let mut sig = vec![0u8; sig_size];
    let msg = b"slh abi prehash proof message";
    let wrong_msg = b"slh abi prehash proof message tampered";

    assert_eq!(
        keygen(vk.as_mut_ptr(), vk.len(), sk.as_mut_ptr(), sk.len()),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        sign(
            sk.as_ptr(),
            sk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        verify(
            vk.as_ptr(),
            vk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        verify(
            vk.as_ptr(),
            vk.len(),
            wrong_msg.as_ptr(),
            wrong_msg.len(),
            sig.as_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_VERIFICATION_FAILED
    );
}

#[test]
fn test_ml_kem_abi_roundtrip_all_levels() {
    run_ml_kem_roundtrip(
        tafrah_ml_kem_512_ek_size(),
        tafrah_ml_kem_512_dk_size(),
        tafrah_ml_kem_512_ct_size(),
        tafrah_ml_kem_512_keygen,
        tafrah_ml_kem_512_encapsulate,
        tafrah_ml_kem_512_decapsulate,
    );
    run_ml_kem_roundtrip(
        tafrah_ml_kem_768_ek_size(),
        tafrah_ml_kem_768_dk_size(),
        tafrah_ml_kem_768_ct_size(),
        tafrah_ml_kem_768_keygen,
        tafrah_ml_kem_768_encapsulate,
        tafrah_ml_kem_768_decapsulate,
    );
    run_ml_kem_roundtrip(
        tafrah_ml_kem_1024_ek_size(),
        tafrah_ml_kem_1024_dk_size(),
        tafrah_ml_kem_1024_ct_size(),
        tafrah_ml_kem_1024_keygen,
        tafrah_ml_kem_1024_encapsulate,
        tafrah_ml_kem_1024_decapsulate,
    );
}

#[test]
fn test_hqc_abi_roundtrip_all_levels() {
    let mut ek128 = vec![0u8; tafrah_hqc_128_ek_size()];
    let mut dk128 = vec![0u8; tafrah_hqc_128_dk_size()];
    let mut ct128 = vec![0u8; tafrah_hqc_128_ct_size()];
    let mut ss128_client = vec![0u8; tafrah_hqc_128_ss_size()];
    let mut ss128_server = vec![0u8; tafrah_hqc_128_ss_size()];

    assert_eq!(
        tafrah_hqc_128_keygen(
            ek128.as_mut_ptr(),
            ek128.len(),
            dk128.as_mut_ptr(),
            dk128.len()
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        tafrah_hqc_128_encapsulate(
            ek128.as_ptr(),
            ek128.len(),
            ct128.as_mut_ptr(),
            ct128.len(),
            ss128_client.as_mut_ptr(),
            ss128_client.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        tafrah_hqc_128_decapsulate(
            dk128.as_ptr(),
            dk128.len(),
            ct128.as_ptr(),
            ct128.len(),
            ss128_server.as_mut_ptr(),
            ss128_server.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(ss128_client, ss128_server);

    let mut ek192 = vec![0u8; tafrah_hqc_192_ek_size()];
    let mut dk192 = vec![0u8; tafrah_hqc_192_dk_size()];
    let mut ct192 = vec![0u8; tafrah_hqc_192_ct_size()];
    let mut ss192_client = vec![0u8; tafrah_hqc_192_ss_size()];
    let mut ss192_server = vec![0u8; tafrah_hqc_192_ss_size()];

    assert_eq!(
        tafrah_hqc_192_keygen(
            ek192.as_mut_ptr(),
            ek192.len(),
            dk192.as_mut_ptr(),
            dk192.len()
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        tafrah_hqc_192_encapsulate(
            ek192.as_ptr(),
            ek192.len(),
            ct192.as_mut_ptr(),
            ct192.len(),
            ss192_client.as_mut_ptr(),
            ss192_client.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        tafrah_hqc_192_decapsulate(
            dk192.as_ptr(),
            dk192.len(),
            ct192.as_ptr(),
            ct192.len(),
            ss192_server.as_mut_ptr(),
            ss192_server.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(ss192_client, ss192_server);

    let mut ek256 = vec![0u8; tafrah_hqc_256_ek_size()];
    let mut dk256 = vec![0u8; tafrah_hqc_256_dk_size()];
    let mut ct256 = vec![0u8; tafrah_hqc_256_ct_size()];
    let mut ss256_client = vec![0u8; tafrah_hqc_256_ss_size()];
    let mut ss256_server = vec![0u8; tafrah_hqc_256_ss_size()];

    assert_eq!(
        tafrah_hqc_256_keygen(
            ek256.as_mut_ptr(),
            ek256.len(),
            dk256.as_mut_ptr(),
            dk256.len()
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        tafrah_hqc_256_encapsulate(
            ek256.as_ptr(),
            ek256.len(),
            ct256.as_mut_ptr(),
            ct256.len(),
            ss256_client.as_mut_ptr(),
            ss256_client.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        tafrah_hqc_256_decapsulate(
            dk256.as_ptr(),
            dk256.len(),
            ct256.as_ptr(),
            ct256.len(),
            ss256_server.as_mut_ptr(),
            ss256_server.len(),
        ),
        TAFRAH_STATUS_OK
    );
    assert_eq!(ss256_client, ss256_server);
}

#[test]
fn test_ml_dsa_abi_sign_verify_all_levels() {
    run_ml_dsa_sign_verify(
        tafrah_ml_dsa_44_vk_size(),
        tafrah_ml_dsa_44_sk_size(),
        tafrah_ml_dsa_44_sig_size(),
        tafrah_ml_dsa_44_keygen,
        tafrah_ml_dsa_44_sign,
        tafrah_ml_dsa_44_verify,
    );
    run_ml_dsa_sign_verify(
        tafrah_ml_dsa_65_vk_size(),
        tafrah_ml_dsa_65_sk_size(),
        tafrah_ml_dsa_65_sig_size(),
        tafrah_ml_dsa_65_keygen,
        tafrah_ml_dsa_65_sign,
        tafrah_ml_dsa_65_verify,
    );
    run_ml_dsa_sign_verify(
        tafrah_ml_dsa_87_vk_size(),
        tafrah_ml_dsa_87_sk_size(),
        tafrah_ml_dsa_87_sig_size(),
        tafrah_ml_dsa_87_keygen,
        tafrah_ml_dsa_87_sign,
        tafrah_ml_dsa_87_verify,
    );
}

#[test]
fn test_slh_dsa_abi_exposes_all_param_set_sizes() {
    let sizes = [
        tafrah_slh_dsa_sha2_128s_vk_size(),
        tafrah_slh_dsa_sha2_128s_sk_size(),
        tafrah_slh_dsa_sha2_128s_sig_size(),
        tafrah_slh_dsa_sha2_128f_vk_size(),
        tafrah_slh_dsa_sha2_128f_sk_size(),
        tafrah_slh_dsa_sha2_128f_sig_size(),
        tafrah_slh_dsa_sha2_192s_vk_size(),
        tafrah_slh_dsa_sha2_192s_sk_size(),
        tafrah_slh_dsa_sha2_192s_sig_size(),
        tafrah_slh_dsa_sha2_192f_vk_size(),
        tafrah_slh_dsa_sha2_192f_sk_size(),
        tafrah_slh_dsa_sha2_192f_sig_size(),
        tafrah_slh_dsa_sha2_256s_vk_size(),
        tafrah_slh_dsa_sha2_256s_sk_size(),
        tafrah_slh_dsa_sha2_256s_sig_size(),
        tafrah_slh_dsa_sha2_256f_vk_size(),
        tafrah_slh_dsa_sha2_256f_sk_size(),
        tafrah_slh_dsa_sha2_256f_sig_size(),
        tafrah_slh_dsa_shake_128s_vk_size(),
        tafrah_slh_dsa_shake_128s_sk_size(),
        tafrah_slh_dsa_shake_128s_sig_size(),
        tafrah_slh_dsa_shake_128f_vk_size(),
        tafrah_slh_dsa_shake_128f_sk_size(),
        tafrah_slh_dsa_shake_128f_sig_size(),
        tafrah_slh_dsa_shake_192s_vk_size(),
        tafrah_slh_dsa_shake_192s_sk_size(),
        tafrah_slh_dsa_shake_192s_sig_size(),
        tafrah_slh_dsa_shake_192f_vk_size(),
        tafrah_slh_dsa_shake_192f_sk_size(),
        tafrah_slh_dsa_shake_192f_sig_size(),
        tafrah_slh_dsa_shake_256s_vk_size(),
        tafrah_slh_dsa_shake_256s_sk_size(),
        tafrah_slh_dsa_shake_256s_sig_size(),
        tafrah_slh_dsa_shake_256f_vk_size(),
        tafrah_slh_dsa_shake_256f_sk_size(),
        tafrah_slh_dsa_shake_256f_sig_size(),
    ];

    assert!(sizes.into_iter().all(|size| size > 0));
}

#[test]
fn test_slh_dsa_abi_sign_verify_selected_families() {
    run_slh_sign_verify(
        tafrah_slh_dsa_sha2_128s_vk_size(),
        tafrah_slh_dsa_sha2_128s_sk_size(),
        tafrah_slh_dsa_sha2_128s_sig_size(),
        tafrah_slh_dsa_sha2_128s_keygen,
        tafrah_slh_dsa_sha2_128s_sign,
        tafrah_slh_dsa_sha2_128s_verify,
    );
    run_slh_sign_verify(
        tafrah_slh_dsa_shake_128f_vk_size(),
        tafrah_slh_dsa_shake_128f_sk_size(),
        tafrah_slh_dsa_shake_128f_sig_size(),
        tafrah_slh_dsa_shake_128f_keygen,
        tafrah_slh_dsa_shake_128f_sign,
        tafrah_slh_dsa_shake_128f_verify,
    );
}

#[test]
fn test_slh_dsa_abi_hash_slh_sign_verify_selected_profile() {
    run_slh_prehash_sign_verify(
        tafrah_slh_dsa_shake_128f_vk_size(),
        tafrah_slh_dsa_shake_128f_sk_size(),
        tafrah_slh_dsa_shake_128f_sig_size(),
        tafrah_slh_dsa_shake_128f_keygen,
        tafrah_slh_dsa_shake_128f_hash_sha2_256_sign,
        tafrah_slh_dsa_shake_128f_hash_sha2_256_verify,
    );
}

#[test]
fn test_falcon_abi_sign_verify() {
    let mut vk = vec![0u8; tafrah_falcon_512_vk_size()];
    let mut sk = vec![0u8; tafrah_falcon_512_sk_size()];
    let mut sig = vec![0u8; tafrah_falcon_512_sig_size()];
    let mut sig_written = 0usize;
    let msg = b"falcon abi proof message";

    assert_eq!(
        tafrah_falcon_512_keygen(vk.as_mut_ptr(), vk.len(), sk.as_mut_ptr(), sk.len()),
        TAFRAH_STATUS_OK
    );
    assert_eq!(
        tafrah_falcon_512_sign(
            sk.as_ptr(),
            sk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_written,
        ),
        TAFRAH_STATUS_OK
    );
    sig.truncate(sig_written);

    assert_eq!(
        tafrah_falcon_512_verify(
            vk.as_ptr(),
            vk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_OK
    );

    let wrong_msg = b"falcon abi proof message tampered";
    assert_eq!(
        tafrah_falcon_512_verify(
            vk.as_ptr(),
            vk.len(),
            wrong_msg.as_ptr(),
            wrong_msg.len(),
            sig.as_ptr(),
            sig.len(),
        ),
        TAFRAH_STATUS_VERIFICATION_FAILED
    );
}
