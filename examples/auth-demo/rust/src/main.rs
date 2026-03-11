use rand::rngs::OsRng;
use tafrah::falcon::falcon_512;
use tafrah::hqc::hqc_128;
use tafrah::ml_dsa::ml_dsa_65;
use tafrah::ml_kem::ml_kem_768;
use tafrah::slh_dsa::params::SLH_DSA_SHAKE_128F;
use tafrah::slh_dsa::{keygen, sign, verify};

fn json_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn main() {
    let mut rng = OsRng;

    let (kem_ek, kem_dk) = ml_kem_768::keygen(&mut rng);
    let (kem_ct, kem_client_ss) = ml_kem_768::encapsulate(&kem_ek, &mut rng).expect("ml-kem encaps");
    let kem_server_ss = ml_kem_768::decapsulate(&kem_dk, &kem_ct).expect("ml-kem decaps");

    let (hqc_ek, hqc_dk) = hqc_128::keygen(&mut rng).expect("hqc keygen");
    let (hqc_ct, hqc_client_ss) = hqc_128::encapsulate(&hqc_ek, &mut rng).expect("hqc encaps");
    let hqc_server_ss = hqc_128::decapsulate(&hqc_dk, &hqc_ct).expect("hqc decaps");

    let (ml_vk, ml_sk) = ml_dsa_65::keygen(&mut rng);
    let ml_message = b"tafrah-auth-demo::ml-dsa-65".to_vec();
    let ml_sig = ml_dsa_65::sign_with_context(&ml_sk, &ml_message, &[], &mut rng).expect("ml-dsa sign");
    let ml_verify_ok = ml_dsa_65::verify_with_context(&ml_vk, &ml_message, &ml_sig, &[]).is_ok();
    let ml_tamper_rejected =
        ml_dsa_65::verify_with_context(&ml_vk, b"tafrah-auth-demo::ml-dsa-65\x01", &ml_sig, &[])
            .is_err();

    let (slh_vk, slh_sk) = keygen::slh_dsa_keygen(&mut rng, &SLH_DSA_SHAKE_128F).expect("slh keygen");
    let slh_message = b"tafrah-auth-demo::slh-dsa-shake-128f".to_vec();
    let slh_sig = sign::slh_dsa_sign(&slh_sk, &slh_message, &mut rng, &SLH_DSA_SHAKE_128F)
        .expect("slh sign");
    let slh_verify_ok = verify::slh_dsa_verify(&slh_vk, &slh_message, &slh_sig, &SLH_DSA_SHAKE_128F).is_ok();
    let slh_tamper_rejected =
        verify::slh_dsa_verify(&slh_vk, b"tafrah-auth-demo::slh-dsa-shake-128f\x02", &slh_sig, &SLH_DSA_SHAKE_128F)
            .is_err();

    let (falcon_vk, falcon_sk) = falcon_512::keygen(&mut rng).expect("falcon keygen");
    let falcon_message = b"tafrah-auth-demo::falcon-512".to_vec();
    let falcon_sig = falcon_512::sign(&falcon_sk, &falcon_message, &mut rng).expect("falcon sign");
    let falcon_verify_ok = falcon_512::verify(&falcon_vk, &falcon_message, &falcon_sig).is_ok();
    let falcon_tamper_rejected =
        falcon_512::verify(&falcon_vk, b"tafrah-auth-demo::falcon-512\x03", &falcon_sig).is_err();

    let overall_ok = kem_client_ss.as_bytes() == kem_server_ss.as_bytes()
        && hqc_client_ss.as_bytes() == hqc_server_ss.as_bytes()
        && ml_verify_ok
        && ml_tamper_rejected
        && slh_verify_ok
        && slh_tamper_rejected
        && falcon_verify_ok
        && falcon_tamper_rejected;

    println!(
        "{{\"language\":\"rust\",\"ml_kem_768_shared_secret_match\":{},\"hqc_128_shared_secret_match\":{},\"ml_dsa_65_verify_ok\":{},\"ml_dsa_65_tamper_rejected\":{},\"slh_dsa_shake_128f_verify_ok\":{},\"slh_dsa_shake_128f_tamper_rejected\":{},\"falcon_512_verify_ok\":{},\"falcon_512_tamper_rejected\":{},\"overall_ok\":{}}}",
        json_bool(kem_client_ss.as_bytes() == kem_server_ss.as_bytes()),
        json_bool(hqc_client_ss.as_bytes() == hqc_server_ss.as_bytes()),
        json_bool(ml_verify_ok),
        json_bool(ml_tamper_rejected),
        json_bool(slh_verify_ok),
        json_bool(slh_tamper_rejected),
        json_bool(falcon_verify_ok),
        json_bool(falcon_tamper_rejected),
        json_bool(overall_ok)
    );

    if !overall_ok {
        std::process::exit(1);
    }
}
