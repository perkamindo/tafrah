use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rand::SeedableRng;
use sha3::{Digest, Sha3_256};
use tafrah_hqc::arithmetic::{cyclic_product_mod_xn_minus_1, vector_add};
use tafrah_hqc::decaps::hqc_decaps;
use tafrah_hqc::keygen::hqc_keygen_from_seeds;
use tafrah_hqc::params::{HQC_128, HQC_192, HQC_256};
use tafrah_hqc::parse::{
    encode_ciphertext, encode_public_key, encode_secret_key, parse_ciphertext, parse_public_key,
    parse_secret_key,
};
use tafrah_hqc::sampling::words_to_bytes_le;
use tafrah_hqc::types::{Ciphertext, DecapsulationKey, EncapsulationKey};
use tafrah_traits::Error;

fn ref_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .join("ref")
}

fn ensure_reference_paths(label: &str, paths: &[PathBuf]) -> bool {
    if let Some(missing) = paths.iter().find(|path| !path.exists()) {
        eprintln!("skipping {label}: missing {}", missing.display());
        return false;
    }
    true
}

fn parse_rsp_entries(path: &Path) -> Vec<BTreeMap<String, String>> {
    let content = fs::read_to_string(path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });

    let mut entries = Vec::new();
    let mut current = BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            if current.contains_key("count") {
                entries.push(std::mem::take(&mut current));
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(" = ") {
            current.insert(key.to_owned(), value.to_owned());
        }
    }

    if current.contains_key("count") {
        entries.push(current);
    }

    entries
}

fn field<'a>(entry: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    entry
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
        .as_str()
}

fn hex_len(hex: &str) -> usize {
    assert_eq!(hex.len() % 2, 0, "hex string has odd length");
    hex.len() / 2
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string has odd length");

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).unwrap();
        bytes.push(u8::from_str_radix(text, 16).unwrap());
    }
    bytes
}

fn sha3_hex(bytes: &[u8]) -> String {
    let digest = Sha3_256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn test_reference_kat_contracts_match_hqc_sizes() {
    let cases = [
        ("hqc-128/hqc-128_kat.rsp", &HQC_128),
        ("hqc-192/hqc-192_kat.rsp", &HQC_192),
        ("hqc-256/hqc-256_kat.rsp", &HQC_256),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(relative_path, _)| {
            ref_root()
                .join("HQC-Round4-FIPS_207")
                .join("KATs")
                .join("Reference_Implementation")
                .join(relative_path)
        })
        .collect();
    if !ensure_reference_paths("HQC size-contract KATs", &required_paths) {
        return;
    }

    for (relative_path, params) in cases {
        let path = ref_root()
            .join("HQC-Round4-FIPS_207")
            .join("KATs")
            .join("Reference_Implementation")
            .join(relative_path);
        let entries = parse_rsp_entries(&path);

        assert!(
            !entries.is_empty(),
            "{} did not contain any KAT entries",
            path.display()
        );

        for entry in entries {
            let count = field(&entry, "count");
            let pk_len = hex_len(field(&entry, "pk"));
            let sk_len = hex_len(field(&entry, "sk"));
            let ct_len = hex_len(field(&entry, "ct"));
            let ss_len = hex_len(field(&entry, "ss"));

            assert_eq!(
                pk_len, params.pk_bytes,
                "{} count={count}: pk length",
                params.alg_name
            );
            assert_eq!(
                sk_len, params.sk_bytes,
                "{} count={count}: sk length",
                params.alg_name
            );
            assert_eq!(
                ct_len, params.ct_bytes,
                "{} count={count}: ct length",
                params.alg_name
            );
            assert_eq!(
                ss_len, params.ss_bytes,
                "{} count={count}: ss length",
                params.alg_name
            );
        }
    }
}

#[test]
fn test_hqc_parse_roundtrip_reference_layouts() {
    let cases = [
        ("hqc-128/hqc-128_kat.rsp", &HQC_128),
        ("hqc-192/hqc-192_kat.rsp", &HQC_192),
        ("hqc-256/hqc-256_kat.rsp", &HQC_256),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(relative_path, _)| {
            ref_root()
                .join("HQC-Round4-FIPS_207")
                .join("KATs")
                .join("Reference_Implementation")
                .join(relative_path)
        })
        .collect();
    if !ensure_reference_paths("HQC parse roundtrip KATs", &required_paths) {
        return;
    }

    for (relative_path, params) in cases {
        let path = ref_root()
            .join("HQC-Round4-FIPS_207")
            .join("KATs")
            .join("Reference_Implementation")
            .join(relative_path);
        let entries = parse_rsp_entries(&path);

        for entry in entries {
            let count = field(&entry, "count");
            let pk = EncapsulationKey {
                bytes: hex_decode(field(&entry, "pk")),
            };
            let sk = DecapsulationKey {
                bytes: hex_decode(field(&entry, "sk")),
            };
            let ct = Ciphertext {
                bytes: hex_decode(field(&entry, "ct")),
            };

            let parsed_pk = parse_public_key(&pk, params).unwrap_or_else(|err| {
                panic!("{} count={count}: pk parse failed: {err}", params.alg_name)
            });
            let parsed_sk = parse_secret_key(&sk, params).unwrap_or_else(|err| {
                panic!("{} count={count}: sk parse failed: {err}", params.alg_name)
            });
            let parsed_ct = parse_ciphertext(&ct, params).unwrap_or_else(|err| {
                panic!("{} count={count}: ct parse failed: {err}", params.alg_name)
            });

            let encoded_pk = encode_public_key(&parsed_pk, params).unwrap();
            let encoded_sk = encode_secret_key(&parsed_sk, params).unwrap();
            let encoded_ct = encode_ciphertext(&parsed_ct, params).unwrap();

            assert_eq!(
                encoded_pk.bytes, pk.bytes,
                "{} count={count}: pk roundtrip",
                params.alg_name
            );
            assert_eq!(
                encoded_sk.bytes, sk.bytes,
                "{} count={count}: sk roundtrip",
                params.alg_name
            );
            assert_eq!(
                encoded_ct.bytes, ct.bytes,
                "{} count={count}: ct roundtrip",
                params.alg_name
            );
        }
    }
}

#[test]
fn test_hqc_128_seed_expansion_matches_reference_digests() {
    let path = ref_root()
        .join("HQC-Round4-FIPS_207")
        .join("KATs")
        .join("Reference_Implementation")
        .join("hqc-128")
        .join("hqc-128_kat.rsp");
    if !ensure_reference_paths("HQC-128 seed-expansion digest check", std::slice::from_ref(&path)) {
        return;
    }
    let entry = parse_rsp_entries(&path)
        .into_iter()
        .find(|entry| field(entry, "count") == "0")
        .expect("count=0 HQC-128 KAT");

    let pk = EncapsulationKey {
        bytes: hex_decode(field(&entry, "pk")),
    };
    let sk = DecapsulationKey {
        bytes: hex_decode(field(&entry, "sk")),
    };

    let parsed_pk = parse_public_key(&pk, &HQC_128).expect("parse pk");
    let parsed_sk = parse_secret_key(&sk, &HQC_128).expect("parse sk");

    assert_eq!(
        parsed_sk.public_key.bytes, pk.bytes,
        "pk embedded in sk mismatch"
    );

    let h_bytes = words_to_bytes_le(&parsed_pk.h, HQC_128.vec_n_size_bytes());
    let s_bytes = words_to_bytes_le(&parsed_pk.s, HQC_128.vec_n_size_bytes());
    let x_bytes = words_to_bytes_le(&parsed_sk.x, HQC_128.vec_n_size_bytes());
    let y_bytes = words_to_bytes_le(&parsed_sk.y, HQC_128.vec_n_size_bytes());

    assert_eq!(
        sha3_hex(&h_bytes),
        "335fc1de60319b6926acfa4f26346981098f16ca21288cc0110759c904c757f1"
    );
    assert_eq!(
        sha3_hex(&s_bytes),
        "97be5b2e912ecb26284155f2dd9ef96d4ba3435e76488f81060e0ad8ac562b2e"
    );
    assert_eq!(
        sha3_hex(&x_bytes),
        "6ee8a37798eac6f8a667ef92f5ba18b961ae242f5339cb9f0b6bc2d3fd348c3c"
    );
    assert_eq!(
        sha3_hex(&y_bytes),
        "3bd56c5df3034e3aebefd2901b24f68418ab8f82f985197a8125a9fe638202ae"
    );
    assert_eq!(
        sha3_hex(&parsed_sk.public_key.bytes),
        "8f240e324cefd5e998c03068e6843392e0d9b314356341e9e4654c80c1400965"
    );

    let reconstructed_s = vector_add(
        &parsed_sk.x,
        &cyclic_product_mod_xn_minus_1(&parsed_sk.y, &parsed_pk.h, &HQC_128),
    );
    let reconstructed_s_bytes = words_to_bytes_le(&reconstructed_s, HQC_128.vec_n_size_bytes());
    assert_eq!(
        reconstructed_s_bytes, s_bytes,
        "native syndrome reconstruction mismatch"
    );
}

#[test]
fn test_hqc_256_seed_expansion_matches_reference_digests() {
    let path = ref_root()
        .join("HQC-Round4-FIPS_207")
        .join("KATs")
        .join("Reference_Implementation")
        .join("hqc-256")
        .join("hqc-256_kat.rsp");
    if !ensure_reference_paths("HQC-256 seed-expansion digest check", std::slice::from_ref(&path)) {
        return;
    }
    let entry = parse_rsp_entries(&path)
        .into_iter()
        .find(|entry| field(entry, "count") == "0")
        .expect("count=0 HQC-256 KAT");

    let pk = EncapsulationKey {
        bytes: hex_decode(field(&entry, "pk")),
    };
    let sk = DecapsulationKey {
        bytes: hex_decode(field(&entry, "sk")),
    };

    let parsed_pk = parse_public_key(&pk, &HQC_256).expect("parse pk");
    let parsed_sk = parse_secret_key(&sk, &HQC_256).expect("parse sk");

    let h_bytes = words_to_bytes_le(&parsed_pk.h, HQC_256.vec_n_size_bytes());
    let s_bytes = words_to_bytes_le(&parsed_pk.s, HQC_256.vec_n_size_bytes());
    let x_bytes = words_to_bytes_le(&parsed_sk.x, HQC_256.vec_n_size_bytes());
    let y_bytes = words_to_bytes_le(&parsed_sk.y, HQC_256.vec_n_size_bytes());

    assert_eq!(
        sha3_hex(&h_bytes),
        "7785d4e009a6984f1d6e7e76f440ff98a7eda0518e1c607853346b2fccd0701d"
    );
    assert_eq!(
        sha3_hex(&s_bytes),
        "e051c5a1e667cb0102236ff5ee9c7df88785c4b64dd497757e3149c6e9588d9a"
    );
    assert_eq!(
        sha3_hex(&x_bytes),
        "97963a92fff2b811064d3f987b69852f40a6e0075fd323405ecfbe2b27b1c45f"
    );
    assert_eq!(
        sha3_hex(&y_bytes),
        "e4db005744c2c85b7d8cbb86ab4eb99f626b9dadf52de64ffae9b3408a75a90f"
    );
    assert_eq!(
        sha3_hex(&parsed_sk.public_key.bytes),
        "455cb8255a152a5727a629dd4bf5848be03f5ffe9dc6d792d2a139b9ebe91679"
    );

    let reconstructed_s = vector_add(
        &parsed_sk.x,
        &cyclic_product_mod_xn_minus_1(&parsed_sk.y, &parsed_pk.h, &HQC_256),
    );
    let reconstructed_s_bytes = words_to_bytes_le(&reconstructed_s, HQC_256.vec_n_size_bytes());
    assert_eq!(
        reconstructed_s_bytes, s_bytes,
        "native HQC-256 syndrome reconstruction mismatch"
    );
}

#[test]
fn test_hqc_keygen_reconstructs_reference_kat_entries() {
    let cases = [
        ("hqc-128/hqc-128_kat.rsp", &HQC_128),
        ("hqc-192/hqc-192_kat.rsp", &HQC_192),
        ("hqc-256/hqc-256_kat.rsp", &HQC_256),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(relative_path, _)| {
            ref_root()
                .join("HQC-Round4-FIPS_207")
                .join("KATs")
                .join("Reference_Implementation")
                .join(relative_path)
        })
        .collect();
    if !ensure_reference_paths("HQC keygen reconstruction KATs", &required_paths) {
        return;
    }

    for (relative_path, params) in cases {
        let path = ref_root()
            .join("HQC-Round4-FIPS_207")
            .join("KATs")
            .join("Reference_Implementation")
            .join(relative_path);
        let entries = parse_rsp_entries(&path);

        for entry in entries {
            let count = field(&entry, "count");
            let pk_bytes = hex_decode(field(&entry, "pk"));
            let sk_bytes = hex_decode(field(&entry, "sk"));

            let mut pk_seed = [0u8; 40];
            pk_seed.copy_from_slice(&pk_bytes[..40]);
            let mut sk_seed = [0u8; 40];
            sk_seed.copy_from_slice(&sk_bytes[..40]);

            let (native_pk, native_sk) = hqc_keygen_from_seeds(&sk_seed, &pk_seed, params)
                .unwrap_or_else(|err| {
                    panic!("{} count={count}: native keygen from seeds failed: {err}", params.alg_name)
                });

            assert_eq!(
                native_pk.bytes, pk_bytes,
                "{} count={count}: pk mismatch",
                params.alg_name
            );
            assert_eq!(
                native_sk.bytes, sk_bytes,
                "{} count={count}: sk mismatch",
                params.alg_name
            );
        }
    }
}

#[test]
fn test_hqc_decapsulates_reference_kat_entries() {
    let cases = [
        ("hqc-128/hqc-128_kat.rsp", &HQC_128),
        ("hqc-192/hqc-192_kat.rsp", &HQC_192),
        ("hqc-256/hqc-256_kat.rsp", &HQC_256),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(relative_path, _)| {
            ref_root()
                .join("HQC-Round4-FIPS_207")
                .join("KATs")
                .join("Reference_Implementation")
                .join(relative_path)
        })
        .collect();
    if !ensure_reference_paths("HQC decapsulation KATs", &required_paths) {
        return;
    }

    for (relative_path, params) in cases {
        let path = ref_root()
            .join("HQC-Round4-FIPS_207")
            .join("KATs")
            .join("Reference_Implementation")
            .join(relative_path);
        let entries = parse_rsp_entries(&path);

        for entry in entries {
            let count = field(&entry, "count");
            let sk = DecapsulationKey {
                bytes: hex_decode(field(&entry, "sk")),
            };
            let ct = Ciphertext {
                bytes: hex_decode(field(&entry, "ct")),
            };
            let expected_ss = hex_decode(field(&entry, "ss"));

            let ss = hqc_decaps(&sk, &ct, params).unwrap_or_else(|err| {
                panic!("{} count={count} decaps failed: {err}", params.alg_name)
            });

            assert_eq!(
                ss.bytes, expected_ss,
                "{} count={count}: shared secret mismatch",
                params.alg_name
            );
        }
    }
}

#[test]
fn test_hqc_public_keygen_api_returns_well_formed_keys() {
    let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);

    let (pk, sk) = tafrah_hqc::hqc_128::keygen(&mut rng).expect("hqc-128 keygen");

    assert_eq!(pk.bytes.len(), HQC_128.pk_bytes);
    assert_eq!(sk.bytes.len(), HQC_128.sk_bytes);

    let parsed_pk = parse_public_key(&pk, &HQC_128).expect("parse generated pk");
    let parsed_sk = parse_secret_key(&sk, &HQC_128).expect("parse generated sk");
    let reconstructed_s = vector_add(
        &parsed_sk.x,
        &cyclic_product_mod_xn_minus_1(&parsed_sk.y, &parsed_pk.h, &HQC_128),
    );

    assert_eq!(
        reconstructed_s, parsed_pk.s,
        "generated syndrome relation mismatch"
    );
    assert_eq!(parsed_sk.public_key.bytes, pk.bytes, "sk should embed pk");
}

#[test]
fn test_hqc_native_roundtrip_all_levels() {
    let mut rng = rand::rngs::StdRng::from_seed([11u8; 32]);

    let (pk128, sk128) = tafrah_hqc::hqc_128::keygen(&mut rng).expect("hqc-128 keygen");
    let (ct128, ss128) =
        tafrah_hqc::hqc_128::encapsulate(&pk128, &mut rng).expect("hqc-128 encaps");
    let ss128_dec = tafrah_hqc::hqc_128::decapsulate(&sk128, &ct128).expect("hqc-128 decaps");
    assert_eq!(
        ss128_dec.bytes, ss128.bytes,
        "HQC-128 shared secret mismatch"
    );

    let (pk192, sk192) = tafrah_hqc::hqc_192::keygen(&mut rng).expect("hqc-192 keygen");
    let (ct192, ss192) =
        tafrah_hqc::hqc_192::encapsulate(&pk192, &mut rng).expect("hqc-192 encaps");
    let ss192_dec = tafrah_hqc::hqc_192::decapsulate(&sk192, &ct192).expect("hqc-192 decaps");
    assert_eq!(
        ss192_dec.bytes, ss192.bytes,
        "HQC-192 shared secret mismatch"
    );

    let (pk256, sk256) = tafrah_hqc::hqc_256::keygen(&mut rng).expect("hqc-256 keygen");
    let (ct256, ss256) =
        tafrah_hqc::hqc_256::encapsulate(&pk256, &mut rng).expect("hqc-256 encaps");
    let ss256_dec = tafrah_hqc::hqc_256::decapsulate(&sk256, &ct256).expect("hqc-256 decaps");
    assert_eq!(
        ss256_dec.bytes, ss256.bytes,
        "HQC-256 shared secret mismatch"
    );
}

#[test]
fn test_hqc_generic_api_rejects_invalid_params() {
    let mut invalid = HQC_128;
    invalid.ct_bytes -= 1;

    let mut rng = rand::rngs::StdRng::from_seed([13u8; 32]);
    let ek = EncapsulationKey {
        bytes: vec![0u8; HQC_128.pk_bytes],
    };
    let dk = DecapsulationKey {
        bytes: vec![0u8; HQC_128.sk_bytes],
    };
    let ct = Ciphertext {
        bytes: vec![0u8; HQC_128.ct_bytes],
    };

    assert!(matches!(
        tafrah_hqc::keygen::hqc_keygen(&mut rng, &invalid),
        Err(Error::InvalidParameter)
    ));
    assert!(matches!(
        tafrah_hqc::encaps::hqc_encaps(&ek, &mut rng, &invalid),
        Err(Error::InvalidParameter)
    ));
    assert!(matches!(
        hqc_decaps(&dk, &ct, &invalid),
        Err(Error::InvalidParameter)
    ));
    assert!(matches!(
        parse_public_key(&ek, &invalid),
        Err(Error::InvalidParameter)
    ));
}

#[test]
fn test_hqc_tampered_ciphertext_zeroes_shared_secret() {
    let mut rng = rand::rngs::StdRng::from_seed([19u8; 32]);
    let (pk, sk) = tafrah_hqc::hqc_128::keygen(&mut rng).expect("keygen");
    let (ct, ss) = tafrah_hqc::hqc_128::encapsulate(&pk, &mut rng).expect("encaps");

    let mut tampered = ct.clone();
    tampered.bytes[0] ^= 0x01;

    let decapped = tafrah_hqc::hqc_128::decapsulate(&sk, &tampered).expect("decaps tampered");
    assert_ne!(
        decapped.bytes, ss.bytes,
        "tampered ciphertext must not recover the original secret"
    );
    assert!(
        decapped.bytes.iter().all(|&byte| byte == 0),
        "tampered ciphertext should zero the shared secret"
    );
}

#[test]
fn test_hqc_shell_rejects_malformed_inputs_without_panicking() {
    let short_ek = EncapsulationKey {
        bytes: vec![0u8; HQC_128.pk_bytes - 1],
    };
    let short_dk = DecapsulationKey {
        bytes: vec![0u8; HQC_128.sk_bytes - 1],
    };
    let short_ct = Ciphertext {
        bytes: vec![0u8; HQC_128.ct_bytes - 1],
    };
    let well_sized_ek = EncapsulationKey {
        bytes: vec![0u8; HQC_128.pk_bytes],
    };
    let well_sized_dk = DecapsulationKey {
        bytes: vec![0u8; HQC_128.sk_bytes],
    };
    let well_sized_ct = Ciphertext {
        bytes: vec![0u8; HQC_128.ct_bytes],
    };
    let mut rng = rand::thread_rng();

    assert!(matches!(
        tafrah_hqc::hqc_128::encapsulate(&short_ek, &mut rng),
        Err(Error::InvalidKeyLength)
    ));
    assert!(matches!(
        tafrah_hqc::hqc_128::decapsulate(&short_dk, &well_sized_ct),
        Err(Error::InvalidKeyLength)
    ));
    assert!(matches!(
        tafrah_hqc::hqc_128::decapsulate(&well_sized_dk, &short_ct),
        Err(Error::InvalidCiphertextLength)
    ));
    let (ct, ss) = tafrah_hqc::hqc_128::encapsulate(&well_sized_ek, &mut rng)
        .expect("well-sized malformed public key should not panic");
    assert_eq!(ct.bytes.len(), HQC_128.ct_bytes);
    assert_eq!(ss.bytes.len(), HQC_128.ss_bytes);

    let ss = tafrah_hqc::hqc_128::decapsulate(&well_sized_dk, &well_sized_ct)
        .expect("well-sized malformed secret key/ciphertext should not panic");
    assert_eq!(ss.bytes.len(), HQC_128.ss_bytes);
}
