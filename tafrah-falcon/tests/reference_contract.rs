#[path = "support/nist_kat_rng.rs"]
mod nist_kat_rng;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

use nist_kat_rng::NistKatDrbg;
use tafrah_falcon::params::{FALCON_1024, FALCON_512};
use tafrah_falcon::types::{Signature, SigningKey, VerifyingKey};
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

fn detached_signature_from_nist_attached(sm: &[u8], msg_len: usize) -> Vec<u8> {
    assert!(sm.len() >= 42 + msg_len, "attached signature too short");

    let encoded_sig_len = ((sm[0] as usize) << 8) | sm[1] as usize;
    assert_eq!(sm.len(), 42 + msg_len + encoded_sig_len);

    let mut detached = Vec::with_capacity(42 + encoded_sig_len);
    detached.extend_from_slice(&sm[..42]);
    detached.extend_from_slice(&sm[(42 + msg_len)..]);
    detached
}

fn nist_attached_signature_from_detached(sig: &[u8], msg: &[u8]) -> Vec<u8> {
    assert!(sig.len() >= 43, "detached signature too short");

    let encoded_sig_len = ((sig[0] as usize) << 8) | sig[1] as usize;
    assert_eq!(sig.len(), 42 + encoded_sig_len);

    let mut attached = Vec::with_capacity(sig.len() + msg.len());
    attached.extend_from_slice(&sig[..42]);
    attached.extend_from_slice(msg);
    attached.extend_from_slice(&sig[42..]);
    attached
}

#[test]
fn test_reference_kat_contracts_match_falcon_sizes() {
    let cases = [
        ("falcon512-KAT.rsp", &FALCON_512),
        ("falcon1024-KAT.rsp", &FALCON_1024),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(file_name, _)| {
            ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name)
        })
        .collect();
    if !ensure_reference_paths("Falcon size-contract KATs", &required_paths) {
        return;
    }

    for (file_name, params) in cases {
        let path = ref_root()
            .join("Falcon-FIPS_206")
            .join("falcon-round3")
            .join("KAT")
            .join(file_name);
        let entries = parse_rsp_entries(&path);

        assert!(
            !entries.is_empty(),
            "{} did not contain any KAT entries",
            path.display()
        );

        for entry in entries {
            let count = field(&entry, "count");
            let msg_len = field(&entry, "mlen").parse::<usize>().unwrap();
            let sm_len = field(&entry, "smlen").parse::<usize>().unwrap();
            let pk_len = hex_len(field(&entry, "pk"));
            let sk_len = hex_len(field(&entry, "sk"));
            let encoded_msg_len = hex_len(field(&entry, "msg"));
            let encoded_sm_len = hex_len(field(&entry, "sm"));

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
                encoded_msg_len, msg_len,
                "{} count={count}: msg encoding length",
                params.alg_name
            );
            assert_eq!(
                encoded_sm_len, sm_len,
                "{} count={count}: sm encoding length",
                params.alg_name
            );

            let sig_len = sm_len - msg_len;
            assert!(
                sig_len > 0 && sig_len <= params.sig_max_bytes,
                "{} count={count}: detached signature length {} outside 1..={}",
                params.alg_name,
                sig_len,
                params.sig_max_bytes
            );
        }
    }
}

#[test]
fn test_reference_falcon_verify_kats() {
    let cases = [
        ("falcon512-KAT.rsp", &FALCON_512),
        ("falcon1024-KAT.rsp", &FALCON_1024),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(file_name, _)| {
            ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name)
        })
        .collect();
    if !ensure_reference_paths("Falcon verify KATs", &required_paths) {
        return;
    }

    for (file_name, params) in cases {
        let path = ref_root()
            .join("Falcon-FIPS_206")
            .join("falcon-round3")
            .join("KAT")
            .join(file_name);
        let entries = parse_rsp_entries(&path);

        for entry in entries {
            let count = field(&entry, "count");
            let msg = hex_decode(field(&entry, "msg"));
            let sm = hex_decode(field(&entry, "sm"));
            let msg_len = field(&entry, "mlen").parse::<usize>().unwrap();
            let vk = VerifyingKey {
                bytes: hex_decode(field(&entry, "pk")),
            };
            let sig = Signature {
                bytes: detached_signature_from_nist_attached(&sm, msg_len),
            };

            tafrah_falcon::verify::falcon_verify(&vk, &msg, &sig, params).unwrap_or_else(|err| {
                panic!(
                    "{} count={count}: verification failed against reference KAT: {err}",
                    params.alg_name
                )
            });
        }
    }
}

#[test]
fn test_reference_falcon_derive_public_from_secret_key() {
    let cases = [
        ("falcon512-KAT.rsp", &FALCON_512),
        ("falcon1024-KAT.rsp", &FALCON_1024),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(file_name, _)| {
            ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name)
        })
        .collect();
    if !ensure_reference_paths("Falcon derive-public KATs", &required_paths) {
        return;
    }

    for (file_name, params) in cases {
        let path = ref_root()
            .join("Falcon-FIPS_206")
            .join("falcon-round3")
            .join("KAT")
            .join(file_name);
        let entries = parse_rsp_entries(&path);

        for entry in entries {
            let count = field(&entry, "count");
            let sk = SigningKey {
                bytes: hex_decode(field(&entry, "sk")),
            };
            let expected = hex_decode(field(&entry, "pk"));
            let derived = match params.log_n {
                9 => tafrah_falcon::falcon_512::derive_verifying_key(&sk),
                10 => tafrah_falcon::falcon_1024::derive_verifying_key(&sk),
                _ => unreachable!(),
            }
            .unwrap_or_else(|err| {
                panic!(
                    "{} count={count}: derive verifying key failed against reference KAT: {err}",
                    params.alg_name
                )
            });

            assert_eq!(
                derived.bytes, expected,
                "{} count={count}: derived public key mismatch",
                params.alg_name
            );
        }
    }
}

#[test]
fn test_reference_falcon_sign_roundtrip_with_reference_keys() {
    let cases = [
        ("falcon512-KAT.rsp", &FALCON_512),
        ("falcon1024-KAT.rsp", &FALCON_1024),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(file_name, _)| {
            ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name)
        })
        .collect();
    if !ensure_reference_paths("Falcon sign-with-reference-key KATs", &required_paths) {
        return;
    }

    for (file_name, params) in cases {
        let path = ref_root()
            .join("Falcon-FIPS_206")
            .join("falcon-round3")
            .join("KAT")
            .join(file_name);
        let entries = parse_rsp_entries(&path);

        for entry in entries.iter().take(2) {
            let count = field(entry, "count");
            let msg = hex_decode(field(entry, "msg"));
            let sk = SigningKey {
                bytes: hex_decode(field(entry, "sk")),
            };
            let vk = VerifyingKey {
                bytes: hex_decode(field(entry, "pk")),
            };
            let mut seed = [0u8; 32];
            seed[0] = params.log_n as u8;
            seed[1] = count.parse::<u8>().unwrap_or(0);
            let mut rng = StdRng::from_seed(seed);

            let sig = match params.log_n {
                9 => tafrah_falcon::falcon_512::sign(&sk, &msg, &mut rng),
                10 => tafrah_falcon::falcon_1024::sign(&sk, &msg, &mut rng),
                _ => unreachable!(),
            }
            .unwrap_or_else(|err| {
                panic!(
                    "{} count={count}: signing failed with reference secret key: {err}",
                    params.alg_name
                )
            });

            assert!(
                sig.bytes.len() <= params.sig_max_bytes,
                "{} count={count}: detached signature exceeds max size",
                params.alg_name
            );
            tafrah_falcon::verify::falcon_verify(&vk, &msg, &sig, params).unwrap_or_else(|err| {
                panic!(
                    "{} count={count}: Rust-signed message failed Falcon verification: {err}",
                    params.alg_name
                )
            });
        }
    }
}

#[test]
fn test_reference_falcon_kat_drbg_matches_reference_oracle() {
    let seed: [u8; 48] =
        hex_decode("64335BF29E5DE62842C941766BA129B0643B5E7121CA26CFC190EC7DC3543830557FDD5C03CF123A456D48EFEA43C868")
            .try_into()
            .expect("seed");
    let expected = hex_decode(
        "4B622DE1350119C45A9F2E2EF3DC5DF50A759D138CDFBD64C81CC7CC2F513345D5A45A4CED06403C5557E87113CB30EA3DC2F39481734DE9E18BCBFBECC6719F137746E7455652AF6FB764833242F064FAAADD993B49FE63BCDFA2C55ED3ECD4E54FBD26F02BF1F560D7D62E4F96A7F3F8413DB578E305B16316D4F4B7BAFDDC72D1256FDA7BEC5F46CAA0539485EC787E77AEE3DA4E57E8B4D961392897F051",
    );
    let mut rng = NistKatDrbg::new(seed);
    let mut actual = vec![0u8; expected.len()];
    rng.fill_bytes(&mut actual);

    assert_eq!(actual, expected, "Falcon KAT DRBG stream mismatch");
}

#[test]
fn test_reference_falcon_deterministic_kat_parity_all_counts() {
    let cases = [
        ("falcon512-KAT.rsp", &FALCON_512),
        ("falcon1024-KAT.rsp", &FALCON_1024),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(file_name, _)| {
            ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name)
        })
        .collect();
    if !ensure_reference_paths("Falcon deterministic parity KATs", &required_paths) {
        return;
    }

    for (file_name, params) in cases {
        let path = ref_root()
            .join("Falcon-FIPS_206")
            .join("falcon-round3")
            .join("KAT")
            .join(file_name);
        let entries = parse_rsp_entries(&path);

        for entry in &entries {
            let count = field(entry, "count");
            let seed: [u8; 48] = hex_decode(field(entry, "seed"))
                .try_into()
                .unwrap_or_else(|_| {
                    panic!("{} count={count}: invalid KAT seed length", params.alg_name)
                });
            let msg = hex_decode(field(entry, "msg"));
            let expected_pk = hex_decode(field(entry, "pk"));
            let expected_sk = hex_decode(field(entry, "sk"));
            let expected_sm = hex_decode(field(entry, "sm"));
            let expected_smlen = field(entry, "smlen").parse::<usize>().unwrap();
            let mut rng = NistKatDrbg::new(seed);

            let (vk, sk) = match params.log_n {
                9 => tafrah_falcon::falcon_512::keygen(&mut rng),
                10 => tafrah_falcon::falcon_1024::keygen(&mut rng),
                _ => unreachable!(),
            }
            .unwrap_or_else(|err| {
                panic!(
                    "{} count={count}: deterministic keygen failed against reference KAT: {err}",
                    params.alg_name
                )
            });

            assert_eq!(
                vk.bytes, expected_pk,
                "{} count={count}: deterministic public key mismatch",
                params.alg_name
            );
            assert_eq!(
                sk.bytes, expected_sk,
                "{} count={count}: deterministic secret key mismatch",
                params.alg_name
            );

            let sig = match params.log_n {
                9 => tafrah_falcon::falcon_512::sign(&sk, &msg, &mut rng),
                10 => tafrah_falcon::falcon_1024::sign(&sk, &msg, &mut rng),
                _ => unreachable!(),
            }
            .unwrap_or_else(|err| {
                panic!(
                    "{} count={count}: deterministic signing failed against reference KAT: {err}",
                    params.alg_name
                )
            });

            let attached = nist_attached_signature_from_detached(&sig.bytes, &msg);
            assert_eq!(
                attached.len(),
                expected_smlen,
                "{} count={count}: deterministic smlen mismatch",
                params.alg_name
            );
            assert_eq!(
                attached, expected_sm,
                "{} count={count}: deterministic attached signature mismatch",
                params.alg_name
            );
        }
    }
}

#[test]
fn test_falcon_shell_rejects_malformed_inputs_without_panicking() {
    let short_vk = VerifyingKey {
        bytes: vec![0u8; FALCON_512.pk_bytes - 1],
    };
    let short_sk = SigningKey {
        bytes: vec![0u8; FALCON_512.sk_bytes - 1],
    };
    let short_sig = Signature {
        bytes: vec![0u8; 42],
    };
    let oversized_sig = Signature {
        bytes: vec![0u8; FALCON_512.sig_max_bytes + 1],
    };
    let well_sized_vk = VerifyingKey {
        bytes: vec![0u8; FALCON_512.pk_bytes],
    };
    let well_sized_sk = SigningKey {
        bytes: vec![0u8; FALCON_512.sk_bytes],
    };
    let malformed_sig = Signature {
        bytes: vec![0x42; 43],
    };
    let mut rng = rand::rng();

    assert!(matches!(
        tafrah_falcon::falcon_512::verify(&short_vk, b"msg", &malformed_sig),
        Err(Error::InvalidKeyLength)
    ));
    assert!(matches!(
        tafrah_falcon::falcon_512::verify(&well_sized_vk, b"msg", &short_sig),
        Err(Error::InvalidSignatureLength)
    ));
    assert!(matches!(
        tafrah_falcon::falcon_512::verify(&well_sized_vk, b"msg", &oversized_sig),
        Err(Error::InvalidSignatureLength)
    ));
    assert!(matches!(
        tafrah_falcon::falcon_512::sign(&short_sk, b"msg", &mut rng),
        Err(Error::InvalidKeyLength)
    ));
    assert!(matches!(
        tafrah_falcon::falcon_512::sign(&well_sized_sk, b"msg", &mut rng),
        Err(Error::DecodingError)
    ));
    assert!(matches!(
        tafrah_falcon::falcon_512::derive_verifying_key(&short_sk),
        Err(Error::InvalidKeyLength)
    ));
    assert!(matches!(
        tafrah_falcon::falcon_512::derive_verifying_key(&well_sized_sk),
        Err(Error::DecodingError)
    ));
    assert!(matches!(
        tafrah_falcon::falcon_512::verify(&well_sized_vk, b"msg", &malformed_sig),
        Err(Error::DecodingError)
    ));
}

#[test]
fn test_falcon_generic_api_rejects_invalid_params() {
    let mut invalid = FALCON_512;
    invalid.sig_max_bytes -= 1;

    let mut rng = rand::rng();
    let dummy_vk = VerifyingKey {
        bytes: vec![0u8; FALCON_512.pk_bytes],
    };
    let dummy_sk = SigningKey {
        bytes: vec![0u8; FALCON_512.sk_bytes],
    };
    let dummy_sig = Signature {
        bytes: vec![0u8; 43],
    };

    assert!(matches!(
        tafrah_falcon::keygen::falcon_keygen(&mut rng, &invalid),
        Err(Error::InvalidParameter)
    ));
    assert!(matches!(
        tafrah_falcon::sign::falcon_sign(&dummy_sk, b"msg", &mut rng, &invalid),
        Err(Error::InvalidParameter)
    ));
    assert!(matches!(
        tafrah_falcon::derive::falcon_derive_verifying_key(&dummy_sk, &invalid),
        Err(Error::InvalidParameter)
    ));
    assert!(matches!(
        tafrah_falcon::verify::falcon_verify(&dummy_vk, b"msg", &dummy_sig, &invalid),
        Err(Error::InvalidParameter)
    ));
}
