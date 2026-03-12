use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sha3::digest::{Digest, ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Sha3_512, Shake256};
use tafrah_ml_dsa::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use tafrah_ml_dsa::types::{Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey};
use tafrah_ml_kem::params::{ML_KEM_1024, ML_KEM_512, ML_KEM_768};
use tafrah_ml_kem::types::{Ciphertext, DecapsulationKey};
use tafrah_slh_dsa::params::{
    Params as SlhDsaParams, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S,
};
use tafrah_slh_dsa::types::{Signature as SlhDsaSignature, VerifyingKey as SlhDsaVerifyingKey};

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

fn parse_rsp_entries(path: &Path, max_entries: Option<usize>) -> Vec<BTreeMap<String, String>> {
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
                if max_entries.is_some_and(|limit| entries.len() >= limit) {
                    return entries;
                }
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

    if current.contains_key("count") && max_entries.is_none_or(|limit| entries.len() < limit) {
        entries.push(current);
    }

    entries
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string has odd length");

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let text = std::str::from_utf8(pair).unwrap();
        bytes.push(u8::from_str_radix(text, 16).unwrap());
    }
    bytes
}

fn field<'a>(entry: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    entry
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
        .as_str()
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&dir)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", dir.display()));
    dir
}

fn cc_available() -> bool {
    Command::new("cc").arg("--version").output().is_ok()
}

fn build_dilithium_master_detkat(mode: u8, out_dir: &Path) -> PathBuf {
    let ref_dir = ref_root()
        .join("Dilithium-FIPS_204")
        .join("dilithium")
        .join("dilithium-master")
        .join("ref");
    let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("support")
        .join("dilithium_master_detkat.c");
    let binary = out_dir.join(format!("dilithium_master_detkat_{mode}"));

    let output = Command::new("cc")
        .arg("-O2")
        .arg(format!("-DDILITHIUM_MODE={mode}"))
        .arg(format!("-I{}", ref_dir.display()))
        .arg("-o")
        .arg(&binary)
        .arg(&helper)
        .arg(ref_dir.join("sign.c"))
        .arg(ref_dir.join("packing.c"))
        .arg(ref_dir.join("polyvec.c"))
        .arg(ref_dir.join("poly.c"))
        .arg(ref_dir.join("ntt.c"))
        .arg(ref_dir.join("reduce.c"))
        .arg(ref_dir.join("rounding.c"))
        .arg(ref_dir.join("fips202.c"))
        .arg(ref_dir.join("symmetric-shake.c"))
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn cc for dilithium-master mode {mode}: {err}"));

    assert!(
        output.status.success(),
        "failed to build dilithium-master mode {mode} oracle:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    binary
}

fn build_mlkem_native_detkat(mode: u16, out_dir: &Path) -> PathBuf {
    let ref_dir = ref_root()
        .join("liboqs-main")
        .join("src")
        .join("kem")
        .join("ml_kem")
        .join("mlkem-native_ml-kem-512_ref");
    let helper_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("support");
    let binary = out_dir.join(format!("mlkem_native_detkat_{mode}"));
    let kyber_fips202_dir = ref_root()
        .join("Kyber-FIPS_203")
        .join("Reference_Implementation")
        .join("crypto_kem")
        .join("kyber512");

    let output = Command::new("cc")
        .arg("-O2")
        .arg("-std=c99")
        .arg(format!("-DMLK_CONFIG_PARAMETER_SET={mode}"))
        .arg(format!(
            "-DMLK_CONFIG_FILE=\"{}\"",
            helper_dir.join("mlkem_native_test_config.h").display()
        ))
        .arg(format!("-I{}", helper_dir.display()))
        .arg(format!("-I{}", ref_dir.join("mlkem").join("src").display()))
        .arg(format!("-I{}", kyber_fips202_dir.display()))
        .arg("-o")
        .arg(&binary)
        .arg(helper_dir.join("mlkem_native_detkat.c"))
        .arg(ref_dir.join("mlkem").join("src").join("kem.c"))
        .arg(ref_dir.join("mlkem").join("src").join("indcpa.c"))
        .arg(ref_dir.join("mlkem").join("src").join("poly.c"))
        .arg(ref_dir.join("mlkem").join("src").join("poly_k.c"))
        .arg(ref_dir.join("mlkem").join("src").join("sampling.c"))
        .arg(ref_dir.join("mlkem").join("src").join("compress.c"))
        .arg(ref_dir.join("mlkem").join("src").join("verify.c"))
        .arg(ref_dir.join("mlkem").join("src").join("debug.c"))
        .arg(kyber_fips202_dir.join("fips202.c"))
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn cc for mlkem-native mode {mode}: {err}"));

    assert!(
        output.status.success(),
        "failed to build mlkem-native mode {mode} oracle:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    binary
}

#[test]
fn test_reference_ml_kem_decapsulation_kats() {
    let cases = [
        ("kyber512", "PQCkemKAT_1632.rsp", &ML_KEM_512),
        ("kyber768", "PQCkemKAT_2400.rsp", &ML_KEM_768),
        ("kyber1024", "PQCkemKAT_3168.rsp", &ML_KEM_1024),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(variant, file_name, _)| {
            ref_root()
                .join("Kyber-FIPS_203")
                .join("KAT")
                .join(variant)
                .join(file_name)
        })
        .collect();
    if !ensure_reference_paths("ML-KEM decapsulation KATs", &required_paths) {
        return;
    }

    for (variant, file_name, params) in cases {
        let path = ref_root()
            .join("Kyber-FIPS_203")
            .join("KAT")
            .join(variant)
            .join(file_name);
        let entries = parse_rsp_entries(&path, None);

        for entry in entries {
            let count = field(&entry, "count");
            let dk = DecapsulationKey {
                bytes: hex_decode(field(&entry, "sk")),
            };
            let ct = Ciphertext {
                bytes: hex_decode(field(&entry, "ct")),
            };
            let expected_ss = hex_decode(field(&entry, "ss"));

            let dk_pke = &dk.bytes[..384 * params.k];
            let ek = &dk.bytes[384 * params.k..384 * params.k + params.ek_size()];
            let h_ek = &dk.bytes
                [384 * params.k + params.ek_size()..384 * params.k + params.ek_size() + 32];

            let m_prime = tafrah_ml_kem::decaps::k_pke_decrypt(dk_pke, &ct.bytes, params)
                .unwrap_or_else(|err| panic!("{variant} count={count}: decrypt failed: {err}"));

            let mut g_input = [0u8; 64];
            g_input[..32].copy_from_slice(&m_prime);
            g_input[32..].copy_from_slice(h_ek);
            let g_output = Sha3_512::digest(&g_input);
            let k_prime = &g_output[..32];
            let r_prime: [u8; 32] = g_output[32..64].try_into().unwrap();

            let ct_prime = tafrah_ml_kem::encaps::k_pke_encrypt(ek, &m_prime, &r_prime, params)
                .unwrap_or_else(|err| panic!("{variant} count={count}: re-encrypt failed: {err}"));

            assert_eq!(
                ct_prime.as_slice(),
                ct.bytes.as_slice(),
                "{variant} count={count}: ciphertext mismatch against reference"
            );

            // The bundled Kyber KAT corpus predates FIPS 203 ML-KEM finalization
            // and derives ss as SHAKE256(pre-k || H(c)). Reconstruct that legacy
            // KDF here so we can still validate parity against the local oracle
            // without changing the library's FIPS 203 semantics.
            let h_ct = Sha3_256::digest(&ct.bytes);
            let mut legacy_kdf_input = [0u8; 64];
            legacy_kdf_input[..32].copy_from_slice(k_prime);
            legacy_kdf_input[32..].copy_from_slice(&h_ct);
            let mut legacy_kdf = Shake256::default();
            legacy_kdf.update(&legacy_kdf_input);
            let mut legacy_reader = legacy_kdf.finalize_xof();
            let mut legacy_ss = [0u8; 32];
            legacy_reader.read(&mut legacy_ss);

            assert_eq!(
                legacy_ss.as_slice(),
                expected_ss.as_slice(),
                "{variant} count={count}: legacy Kyber KAT shared secret mismatch"
            );
        }
    }
}

#[test]
fn test_reference_ml_kem_final_oracle_parity() {
    if !cc_available() {
        eprintln!("skipping ML-KEM final oracle parity test: no local cc toolchain");
        return;
    }
    let required_paths = vec![
        ref_root()
            .join("liboqs-main")
            .join("src")
            .join("kem")
            .join("ml_kem")
            .join("mlkem-native_ml-kem-512_ref")
            .join("mlkem")
            .join("src")
            .join("kem.c"),
        ref_root()
            .join("Kyber-FIPS_203")
            .join("Reference_Implementation")
            .join("crypto_kem")
            .join("kyber512")
            .join("fips202.c"),
    ];
    if !ensure_reference_paths("ML-KEM final oracle parity", &required_paths) {
        return;
    }

    let cases = [
        ("ml-kem-512", 512u16, &ML_KEM_512),
        ("ml-kem-768", 768u16, &ML_KEM_768),
        ("ml-kem-1024", 1024u16, &ML_KEM_1024),
    ];

    for (variant, mode, params) in cases {
        let work_dir = unique_temp_dir(&format!("tafrah-mlkem-native-mode{mode}"));
        let binary = build_mlkem_native_detkat(mode, &work_dir);
        let run = Command::new(&binary)
            .current_dir(&work_dir)
            .output()
            .unwrap_or_else(|err| panic!("failed to run {variant} oracle: {err}"));

        assert!(
            run.status.success(),
            "{variant}: oracle failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );

        let rsp_path = work_dir.join(format!("{variant}.rsp"));
        fs::write(&rsp_path, &run.stdout)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", rsp_path.display()));
        let entries = parse_rsp_entries(&rsp_path, None);

        for entry in entries {
            let count = field(&entry, "count");
            let key_seed = hex_decode(field(&entry, "key_seed"));
            let enc_seed = hex_decode(field(&entry, "enc_seed"));
            let expected_pk = hex_decode(field(&entry, "pk"));
            let expected_sk = hex_decode(field(&entry, "sk"));
            let expected_ct = hex_decode(field(&entry, "ct"));
            let expected_ss = hex_decode(field(&entry, "ss"));

            let d: [u8; 32] = key_seed[..32].try_into().unwrap();
            let z = &key_seed[32..];
            let m: [u8; 32] = enc_seed.as_slice().try_into().unwrap();

            let (ek_pke, dk_pke) = tafrah_ml_kem::keygen::k_pke_keygen(&d, params)
                .unwrap_or_else(|err| panic!("{variant} count={count}: keygen failed: {err}"));
            let h_ek = Sha3_256::digest(&ek_pke);

            let mut sk_bytes = dk_pke.clone();
            sk_bytes.extend_from_slice(&ek_pke);
            sk_bytes.extend_from_slice(&h_ek);
            sk_bytes.extend_from_slice(z);

            assert_eq!(
                ek_pke.as_slice(),
                expected_pk.as_slice(),
                "{variant} count={count}: public key mismatch against final oracle"
            );
            assert_eq!(
                sk_bytes.as_slice(),
                expected_sk.as_slice(),
                "{variant} count={count}: secret key mismatch against final oracle"
            );

            let mut g_input = [0u8; 64];
            g_input[..32].copy_from_slice(&m);
            g_input[32..].copy_from_slice(&h_ek);
            let g_output = Sha3_512::digest(&g_input);
            let r: [u8; 32] = g_output[32..64].try_into().unwrap();
            let ct_bytes = tafrah_ml_kem::encaps::k_pke_encrypt(&ek_pke, &m, &r, params)
                .unwrap_or_else(|err| panic!("{variant} count={count}: encaps failed: {err}"));

            assert_eq!(
                ct_bytes.as_slice(),
                expected_ct.as_slice(),
                "{variant} count={count}: ciphertext mismatch against final oracle"
            );
            assert_eq!(
                g_output[..32].as_ref(),
                expected_ss.as_slice(),
                "{variant} count={count}: shared secret mismatch against final oracle"
            );

            let ss = tafrah_ml_kem::decaps::ml_kem_decaps(
                &DecapsulationKey { bytes: sk_bytes },
                &Ciphertext { bytes: ct_bytes },
                params,
            )
            .unwrap_or_else(|err| panic!("{variant} count={count}: decapsulation failed: {err}"));

            assert_eq!(
                ss.bytes.as_slice(),
                expected_ss.as_slice(),
                "{variant} count={count}: decapsulation shared secret mismatch"
            );
        }

        let _ = fs::remove_dir_all(&work_dir);
    }
}

#[test]
fn test_reference_ml_dsa_verify_dilithium_master_kats() {
    if !cc_available() {
        eprintln!("skipping ML-DSA reference oracle test: no local cc toolchain");
        return;
    }
    let required_paths = vec![
        ref_root()
            .join("Dilithium-FIPS_204")
            .join("dilithium")
            .join("dilithium-master")
            .join("ref")
            .join("sign.c"),
        ref_root()
            .join("Dilithium-FIPS_204")
            .join("dilithium")
            .join("dilithium-master")
            .join("ref")
            .join("fips202.c"),
    ];
    if !ensure_reference_paths("ML-DSA reference oracle parity", &required_paths) {
        return;
    }

    let cases = [
        ("ml-dsa-44", 2u8, &ML_DSA_44),
        ("ml-dsa-65", 3u8, &ML_DSA_65),
        ("ml-dsa-87", 5u8, &ML_DSA_87),
    ];

    for (variant, mode, params) in cases {
        let work_dir = unique_temp_dir(&format!("tafrah-dilithium-master-mode{mode}"));
        let binary = build_dilithium_master_detkat(mode, &work_dir);
        let run = Command::new(&binary)
            .current_dir(&work_dir)
            .output()
            .unwrap_or_else(|err| panic!("failed to run {variant} oracle: {err}"));

        assert!(
            run.status.success(),
            "{variant}: oracle failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );

        let rsp_path = work_dir.join(format!("{variant}.rsp"));
        fs::write(&rsp_path, &run.stdout)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", rsp_path.display()));
        let entries = parse_rsp_entries(&rsp_path, None);

        for entry in entries {
            let count = field(&entry, "count");
            let msg = hex_decode(field(&entry, "msg"));
            let sm = hex_decode(field(&entry, "sm"));
            let sig_len = sm.len() - msg.len();
            let sig = MlDsaSignature {
                bytes: sm[..sig_len].to_vec(),
            };
            let vk = MlDsaVerifyingKey {
                bytes: hex_decode(field(&entry, "pk")),
            };

            tafrah_ml_dsa::verify::ml_dsa_verify(&vk, &msg, &sig, params).unwrap_or_else(|err| {
                panic!("{variant} count={count}: verification failed against reference KAT: {err}")
            });
        }

        let _ = fs::remove_dir_all(&work_dir);
    }
}

#[test]
#[ignore = "legacy SPHINCS KAT corpus diverges from current FIPS 205 SHA2 semantics"]
fn test_reference_slh_dsa_verify_kats() {
    let cases: [(&str, &SlhDsaParams); 12] = [
        ("sphincs-sha256-128f-simple", &SLH_DSA_SHA2_128F),
        ("sphincs-sha256-128s-simple", &SLH_DSA_SHA2_128S),
        ("sphincs-sha256-192f-simple", &SLH_DSA_SHA2_192F),
        ("sphincs-sha256-192s-simple", &SLH_DSA_SHA2_192S),
        ("sphincs-sha256-256f-simple", &SLH_DSA_SHA2_256F),
        ("sphincs-sha256-256s-simple", &SLH_DSA_SHA2_256S),
        ("sphincs-shake256-128f-simple", &SLH_DSA_SHAKE_128F),
        ("sphincs-shake256-128s-simple", &SLH_DSA_SHAKE_128S),
        ("sphincs-shake256-192f-simple", &SLH_DSA_SHAKE_192F),
        ("sphincs-shake256-192s-simple", &SLH_DSA_SHAKE_192S),
        ("sphincs-shake256-256f-simple", &SLH_DSA_SHAKE_256F),
        ("sphincs-shake256-256s-simple", &SLH_DSA_SHAKE_256S),
    ];
    let required_paths: Vec<PathBuf> = cases
        .iter()
        .map(|(variant, params)| {
            ref_root()
                .join("SPHINCS-FIPS_205")
                .join("KAT")
                .join(variant)
                .join(format!("PQCsignKAT_{}.rsp", params.n * 4))
        })
        .collect();
    if !ensure_reference_paths("SLH-DSA legacy verify KATs", &required_paths) {
        return;
    }

    for (variant, params) in cases {
        let path = ref_root()
            .join("SPHINCS-FIPS_205")
            .join("KAT")
            .join(variant)
            .join(format!("PQCsignKAT_{}.rsp", params.n * 4));
        let entries = parse_rsp_entries(&path, None);

        for entry in entries {
            let count = field(&entry, "count");
            let msg = hex_decode(field(&entry, "msg"));
            let sm = hex_decode(field(&entry, "sm"));
            let sig_len = sm.len() - msg.len();
            let sig = SlhDsaSignature {
                bytes: sm[..sig_len].to_vec(),
            };
            let vk = SlhDsaVerifyingKey {
                bytes: hex_decode(field(&entry, "pk")),
            };

            tafrah_slh_dsa::verify::slh_dsa_verify(&vk, &msg, &sig, params).unwrap_or_else(|err| {
                panic!("{variant} count={count}: verification failed against reference KAT: {err}")
            });
        }
    }
}
