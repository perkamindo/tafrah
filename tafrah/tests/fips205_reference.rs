#[path = "support/nist_kat_rng.rs"]
mod nist_kat_rng;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nist_kat_rng::NistKatDrbg;
use rand_core::Rng;
use tafrah_slh_dsa::keygen::slh_keygen_internal;
use tafrah_slh_dsa::params::{
    HashType, Params, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S,
    SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S,
    SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F, SLH_DSA_SHAKE_256S,
};
use tafrah_slh_dsa::prehash::{hash_slh_sign, hash_slh_verify, PrehashAlgorithm};
use tafrah_slh_dsa::sign::{slh_sign, slh_sign_internal};
use tafrah_slh_dsa::verify::{slh_verify, slh_verify_internal};

fn ref_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .join("ref")
}

fn is_fips205_reference_checkout(path: &Path) -> bool {
    [
        "slh_dsa.c",
        "slh_prehash.c",
        "slh_sha2.c",
        "slh_shake.c",
        "slh_dsa.h",
    ]
    .iter()
    .all(|file| path.join(file).exists())
}

fn discover_reference_checkout(root: &Path) -> Option<PathBuf> {
    if is_fips205_reference_checkout(root) {
        return Some(root.to_path_buf());
    }

    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && is_fips205_reference_checkout(&path) {
            return Some(path);
        }
    }
    None
}

fn fips205_reference_root() -> Option<PathBuf> {
    if let Ok(path) = env::var("SPHINCS_FIPS205_REF") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }

    discover_reference_checkout(Path::new("/tmp"))
        .or_else(|| discover_reference_checkout(&ref_root()))
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

fn hex_encode_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02X}").expect("write to string");
    }
    out
}

fn field<'a>(entry: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    entry
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
        .as_str()
}

fn cc_available() -> bool {
    Command::new("cc").arg("--version").output().is_ok()
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

fn build_fips205_reference_oracle(out_dir: &Path) -> Option<PathBuf> {
    let ref_dir = fips205_reference_root()?;
    let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("support")
        .join("fips205_sphincs_detkat.c");
    let binary = out_dir.join("fips205_sphincs_detkat");

    let output = Command::new("cc")
        .arg("-O2")
        .arg("-std=c99")
        .arg(format!("-I{}", ref_dir.display()))
        .arg("-o")
        .arg(&binary)
        .arg(&helper)
        .arg(ref_dir.join("sha2_256.c"))
        .arg(ref_dir.join("sha2_512.c"))
        .arg(ref_dir.join("sha3_api.c"))
        .arg(ref_dir.join("sha3_f1600.c"))
        .arg(ref_dir.join("slh_dsa.c"))
        .arg(ref_dir.join("slh_prehash.c"))
        .arg(ref_dir.join("slh_sha2.c"))
        .arg(ref_dir.join("slh_shake.c"))
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn cc for FIPS 205 reference oracle: {err}"));

    assert!(
        output.status.success(),
        "failed to build FIPS 205 reference oracle:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Some(binary)
}

fn run_fips205_reference_oracle(
    binary: &Path,
    params: &Params,
    mode: &str,
    seed_material: &[u8],
    msg: &[u8],
    ctx: &[u8],
    addrnd: Option<&[u8]>,
    ph: Option<PrehashAlgorithm>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let output = Command::new(binary)
        .arg(params.alg_id().expect("standard algorithm id"))
        .arg(mode)
        .arg(hex_encode_upper(seed_material))
        .arg(hex_encode_upper(msg))
        .arg(hex_encode_upper(ctx))
        .arg(
            addrnd
                .map(hex_encode_upper)
                .unwrap_or_else(|| "-".to_owned()),
        )
        .arg(ph.map(|ph| ph.identifier()).unwrap_or("-"))
        .output()
        .unwrap_or_else(|err| panic!("failed to execute FIPS 205 reference oracle: {err}"));

    assert!(
        output.status.success(),
        "FIPS 205 reference oracle failed for {} mode {mode}:\nstdout:\n{}\nstderr:\n{}",
        params.alg_id().unwrap_or("unknown"),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("invalid oracle stdout: {err}"));
    let mut lines = stdout.lines();
    (
        hex_decode(lines.next().expect("missing oracle pk")),
        hex_decode(lines.next().expect("missing oracle sk")),
        hex_decode(lines.next().expect("missing oracle sig")),
    )
}

fn kat_cases() -> [(&'static str, &'static Params); 12] {
    [
        ("sphincs-sha256-128s-simple", &SLH_DSA_SHA2_128S),
        ("sphincs-sha256-128f-simple", &SLH_DSA_SHA2_128F),
        ("sphincs-sha256-192s-simple", &SLH_DSA_SHA2_192S),
        ("sphincs-sha256-192f-simple", &SLH_DSA_SHA2_192F),
        ("sphincs-sha256-256s-simple", &SLH_DSA_SHA2_256S),
        ("sphincs-sha256-256f-simple", &SLH_DSA_SHA2_256F),
        ("sphincs-shake256-128s-simple", &SLH_DSA_SHAKE_128S),
        ("sphincs-shake256-128f-simple", &SLH_DSA_SHAKE_128F),
        ("sphincs-shake256-192s-simple", &SLH_DSA_SHAKE_192S),
        ("sphincs-shake256-192f-simple", &SLH_DSA_SHAKE_192F),
        ("sphincs-shake256-256s-simple", &SLH_DSA_SHAKE_256S),
        ("sphincs-shake256-256f-simple", &SLH_DSA_SHAKE_256F),
    ]
}

fn selected_prehash(params: &Params) -> PrehashAlgorithm {
    match params.hash_type {
        HashType::Sha2 => PrehashAlgorithm::Sha2_256,
        HashType::Shake => PrehashAlgorithm::Shake256,
    }
}

fn assert_count0_case_matches_reference(variant: &str, params: &Params, binary: &Path, ctx: &[u8]) {
    let path = ref_root()
        .join("SPHINCS-FIPS_205")
        .join("KAT")
        .join(variant)
        .join(format!("PQCsignKAT_{}.rsp", params.n * 4));
    let entry = parse_rsp_entries(&path, Some(1))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{variant}: missing count=0 entry"));

    let seed: [u8; 48] = hex_decode(field(&entry, "seed"))
        .try_into()
        .unwrap_or_else(|_| panic!("{variant}: invalid KAT seed length"));
    let msg = hex_decode(field(&entry, "msg"));

    let mut kat_rng = NistKatDrbg::new(seed);
    let mut seed_material = vec![0u8; 3 * params.n];
    kat_rng.fill_bytes(&mut seed_material);
    let mut optrand = vec![0u8; params.n];
    kat_rng.fill_bytes(&mut optrand);

    let (oracle_pk, oracle_sk, oracle_internal_sig) = run_fips205_reference_oracle(
        binary,
        params,
        "internal",
        &seed_material,
        &msg,
        &[],
        Some(&optrand),
        None,
    );

    let (vk, sk) = slh_keygen_internal(
        &seed_material[..params.n],
        &seed_material[params.n..2 * params.n],
        &seed_material[2 * params.n..3 * params.n],
        params,
    )
    .unwrap();

    assert_eq!(vk.bytes, oracle_pk, "{variant}: oracle public key mismatch");
    assert_eq!(sk.bytes, oracle_sk, "{variant}: oracle secret key mismatch");

    let internal_sig = slh_sign_internal(&sk, &msg, Some(&optrand), params).unwrap();
    let fors_len = params.k * (1 + params.a) * params.n;
    assert_eq!(
        &internal_sig.bytes[..params.n],
        &oracle_internal_sig[..params.n],
        "{variant}: internal R mismatch vs FIPS 205 reference"
    );
    assert_eq!(
        &internal_sig.bytes[params.n..params.n + fors_len],
        &oracle_internal_sig[params.n..params.n + fors_len],
        "{variant}: internal FORS mismatch vs FIPS 205 reference"
    );
    assert_eq!(
        &internal_sig.bytes[params.n + fors_len..],
        &oracle_internal_sig[params.n + fors_len..],
        "{variant}: internal HT mismatch vs FIPS 205 reference"
    );
    assert_eq!(
        internal_sig.bytes, oracle_internal_sig,
        "{variant}: internal signature mismatch vs FIPS 205 reference"
    );
    slh_verify_internal(&vk, &msg, &internal_sig, params).unwrap();

    let (_, _, oracle_pure_sig) = run_fips205_reference_oracle(
        binary,
        params,
        "pure",
        &seed_material,
        &msg,
        ctx,
        Some(&optrand),
        None,
    );
    let pure_sig = slh_sign(&sk, &msg, ctx, Some(&optrand), params).unwrap();
    assert_eq!(
        &pure_sig.bytes[..params.n],
        &oracle_pure_sig[..params.n],
        "{variant}: pure R mismatch vs FIPS 205 reference"
    );
    assert_eq!(
        pure_sig.bytes, oracle_pure_sig,
        "{variant}: pure signature mismatch vs FIPS 205 reference"
    );
    slh_verify(&vk, &msg, &pure_sig, ctx, params).unwrap();

    let prehash = selected_prehash(params);
    let (_, _, oracle_prehash_sig) = run_fips205_reference_oracle(
        binary,
        params,
        "prehash",
        &seed_material,
        &msg,
        ctx,
        Some(&optrand),
        Some(prehash),
    );
    let prehash_sig = hash_slh_sign(&sk, &msg, ctx, prehash, Some(&optrand), params).unwrap();
    assert_eq!(
        &prehash_sig.bytes[..params.n],
        &oracle_prehash_sig[..params.n],
        "{variant}: prehash R mismatch vs FIPS 205 reference"
    );
    assert_eq!(
        prehash_sig.bytes, oracle_prehash_sig,
        "{variant}: prehash signature mismatch vs FIPS 205 reference"
    );
    hash_slh_verify(&vk, &msg, &prehash_sig, ctx, prehash, params).unwrap();
}

#[test]
fn test_fips205_sha256_128s_count0_regression() {
    if !cc_available() {
        return;
    }
    let reference_root = match fips205_reference_root() {
        Some(root) => root,
        None => {
            eprintln!("skipping FIPS 205 reference parity: missing SPHINCS+ reference checkout");
            return;
        }
    };
    let required_paths = [
        ref_root()
            .join("SPHINCS-FIPS_205")
            .join("KAT")
            .join("sphincs-sha256-128s-simple")
            .join("PQCsignKAT_64.rsp"),
        reference_root.join("slh_dsa.c"),
        reference_root.join("slh_prehash.c"),
        reference_root.join("slh_sha2.c"),
        reference_root.join("slh_shake.c"),
    ];
    if let Some(missing) = required_paths.iter().find(|path| !path.exists()) {
        eprintln!(
            "skipping FIPS 205 reference parity: missing {}",
            missing.display()
        );
        return;
    }

    let work_dir = unique_temp_dir("tafrah-fips205-regression");
    let binary = build_fips205_reference_oracle(&work_dir).expect("reference root already checked");
    assert_count0_case_matches_reference(
        "sphincs-sha256-128s-simple",
        &SLH_DSA_SHA2_128S,
        &binary,
        b"tafrah-pure",
    );
    let _ = fs::remove_dir_all(&work_dir);
}

#[test]
fn test_fips205_count0_all_param_sets_internal_pure_and_prehash() {
    if !cc_available() {
        return;
    }
    let reference_root = match fips205_reference_root() {
        Some(root) => root,
        None => {
            eprintln!("skipping FIPS 205 reference parity: missing SPHINCS+ reference checkout");
            return;
        }
    };
    let mut required_paths: Vec<PathBuf> = kat_cases()
        .iter()
        .map(|(variant, params)| {
            ref_root()
                .join("SPHINCS-FIPS_205")
                .join("KAT")
                .join(variant)
                .join(format!("PQCsignKAT_{}.rsp", params.n * 4))
        })
        .collect();
    required_paths.extend([
        reference_root.join("slh_dsa.c"),
        reference_root.join("slh_prehash.c"),
        reference_root.join("slh_sha2.c"),
        reference_root.join("slh_shake.c"),
    ]);
    if let Some(missing) = required_paths.iter().find(|path| !path.exists()) {
        eprintln!(
            "skipping FIPS 205 reference parity: missing {}",
            missing.display()
        );
        return;
    }

    let work_dir = unique_temp_dir("tafrah-fips205");
    let binary = build_fips205_reference_oracle(&work_dir).expect("reference root already checked");
    let ctx = b"tafrah-pure";

    for (variant, params) in kat_cases() {
        assert_count0_case_matches_reference(variant, params, &binary, ctx);
    }

    let _ = fs::remove_dir_all(&work_dir);
}

#[test]
fn test_fips205_prehash_reference_all_algorithms() {
    if !cc_available() {
        return;
    }
    if fips205_reference_root().is_none() {
        eprintln!("skipping FIPS 205 prehash parity: missing SPHINCS+ reference checkout");
        return;
    }

    let params = SLH_DSA_SHAKE_128F;
    let work_dir = unique_temp_dir("tafrah-fips205-prehash");
    let binary = build_fips205_reference_oracle(&work_dir).expect("reference root already checked");
    let ctx = b"tafrah-prehash";
    let msg = b"HashSLH-DSA oracle parity";
    let n = params.n;
    let seed_material: Vec<u8> = (0..(3 * n)).map(|i| (i as u8).wrapping_mul(29)).collect();
    let optrand = vec![0x5A; n];
    let (vk, sk) = slh_keygen_internal(
        &seed_material[..n],
        &seed_material[n..2 * n],
        &seed_material[2 * n..3 * n],
        &params,
    )
    .unwrap();

    let algorithms = [
        PrehashAlgorithm::Sha2_224,
        PrehashAlgorithm::Sha2_256,
        PrehashAlgorithm::Sha2_384,
        PrehashAlgorithm::Sha2_512,
        PrehashAlgorithm::Sha2_512_224,
        PrehashAlgorithm::Sha2_512_256,
        PrehashAlgorithm::Sha3_224,
        PrehashAlgorithm::Sha3_256,
        PrehashAlgorithm::Sha3_384,
        PrehashAlgorithm::Sha3_512,
        PrehashAlgorithm::Shake128,
        PrehashAlgorithm::Shake256,
    ];

    for algorithm in algorithms {
        let (oracle_pk, oracle_sk, oracle_sig) = run_fips205_reference_oracle(
            &binary,
            &params,
            "prehash",
            &seed_material,
            msg,
            ctx,
            Some(&optrand),
            Some(algorithm),
        );
        assert_eq!(
            oracle_pk,
            vk.bytes,
            "{}: oracle pk drift",
            algorithm.identifier()
        );
        assert_eq!(
            oracle_sk,
            sk.bytes,
            "{}: oracle sk drift",
            algorithm.identifier()
        );

        let sig = hash_slh_sign(&sk, msg, ctx, algorithm, Some(&optrand), &params).unwrap();
        assert_eq!(
            sig.bytes,
            oracle_sig,
            "{}: prehash mismatch",
            algorithm.identifier()
        );
        hash_slh_verify(&vk, msg, &sig, ctx, algorithm, &params).unwrap();
    }

    let _ = fs::remove_dir_all(&work_dir);
}

#[test]
#[ignore = "deep FIPS 205 parity audit; expensive"]
fn test_fips205_selected_deep_counts() {
    if !cc_available() {
        return;
    }
    let reference_root = match fips205_reference_root() {
        Some(root) => root,
        None => {
            eprintln!("skipping deep FIPS 205 parity: missing SPHINCS+ reference checkout");
            return;
        }
    };
    if !reference_root.join("slh_dsa.c").exists() {
        return;
    }

    let cases = [
        ("sphincs-sha256-128f-simple", &SLH_DSA_SHA2_128F),
        ("sphincs-sha256-256s-simple", &SLH_DSA_SHA2_256S),
        ("sphincs-shake256-128f-simple", &SLH_DSA_SHAKE_128F),
        ("sphincs-shake256-256s-simple", &SLH_DSA_SHAKE_256S),
    ];
    let counts = ["0", "99"];
    let ctx = b"tafrah-deep";
    let work_dir = unique_temp_dir("tafrah-fips205-deep");
    let binary = build_fips205_reference_oracle(&work_dir).expect("reference root already checked");

    for (variant, params) in cases {
        let path = ref_root()
            .join("SPHINCS-FIPS_205")
            .join("KAT")
            .join(variant)
            .join(format!("PQCsignKAT_{}.rsp", params.n * 4));
        let entries = parse_rsp_entries(&path, None);

        for target_count in counts {
            let entry = entries
                .iter()
                .find(|entry| field(entry, "count") == target_count)
                .unwrap_or_else(|| panic!("{variant}: missing count={target_count} entry"));

            let seed: [u8; 48] = hex_decode(field(entry, "seed"))
                .try_into()
                .unwrap_or_else(|_| {
                    panic!("{variant} count={target_count}: invalid KAT seed length")
                });
            let msg = hex_decode(field(entry, "msg"));

            let mut kat_rng = NistKatDrbg::new(seed);
            let mut seed_material = vec![0u8; 3 * params.n];
            kat_rng.fill_bytes(&mut seed_material);
            let mut optrand = vec![0u8; params.n];
            kat_rng.fill_bytes(&mut optrand);

            let (vk, sk) = slh_keygen_internal(
                &seed_material[..params.n],
                &seed_material[params.n..2 * params.n],
                &seed_material[2 * params.n..3 * params.n],
                params,
            )
            .unwrap();

            for (mode, prehash) in [
                ("internal", None),
                ("pure", None),
                ("prehash", Some(selected_prehash(params))),
            ] {
                let (_, _, oracle_sig) = run_fips205_reference_oracle(
                    &binary,
                    params,
                    mode,
                    &seed_material,
                    &msg,
                    ctx,
                    Some(&optrand),
                    prehash,
                );
                let rust_sig = match mode {
                    "internal" => slh_sign_internal(&sk, &msg, Some(&optrand), params).unwrap(),
                    "pure" => slh_sign(&sk, &msg, ctx, Some(&optrand), params).unwrap(),
                    "prehash" => {
                        hash_slh_sign(&sk, &msg, ctx, prehash.unwrap(), Some(&optrand), params)
                            .unwrap()
                    }
                    _ => unreachable!(),
                };
                assert_eq!(
                    rust_sig.bytes, oracle_sig,
                    "{variant} count={target_count}: {mode} mismatch vs FIPS 205 reference"
                );
            }

            slh_verify_internal(
                &vk,
                &msg,
                &slh_sign_internal(&sk, &msg, Some(&optrand), params).unwrap(),
                params,
            )
            .unwrap();
        }
    }

    let _ = fs::remove_dir_all(&work_dir);
}
