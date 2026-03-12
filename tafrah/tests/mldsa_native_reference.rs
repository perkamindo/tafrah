use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use tafrah_ml_dsa::keygen::ml_dsa_keygen_internal;
use tafrah_ml_dsa::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87, Params};
use tafrah_ml_dsa::prehash::{shake256_prehash, PreHashAlgorithm};
use tafrah_ml_dsa::sign::{
    ml_dsa_sign_internal, ml_dsa_sign_prehash_internal, ML_DSA_RNDBYTES,
};
use tafrah_ml_dsa::types::{Signature, SignedMessage};
use tafrah_ml_dsa::verify::{ml_dsa_open_signed_message_with_context, ml_dsa_verify_with_context};

const SELECTED_DEEP_COUNTS: &[u32] = &[0, 1, 2, 7, 15, 31, 63, 99];

fn maybe_mldsa_native_root() -> Option<PathBuf> {
    if let Ok(dir) = env::var("MLDSA_NATIVE_DIR") {
        let path = PathBuf::from(dir);
        if path.join("mldsa").join("mldsa_native.c").exists() {
            return Some(path);
        }
    }

    let candidates = [
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("workspace root")
            .join("ref")
            .join("mldsa-native"),
        PathBuf::from("/tmp/mldsa-native-audit"),
    ];

    candidates.into_iter().find(|path| path.join("mldsa").join("mldsa_native.c").exists())
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
        if let Some((key, value)) = line.split_once('=') {
            current.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    if current.contains_key("count") {
        entries.push(current);
    }
    entries
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

fn field<'a>(entry: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    entry
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
        .as_str()
}

fn build_mldsa_native_oracle(mode: u8, out_dir: &Path, repo_root: &Path) -> PathBuf {
    let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("support")
        .join("mldsa_native_detkat.c");
    let binary = out_dir.join(format!("mldsa_native_detkat_{mode}"));

    let output = Command::new("cc")
        .arg("-O2")
        .arg("-std=c99")
        .arg(format!("-DMLD_CONFIG_PARAMETER_SET={mode}"))
        .arg("-DMLD_CONFIG_NAMESPACE_PREFIX=mldsa")
        .arg("-DMLD_CONFIG_NO_RANDOMIZED_API")
        .arg(format!("-I{}", repo_root.join("mldsa").display()))
        .arg("-o")
        .arg(&binary)
        .arg(&helper)
        .arg(repo_root.join("mldsa").join("mldsa_native.c"))
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn cc for mldsa-native mode {mode}: {err}"));

    assert!(
        output.status.success(),
        "failed to build mldsa-native mode {mode} oracle:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    binary
}

fn run_mldsa_native_oracle(
    binary: &Path,
    work_dir: &Path,
    counts: &[u32],
) -> std::process::Output {
    let mut command = Command::new(binary);
    command.current_dir(work_dir);
    for count in counts {
        command.arg(count.to_string());
    }
    command
        .output()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", binary.display()))
}

fn params_for_mode(mode: u8) -> &'static Params {
    match mode {
        44 => &ML_DSA_44,
        65 => &ML_DSA_65,
        87 => &ML_DSA_87,
        _ => panic!("unsupported ML-DSA mode {mode}"),
    }
}

fn assert_mldsa_native_feature_parity(counts: &[u32]) {
    let Some(repo_root) = maybe_mldsa_native_root() else {
        eprintln!("skipping mldsa-native parity test: missing repository checkout");
        return;
    };

    let cases = [44u8, 65u8, 87u8];
    for mode in cases {
        let params = params_for_mode(mode);
        let work_dir = unique_temp_dir(&format!("tafrah-mldsa-native-mode{mode}"));
        let binary = build_mldsa_native_oracle(mode, &work_dir, &repo_root);
        let run = run_mldsa_native_oracle(&binary, &work_dir, counts);

        assert!(
            run.status.success(),
            "ML-DSA mode {mode}: oracle failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );

        let rsp_path = work_dir.join(format!("ml-dsa-{mode}.rsp"));
        fs::write(&rsp_path, &run.stdout)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", rsp_path.display()));
        let entries = parse_rsp_entries(&rsp_path);

        for entry in entries {
            let count = field(&entry, "count");
            let seed: [u8; 32] = hex_decode(field(&entry, "seed")).try_into().unwrap();
            let rnd: [u8; ML_DSA_RNDBYTES] = hex_decode(field(&entry, "rnd")).try_into().unwrap();
            let ctx = hex_decode(field(&entry, "ctx"));
            let msg = hex_decode(field(&entry, "msg"));
            let mu: [u8; 64] = hex_decode(field(&entry, "mu")).try_into().unwrap();
            let ph_sha2_256 = hex_decode(field(&entry, "ph_sha2_256"));
            let expected_pk = hex_decode(field(&entry, "pk"));
            let expected_sk = hex_decode(field(&entry, "sk"));
            let expected_sig_pure = hex_decode(field(&entry, "sig_pure"));
            let expected_sig_extmu = hex_decode(field(&entry, "sig_extmu"));
            let expected_sig_prehash_sha2_256 = hex_decode(field(&entry, "sig_prehash_sha2_256"));
            let expected_sig_prehash_shake256 = hex_decode(field(&entry, "sig_prehash_shake256"));

            let (vk, sk) = ml_dsa_keygen_internal(&seed, params)
                .unwrap_or_else(|err| panic!("mode {mode} count={count}: keygen failed: {err}"));

            assert_eq!(
                vk.as_bytes(),
                expected_pk.as_slice(),
                "mode {mode} count={count}: public key mismatch"
            );
            assert_eq!(
                sk.as_bytes(),
                expected_sk.as_slice(),
                "mode {mode} count={count}: secret key mismatch"
            );

            let mut pure_prefix = vec![0u8; 2 + ctx.len()];
            pure_prefix[1] = ctx.len() as u8;
            pure_prefix[2..].copy_from_slice(&ctx);

            let pure_sig = ml_dsa_sign_internal(&sk, &msg, &pure_prefix, &rnd, false, params)
                .unwrap_or_else(|err| panic!("mode {mode} count={count}: pure sign failed: {err}"));
            assert_eq!(
                pure_sig.as_bytes(),
                expected_sig_pure.as_slice(),
                "mode {mode} count={count}: pure signature mismatch"
            );
            ml_dsa_verify_with_context(&vk, &msg, &pure_sig, &ctx, params)
                .unwrap_or_else(|err| panic!("mode {mode} count={count}: pure verify failed: {err}"));

            let extmu_sig = ml_dsa_sign_internal(&sk, &mu, &[], &rnd, true, params)
                .unwrap_or_else(|err| panic!("mode {mode} count={count}: extmu sign failed: {err}"));
            assert_eq!(
                extmu_sig.as_bytes(),
                expected_sig_extmu.as_slice(),
                "mode {mode} count={count}: extmu signature mismatch"
            );
            ml_dsa_sign_internal(&sk, &mu, &[], &rnd, true, params)
                .unwrap_or_else(|err| panic!("mode {mode} count={count}: extmu internal retry failed: {err}"));
            tafrah_ml_dsa::verify::ml_dsa_verify_extmu(&vk, &mu, &extmu_sig, params)
                .unwrap_or_else(|err| panic!("mode {mode} count={count}: extmu verify failed: {err}"));

            let prehash_sig = ml_dsa_sign_prehash_internal(
                &sk,
                &ph_sha2_256,
                &ctx,
                &rnd,
                PreHashAlgorithm::Sha2_256,
                params,
            )
            .unwrap_or_else(|err| panic!("mode {mode} count={count}: prehash sign failed: {err}"));
            assert_eq!(
                prehash_sig.as_bytes(),
                expected_sig_prehash_sha2_256.as_slice(),
                "mode {mode} count={count}: prehash signature mismatch"
            );
            tafrah_ml_dsa::verify::ml_dsa_verify_prehash(
                &vk,
                &ph_sha2_256,
                &prehash_sig,
                &ctx,
                PreHashAlgorithm::Sha2_256,
                params,
            )
            .unwrap_or_else(|err| panic!("mode {mode} count={count}: prehash verify failed: {err}"));

            let shake_digest = shake256_prehash(&msg);
            let shake_sig = ml_dsa_sign_prehash_internal(
                &sk,
                &shake_digest,
                &ctx,
                &rnd,
                PreHashAlgorithm::Shake256,
                params,
            )
            .unwrap_or_else(|err| panic!("mode {mode} count={count}: shake256 prehash sign failed: {err}"));
            assert_eq!(
                shake_sig.as_bytes(),
                expected_sig_prehash_shake256.as_slice(),
                "mode {mode} count={count}: shake256 prehash signature mismatch"
            );
            tafrah_ml_dsa::verify::ml_dsa_verify_prehash_shake256(&vk, &msg, &shake_sig, &ctx, params).unwrap_or_else(
                |err| panic!("mode {mode} count={count}: shake256 prehash verify failed: {err}"),
            );

            let mut signed_bytes = pure_sig.as_bytes().to_vec();
            signed_bytes.extend_from_slice(&msg);
            let signed = SignedMessage { bytes: signed_bytes };
            assert_eq!(
                &signed.as_bytes()[..params.sig_size()],
                expected_sig_pure.as_slice(),
                "mode {mode} count={count}: signed-message signature prefix mismatch"
            );
            assert_eq!(
                &signed.as_bytes()[params.sig_size()..],
                msg.as_slice(),
                "mode {mode} count={count}: signed-message payload mismatch"
            );

            let opened = ml_dsa_open_signed_message_with_context(&vk, &signed, &ctx, params)
                .unwrap_or_else(|err| panic!("mode {mode} count={count}: open failed: {err}"));
            assert_eq!(
                opened.as_slice(),
                msg.as_slice(),
                "mode {mode} count={count}: opened message mismatch"
            );

            let helper_sig = Signature {
                bytes: expected_sig_pure.clone(),
            };
            ml_dsa_verify_with_context(&vk, &msg, &helper_sig, &ctx, params).unwrap();
        }

        let _ = fs::remove_dir_all(&work_dir);
    }
}

#[test]
fn test_mldsa_native_feature_parity_selected_deep_counts() {
    assert_mldsa_native_feature_parity(SELECTED_DEEP_COUNTS);
}

#[test]
#[ignore = "deep ML-DSA parity audit across all deterministic oracle counts"]
fn test_mldsa_native_feature_parity_all_counts() {
    let counts: Vec<u32> = (0..100).collect();
    assert_mldsa_native_feature_parity(&counts);
}
