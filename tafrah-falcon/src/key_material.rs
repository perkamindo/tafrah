extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::codec::{modq_encode, trim_i8_decode, trim_i8_encode};
use crate::mq::{complete_private_from_small, compute_public_from_small};
use crate::params::Params;
use crate::types::{SigningKey, VerifyingKey};
use tafrah_traits::Error;

#[derive(Zeroize)]
#[zeroize(drop)]
pub(crate) struct DecodedSigningKey {
    pub(crate) f: Vec<i8>,
    pub(crate) g: Vec<i8>,
    pub(crate) capital_f: Vec<i8>,
    pub(crate) capital_g: Vec<i8>,
}

pub(crate) fn decode_signing_key(
    sk_bytes: &[u8],
    params: &Params,
) -> Result<DecodedSigningKey, Error> {
    if sk_bytes.len() != params.sk_bytes {
        return Err(Error::InvalidKeyLength);
    }
    if sk_bytes.first().copied() != Some(params.sk_tag()) {
        return Err(Error::DecodingError);
    }

    let logn = params.log_n;
    let n = 1usize << logn;
    let mut f = vec![0i8; n];
    let mut g = vec![0i8; n];
    let mut capital_f = vec![0i8; n];
    let mut offset = 1usize;

    let used = trim_i8_decode(&mut f, logn, params.fg_bits(), &sk_bytes[offset..])
        .ok_or(Error::DecodingError)?;
    offset += used;
    let used = trim_i8_decode(&mut g, logn, params.fg_bits(), &sk_bytes[offset..])
        .ok_or(Error::DecodingError)?;
    offset += used;
    let used = trim_i8_decode(
        &mut capital_f,
        logn,
        params.capital_fg_bits(),
        &sk_bytes[offset..],
    )
    .ok_or(Error::DecodingError)?;
    offset += used;

    if offset != sk_bytes.len() {
        return Err(Error::DecodingError);
    }

    let capital_g =
        complete_private_from_small(&f, &g, &capital_f, logn).ok_or(Error::DecodingError)?;

    Ok(DecodedSigningKey {
        f,
        g,
        capital_f,
        capital_g,
    })
}

pub(crate) fn decode_and_compute_public(
    sk_bytes: &[u8],
    params: &Params,
) -> Result<Vec<u16>, Error> {
    let decoded = decode_signing_key(sk_bytes, params)?;
    compute_public_from_small(&decoded.f, &decoded.g, params.log_n).ok_or(Error::DecodingError)
}

pub(crate) fn encode_signing_key(
    f: &[i8],
    g: &[i8],
    capital_f: &[i8],
    params: &Params,
) -> Result<SigningKey, Error> {
    let n = 1usize << params.log_n;
    if f.len() != n || g.len() != n || capital_f.len() != n {
        return Err(Error::InvalidKeyLength);
    }

    let encoded_f =
        trim_i8_encode(f, params.log_n, params.fg_bits()).ok_or(Error::DecodingError)?;
    let encoded_g =
        trim_i8_encode(g, params.log_n, params.fg_bits()).ok_or(Error::DecodingError)?;
    let encoded_capital_f = trim_i8_encode(capital_f, params.log_n, params.capital_fg_bits())
        .ok_or(Error::DecodingError)?;

    let mut out = Vec::with_capacity(params.sk_bytes);
    out.push(params.sk_tag());
    out.extend_from_slice(&encoded_f);
    out.extend_from_slice(&encoded_g);
    out.extend_from_slice(&encoded_capital_f);
    if out.len() != params.sk_bytes {
        return Err(Error::DecodingError);
    }

    Ok(SigningKey { bytes: out })
}

pub(crate) fn encode_verifying_key(h: &[u16], params: &Params) -> Result<VerifyingKey, Error> {
    let n = 1usize << params.log_n;
    if h.len() != n {
        return Err(Error::InvalidKeyLength);
    }

    let encoded = modq_encode(h, params.log_n).ok_or(Error::DecodingError)?;
    let mut out = Vec::with_capacity(params.pk_bytes);
    out.push(params.pk_tag());
    out.extend_from_slice(&encoded);
    if out.len() != params.pk_bytes {
        return Err(Error::DecodingError);
    }

    Ok(VerifyingKey { bytes: out })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::borrow::ToOwned;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::string::String;
    use std::vec::Vec;

    use crate::params::{FALCON_1024, FALCON_512};

    use super::{
        decode_and_compute_public, decode_signing_key, encode_signing_key, encode_verifying_key,
    };

    fn ref_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("workspace root")
            .join("ref")
    }

    fn ensure_reference_paths(label: &str, paths: &[PathBuf]) -> bool {
        if let Some(missing) = paths.iter().find(|path| !path.exists()) {
            std::eprintln!("skipping {label}: missing {}", missing.display());
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
                    entries.push(core::mem::take(&mut current));
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

    fn hex_decode(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex string has odd length");
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            let text = std::str::from_utf8(pair).unwrap();
            bytes.push(u8::from_str_radix(text, 16).unwrap());
        }
        bytes
    }

    #[test]
    fn test_reference_key_encodings_roundtrip() {
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
        if !ensure_reference_paths("Falcon key-material KATs", &required_paths) {
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
                let sk_bytes = hex_decode(entry.get("sk").expect("missing sk"));
                let pk_bytes = hex_decode(entry.get("pk").expect("missing pk"));

                let decoded = decode_signing_key(&sk_bytes, params).expect("decode signing key");
                let reencoded_sk =
                    encode_signing_key(&decoded.f, &decoded.g, &decoded.capital_f, params)
                        .expect("re-encode sk");
                assert_eq!(reencoded_sk.bytes, sk_bytes);

                let h = decode_and_compute_public(&sk_bytes, params).expect("compute public");
                let reencoded_pk = encode_verifying_key(&h, params).expect("re-encode pk");
                assert_eq!(reencoded_pk.bytes, pk_bytes);
            }
        }
    }
}
