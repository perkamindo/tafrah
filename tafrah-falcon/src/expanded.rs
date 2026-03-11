extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::fft::{
    fft, poly_add, poly_ldlmv_fft, poly_muladj_fft, poly_mulselfadj_fft, poly_neg, poly_split_fft,
    smallints_to_fpr,
};
use crate::fpr::{fpr_mul, fpr_sqrt, Fpr, GmTable, INV_SIGMA};
use crate::key_material::DecodedSigningKey;

fn ffldl_treesize(logn: usize) -> usize {
    (logn + 1) << logn
}

fn skoff_b00(_logn: usize) -> usize {
    0
}

fn skoff_b01(logn: usize) -> usize {
    1usize << logn
}

fn skoff_b10(logn: usize) -> usize {
    2usize << logn
}

fn skoff_b11(logn: usize) -> usize {
    3usize << logn
}

fn skoff_tree(logn: usize) -> usize {
    4usize << logn
}

fn ffldl_fft_inner(
    tree: &mut [Fpr],
    g0: &mut [Fpr],
    g1: &mut [Fpr],
    logn: usize,
    gm: &GmTable,
    tmp: &mut [Fpr],
) {
    let n = 1usize << logn;
    if n == 1 {
        tree[0] = g0[0];
        return;
    }

    let hn = n >> 1;
    let (tmp_d11, _) = tmp.split_at_mut(n);
    let (tree_head, _) = tree.split_at_mut(n);
    poly_ldlmv_fft(tmp_d11, tree_head, g0, g1, g0, logn);

    let (left_g1, right_g1) = g1.split_at_mut(hn);
    poly_split_fft(left_g1, right_g1, g0, logn, gm);

    let (left_g0, right_g0) = g0.split_at_mut(hn);
    poly_split_fft(left_g0, right_g0, tmp_d11, logn, gm);

    let subtree_len = ffldl_treesize(logn - 1);
    ffldl_fft_inner(
        &mut tree[n..n + subtree_len],
        left_g1,
        right_g1,
        logn - 1,
        gm,
        tmp,
    );
    ffldl_fft_inner(
        &mut tree[n + subtree_len..n + (subtree_len << 1)],
        left_g0,
        right_g0,
        logn - 1,
        gm,
        tmp,
    );
}

fn ffldl_fft(
    tree: &mut [Fpr],
    g00: &[Fpr],
    g01: &[Fpr],
    g11: &[Fpr],
    logn: usize,
    gm: &GmTable,
    tmp: &mut [Fpr],
) {
    let n = 1usize << logn;
    if n == 1 {
        tree[0] = g00[0];
        return;
    }

    let hn = n >> 1;
    let (d00, rest) = tmp.split_at_mut(n);
    let (d11, rest) = rest.split_at_mut(n);
    let (split_tmp, rest) = rest.split_at_mut(n);

    d00.copy_from_slice(g00);
    let (tree_head, _) = tree.split_at_mut(n);
    poly_ldlmv_fft(d11, tree_head, g00, g01, g11, logn);

    let (split_left, split_right) = split_tmp.split_at_mut(hn);
    poly_split_fft(split_left, split_right, d00, logn, gm);
    let (d00_left, d00_right) = d00.split_at_mut(hn);
    poly_split_fft(d00_left, d00_right, d11, logn, gm);
    d11.copy_from_slice(split_tmp);

    let subtree_len = ffldl_treesize(logn - 1);
    let (d11_left, d11_right) = d11.split_at_mut(hn);
    ffldl_fft_inner(
        &mut tree[n..n + subtree_len],
        d11_left,
        d11_right,
        logn - 1,
        gm,
        rest,
    );
    let (d00_left, d00_right) = d00.split_at_mut(hn);
    ffldl_fft_inner(
        &mut tree[n + subtree_len..n + (subtree_len << 1)],
        d00_left,
        d00_right,
        logn - 1,
        gm,
        rest,
    );
}

fn ffldl_binary_normalize(tree: &mut [Fpr], orig_logn: usize, logn: usize) {
    let n = 1usize << logn;
    if n == 1 {
        tree[0] = fpr_mul(fpr_sqrt(tree[0]), INV_SIGMA[orig_logn]);
        return;
    }

    let subtree_len = ffldl_treesize(logn - 1);
    ffldl_binary_normalize(&mut tree[n..n + subtree_len], orig_logn, logn - 1);
    ffldl_binary_normalize(
        &mut tree[n + subtree_len..n + (subtree_len << 1)],
        orig_logn,
        logn - 1,
    );
}

pub(crate) struct ExpandedSigningKey {
    logn: usize,
    data: Vec<Fpr>,
}

impl ExpandedSigningKey {
    pub(crate) fn from_decoded(decoded: &DecodedSigningKey, logn: usize) -> Self {
        let n = 1usize << logn;
        let total_len = skoff_tree(logn) + ffldl_treesize(logn);
        let mut data = vec![0.0; total_len];
        let gm = GmTable::new();

        {
            let (b00, rest): (&mut [Fpr], &mut [Fpr]) = data.split_at_mut(skoff_b01(logn));
            let (b01, rest): (&mut [Fpr], &mut [Fpr]) = rest.split_at_mut(n);
            let (b10, rest): (&mut [Fpr], &mut [Fpr]) = rest.split_at_mut(n);
            let (b11, tree): (&mut [Fpr], &mut [Fpr]) = rest.split_at_mut(n);

            let mut rf = smallints_to_fpr(&decoded.f, logn);
            let mut rg = smallints_to_fpr(&decoded.g, logn);
            let mut r_f = smallints_to_fpr(&decoded.capital_f, logn);
            let mut r_g = smallints_to_fpr(&decoded.capital_g, logn);

            fft(&mut rf, logn, &gm);
            fft(&mut rg, logn, &gm);
            fft(&mut r_f, logn, &gm);
            fft(&mut r_g, logn, &gm);
            poly_neg(&mut rf);
            poly_neg(&mut r_f);

            b00.copy_from_slice(&rg);
            b01.copy_from_slice(&rf);
            b10.copy_from_slice(&r_g);
            b11.copy_from_slice(&r_f);

            let mut g00 = b00.to_vec();
            poly_mulselfadj_fft(&mut g00, logn);
            let mut gxx = b01.to_vec();
            poly_mulselfadj_fft(&mut gxx, logn);
            poly_add(&mut g00, &gxx);

            let mut g01 = b00.to_vec();
            poly_muladj_fft(&mut g01, b10, logn);
            let mut gxx = b01.to_vec();
            poly_muladj_fft(&mut gxx, b11, logn);
            poly_add(&mut g01, &gxx);

            let mut g11 = b10.to_vec();
            poly_mulselfadj_fft(&mut g11, logn);
            let mut gxx = b11.to_vec();
            poly_mulselfadj_fft(&mut gxx, logn);
            poly_add(&mut g11, &gxx);

            let mut tmp = vec![0.0; n << 2];
            ffldl_fft(tree, &g00, &g01, &g11, logn, &gm, &mut tmp);
            ffldl_binary_normalize(tree, logn, logn);
        }

        Self { logn, data }
    }

    pub(crate) fn b00(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[skoff_b00(self.logn)..skoff_b00(self.logn) + n]
    }

    pub(crate) fn b01(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[skoff_b01(self.logn)..skoff_b01(self.logn) + n]
    }

    pub(crate) fn b10(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[skoff_b10(self.logn)..skoff_b10(self.logn) + n]
    }

    pub(crate) fn b11(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[skoff_b11(self.logn)..skoff_b11(self.logn) + n]
    }

    pub(crate) fn tree(&self) -> &[Fpr] {
        &self.data[skoff_tree(self.logn)..]
    }
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

    use crate::fft::ifft;
    use crate::fpr::GmTable;
    use crate::key_material::decode_signing_key;
    use crate::params::{FALCON_1024, FALCON_512};

    use super::{ffldl_treesize, ExpandedSigningKey};

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

    fn approx_eq(lhs: f64, rhs: f64) -> bool {
        (lhs - rhs).abs() <= 1e-9
    }

    fn assert_basis_matches(
        expanded_basis: &[f64],
        expected: &[i8],
        negate: bool,
        gm: &GmTable,
        logn: usize,
    ) {
        let mut coeffs = expanded_basis.to_vec();
        ifft(&mut coeffs, logn, gm);
        for (got, want) in coeffs.iter().zip(expected.iter()) {
            let want = if negate {
                -(*want as f64)
            } else {
                *want as f64
            };
            assert!(approx_eq(*got, want), "{got} != {want}");
        }
    }

    #[test]
    fn test_expanded_key_roundtrips_reference_basis() {
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
        if !ensure_reference_paths("Falcon expanded-key KATs", &required_paths) {
            return;
        }

        for (file_name, params) in cases {
            let path = ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name);
            let entries = parse_rsp_entries(&path);
            let gm = GmTable::new();

            for entry in entries.iter().take(2) {
                let sk = hex_decode(entry.get("sk").expect("missing sk"));
                let decoded = decode_signing_key(&sk, params).expect("decode signing key");
                let expanded = ExpandedSigningKey::from_decoded(&decoded, params.log_n);

                assert_eq!(expanded.tree().len(), ffldl_treesize(params.log_n));
                assert_basis_matches(expanded.b00(), &decoded.g, false, &gm, params.log_n);
                assert_basis_matches(expanded.b01(), &decoded.f, true, &gm, params.log_n);
                assert_basis_matches(expanded.b10(), &decoded.capital_g, false, &gm, params.log_n);
                assert_basis_matches(expanded.b11(), &decoded.capital_f, true, &gm, params.log_n);
            }
        }
    }
}
