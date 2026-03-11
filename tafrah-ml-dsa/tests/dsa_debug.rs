/// Debug test for ML-DSA sign/verify
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use tafrah_math::poly::dsa::Poly;
use tafrah_math::sampling::dsa;
use tafrah_ml_dsa::encode;
use tafrah_ml_dsa::hint;
use tafrah_ml_dsa::keygen::ml_dsa_keygen;
use tafrah_ml_dsa::params::ML_DSA_44;
use tafrah_ml_dsa::sign::ml_dsa_sign;

fn ref_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .join("ref")
}

fn parse_first_rsp_entry(path: &Path) -> BTreeMap<String, String> {
    let content = fs::read_to_string(path).expect("read rsp");
    let mut current = BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() && current.contains_key("count") {
            return current;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(" = ") {
            current.insert(key.to_owned(), value.to_owned());
        }
    }

    current
}

fn hex_decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[test]
fn test_dsa_debug_trace() {
    let params = &ML_DSA_44;
    let mut rng = OsRng;

    let (vk, sk) = ml_dsa_keygen(&mut rng, params).unwrap();
    eprintln!("VK bytes: {}", vk.bytes.len());
    eprintln!("SK bytes: {}", sk.bytes.len());

    let msg = b"test message";
    let sig = ml_dsa_sign(&sk, msg, &mut rng, params).unwrap();
    eprintln!("Sig bytes: {}", sig.bytes.len());

    // Now manually verify step by step
    let k = params.k;
    let l = params.l;
    let alpha = 2 * params.gamma2;

    // Parse VK
    let rho = &vk.bytes[..32];
    let t1_bytes = 320;
    let mut t1: Vec<Poly> = Vec::new();
    for i in 0..k {
        let start = 32 + i * t1_bytes;
        t1.push(encode::unpack_t1(&vk.bytes[start..start + t1_bytes]));
    }

    // Parse signature
    let c_tilde = &sig.bytes[..params.c_tilde_bytes];

    let z_bytes = match params.gamma1_bits {
        17 => 576,
        19 => 640,
        _ => panic!(),
    };

    let mut offset = params.c_tilde_bytes;
    let mut z: Vec<Poly> = Vec::new();
    for _ in 0..l {
        z.push(encode::unpack_z(
            &sig.bytes[offset..offset + z_bytes],
            params.gamma1_bits,
        ));
        offset += z_bytes;
    }

    let hint_vec =
        encode::unpack_hint(&sig.bytes[offset..], k, params.omega).expect("hint unpack failed");

    // Check z norm
    let z_bound = params.gamma1 - params.beta;
    for (i, zi) in z.iter().enumerate() {
        let max_coeff = zi.coeffs.iter().map(|c| c.abs()).max().unwrap();
        eprintln!("z[{}] max abs coeff: {} (bound: {})", i, max_coeff, z_bound);
        assert!(zi.check_norm(z_bound), "z[{}] norm check failed", i);
    }

    // Count hints
    let total_hints: usize = hint_vec
        .iter()
        .map(|h| h.iter().filter(|&&b| b).count())
        .sum();
    eprintln!("Total hints: {} (omega: {})", total_hints, params.omega);

    // Expand A
    let mut a_hat: Vec<Vec<Poly>> = Vec::new();
    for i in 0..k {
        let mut row = Vec::new();
        for j in 0..l {
            let mut seed = Vec::with_capacity(34);
            seed.extend_from_slice(rho);
            seed.push(j as u8);
            seed.push(i as u8);
            row.push(dsa::sample_uniform(&seed));
        }
        a_hat.push(row);
    }

    // tr = H(vk)
    use sha3::digest::{ExtendableOutput, XofReader};
    use sha3::Shake256;

    let mut tr_hasher = Shake256::default();
    sha3::digest::Update::update(&mut tr_hasher, &vk.bytes);
    let mut tr_reader = tr_hasher.finalize_xof();
    let mut tr = [0u8; 64];
    tr_reader.read(&mut tr);

    // mu = H(tr || pre || M) with empty context encoded as 0x00 0x00
    let mut mu_hasher = Shake256::default();
    sha3::digest::Update::update(&mut mu_hasher, &tr);
    sha3::digest::Update::update(&mut mu_hasher, &[0u8, 0u8]);
    sha3::digest::Update::update(&mut mu_hasher, msg);
    let mut mu_reader = mu_hasher.finalize_xof();
    let mut mu = [0u8; 64];
    mu_reader.read(&mut mu);

    // c from SampleInBall
    let mut c = dsa::sample_in_ball(c_tilde, params.tau);
    let c_nonzero: usize = c.coeffs.iter().filter(|&&v| v != 0).count();
    eprintln!(
        "Challenge c nonzero count: {} (expected: {})",
        c_nonzero, params.tau
    );
    c.ntt();

    // NTT(z)
    let mut z_hat: Vec<Poly> = z.clone();
    for p in z_hat.iter_mut() {
        p.ntt();
    }

    // NTT(t1 * 2^d)
    let mut t1_2d_hat: Vec<Poly> = Vec::new();
    for i in 0..k {
        let mut t = Poly::zero();
        for j in 0..256 {
            t.coeffs[j] = t1[i].coeffs[j] << params.d;
        }
        t.ntt();
        t1_2d_hat.push(t);
    }

    // w'_approx = NTT^{-1}(A*z - c*t1*2^d)
    let mut w_approx: Vec<Poly> = Vec::new();
    for i in 0..k {
        let mut wi = Poly::zero();
        for j in 0..l {
            let prod = a_hat[i][j].pointwise_mul(&z_hat[j]);
            wi.add_assign(&prod);
        }
        let ct1 = c.pointwise_mul(&t1_2d_hat[i]);
        wi = wi.sub(&ct1);
        wi.reduce();
        wi.inv_ntt();
        wi.caddq();
        w_approx.push(wi);
    }

    // w'_1 = UseHint(h, w'_approx)
    let mut w1_prime: Vec<Poly> = Vec::new();
    for i in 0..k {
        let mut w1i = Poly::zero();
        for j in 0..256 {
            w1i.coeffs[j] = hint::try_use_hint(hint_vec[i][j], w_approx[i].coeffs[j], alpha)
                .unwrap();
        }
        w1_prime.push(w1i);
    }

    // c'_tilde = H(mu || w1Encode(w'_1))
    let mut c_prime_hasher = Shake256::default();
    sha3::digest::Update::update(&mut c_prime_hasher, &mu);
    for p in &w1_prime {
        let packed = encode::pack_w1(p, params.gamma2);
        sha3::digest::Update::update(&mut c_prime_hasher, &packed);
    }
    let mut c_prime_reader = c_prime_hasher.finalize_xof();
    let mut c_prime_tilde = vec![0u8; params.c_tilde_bytes];
    c_prime_reader.read(&mut c_prime_tilde);

    eprintln!("c_tilde first 8:  {:?}", &c_tilde[..8]);
    eprintln!("c'_tilde first 8: {:?}", &c_prime_tilde[..8]);

    if c_tilde != c_prime_tilde.as_slice() {
        eprintln!("MISMATCH: c_tilde != c'_tilde");

        // Check w1_prime values
        for i in 0..k {
            let max_w1 = w1_prime[i].coeffs.iter().max().unwrap();
            let min_w1 = w1_prime[i].coeffs.iter().min().unwrap();
            eprintln!("w1_prime[{}] range: [{}, {}]", i, min_w1, max_w1);
        }
    } else {
        eprintln!("SUCCESS: c_tilde == c'_tilde");
    }

    assert_eq!(c_tilde, c_prime_tilde.as_slice(), "verification failed");
}

#[test]
#[ignore = "debug trace for Dilithium2 reference alignment"]
fn test_dsa_reference_debug_first_case() {
    let params = &ML_DSA_44;
    let path = ref_root()
        .join("Dilithium-FIPS_204")
        .join("dilithium")
        .join("KAT")
        .join("dilithium2")
        .join("PQCsignKAT_2544.rsp");
    let entry = parse_first_rsp_entry(&path);

    let msg = hex_decode(entry.get("msg").unwrap());
    let pk = hex_decode(entry.get("pk").unwrap());
    let sm = hex_decode(entry.get("sm").unwrap());
    let sig = &sm[..sm.len() - msg.len()];

    let rho = &pk[..32];
    let t1_bytes = 320;
    let mut t1: Vec<Poly> = Vec::new();
    let mut repacked_pk = Vec::with_capacity(pk.len());
    repacked_pk.extend_from_slice(rho);
    for i in 0..params.k {
        let start = 32 + i * t1_bytes;
        let poly = encode::unpack_t1(&pk[start..start + t1_bytes]);
        repacked_pk.extend_from_slice(&encode::pack_t1(&poly));
        t1.push(poly);
    }
    eprintln!("pk roundtrip exact: {}", repacked_pk == pk);

    let c_tilde = &sig[..params.c_tilde_bytes];
    let z_bytes = 576;
    let mut offset = params.c_tilde_bytes;
    let mut z: Vec<Poly> = Vec::new();
    let mut repacked_sig = Vec::with_capacity(sig.len());
    repacked_sig.extend_from_slice(c_tilde);
    for _ in 0..params.l {
        let poly = encode::unpack_z(&sig[offset..offset + z_bytes], params.gamma1_bits);
        repacked_sig.extend_from_slice(&encode::pack_z(&poly, params.gamma1_bits));
        z.push(poly);
        offset += z_bytes;
    }
    let hint_vec = encode::unpack_hint(&sig[offset..], params.k, params.omega).expect("hint");
    repacked_sig.extend_from_slice(&encode::pack_hint(&hint_vec, params.omega));
    eprintln!("sig roundtrip exact: {}", repacked_sig == sig);

    let alpha = 2 * params.gamma2;
    let mut a_hat: Vec<Vec<Poly>> = Vec::new();
    for i in 0..params.k {
        let mut row = Vec::new();
        for j in 0..params.l {
            let mut seed = Vec::with_capacity(34);
            seed.extend_from_slice(rho);
            seed.push(j as u8);
            seed.push(i as u8);
            row.push(dsa::sample_uniform(&seed));
        }
        a_hat.push(row);
    }

    use sha3::digest::{ExtendableOutput, XofReader};
    use sha3::Shake256;

    let mut tr_hasher = Shake256::default();
    sha3::digest::Update::update(&mut tr_hasher, &pk);
    let mut tr_reader = tr_hasher.finalize_xof();
    let mut tr = [0u8; 64];
    tr_reader.read(&mut tr);

    let mut mu_hasher = Shake256::default();
    sha3::digest::Update::update(&mut mu_hasher, &tr);
    sha3::digest::Update::update(&mut mu_hasher, &msg);
    let mut mu_reader = mu_hasher.finalize_xof();
    let mut mu = [0u8; 64];
    mu_reader.read(&mut mu);

    let mut c = dsa::sample_in_ball(c_tilde, params.tau);
    c.ntt();

    let mut z_hat = z.clone();
    for poly in &mut z_hat {
        poly.ntt();
    }

    let mut packed_w1 = Vec::new();
    for i in 0..params.k {
        let mut t = Poly::zero();
        for j in 0..256 {
            t.coeffs[j] = t1[i].coeffs[j] << params.d;
        }
        t.ntt();

        let mut wi = Poly::zero();
        for j in 0..params.l {
            let prod = a_hat[i][j].pointwise_mul(&z_hat[j]);
            wi.add_assign(&prod);
        }
        let ct1 = c.pointwise_mul(&t);
        wi = wi.sub(&ct1);
        wi.reduce();
        wi.inv_ntt();
        wi.caddq();

        let mut w1 = Poly::zero();
        for j in 0..256 {
            w1.coeffs[j] = hint::try_use_hint(hint_vec[i][j], wi.coeffs[j], alpha).unwrap();
        }
        packed_w1.extend_from_slice(&encode::pack_w1(&w1, params.gamma2));
    }

    let mut c_prime_hasher = Shake256::default();
    sha3::digest::Update::update(&mut c_prime_hasher, &mu);
    sha3::digest::Update::update(&mut c_prime_hasher, &packed_w1);
    let mut c_prime_reader = c_prime_hasher.finalize_xof();
    let mut c_prime_tilde = vec![0u8; params.c_tilde_bytes];
    c_prime_reader.read(&mut c_prime_tilde);

    eprintln!("c_tilde[..8]     = {:02x?}", &c_tilde[..8]);
    eprintln!("c_prime_tilde[..8] = {:02x?}", &c_prime_tilde[..8]);
    eprintln!("packed_w1[..12]  = {:02x?}", &packed_w1[..12]);

    assert_eq!(
        c_tilde,
        c_prime_tilde.as_slice(),
        "reference verification failed"
    );
}
