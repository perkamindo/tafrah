use tafrah_ml_kem::decaps::k_pke_decrypt;
use tafrah_ml_kem::encaps::k_pke_encrypt;
use tafrah_ml_kem::encode;
/// Debug test for K-PKE encrypt/decrypt
use tafrah_ml_kem::keygen::k_pke_keygen;
use tafrah_ml_kem::params::ML_KEM_512;

use tafrah_math::compress;
use tafrah_math::field::kem as field;
use tafrah_math::poly::kem::Poly;

/// Schoolbook multiplication in Zq[X]/(X^256+1)
fn schoolbook_mul(a: &Poly, b: &Poly) -> Poly {
    let q = 3329i32;
    let mut result = [0i64; 256];
    for i in 0..256 {
        for j in 0..256 {
            let idx = i + j;
            let prod = a.coeffs[i] as i64 * b.coeffs[j] as i64;
            if idx < 256 {
                result[idx] += prod;
            } else {
                result[idx - 256] -= prod;
            }
        }
    }
    let mut out = Poly::zero();
    for i in 0..256 {
        out.coeffs[i] = ((result[i] % q as i64 + q as i64) % q as i64) as i16;
    }
    out
}

/// Verify the full encrypt/decrypt flow by manually tracing through
#[test]
fn test_kpke_manual_trace() {
    let params = &ML_KEM_512;
    let k = params.k;

    // Use deterministic seed
    let d = [7u8; 32];
    let (ek_bytes, dk_bytes) = k_pke_keygen(&d, params).unwrap();

    // Zero message should decrypt to zero
    let m_zero = [0u8; 32];
    let r = [0x42u8; 32];
    let ct = k_pke_encrypt(&ek_bytes, &m_zero, &r, params).unwrap();
    let m_recovered = k_pke_decrypt(&dk_bytes, &ct, params).unwrap();

    eprintln!("Zero message test:");
    let diff_count = m_zero
        .iter()
        .zip(m_recovered.iter())
        .filter(|(a, b)| a != b)
        .count();
    eprintln!("  Differing bytes: {}/32", diff_count);
    if diff_count > 0 {
        eprintln!("  First 8 bytes recovered: {:?}", &m_recovered[..8]);
    }

    // All-ones message
    let m_ones = [0xFFu8; 32];
    let ct = k_pke_encrypt(&ek_bytes, &m_ones, &r, params).unwrap();
    let m_recovered = k_pke_decrypt(&dk_bytes, &ct, params).unwrap();

    eprintln!("Ones message test:");
    let diff_count = m_ones
        .iter()
        .zip(m_recovered.iter())
        .filter(|(a, b)| a != b)
        .count();
    eprintln!("  Differing bytes: {}/32", diff_count);

    // Now verify the encrypt/decrypt at each step
    // Parse the keys
    let t_hat = encode::decode_poly_vec(&ek_bytes[..384 * k], k);
    let rho: [u8; 32] = ek_bytes[384 * k..384 * k + 32].try_into().unwrap();
    let s_hat = encode::decode_poly_vec(&dk_bytes, k);

    // Get s and e in time domain for verification
    let mut s_time = Vec::new();
    for j in 0..k {
        let mut sj = s_hat[j].clone();
        sj.inv_ntt();
        for i in 0..256 {
            sj.coeffs[i] = field::fqmul(sj.coeffs[i], 1);
        }
        sj.reduce();
        s_time.push(sj);
    }

    // Verify: s should have small coefficients (CBD with eta=3)
    let s_max = s_time
        .iter()
        .flat_map(|p| p.coeffs.iter())
        .map(|&c| {
            let c = if c > 3329 / 2 { c - 3329 } else { c };
            c.abs()
        })
        .max()
        .unwrap();
    eprintln!("Max |s| coefficient: {} (should be <= 3)", s_max);

    // Reconstruct A
    let mut a_hat: Vec<Vec<Poly>> = Vec::new();
    for i in 0..k {
        let mut row = Vec::new();
        for j in 0..k {
            let seed = tafrah_math::sampling::kem::xof_seed(&rho, i as u8, j as u8);
            row.push(tafrah_math::sampling::kem::sample_ntt(&seed));
        }
        a_hat.push(row);
    }

    // Get t in time domain for verification
    let mut t_time = Vec::new();
    for j in 0..k {
        let mut tj = t_hat[j].clone();
        tj.inv_ntt();
        for i in 0..256 {
            tj.coeffs[i] = field::fqmul(tj.coeffs[i], 1);
        }
        tj.reduce();
        t_time.push(tj);
    }

    // Get A in time domain
    let mut a_time: Vec<Vec<Poly>> = Vec::new();
    for i in 0..k {
        let mut row = Vec::new();
        for j in 0..k {
            let mut aij = a_hat[i][j].clone();
            aij.inv_ntt();
            for c in 0..256 {
                aij.coeffs[c] = field::fqmul(aij.coeffs[c], 1);
            }
            aij.reduce();
            row.push(aij);
        }
        a_time.push(row);
    }

    // Verify t = A*s + e by checking t - A*s is small
    for i in 0..k {
        let mut as_i = Poly::zero();
        for j in 0..k {
            let prod = schoolbook_mul(&a_time[i][j], &s_time[j]);
            for c in 0..256 {
                as_i.coeffs[c] =
                    ((as_i.coeffs[c] as i32 + prod.coeffs[c] as i32) % 3329 + 3329) as i16 % 3329;
            }
        }
        // e[i] = t[i] - A[i]*s
        let mut e_max: i16 = 0;
        for c in 0..256 {
            let diff = (t_time[i].coeffs[c] as i32 - as_i.coeffs[c] as i32 + 3329) % 3329;
            let centered = if diff > 3329 / 2 { diff - 3329 } else { diff };
            if centered.abs() as i16 > e_max {
                e_max = centered.abs() as i16;
            }
        }
        eprintln!(
            "Max |e[{}]| coefficient: {} (should be <= 3 for eta1=3)",
            i, e_max
        );
    }

    // Now encrypt with known message and check decrypt
    let m = [0xABu8; 32];
    let ct = k_pke_encrypt(&ek_bytes, &m, &r, params).unwrap();

    // Manually decrypt step by step
    let c1_len = 32 * params.du as usize * k;

    // Decompress u from c1
    let mut u_dec: Vec<Poly> = Vec::new();
    for i in 0..k {
        let start = i * 32 * params.du as usize;
        let compressed =
            encode::byte_decode(&ct[start..start + 32 * params.du as usize], params.du);
        let mut ui = Poly::zero();
        for j in 0..256 {
            ui.coeffs[j] = compress::decompress(compressed.coeffs[j] as u16, params.du);
        }
        u_dec.push(ui);
    }

    // Decompress v from c2
    let v_compressed = encode::byte_decode(&ct[c1_len..], params.dv);
    let mut v_dec = Poly::zero();
    for j in 0..256 {
        v_dec.coeffs[j] = compress::decompress(v_compressed.coeffs[j] as u16, params.dv);
    }

    // Compute s^T * u via schoolbook (time domain)
    let mut su_schoolbook = Poly::zero();
    for j in 0..k {
        let prod = schoolbook_mul(&s_time[j], &u_dec[j]);
        for i in 0..256 {
            su_schoolbook.coeffs[i] =
                ((su_schoolbook.coeffs[i] as i32 + prod.coeffs[i] as i32) % 3329 + 3329) as i16
                    % 3329;
        }
    }

    // Compute s^T * u via NTT (the actual decrypt way)
    let mut u_hat: Vec<Poly> = u_dec.clone();
    for p in u_hat.iter_mut() {
        p.ntt();
    }
    let mut su_ntt = Poly::zero();
    for j in 0..k {
        let prod = s_hat[j].basemul_montgomery(&u_hat[j]);
        su_ntt.add_assign(&prod);
    }
    su_ntt.inv_ntt();
    su_ntt.reduce();

    // Compare schoolbook vs NTT inner product
    let mut ntt_mismatches = 0;
    for i in 0..256 {
        let a = su_schoolbook.coeffs[i] as i32;
        let b = su_ntt.coeffs[i] as i32;
        if a != b {
            let diff = (a - b + 3329) % 3329;
            let centered = if diff > 3329 / 2 { diff - 3329 } else { diff };
            if ntt_mismatches < 3 {
                eprintln!("NTT vs schoolbook inner product mismatch at {}: ntt={}, schoolbook={}, diff={}", i, b, a, centered);
            }
            ntt_mismatches += 1;
        }
    }
    eprintln!(
        "NTT vs schoolbook inner product mismatches: {}/256",
        ntt_mismatches
    );

    // Now compute w = v - inner both ways
    let mut w_schoolbook = Poly::zero();
    for i in 0..256 {
        w_schoolbook.coeffs[i] =
            ((v_dec.coeffs[i] as i32 - su_schoolbook.coeffs[i] as i32 + 3329) % 3329) as i16;
    }

    let mut w_ntt = Poly::zero();
    for i in 0..256 {
        w_ntt.coeffs[i] = ((v_dec.coeffs[i] as i32 - su_ntt.coeffs[i] as i32 + 3329) % 3329) as i16;
    }

    // Message recovery from w_schoolbook
    let mut m_from_schoolbook = [0u8; 32];
    for i in 0..256 {
        let bit = compress::compress(w_schoolbook.coeffs[i], 1);
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        m_from_schoolbook[byte_idx] |= (bit as u8) << bit_idx;
    }

    eprintln!(
        "Message from schoolbook decrypt first 8: {:?}",
        &m_from_schoolbook[..8]
    );
    eprintln!("Original message first 8: {:?}", &m[..8]);

    let diff_schoolbook = m
        .iter()
        .zip(m_from_schoolbook.iter())
        .filter(|(a, b)| a != b)
        .count();
    eprintln!("Schoolbook decrypt differing bytes: {}/32", diff_schoolbook);

    // Also check w values near the decision boundary
    let mut near_boundary = 0;
    for i in 0..256 {
        let w = w_schoolbook.coeffs[i] as i32;
        let dist_to_0 = w.min(3329 - w);
        let dist_to_half = (w - 1665)
            .abs()
            .min((w - 1665 + 3329).abs())
            .min((w - 1665 - 3329).abs());
        let min_dist = dist_to_0.min(dist_to_half);
        if min_dist < 100 {
            near_boundary += 1;
        }
    }
    eprintln!(
        "Coefficients near decision boundary (< 100): {}/256",
        near_boundary
    );
}
