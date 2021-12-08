use tafrah_math::field::kem;
/// Test NTT-based polynomial multiplication against schoolbook multiplication
use tafrah_math::poly::kem::Poly;

/// Schoolbook multiplication in Zq[X]/(X^256+1)
fn schoolbook_mul(a: &Poly, b: &Poly) -> Poly {
    let q = 3329i32;
    let mut result = [0i32; 256];

    for i in 0..256 {
        for j in 0..256 {
            let idx = i + j;
            let prod = a.coeffs[i] as i32 * b.coeffs[j] as i32;
            if idx < 256 {
                result[idx] += prod;
            } else {
                // X^256 = -1 in the ring
                result[idx - 256] -= prod;
            }
        }
    }

    let mut out = Poly::zero();
    for i in 0..256 {
        out.coeffs[i] = ((result[i] % q + q) % q) as i16;
    }
    out
}

#[test]
fn test_ntt_multiplication_vs_schoolbook() {
    // Simple test polynomials
    let mut a = Poly::zero();
    let mut b = Poly::zero();

    // a = 1 + 2*X + 3*X^2
    a.coeffs[0] = 1;
    a.coeffs[1] = 2;
    a.coeffs[2] = 3;

    // b = 4 + 5*X
    b.coeffs[0] = 4;
    b.coeffs[1] = 5;

    // Expected schoolbook result
    let expected = schoolbook_mul(&a, &b);

    // NTT-based multiplication
    let mut a_ntt = a.clone();
    let mut b_ntt = b.clone();
    a_ntt.ntt();
    b_ntt.ntt();

    let mut c_ntt = a_ntt.basemul_montgomery(&b_ntt);
    c_ntt.inv_ntt();

    // After basemul(R^{-1}) + inv_ntt(R), Montgomery factors cancel.
    // Result is already in standard form!
    for i in 0..256 {
        c_ntt.coeffs[i] = ((c_ntt.coeffs[i] as i32 % 3329 + 3329) % 3329) as i16;
    }

    for i in 0..256 {
        assert_eq!(
            c_ntt.coeffs[i], expected.coeffs[i],
            "Mismatch at index {}: ntt={}, schoolbook={}",
            i, c_ntt.coeffs[i], expected.coeffs[i]
        );
    }
}

#[test]
fn test_ntt_multiplication_random_like() {
    // Use polynomial with more coefficients
    let mut a = Poly::zero();
    let mut b = Poly::zero();

    for i in 0..256 {
        a.coeffs[i] = ((i * 7 + 3) % 3329) as i16;
        b.coeffs[i] = ((i * 11 + 5) % 3329) as i16;
    }

    let expected = schoolbook_mul(&a, &b);

    let mut a_ntt = a.clone();
    let mut b_ntt = b.clone();
    a_ntt.ntt();
    b_ntt.ntt();

    let mut c_ntt = a_ntt.basemul_montgomery(&b_ntt);
    c_ntt.inv_ntt();

    // Result is in standard form (Montgomery factors cancel)
    for i in 0..256 {
        c_ntt.coeffs[i] = ((c_ntt.coeffs[i] as i32 % 3329 + 3329) % 3329) as i16;
    }

    let mut mismatches = 0;
    for i in 0..256 {
        if c_ntt.coeffs[i] != expected.coeffs[i] {
            if mismatches < 5 {
                eprintln!(
                    "Mismatch at {}: ntt={}, schoolbook={}",
                    i, c_ntt.coeffs[i], expected.coeffs[i]
                );
            }
            mismatches += 1;
        }
    }
    if mismatches > 0 {
        panic!(
            "{} mismatches in NTT vs schoolbook multiplication",
            mismatches
        );
    }
}

/// Test the full keygen/encrypt/decrypt Montgomery chain
#[test]
fn test_keygen_encrypt_montgomery_chain() {
    // Simulate the keygen flow:
    // s, e sampled → NTT(s), NTT(e)
    // t = tomont(basemul_acc(A, s)) + e  (keygen)
    //
    // Then encrypt:
    // r sampled → NTT(r)
    // u = INTT(basemul_acc(A^T, r)) + e1
    // v = INTT(basemul_acc(t, r)) + e2 + decompress(m)
    //
    // Then decrypt:
    // s^T * NTT(u) → INTT → subtract from v → compress → m'
    //
    // The key question: after tomont in keygen, t is in a different
    // representation than if we hadn't called tomont.
    // In encrypt/decrypt basemul_acc produces result * R^{-1} in NTT domain,
    // INTT converts it to result * R^{-1} * R = result.
    // But if t was "tomonted" (multiplied by R), then:
    // basemul(t*R, r) = t*R*r*R^{-1} = t*r (correct product!)
    // Then INTT gives t*r * R (from the INTT scaling).
    // But we actually want just t*r (without extra R).
    //
    // Hmm, so after INTT of basemul_acc(t, r), we get t*r * ??? Let's test.

    let mut a = Poly::zero();
    let mut s = Poly::zero();
    let mut r_poly = Poly::zero();

    a.coeffs[0] = 100;
    a.coeffs[1] = 200;
    s.coeffs[0] = 3;
    s.coeffs[1] = 5;
    r_poly.coeffs[0] = 7;
    r_poly.coeffs[1] = 11;

    // Schoolbook: t = a * s (in ring)
    let t_expected = schoolbook_mul(&a, &s);
    // Schoolbook: t * r
    let tr_expected = schoolbook_mul(&t_expected, &r_poly);
    // Schoolbook: s * (a^T * r) = s * a * r (same as t * r for single polynomials)
    // For vectors this would differ, but for single polys: s*(a*r) = t*r

    // NTT-based keygen flow
    let mut a_ntt = a.clone();
    let mut s_ntt = s.clone();
    a_ntt.ntt();
    s_ntt.ntt();

    // basemul_acc + tomont (keygen)
    let mut t_ntt = a_ntt.basemul_montgomery(&s_ntt);
    // In keygen, poly_tomont is called on the basemul result
    for i in 0..256 {
        t_ntt.coeffs[i] = kem::fqmul(t_ntt.coeffs[i], 1353); // tomont: multiply by R
    }

    // Now t_ntt is "t in NTT domain, in Montgomery representation"
    // The reference stores this (after adding e and reducing)

    // NTT-based encrypt: basemul(t, r) + INTT
    let mut r_ntt = r_poly.clone();
    r_ntt.ntt();

    let mut v_ntt = t_ntt.basemul_montgomery(&r_ntt);
    v_ntt.inv_ntt();

    // What's the result? Normalize and compare.
    for i in 0..256 {
        v_ntt.coeffs[i] = ((v_ntt.coeffs[i] as i32 % 3329 + 3329) % 3329) as i16;
    }

    for i in 0..10 {
        let expected = tr_expected.coeffs[i];
        let got = v_ntt.coeffs[i];
        eprintln!("v[{}]: got={}, expected={}", i, got, expected);
    }

    // Also try without tomont to see the difference
    let t_ntt2 = a_ntt.basemul_montgomery(&s_ntt);
    // NO tomont
    let mut v_ntt2 = t_ntt2.basemul_montgomery(&r_ntt);
    v_ntt2.inv_ntt();
    for i in 0..256 {
        v_ntt2.coeffs[i] = ((v_ntt2.coeffs[i] as i32 % 3329 + 3329) % 3329) as i16;
    }

    eprintln!("\nWithout tomont:");
    for i in 0..10 {
        let expected = tr_expected.coeffs[i];
        let got = v_ntt2.coeffs[i];
        eprintln!("v[{}]: got={}, expected={}", i, got, expected);
    }
}
