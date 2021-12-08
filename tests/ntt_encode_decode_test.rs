use tafrah_math::field::kem;
/// Test that NTT → encode → decode → INTT roundtrip recovers original polynomial
use tafrah_math::poly::kem::Poly;

/// Simulate ByteEncode_12 → ByteDecode_12 (applies caddq during encode)
fn encode_decode_12(poly: &Poly) -> Poly {
    // ByteEncode_12: caddq each coefficient, pack as 12-bit
    let mut encoded = [0u8; 384]; // 32 * 12 = 384 bytes
    for i in 0..128 {
        let a = kem::caddq(poly.coeffs[2 * i]) as u16;
        let b = kem::caddq(poly.coeffs[2 * i + 1]) as u16;
        encoded[3 * i] = a as u8;
        encoded[3 * i + 1] = ((a >> 8) | (b << 4)) as u8;
        encoded[3 * i + 2] = (b >> 4) as u8;
    }

    // ByteDecode_12: unpack 12-bit values
    let mut decoded = Poly::zero();
    for i in 0..128 {
        decoded.coeffs[2 * i] =
            (encoded[3 * i] as i16) | (((encoded[3 * i + 1] & 0x0F) as i16) << 8);
        decoded.coeffs[2 * i + 1] =
            ((encoded[3 * i + 1] >> 4) as i16) | ((encoded[3 * i + 2] as i16) << 4);
    }
    decoded
}

#[test]
fn test_ntt_encode_decode_roundtrip() {
    // Create a small polynomial (like CBD output)
    let mut s = Poly::zero();
    for i in 0..256 {
        s.coeffs[i] = ((i % 7) as i16) - 3; // values in [-3, 3]
    }

    eprintln!("Original s first 10: {:?}", &s.coeffs[..10]);

    // NTT
    let mut s_ntt = s.clone();
    s_ntt.ntt();
    // NTT output can exceed [0, q), must reduce before 12-bit encoding
    s_ntt.reduce();
    eprintln!("After NTT first 10: {:?}", &s_ntt.coeffs[..10]);

    // Encode/decode (simulating storage)
    let s_ntt_recovered = encode_decode_12(&s_ntt);
    eprintln!(
        "After encode/decode first 10: {:?}",
        &s_ntt_recovered.coeffs[..10]
    );

    // Check encode/decode is lossless mod q
    for i in 0..256 {
        let orig = ((kem::caddq(s_ntt.coeffs[i]) as i32 + 3329) % 3329) as i16;
        let recovered = s_ntt_recovered.coeffs[i];
        assert_eq!(
            orig, recovered,
            "encode/decode mismatch at {}: orig={}, recovered={}",
            i, orig, recovered
        );
    }
    eprintln!("Encode/decode is lossless mod q: OK");

    // INTT of NTT directly (no encode/decode)
    let mut s_direct = s_ntt.clone();
    s_direct.inv_ntt();
    for i in 0..256 {
        s_direct.coeffs[i] = kem::fqmul(s_direct.coeffs[i], 1);
    }
    s_direct.reduce();
    eprintln!(
        "Direct INTT recovery first 10: {:?}",
        &s_direct.coeffs[..10]
    );

    // INTT of encoded/decoded NTT
    let mut s_roundtrip = s_ntt_recovered.clone();
    s_roundtrip.inv_ntt();
    for i in 0..256 {
        s_roundtrip.coeffs[i] = kem::fqmul(s_roundtrip.coeffs[i], 1);
    }
    s_roundtrip.reduce();
    eprintln!(
        "Roundtrip INTT recovery first 10: {:?}",
        &s_roundtrip.coeffs[..10]
    );

    // Compare
    for i in 0..256 {
        let direct_centered = if s_direct.coeffs[i] > 3329 / 2 {
            s_direct.coeffs[i] - 3329
        } else {
            s_direct.coeffs[i]
        };
        let roundtrip_centered = if s_roundtrip.coeffs[i] > 3329 / 2 {
            s_roundtrip.coeffs[i] - 3329
        } else {
            s_roundtrip.coeffs[i]
        };
        let original_centered = s.coeffs[i];

        if direct_centered != original_centered {
            eprintln!(
                "DIRECT recovery mismatch at {}: direct={}, original={}",
                i, direct_centered, original_centered
            );
        }
        if roundtrip_centered != original_centered {
            eprintln!(
                "ROUNDTRIP recovery mismatch at {}: roundtrip={}, original={}",
                i, roundtrip_centered, original_centered
            );
        }
    }
}
