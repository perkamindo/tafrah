use std::hint::black_box;
use std::time::Instant;

use rand::SeedableRng;
use tafrah::falcon::falcon_512;
use tafrah::hqc::hqc_128;
use tafrah::ml_dsa::params::ML_DSA_65;
use tafrah::ml_dsa::{keygen as ml_dsa_keygen, sign as ml_dsa_sign, verify as ml_dsa_verify};
use tafrah::ml_kem::ml_kem_768;
use tafrah::slh_dsa::params::SLH_DSA_SHAKE_128F;
use tafrah::slh_dsa::{keygen as slh_keygen, sign as slh_sign, verify as slh_verify};
use tafrah_math::ntt;
use tafrah_math::poly;

struct BenchRow {
    group: &'static str,
    name: &'static str,
    iterations: usize,
    total_ns: u128,
}

impl BenchRow {
    fn avg_ns(&self) -> u128 {
        self.total_ns / self.iterations as u128
    }
}

fn bench(
    group: &'static str,
    name: &'static str,
    iterations: usize,
    mut op: impl FnMut(),
) -> BenchRow {
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(op());
    }
    BenchRow {
        group,
        name,
        iterations,
        total_ns: start.elapsed().as_nanos(),
    }
}

fn make_kem_poly(seed: i16) -> poly::kem::Poly {
    let mut p = poly::kem::Poly::zero();
    for (i, coeff) in p.coeffs.iter_mut().enumerate() {
        let base = (i as i16).wrapping_mul(17).wrapping_add(seed);
        *coeff = base.rem_euclid(3329);
    }
    p
}

fn make_dsa_poly(seed: i32) -> poly::dsa::Poly {
    let mut p = poly::dsa::Poly::zero();
    for (i, coeff) in p.coeffs.iter_mut().enumerate() {
        let base = (i as i32).wrapping_mul(65537).wrapping_add(seed);
        *coeff = base.rem_euclid(8_380_417);
    }
    p
}

fn cpu_features_json() -> String {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        format!(
            "{{\"sse2\":{},\"avx\":{},\"avx2\":{}}}",
            is_x86_feature_detected!("sse2"),
            is_x86_feature_detected!("avx"),
            is_x86_feature_detected!("avx2"),
        )
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        "{\"sse2\":false,\"avx\":false,\"avx2\":false}".to_owned()
    }
}

fn print_json(rows: &[BenchRow]) {
    println!("{{");
    println!("  \"arch\": \"{}\",", std::env::consts::ARCH);
    println!("  \"os\": \"{}\",", std::env::consts::OS);
    println!("  \"cpu_features\": {},", cpu_features_json());
    println!(
        "  \"math_backends\": {{\"ml_kem\":\"{}\",\"ml_dsa\":\"{}\"}},",
        ntt::kem::backend_name(),
        ntt::dsa::backend_name()
    );
    println!("  \"rows\": [");
    for (index, row) in rows.iter().enumerate() {
        let trailing = if index + 1 == rows.len() { "" } else { "," };
        println!(
            "    {{\"group\":\"{}\",\"name\":\"{}\",\"iterations\":{},\"total_ns\":{},\"avg_ns\":{}}}{}",
            row.group,
            row.name,
            row.iterations,
            row.total_ns,
            row.avg_ns(),
            trailing
        );
    }
    println!("  ]");
    println!("}}");
}

fn print_table(rows: &[BenchRow]) {
    println!("arch: {}", std::env::consts::ARCH);
    println!("os: {}", std::env::consts::OS);
    println!("cpu_features: {}", cpu_features_json());
    println!(
        "math_backends: {{\"ml_kem\":\"{}\",\"ml_dsa\":\"{}\"}}",
        ntt::kem::backend_name(),
        ntt::dsa::backend_name()
    );
    println!();
    println!(
        "{:<12} {:<28} {:>10} {:>14}",
        "group", "name", "iters", "avg_ns"
    );
    for row in rows {
        println!(
            "{:<12} {:<28} {:>10} {:>14}",
            row.group,
            row.name,
            row.iterations,
            row.avg_ns()
        );
    }
}

fn main() {
    let json = std::env::args().any(|arg| arg == "--json");
    let mut rows = Vec::new();

    let kem_ntt = make_kem_poly(11);
    let mut kem_inv = make_kem_poly(19);
    kem_inv.ntt();
    let kem_a = make_kem_poly(23);
    let kem_b = make_kem_poly(29);

    rows.push(bench("math", "ml_kem_ntt_256", 20_000, || {
        let mut p = kem_ntt.clone();
        ntt::kem::ntt(&mut p.coeffs);
        black_box(p);
    }));
    rows.push(bench("math", "ml_kem_inv_ntt_256", 20_000, || {
        let mut p = kem_inv.clone();
        ntt::kem::inv_ntt(&mut p.coeffs);
        black_box(p);
    }));
    rows.push(bench("math", "ml_kem_basemul_256", 20_000, || {
        let c = kem_a.basemul_montgomery(&kem_b);
        black_box(c);
    }));

    let dsa_ntt = make_dsa_poly(31);
    let mut dsa_inv = make_dsa_poly(37);
    dsa_inv.ntt();
    let dsa_a = make_dsa_poly(41);
    let dsa_b = make_dsa_poly(43);

    rows.push(bench("math", "ml_dsa_ntt_256", 8_000, || {
        let mut p = dsa_ntt.clone();
        ntt::dsa::ntt(&mut p.coeffs);
        black_box(p);
    }));
    rows.push(bench("math", "ml_dsa_inv_ntt_256", 8_000, || {
        let mut p = dsa_inv.clone();
        ntt::dsa::inv_ntt(&mut p.coeffs);
        black_box(p);
    }));
    rows.push(bench("math", "ml_dsa_pointwise_256", 12_000, || {
        let c = dsa_a.pointwise_mul(&dsa_b);
        black_box(c);
    }));

    let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);
    let (kem_ek, kem_dk) = ml_kem_768::keygen(&mut rng);
    let (kem_ct, _) = ml_kem_768::encapsulate(&kem_ek, &mut rng).expect("ml-kem encaps");
    rows.push(bench("scheme", "ml_kem_768_keygen", 200, || {
        black_box(ml_kem_768::keygen(&mut rng));
    }));
    rows.push(bench("scheme", "ml_kem_768_encaps", 400, || {
        black_box(ml_kem_768::encapsulate(&kem_ek, &mut rng).expect("ml-kem encaps"));
    }));
    rows.push(bench("scheme", "ml_kem_768_decaps", 400, || {
        black_box(ml_kem_768::decapsulate(&kem_dk, &kem_ct).expect("ml-kem decaps"));
    }));

    let (ml_vk, ml_sk) = ml_dsa_keygen::ml_dsa_keygen(&mut rng, &ML_DSA_65).expect("ml-dsa keygen");
    let ml_msg = [0xA5u8; 32];
    let ml_sig =
        ml_dsa_sign::ml_dsa_sign_deterministic(&ml_sk, &ml_msg, &ML_DSA_65).expect("ml-dsa sign");
    rows.push(bench("scheme", "ml_dsa_65_keygen", 80, || {
        black_box(ml_dsa_keygen::ml_dsa_keygen(&mut rng, &ML_DSA_65).expect("ml-dsa keygen"));
    }));
    rows.push(bench("scheme", "ml_dsa_65_sign", 120, || {
        black_box(
            ml_dsa_sign::ml_dsa_sign_deterministic(&ml_sk, &ml_msg, &ML_DSA_65)
                .expect("ml-dsa sign"),
        );
    }));
    rows.push(bench("scheme", "ml_dsa_65_verify", 240, || {
        black_box(
            ml_dsa_verify::ml_dsa_verify(&ml_vk, &ml_msg, &ml_sig, &ML_DSA_65)
                .expect("ml-dsa verify"),
        );
    }));

    let (slh_vk, slh_sk) =
        slh_keygen::slh_dsa_keygen(&mut rng, &SLH_DSA_SHAKE_128F).expect("slh keygen");
    let slh_msg = [0x5Au8; 32];
    let slh_sig = slh_sign::slh_sign_internal(&slh_sk, &slh_msg, None, &SLH_DSA_SHAKE_128F)
        .expect("slh sign");
    rows.push(bench("scheme", "slh_dsa_128f_keygen", 8, || {
        black_box(slh_keygen::slh_dsa_keygen(&mut rng, &SLH_DSA_SHAKE_128F).expect("slh keygen"));
    }));
    rows.push(bench("scheme", "slh_dsa_128f_sign", 12, || {
        black_box(
            slh_sign::slh_sign_internal(&slh_sk, &slh_msg, None, &SLH_DSA_SHAKE_128F)
                .expect("slh sign"),
        );
    }));
    rows.push(bench("scheme", "slh_dsa_128f_verify", 24, || {
        black_box(
            slh_verify::slh_dsa_verify(&slh_vk, &slh_msg, &slh_sig, &SLH_DSA_SHAKE_128F)
                .expect("slh verify"),
        );
    }));

    let (falcon_vk, falcon_sk) = falcon_512::keygen(&mut rng).expect("falcon keygen");
    let falcon_msg = [0x33u8; 32];
    let falcon_sig = falcon_512::sign(&falcon_sk, &falcon_msg, &mut rng).expect("falcon sign");
    rows.push(bench("scheme", "falcon_512_keygen", 30, || {
        black_box(falcon_512::keygen(&mut rng).expect("falcon keygen"));
    }));
    rows.push(bench("scheme", "falcon_512_sign", 120, || {
        black_box(falcon_512::sign(&falcon_sk, &falcon_msg, &mut rng).expect("falcon sign"));
    }));
    rows.push(bench("scheme", "falcon_512_verify", 240, || {
        black_box(falcon_512::verify(&falcon_vk, &falcon_msg, &falcon_sig).expect("falcon verify"));
    }));

    let (hqc_ek, hqc_dk) = hqc_128::keygen(&mut rng).expect("hqc keygen");
    let (hqc_ct, _) = hqc_128::encapsulate(&hqc_ek, &mut rng).expect("hqc encaps");
    rows.push(bench("scheme", "hqc_128_keygen", 30, || {
        black_box(hqc_128::keygen(&mut rng).expect("hqc keygen"));
    }));
    rows.push(bench("scheme", "hqc_128_encaps", 60, || {
        black_box(hqc_128::encapsulate(&hqc_ek, &mut rng).expect("hqc encaps"));
    }));
    rows.push(bench("scheme", "hqc_128_decaps", 60, || {
        black_box(hqc_128::decapsulate(&hqc_dk, &hqc_ct).expect("hqc decaps"));
    }));

    if json {
        print_json(&rows);
    } else {
        print_table(&rows);
    }
}
