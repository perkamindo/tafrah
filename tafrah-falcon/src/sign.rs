//! Generic Falcon signing entry point.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;

use crate::codec::comp_encode;
use crate::common::{hash_to_point_vartime, is_short_half};
use crate::expanded::ExpandedSigningKey;
use crate::fft::{
    fft, ifft, poly_add, poly_merge_fft, poly_mul_fft, poly_mulconst, poly_split_fft, poly_sub,
};
use crate::fpr::{
    fpr_expm_p63, fpr_floor, fpr_half, fpr_mul, fpr_neg, fpr_of, fpr_rint, fpr_sqr, fpr_sub,
    fpr_trunc, Fpr, GmTable, INVERSE_OF_Q, INV_2SQRSIGMA0, INV_LOG2, LOG2, SIGMA_MIN,
};
use crate::key_material::decode_signing_key;
use crate::params::Params;
use crate::prng::Prng;
use crate::types::{Signature, SigningKey};
use tafrah_traits::Error;

const DIST: [u32; 54] = [
    10745844, 3068844, 3741698, 5559083, 1580863, 8248194, 2260429, 13669192, 2736639, 708981,
    4421575, 10046180, 169348, 7122675, 4136815, 30538, 13063405, 7650655, 4132, 14505003, 7826148,
    417, 16768101, 11363290, 31, 8444042, 8086568, 1, 12844466, 265321, 0, 1232676, 13644283, 0,
    38047, 9111839, 0, 870, 6138264, 0, 14, 12545723, 0, 0, 3104126, 0, 0, 28824, 0, 0, 198, 0, 0,
    1,
];

struct SamplerContext {
    prng: Prng,
    sigma_min: Fpr,
}

fn ffldl_treesize(logn: usize) -> usize {
    (logn + 1) << logn
}

fn gaussian0_sampler(prng: &mut Prng) -> i32 {
    let lo = prng.get_u64();
    let hi = prng.get_u8() as u32;
    let v0 = lo as u32 & 0x00FF_FFFF;
    let v1 = ((lo >> 24) as u32) & 0x00FF_FFFF;
    let v2 = ((lo >> 48) as u32) | (hi << 16);

    let mut z = 0i32;
    for chunk in DIST.chunks_exact(3) {
        let w0 = chunk[2];
        let w1 = chunk[1];
        let w2 = chunk[0];
        let mut cc = v0.wrapping_sub(w0) >> 31;
        cc = v1.wrapping_sub(w1).wrapping_sub(cc) >> 31;
        cc = v2.wrapping_sub(w2).wrapping_sub(cc) >> 31;
        z += cc as i32;
    }
    z
}

fn ber_exp(prng: &mut Prng, x: Fpr, ccs: Fpr) -> bool {
    let mut s = fpr_trunc(fpr_mul(x, INV_LOG2)) as i32;
    let r = fpr_sub(x, fpr_mul(fpr_of(s as i64), LOG2));

    let mut sw = s as u32;
    let mask = 0u32.wrapping_sub(63u32.wrapping_sub(sw) >> 31);
    sw ^= (sw ^ 63) & mask;
    s = sw as i32;

    let z = fpr_expm_p63(r, ccs).wrapping_shl(1).wrapping_sub(1) >> s;

    let mut i = 64u32;
    loop {
        i -= 8;
        let w = (prng.get_u8() as u32).wrapping_sub(((z >> i) & 0xFF) as u32);
        if w != 0 || i == 0 {
            return (w >> 31) != 0;
        }
    }
}

fn sampler(ctx: &mut SamplerContext, mu: Fpr, isigma: Fpr) -> i32 {
    let s = fpr_floor(mu) as i32;
    let r = fpr_sub(mu, fpr_of(s as i64));
    let dss = fpr_half(fpr_sqr(isigma));
    let ccs = fpr_mul(isigma, ctx.sigma_min);

    loop {
        let z0 = gaussian0_sampler(&mut ctx.prng);
        let b = (ctx.prng.get_u8() & 1) as i32;
        let z = b + ((b << 1) - 1) * z0;

        let mut x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(z as i64), r)), dss);
        x = fpr_sub(x, fpr_mul(fpr_of((z0 * z0) as i64), INV_2SQRSIGMA0));
        if ber_exp(&mut ctx.prng, x, ccs) {
            return s + z;
        }
    }
}

fn ff_sampling_fft(
    ctx: &mut SamplerContext,
    z0: &mut [Fpr],
    z1: &mut [Fpr],
    tree: &[Fpr],
    t0: &[Fpr],
    t1: &[Fpr],
    logn: usize,
    gm: &GmTable,
    tmp: &mut [Fpr],
) {
    if logn == 0 {
        z0[0] = fpr_of(sampler(ctx, t0[0], tree[0]) as i64);
        z1[0] = fpr_of(sampler(ctx, t1[0], tree[0]) as i64);
        return;
    }

    let n = 1usize << logn;
    let hn = n >> 1;
    let subtree_len = ffldl_treesize(logn - 1);
    let tree0 = &tree[n..n + subtree_len];
    let tree1 = &tree[n + subtree_len..n + (subtree_len << 1)];

    let (z1_lo, z1_hi) = z1.split_at_mut(hn);
    poly_split_fft(z1_lo, z1_hi, t1, logn, gm);
    let (tmp_lo, tmp_rest) = tmp.split_at_mut(hn);
    let (tmp_hi, tmp_work) = tmp_rest.split_at_mut(hn);
    ff_sampling_fft(
        ctx,
        tmp_lo,
        tmp_hi,
        tree1,
        z1_lo,
        z1_hi,
        logn - 1,
        gm,
        tmp_work,
    );
    poly_merge_fft(z1, tmp_lo, tmp_hi, logn, gm);

    let (tmp_poly, _tmp_work) = tmp.split_at_mut(n);
    tmp_poly.copy_from_slice(t1);
    poly_sub(tmp_poly, z1);
    poly_mul_fft(tmp_poly, &tree[..n], logn);
    poly_add(tmp_poly, t0);

    let (z0_lo, z0_hi) = z0.split_at_mut(hn);
    poly_split_fft(z0_lo, z0_hi, tmp_poly, logn, gm);
    let (tmp_lo, tmp_rest) = tmp.split_at_mut(hn);
    let (tmp_hi, tmp_work2) = tmp_rest.split_at_mut(hn);
    ff_sampling_fft(
        ctx,
        tmp_lo,
        tmp_hi,
        tree0,
        z0_lo,
        z0_hi,
        logn - 1,
        gm,
        tmp_work2,
    );
    poly_merge_fft(z0, tmp_lo, tmp_hi, logn, gm);
}

fn do_sign_tree(
    ctx: &mut SamplerContext,
    expanded_key: &ExpandedSigningKey,
    hm: &[u16],
    logn: usize,
    gm: &GmTable,
) -> Option<Vec<i16>> {
    let n = 1usize << logn;
    let mut tmp = vec![0.0; 6 * n];
    let (t0, rest) = tmp.split_at_mut(n);
    let (t1, rest) = rest.split_at_mut(n);
    let (tx, rest) = rest.split_at_mut(n);
    let (ty, work) = rest.split_at_mut(n);

    for (slot, &value) in t0.iter_mut().zip(hm.iter()) {
        *slot = fpr_of(value as i64);
    }

    fft(t0, logn, gm);
    t1.copy_from_slice(t0);
    poly_mul_fft(t1, expanded_key.b01(), logn);
    poly_mulconst(t1, fpr_neg(INVERSE_OF_Q));
    poly_mul_fft(t0, expanded_key.b11(), logn);
    poly_mulconst(t0, INVERSE_OF_Q);

    ff_sampling_fft(ctx, tx, ty, expanded_key.tree(), t0, t1, logn, gm, work);

    t0.copy_from_slice(tx);
    t1.copy_from_slice(ty);
    poly_mul_fft(tx, expanded_key.b00(), logn);
    poly_mul_fft(ty, expanded_key.b10(), logn);
    poly_add(tx, ty);
    ty.copy_from_slice(t0);
    poly_mul_fft(ty, expanded_key.b01(), logn);
    t0.copy_from_slice(tx);
    poly_mul_fft(t1, expanded_key.b11(), logn);
    poly_add(t1, ty);

    ifft(t0, logn, gm);
    ifft(t1, logn, gm);

    let mut sqn = 0u32;
    let mut ng = 0u32;
    let mut s2 = vec![0i16; n];
    for u in 0..n {
        let z = hm[u] as i64 - fpr_rint(t0[u]);
        if z < i32::MIN as i64 || z > i32::MAX as i64 {
            return None;
        }
        let z = z as i32;
        sqn = sqn.wrapping_add((z as i64 * z as i64) as u32);
        ng |= sqn;

        let s2_value = -fpr_rint(t1[u]);
        if s2_value < i16::MIN as i64 || s2_value > i16::MAX as i64 {
            return None;
        }
        s2[u] = s2_value as i16;
    }
    sqn |= 0u32.wrapping_sub(ng >> 31);

    if is_short_half(sqn, &s2, logn) {
        Some(s2)
    } else {
        None
    }
}

/// Signs a message with Falcon using the supplied parameter set.
pub fn falcon_sign(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<Signature, Error> {
    params.validate()?;
    let decoded = decode_signing_key(&sk.bytes, params)?;
    let expanded = ExpandedSigningKey::from_decoded(&decoded, params.log_n);
    let gm = GmTable::new();
    let logn = params.log_n;

    loop {
        let mut nonce = [0u8; 40];
        let mut seed = [0u8; 48];
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut seed);

        let hm = hash_to_point_vartime(&nonce, msg, logn);
        let mut hasher = Shake256::default();
        hasher.update(&seed);
        let mut seed_reader = hasher.finalize_xof();

        let mut sampler_ctx = SamplerContext {
            prng: Prng::new(),
            sigma_min: SIGMA_MIN[logn],
        };
        let s2 = loop {
            sampler_ctx.prng.init(&mut seed_reader);
            if let Some(sig) = do_sign_tree(&mut sampler_ctx, &expanded, &hm, logn, &gm) {
                break sig;
            }
        };

        let encoded = match comp_encode(&s2, logn) {
            Some(encoded) => encoded,
            None => continue,
        };
        let encoded_sig_len = encoded.len() + 1;
        let total_len = 42 + encoded_sig_len;
        if total_len > params.sig_max_bytes || encoded_sig_len > u16::MAX as usize {
            continue;
        }

        let mut out = Vec::with_capacity(total_len);
        out.push((encoded_sig_len >> 8) as u8);
        out.push(encoded_sig_len as u8);
        out.extend_from_slice(&nonce);
        out.push(params.sig_tag());
        out.extend_from_slice(&encoded);
        return Ok(Signature { bytes: out });
    }
}
