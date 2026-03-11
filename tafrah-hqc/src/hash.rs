use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const G_FCT_DOMAIN: u8 = 3;
pub const H_FCT_DOMAIN: u8 = 4;
pub const K_FCT_DOMAIN: u8 = 5;

pub fn shake256_512_ds(input: &[u8], domain: u8) -> [u8; 64] {
    let mut shake = Shake256::default();
    shake.update(input);
    shake.update(&[domain]);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; 64];
    reader.read(&mut out);
    out
}
