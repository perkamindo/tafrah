//! Address representation for SLH-DSA.

use crate::params::{HashType, Params};

/// FIPS 205 ADRS value used to domain-separate hash invocations.
#[derive(Clone, Default)]
pub struct Adrs {
    /// Raw 32-byte address state.
    pub bytes: [u8; 32],
}

// Address field positions
const LAYER_OFFSET: usize = 0; // bytes 0..3
const _TREE_OFFSET: usize = 4; // bytes 4..15 (96 bits)
const TYPE_OFFSET: usize = 16; // bytes 16..19
const WORD1_OFFSET: usize = 20; // bytes 20..23 (keypair address)
const WORD2_OFFSET: usize = 24; // bytes 24..27 (chain address / tree height)
const WORD3_OFFSET: usize = 28; // bytes 28..31 (hash address)

/// ADRS type for WOTS+ chain hashes.
pub const WOTS_HASH: u32 = 0;
/// ADRS type for WOTS+ public key compression.
pub const WOTS_PK: u32 = 1;
/// ADRS type for XMSS tree nodes.
pub const TREE: u32 = 2;
/// ADRS type for FORS tree nodes.
pub const FORS_TREE: u32 = 3;
/// ADRS type for FORS public key compression.
pub const FORS_ROOTS: u32 = 4;
/// ADRS type for WOTS+ PRF calls.
pub const WOTS_PRF: u32 = 5;
/// ADRS type for FORS PRF calls.
pub const FORS_PRF: u32 = 6;

impl Adrs {
    /// Returns an all-zero ADRS value.
    pub fn new() -> Self {
        Adrs { bytes: [0u8; 32] }
    }

    fn set_u32(&mut self, offset: usize, val: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
    }

    fn get_u32(&self, offset: usize) -> u32 {
        u32::from_be_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
    }

    /// Sets the ADRS layer field.
    pub fn set_layer_address(&mut self, layer: u32) {
        self.set_u32(LAYER_OFFSET, layer);
    }

    /// Returns the ADRS layer field.
    pub fn get_layer_address(&self) -> u32 {
        self.get_u32(LAYER_OFFSET)
    }

    /// Sets the ADRS tree field using the low 64 bits of the tree identifier.
    pub fn set_tree_address(&mut self, tree: u64) {
        // Tree address is 12 bytes, we use the lower 8 bytes
        self.bytes[4..8].copy_from_slice(&[0u8; 4]);
        self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Returns the low 64 bits of the ADRS tree field.
    pub fn get_tree_address(&self) -> u64 {
        u64::from_be_bytes(self.bytes[8..16].try_into().unwrap())
    }

    /// Sets the ADRS type field without altering type-specific payload words.
    pub fn set_type(&mut self, addr_type: u32) {
        self.set_u32(TYPE_OFFSET, addr_type);
    }

    /// Mirrors the FIPS 205 `ADRS.setTypeAndClear(Y)` behavior.
    pub fn set_type_and_clear(&mut self, addr_type: u32) {
        self.set_type(addr_type);
        self.bytes[20..32].fill(0);
    }

    /// Mirrors the SPHINCS+ / FIPS 205 type switch that preserves the key-pair
    /// coordinate while clearing the chain/tree payload words.
    pub fn set_type_and_clear_not_keypair(&mut self, addr_type: u32) {
        self.set_type(addr_type);
        self.bytes[24..32].fill(0);
    }

    /// Returns the ADRS type field.
    pub fn get_type(&self) -> u32 {
        self.get_u32(TYPE_OFFSET)
    }

    pub fn set_keypair_address(&mut self, kp: u32) {
        self.set_u32(WORD1_OFFSET, kp);
    }

    pub fn get_keypair_address(&self) -> u32 {
        self.get_u32(WORD1_OFFSET)
    }

    pub fn set_chain_address(&mut self, chain: u32) {
        self.set_u32(WORD2_OFFSET, chain);
    }

    pub fn set_tree_height(&mut self, height: u32) {
        self.set_u32(WORD2_OFFSET, height);
    }

    pub fn set_hash_address(&mut self, hash: u32) {
        self.set_u32(WORD3_OFFSET, hash);
    }

    pub fn set_tree_index(&mut self, index: u32) {
        self.set_u32(WORD3_OFFSET, index);
    }

    pub fn get_tree_index(&self) -> u32 {
        self.get_u32(WORD3_OFFSET)
    }

    fn get_word2(&self) -> u32 {
        self.get_u32(WORD2_OFFSET)
    }

    fn get_word3(&self) -> u32 {
        self.get_u32(WORD3_OFFSET)
    }

    fn serialize_sha2(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let tree = self.get_tree_address();
        let keypair = self.get_keypair_address();

        out[0] = self.get_layer_address() as u8;
        out[1..9].copy_from_slice(&tree.to_be_bytes());
        out[9] = self.get_type() as u8;
        out[12] = (keypair >> 8) as u8;
        out[13] = keypair as u8;
        out[17] = self.get_word2() as u8;
        out[18..22].copy_from_slice(&self.get_word3().to_be_bytes());
        out
    }

    fn serialize_shake(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let tree = self.get_tree_address();
        let keypair = self.get_keypair_address();

        out[3] = self.get_layer_address() as u8;
        out[8..16].copy_from_slice(&tree.to_be_bytes());
        out[19] = self.get_type() as u8;
        out[22] = (keypair >> 8) as u8;
        out[23] = keypair as u8;
        out[27] = self.get_word2() as u8;
        out[28..32].copy_from_slice(&self.get_word3().to_be_bytes());
        out
    }

    /// Serializes the address in the hash-specific layout required by FIPS 205.
    pub fn to_hash_bytes(&self, params: &Params) -> [u8; 32] {
        match params.hash_type {
            HashType::Sha2 => self.serialize_sha2(),
            HashType::Shake => self.serialize_shake(),
        }
    }

    /// Returns the 22-byte compressed SHA2 layout used by the SHA2 parameter sets.
    pub fn to_sha2_compressed_bytes(&self) -> [u8; 22] {
        let full = self.serialize_sha2();
        let mut out = [0u8; 22];
        out.copy_from_slice(&full[..22]);
        out
    }

    /// Copies the layer and tree subtree coordinates while preserving the current type layout.
    pub fn copy_subtree(&self) -> Adrs {
        let new = self.clone();
        // Keep layer, tree
        new
    }
}
