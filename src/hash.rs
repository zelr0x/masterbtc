use ripemd::{Ripemd160, Digest};
use sha2::Sha256;
use crate::hash;

pub fn checksum(data: &[u8]) -> Vec<u8> {
    hash::sha256d(&data)[..4].to_vec()
}

pub fn hash160(data: &[u8]) -> Vec<u8> {
    ripemd160(&sha256(data))
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

pub fn sha256d(data: &[u8]) -> Vec<u8> {
    sha256(&sha256(&data))
}

pub fn ripemd160(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
