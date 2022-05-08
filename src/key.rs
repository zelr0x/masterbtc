use bitcoin::secp256k1::{self, SecretKey, Secp256k1, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct B16PrivKey(String);

impl From<String> for B16PrivKey {
    fn from(s: String) -> B16PrivKey {
        B16PrivKey(s)
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct PrivKeyBytes(Vec<u8>);

impl TryFrom<B16PrivKey> for PrivKeyBytes {
    type Error = base16::DecodeError;

    fn try_from(b16priv: B16PrivKey) -> Result<Self, Self::Error> {
        let decoded = base16::decode(&b16priv.0)?;
        Ok(PrivKeyBytes(decoded))
    }
}

impl TryFrom<PrivKeyBytes> for SecretKey {
    type Error = secp256k1::Error;

    fn try_from(privkey: PrivKeyBytes) -> Result<Self, Self::Error> {
        SecretKey::from_slice(&privkey.0)
    }
}

pub fn pub_from_priv(sk: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new(); // use global-context feature and from_secret_key_global?
    PublicKey::from_secret_key(&secp, &sk)
}

#[derive(Debug, PartialEq)]
pub enum B16PrivIntoPrivKeyErr {
    Base16DecodeErr(base16::DecodeError),
    Secp256K1Err(secp256k1::Error),
}

impl From<base16::DecodeError> for B16PrivIntoPrivKeyErr {
    fn from(err: base16::DecodeError) -> Self {
        B16PrivIntoPrivKeyErr::Base16DecodeErr(err)
    }
}

impl From<secp256k1::Error> for B16PrivIntoPrivKeyErr {
    fn from(err: secp256k1::Error) -> Self {
        B16PrivIntoPrivKeyErr::Secp256K1Err(err)
    }
}

pub fn b16priv_into_priv_key(b16priv: B16PrivKey) -> Result<SecretKey, B16PrivIntoPrivKeyErr> {
    let decoded: PrivKeyBytes = b16priv.try_into()?;
    decoded.try_into()
        .map_err(|e: secp256k1::Error| e.into())
}
