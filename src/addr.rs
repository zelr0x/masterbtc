use bitcoin::{util::base58, secp256k1::PublicKey};
use crate::{hash, key::{self, B16PrivKey, B16PrivIntoPrivKeyErr}};

pub fn pub_to_b58check_addr(pubkey: &PublicKey) -> String {
    let pubkey_data = pubkey.serialize();
    #[cfg(debug_assertions)]
    {
        println!("Public key: {}", hex::encode(&pubkey_data));
    }
    let pubkey_h160 = hash::hash160(&pubkey_data);
    let mut payload: Vec<u8> = Vec::with_capacity(25);
    payload.push(0x00);
    payload.extend_from_slice(&pubkey_h160);
    let chck = hash::checksum(&payload);
    payload.extend_from_slice(&chck);
    base58::encode_slice(&payload)
}

pub fn b16priv_into_b58check_addr(b16priv: B16PrivKey) -> Result<String, B16PrivIntoPrivKeyErr> {
    let privkey = key::b16priv_into_priv_key(b16priv)?;
    let pubkey = key::pub_from_priv(&privkey);
    Ok(pub_to_b58check_addr(&pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b16priv_into_b58check_addr_works() {
        let b16priv = String::from("038109007313a5807b2eccc082c8c3fbb988a973cacf1a7df9ce725c31b14776");
        let got = b16priv_into_b58check_addr(b16priv.into()).unwrap();
        let expected = "1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK";
        assert_eq!(expected, got);
    }
}
