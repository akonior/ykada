use std::convert::TryInto;

use log::info;
use yubikey::piv::{AlgorithmId, SlotId, import_cv_key, sign_data};
use yubikey::{MgmKey, PinPolicy, TouchPolicy, YubiKey};

use ed25519_dalek::{SecretKey, Signature, SigningKey, VerifyingKey};

const DEFAULT_PIN: &[u8] = b"123456";
const DEFAULT_SECRET_KEY: &SecretKey = &[0u8; 32];

pub fn initialize_logger() {
    env_logger::init();
    info!("logger initialized");
}

pub fn initialize_yubikey() -> VerifyingKey {
    let mut yubikey = YubiKey::open().unwrap();

    println!("YubiKey: {:?}", yubikey);

    yubikey
        .authenticate(&MgmKey::get_default(&yubikey).unwrap())
        .unwrap();

    let sk = SigningKey::from_bytes(DEFAULT_SECRET_KEY);

    println!("Signing key: {:?}", sk);

    let key_data = sk.as_bytes();

    let result = import_cv_key(
        &mut yubikey,
        SlotId::Signature,
        AlgorithmId::Ed25519,
        key_data,
        TouchPolicy::Never,
        PinPolicy::Always,
    )
    .unwrap();
    println!("Result of import_ecc_key: {:?}", result);

    sk.verifying_key()
}

pub fn sign_raw_data(data: &[u8]) -> Signature {
    let mut yubikey = YubiKey::open().unwrap();

    yubikey.verify_pin(DEFAULT_PIN).unwrap();
    println!("PIN verified");

    let signature_yubikey: Vec<u8> =
        sign_data(&mut yubikey, data, AlgorithmId::Ed25519, SlotId::Signature)
            .unwrap()
            .to_vec();
    println!("Result of sign_data: {:?}", signature_yubikey);

    let sig_bytes: [u8; Signature::BYTE_SIZE] = signature_yubikey[..]
        .try_into()
        .expect("signature must be 64 bytes");

    sig_bytes.into()
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(4, 4);
    }
}
