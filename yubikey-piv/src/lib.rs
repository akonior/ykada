use std::convert::TryInto;

use log::info;
use yubikey::piv::{AlgorithmId, SlotId, import_cv_key, sign_data};
use yubikey::{MgmKey, PinPolicy, TouchPolicy, YubiKey};

use ed25519_dalek::{Signature, SigningKey};

const DEFAULT_PIN: &[u8] = b"123456";

pub fn sign_raw_data() {
    println!("import_keys binary initialized");
    env_logger::init();
    info!("import_key binary initialized");

    let mut yubikey = YubiKey::open().unwrap();

    println!("YubiKey: {:?}", yubikey);

    yubikey
        .authenticate(&MgmKey::get_default(&yubikey).unwrap())
        .unwrap();

    let sk = SigningKey::from_bytes(&[0u8; 32]);

    println!("Signing key: {:?}", sk);

    let key_data = sk.as_bytes();

    let result = import_cv_key(
        &mut yubikey,
        SlotId::Signature,
        AlgorithmId::Ed25519,
        key_data,
        TouchPolicy::Never,
        PinPolicy::Always,
    );
    println!("Result of import_ecc_key: {:?}", result);

    yubikey.verify_pin(DEFAULT_PIN).unwrap();
    println!("PIN verified");

    let signature_result = sign_data(
        &mut yubikey,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8],
        AlgorithmId::Ed25519,
        SlotId::Signature,
    )
    .unwrap();
    println!("Result of sign_data: {:?}", signature_result);

    let sig_bytes: [u8; 64] = signature_result[..]
        .try_into()
        .expect("signature must be 64 bytes");
    let signature = Signature::from_bytes(&sig_bytes);

    sk.verify(&[0, 1, 2, 3, 4, 5, 6, 7, 8], &signature).unwrap();
    println!("Signature verified");
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(4, 4);
    }
}
