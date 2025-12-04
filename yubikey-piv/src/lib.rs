use std::convert::TryInto;

use ed25519_dalek::pkcs8::DecodePrivateKey;
use log::info;
use yubikey::piv::{AlgorithmId, SlotId, import_cv_key, sign_data};
use yubikey::{Context, MgmKey, PinPolicy, TouchPolicy, YubiKey};

use ed25519_dalek::{SecretKey, Signature, SigningKey, VerifyingKey};

const DEFAULT_PIN: &[u8] = b"123456";
const DEFAULT_SECRET_KEY: &SecretKey = &[0u8; 32];

pub fn initialize_logger() {
    env_logger::init();
    info!("logger initialized");
}

pub fn find_first_yubikey() -> YubiKey {
    let mut readers = Context::open().unwrap();
    for reader in readers.iter().unwrap() {
        if let Ok(yk_found) = reader.open() {
            // println!("Connected to reader: {:?}", reader.name());
            // println!("YubiKey ATR: {:?}", yk_found);

            return yk_found;
        }
    }
    panic!("No YubiKey found");
}

pub fn initialize_yubikey() -> VerifyingKey {
    let sk = SigningKey::from_bytes(DEFAULT_SECRET_KEY);
    load_sk_to_yubikey(sk)
}

pub fn load_sk_to_yubikey(sk: SigningKey) -> VerifyingKey {
    let mut yubikey = find_first_yubikey();

    println!("YubiKey: {:?}", yubikey);

    yubikey
        .authenticate(&MgmKey::get_default(&yubikey).unwrap())
        .unwrap();

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
    let mut yubikey = find_first_yubikey();

    yubikey.verify_pin(DEFAULT_PIN).unwrap();
    // println!("PIN verified");

    let signature_yubikey: Vec<u8> =
        sign_data(&mut yubikey, data, AlgorithmId::Ed25519, SlotId::Signature)
            .unwrap()
            .to_vec();
    // println!("Result of sign_data: {:?}", signature_yubikey);

    let sig_bytes: [u8; Signature::BYTE_SIZE] = signature_yubikey[..]
        .try_into()
        .expect("signature must be 64 bytes");

    sig_bytes.into()
}

pub fn load_der_to_yubikey(_der: &[u8]) {
    // Parse DER and extract EdDSA (Ed25519) private key
    let signing_key =
        SigningKey::from_pkcs8_der(_der).expect("Failed to parse DER as Ed25519 private key");

    println!("Imported private key from DER: {:?}", signing_key);

    load_sk_to_yubikey(signing_key);

    println!("Loaded private key to YubiKey");
}

pub fn sign_bin_data(buf: &[u8]) -> [u8; Signature::BYTE_SIZE] {
    let signature = sign_raw_data(buf);
    // println!("Signed data: {:?}", signature);
    signature.to_bytes()
}
