// Legacy functions - these will be refactored to use trait-based approach
// TODO: Refactor to use yubikey::ops traits

use std::convert::TryInto;

use ed25519_dalek::pkcs8::DecodePrivateKey;
use tracing::{debug, info};

// Import yubikey crate types - these are used by legacy functions
// Use fully qualified paths to avoid conflict with our yubikey module
use ::yubikey::piv::{import_cv_key, sign_data};
use ::yubikey::{Context, MgmKey, PinPolicy as YkPinPolicy, TouchPolicy as YkTouchPolicy, YubiKey};

// Use model types and convert - this is the proper way going forward
use crate::model::{Algorithm, Slot};

use ed25519_dalek::{SecretKey, Signature, SigningKey, VerifyingKey};

mod adapters;
pub mod api;
pub mod error;
mod logic;
pub mod model;
pub mod ports;
pub mod use_cases;

// Re-export commonly used types
pub use error::{YkadaError, YkadaResult};

// Re-export public API
pub use api::{generate_key, generate_key_with_config};

const DEFAULT_PIN: &[u8] = b"123456";
const DEFAULT_SECRET_KEY: &SecretKey = &[0u8; 32];

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

    debug!("YubiKey: {:?}", yubikey);

    yubikey
        .authenticate(&MgmKey::get_default(&yubikey).unwrap())
        .unwrap();

    debug!("Signing key: {:?}", sk);

    let key_data = sk.as_bytes();

    import_cv_key(
        &mut yubikey,
        Slot::default_signing().to_yubikey_slot_id(),
        Algorithm::default_cardano().to_yubikey_algorithm_id(),
        key_data,
        YkTouchPolicy::Never,
        YkPinPolicy::Always,
    )
    .unwrap();

    info!("Imported private key to YubiKey");

    sk.verifying_key()
}

pub fn sign_raw_data(data: &[u8]) -> Signature {
    let mut yubikey = find_first_yubikey();

    yubikey.verify_pin(DEFAULT_PIN).unwrap();
    debug!("PIN verified");

    let signature_yubikey: Vec<u8> = sign_data(
        &mut yubikey,
        data,
        Algorithm::default_cardano().to_yubikey_algorithm_id(),
        Slot::default_signing().to_yubikey_slot_id(),
    )
    .unwrap()
    .to_vec();
    debug!("Result of sign_data: {:?}", signature_yubikey);

    let sig_bytes: [u8; Signature::BYTE_SIZE] = signature_yubikey[..]
        .try_into()
        .expect("signature must be 64 bytes");

    sig_bytes.into()
}

pub fn load_der_to_yubikey(_der: &[u8]) {
    // Parse DER and extract EdDSA (Ed25519) private key
    let signing_key =
        SigningKey::from_pkcs8_der(_der).expect("Failed to parse DER as Ed25519 private key");

    debug!("Imported private key from DER: {:?}", signing_key);

    load_sk_to_yubikey(signing_key);

    debug!("Loaded private key to YubiKey");
}

pub fn sign_bin_data(buf: &[u8]) -> [u8; Signature::BYTE_SIZE] {
    let signature = sign_raw_data(buf);
    debug!("Signed data: {:?}", signature);
    signature.to_bytes()
}
