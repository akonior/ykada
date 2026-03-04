use bech32::ToBase32;
use ed25519_dalek::{SigningKey, VerifyingKey};
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("BECH32 encoding error: {0}")]
pub struct Bech32Error(String);

impl From<bech32::Error> for Bech32Error {
    fn from(err: bech32::Error) -> Self {
        Bech32Error(err.to_string())
    }
}

pub trait Bech32Encodable {
    fn to_bech32(&self) -> Result<String, Bech32Error>;
}

impl Bech32Encodable for VerifyingKey {
    fn to_bech32(&self) -> Result<String, Bech32Error> {
        let bytes = self.as_bytes();
        bech32::encode("addr_vk", bytes.to_base32(), bech32::Variant::Bech32)
            .map_err(Bech32Error::from)
    }
}

impl Bech32Encodable for SigningKey {
    fn to_bech32(&self) -> Result<String, Bech32Error> {
        let bytes = self.as_bytes();
        bech32::encode("addr_sk", bytes.to_base32(), bech32::Variant::Bech32)
            .map_err(Bech32Error::from)
    }
}

pub struct StakeVerifyingKey(pub VerifyingKey);

impl Bech32Encodable for StakeVerifyingKey {
    fn to_bech32(&self) -> Result<String, Bech32Error> {
        bech32::encode(
            "stake_vk",
            self.0.as_bytes().to_base32(),
            bech32::Variant::Bech32,
        )
        .map_err(Bech32Error::from)
    }
}

pub fn decode_bech32_address(bech32_str: &str) -> Result<Vec<u8>, Bech32Error> {
    let (_, data, _) =
        bech32::decode(bech32_str).map_err(|e| Bech32Error(format!("decode error: {e}")))?;
    bech32::convert_bits(&data, 5, 8, false)
        .map_err(|e| Bech32Error(format!("convert_bits error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::FromBase32;
    use ed25519_dalek::SecretKey;

    #[test]
    fn test_verifying_key_bech32_encoding() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = 1;
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();

        let encoded = verifying_key.to_bech32();
        assert!(encoded.is_ok());
        let encoded_str = encoded.unwrap();
        assert!(encoded_str.starts_with("addr_vk"));
    }

    #[test]
    fn test_signing_key_bech32_encoding() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = 1;
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));

        let encoded = signing_key.to_bech32();
        assert!(encoded.is_ok());
        let encoded_str = encoded.unwrap();
        assert!(encoded_str.starts_with("addr_sk"));
    }

    #[test]
    fn test_bech32_round_trip_verifying_key() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = 1;
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();

        let encoded = verifying_key.to_bech32().unwrap();
        let (hrp, data, variant) = bech32::decode(&encoded).unwrap();
        assert_eq!(hrp, "addr_vk");
        assert_eq!(variant, bech32::Variant::Bech32);

        let decoded_bytes: Vec<u8> = Vec::from_base32(&data).unwrap();
        assert_eq!(decoded_bytes.len(), 32);
        assert_eq!(decoded_bytes.as_slice(), verifying_key.as_bytes());
    }

    #[test]
    fn test_bech32_round_trip_signing_key() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = 1;
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));

        let encoded = signing_key.to_bech32().unwrap();
        let (hrp, data, variant) = bech32::decode(&encoded).unwrap();
        assert_eq!(hrp, "addr_sk");
        assert_eq!(variant, bech32::Variant::Bech32);

        let decoded_bytes: Vec<u8> = Vec::from_base32(&data).unwrap();
        assert_eq!(decoded_bytes.len(), 32);
        assert_eq!(decoded_bytes.as_slice(), signing_key.as_bytes());
    }

    #[test]
    fn test_stake_verifying_key_bech32_prefix() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = 1;
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();

        let encoded = StakeVerifyingKey(verifying_key).to_bech32().unwrap();
        assert!(encoded.starts_with("stake_vk"), "got: {}", encoded);
    }

    #[test]
    fn test_decode_bech32_address_valid() {
        // Known testnet address — 57 bytes (header + 28 payment hash + 28 stake hash)
        let addr = "addr_test1qrfw6ye0m7f2kvqapnkp7jzlfydq0h6j5rnsvj2wm9vlhg0y86x894xrsh5xu8qlm6yld03hp7sx6u552w6uupd799fqz0vpte";
        let decoded = decode_bech32_address(addr).expect("should decode");
        assert_eq!(decoded.len(), 57, "Cardano base address must be 57 bytes");
    }

    #[test]
    fn test_decode_bech32_address_invalid() {
        let result = decode_bech32_address("not_a_valid_bech32!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_stake_verifying_key_round_trip() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = 1;
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();

        let encoded = StakeVerifyingKey(verifying_key).to_bech32().unwrap();
        let (hrp, data, variant) = bech32::decode(&encoded).unwrap();
        assert_eq!(hrp, "stake_vk");
        assert_eq!(variant, bech32::Variant::Bech32);

        let decoded_bytes: Vec<u8> = Vec::from_base32(&data).unwrap();
        assert_eq!(decoded_bytes.len(), 32);
        assert_eq!(decoded_bytes.as_slice(), verifying_key.as_bytes());
    }
}
