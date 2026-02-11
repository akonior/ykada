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
}
