use ed25519_dalek::SigningKey;
use std::fmt;
use thiserror::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519PrivateKey([u8; 32]);

impl Ed25519PrivateKey {
    pub fn from_slice(key: &[u8]) -> Result<Self, KeyMaterialError> {
        let bytes: [u8; 32] = key
            .try_into()
            .map_err(|_| KeyMaterialError::InvalidLength {
                expected: 32,
                actual: key.len(),
            })?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.as_array())
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

impl From<SigningKey> for Ed25519PrivateKey {
    fn from(key: SigningKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl From<&SigningKey> for Ed25519PrivateKey {
    fn from(key: &SigningKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl From<[u8; 32]> for Ed25519PrivateKey {
    fn from(key: [u8; 32]) -> Self {
        Self(key)
    }
}

impl From<&[u8; 32]> for Ed25519PrivateKey {
    fn from(key: &[u8; 32]) -> Self {
        Self(*key)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DerPrivateKey(pub Vec<u8>);

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterialError {
    #[error("Key must be exactly {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SecretKey;
    use rand::rng;
    use rand::RngCore;

    #[test]
    fn test_private_key_from_slice_valid() {
        let bytes = [0u8; 32];
        assert!(Ed25519PrivateKey::from_slice(&bytes).is_ok());
    }

    #[test]
    fn test_private_key_from_slice_invalid_length() {
        let bytes = [0u8; 16];
        assert_eq!(
            Ed25519PrivateKey::from_slice(&bytes).unwrap_err(),
            KeyMaterialError::InvalidLength {
                expected: 32,
                actual: 16
            }
        );
    }

    #[test]
    fn test_private_key_from_signing_key() {
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let private_key = Ed25519PrivateKey::from(&signing_key);
        assert_eq!(private_key.as_bytes(), signing_key.as_bytes());
    }

    #[test]
    fn test_private_key_debug_redacted() {
        let key = Ed25519PrivateKey::from_slice(&[1u8; 32]).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("REDACTED"));
    }
}
