use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fmt;
use thiserror::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519PrivateKey([u8; 32]);

impl Ed25519PrivateKey {
    pub fn from_slice(key: &[u8]) -> Result<Self, KeyMaterialError> {
        if key.len() != 32 {
            return Err(KeyMaterialError::InvalidLength {
                expected: 32,
                actual: key.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(key);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
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

#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    pub fn from_slice(key: &[u8]) -> Result<Self, KeyMaterialError> {
        if key.len() != 32 {
            return Err(KeyMaterialError::InvalidLength {
                expected: 32,
                actual: key.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(key);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(&self.0[..8]))
    }
}

impl From<VerifyingKey> for Ed25519PublicKey {
    fn from(key: VerifyingKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl From<&VerifyingKey> for Ed25519PublicKey {
    fn from(key: &VerifyingKey) -> Self {
        Self(*key.as_bytes())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519KeyPair {
    private: Ed25519PrivateKey,
    public: Ed25519PublicKey,
}

impl Ed25519KeyPair {
    pub fn new(private: Ed25519PrivateKey, public: Ed25519PublicKey) -> Self {
        Self { private, public }
    }

    pub fn private(&self) -> &Ed25519PrivateKey {
        &self.private
    }

    pub fn public(&self) -> &Ed25519PublicKey {
        &self.public
    }
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private: [REDACTED], public: {} }}",
            hex::encode(&self.public.0[..8])
        )
    }
}

impl From<SigningKey> for Ed25519KeyPair {
    fn from(key: SigningKey) -> Self {
        let verifying_key = key.verifying_key();
        Self {
            private: Ed25519PrivateKey::from(&key),
            public: Ed25519PublicKey::from(&verifying_key),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DerPrivateKey(pub Vec<u8>);

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterialError {
    #[error("Key must be exactly {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Invalid SPKI format: {reason}")]
    InvalidSpkiFormat { reason: String },
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
    fn test_public_key_from_slice_valid() {
        let bytes = [0u8; 32];
        assert!(Ed25519PublicKey::from_slice(&bytes).is_ok());
    }

    #[test]
    fn test_public_key_from_slice_invalid_length() {
        let bytes = [0u8; 16];
        assert_eq!(
            Ed25519PublicKey::from_slice(&bytes).unwrap_err(),
            KeyMaterialError::InvalidLength {
                expected: 32,
                actual: 16
            }
        );
    }

    #[test]
    fn test_public_key_from_verifying_key() {
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();
        let public_key = Ed25519PublicKey::from(&verifying_key);
        assert_eq!(public_key.as_bytes(), verifying_key.as_bytes());
    }

    #[test]
    fn test_key_pair_from_signing_key() {
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();
        let signing_key_bytes = *signing_key.as_bytes();
        let key_pair = Ed25519KeyPair::from(signing_key);

        assert_eq!(key_pair.private().as_bytes(), &signing_key_bytes);
        assert_eq!(key_pair.public().as_bytes(), verifying_key.as_bytes());
    }

    #[test]
    fn test_key_pair_new() {
        let private = Ed25519PrivateKey::from_slice(&[1u8; 32]).unwrap();
        let public = Ed25519PublicKey::from_slice(&[2u8; 32]).unwrap();
        let key_pair = Ed25519KeyPair::new(private.clone(), public.clone());

        assert_eq!(key_pair.private(), &private);
        assert_eq!(key_pair.public(), &public);
    }

    #[test]
    fn test_private_key_debug_redacted() {
        let key = Ed25519PrivateKey::from_slice(&[1u8; 32]).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_public_key_debug_shows_partial() {
        let key = Ed25519PublicKey::from_slice(&[1u8; 32]).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("PublicKey"));
    }
}
