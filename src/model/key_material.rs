//! Key material types (PrivateKey, PublicKey, KeyPair)
//!
//! These types wrap raw key bytes to prevent primitive obsession and ensure
//! type safety when working with cryptographic keys.

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fmt;
use thiserror::Error;

/// Ed25519 private key (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    /// Create a new PrivateKey from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the slice length is not exactly 32 bytes
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

    /// Get the private key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the private key as an array reference
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

impl From<SigningKey> for PrivateKey {
    fn from(key: SigningKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl From<&SigningKey> for PrivateKey {
    fn from(key: &SigningKey) -> Self {
        Self(*key.as_bytes())
    }
}

/// Ed25519 public key (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Create a new PublicKey from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the slice length is not exactly 32 bytes
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

    /// Get the public key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the public key as an array reference
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(&self.0[..8]))
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(key: VerifyingKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(key: &VerifyingKey) -> Self {
        Self(*key.as_bytes())
    }
}

// Conversion from SPKI is handled in logic/key_conversion.rs
// to avoid direct dependency on x509_cert in model layer

/// Ed25519 key pair (private + public key)
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey,
}

impl KeyPair {
    /// Create a new KeyPair from private and public keys
    pub fn new(private: PrivateKey, public: PublicKey) -> Self {
        Self { private, public }
    }

    /// Get the private key
    pub fn private(&self) -> &PrivateKey {
        &self.private
    }

    /// Get the public key
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private: [REDACTED], public: {} }}",
            hex::encode(&self.public.0[..8])
        )
    }
}

impl From<SigningKey> for KeyPair {
    fn from(key: SigningKey) -> Self {
        let verifying_key = key.verifying_key();
        Self {
            private: PrivateKey::from(&key),
            public: PublicKey::from(&verifying_key),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DerPrivateKey(pub Vec<u8>);

/// Errors that can occur when working with key material
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterialError {
    /// Key has invalid length
    #[error("Key must be exactly {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// SPKI format is invalid or unsupported
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
        assert!(PrivateKey::from_slice(&bytes).is_ok());
    }

    #[test]
    fn test_private_key_from_slice_invalid_length() {
        let bytes = [0u8; 16];
        assert_eq!(
            PrivateKey::from_slice(&bytes).unwrap_err(),
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
        let private_key = PrivateKey::from(&signing_key);
        assert_eq!(private_key.as_bytes(), signing_key.as_bytes());
    }

    #[test]
    fn test_public_key_from_slice_valid() {
        let bytes = [0u8; 32];
        assert!(PublicKey::from_slice(&bytes).is_ok());
    }

    #[test]
    fn test_public_key_from_slice_invalid_length() {
        let bytes = [0u8; 16];
        assert_eq!(
            PublicKey::from_slice(&bytes).unwrap_err(),
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
        let public_key = PublicKey::from(&verifying_key);
        assert_eq!(public_key.as_bytes(), verifying_key.as_bytes());
    }

    #[test]
    fn test_key_pair_from_signing_key() {
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();
        let signing_key_bytes = *signing_key.as_bytes();
        let key_pair = KeyPair::from(signing_key);

        assert_eq!(key_pair.private().as_bytes(), &signing_key_bytes);
        assert_eq!(key_pair.public().as_bytes(), verifying_key.as_bytes());
    }

    #[test]
    fn test_key_pair_new() {
        let private = PrivateKey::from_slice(&[1u8; 32]).unwrap();
        let public = PublicKey::from_slice(&[2u8; 32]).unwrap();
        let key_pair = KeyPair::new(private.clone(), public.clone());

        assert_eq!(key_pair.private(), &private);
        assert_eq!(key_pair.public(), &public);
    }

    #[test]
    fn test_private_key_debug_redacted() {
        let key = PrivateKey::from_slice(&[1u8; 32]).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_public_key_debug_shows_partial() {
        let key = PublicKey::from_slice(&[1u8; 32]).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("PublicKey"));
    }
}
