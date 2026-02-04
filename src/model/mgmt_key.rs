//! Management Key type for YubiKey PIV authentication
//!
//! This module defines a domain type for the PIV Management Key and
//! provides idiomatic conversions to the yubikey crate's `MgmKey`.

use std::convert::TryFrom;
use std::fmt;

use thiserror::Error;
use yubikey::{MgmAlgorithmId, MgmKey};

/// Management Key for YubiKey PIV authentication
///
/// A Management Key is a 24-byte key (3 DES keys of 8 bytes each) used to
/// authenticate for key management operations on the YubiKey.
/// This type ensures key validity at construction time.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagementKey([u8; 24]);

impl ManagementKey {
    /// Management Key length in bytes
    pub const LENGTH: usize = 24;

    pub const fn new(key: [u8; 24]) -> Self {
        Self(key)
    }

    /// Create a Management Key from a byte slice
    ///
    /// # Errors
    ///
    /// Returns an error if the slice length is not exactly 24 bytes
    pub fn from_slice(key: &[u8]) -> Result<Self, ManagementKeyError> {
        if key.len() != Self::LENGTH {
            return Err(ManagementKeyError::InvalidLength {
                expected: Self::LENGTH,
                actual: key.len(),
            });
        }
        let mut bytes = [0u8; 24];
        bytes.copy_from_slice(key);
        Ok(Self(bytes))
    }

    /// Get the Management Key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the Management Key as an array reference
    pub fn as_array(&self) -> &[u8; 24] {
        &self.0
    }
}

impl fmt::Debug for ManagementKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManagementKey([REDACTED])")
    }
}

/// Errors that can occur when creating or converting a Management Key
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ManagementKeyError {
    /// Management Key has invalid length
    #[error("Management Key must be exactly {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Underlying yubikey crate rejected the key material
    #[error("Invalid Management Key material: {reason}")]
    InvalidMaterial { reason: String },
}

/// Fallible conversion from domain `ManagementKey` to yubikey crate's `MgmKey`.
///
/// This keeps the conversion logic close to the domain type and allows
/// call-sites to use idiomatic `try_from` / `try_into` / `?` patterns.
impl TryFrom<&ManagementKey> for MgmKey {
    type Error = ManagementKeyError;

    fn try_from(key: &ManagementKey) -> Result<Self, Self::Error> {
        MgmKey::from_bytes(key.as_array(), Some(MgmAlgorithmId::Aes192)).map_err(|e| {
            ManagementKeyError::InvalidMaterial {
                reason: e.to_string(),
            }
        })
    }
}

impl TryFrom<ManagementKey> for MgmKey {
    type Error = ManagementKeyError;

    fn try_from(key: ManagementKey) -> Result<Self, Self::Error> {
        MgmKey::try_from(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mgmt_key_valid() {
        let key_bytes = [0u8; 24];
        let key = ManagementKey::new(key_bytes);
        assert_eq!(key.as_bytes().len(), 24);
    }

    #[test]
    fn test_mgmt_key_from_slice_valid() {
        let key_bytes = [0u8; 24];
        assert!(ManagementKey::from_slice(&key_bytes).is_ok());
    }

    #[test]
    fn test_mgmt_key_from_slice_invalid_length() {
        let key_bytes = [0u8; 16];
        assert_eq!(
            ManagementKey::from_slice(&key_bytes).unwrap_err(),
            ManagementKeyError::InvalidLength {
                expected: 24,
                actual: 16
            }
        );
    }

    #[test]
    fn test_mgmt_key_debug_redacted() {
        let key = ManagementKey::new([0u8; 24]);
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("REDACTED"));
    }
}
