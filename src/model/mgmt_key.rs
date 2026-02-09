use std::convert::TryFrom;
use std::fmt;

use thiserror::Error;
use yubikey::{MgmAlgorithmId, MgmKey};

#[derive(Clone, PartialEq, Eq)]
pub struct ManagementKey([u8; 24]);

impl ManagementKey {
    pub const LENGTH: usize = 24;

    pub const fn new(key: [u8; 24]) -> Self {
        Self(key)
    }

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

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_array(&self) -> &[u8; 24] {
        &self.0
    }
}

impl fmt::Debug for ManagementKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManagementKey([REDACTED])")
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ManagementKeyError {
    #[error("Management Key must be exactly {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Invalid Management Key material: {reason}")]
    InvalidMaterial { reason: String },
}

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

impl TryFrom<String> for ManagementKey {
    type Error = ManagementKeyError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(&s).map_err(|e| ManagementKeyError::InvalidMaterial {
            reason: e.to_string(),
        })?;
        ManagementKey::from_slice(&bytes)
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
