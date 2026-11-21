use std::convert::TryFrom;
use std::fmt;

use thiserror::Error;
use yubikey::{MgmAlgorithmId, MgmKey};

#[derive(Clone, PartialEq, Eq)]
pub struct ManagementKey([u8; 24]);

impl ManagementKey {
    pub const fn new(key: [u8; 24]) -> Self {
        Self(key)
    }
}

impl fmt::Debug for ManagementKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManagementKey([REDACTED])")
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ManagementKeyError {
    #[error("Management Key must be exactly 24 bytes, got {actual}")]
    InvalidLength { actual: usize },

    #[error("Invalid Management Key material: {reason}")]
    InvalidMaterial { reason: String },
}

impl TryFrom<&ManagementKey> for MgmKey {
    type Error = ManagementKeyError;

    fn try_from(key: &ManagementKey) -> Result<Self, Self::Error> {
        MgmKey::from_bytes(key.0, Some(MgmAlgorithmId::Aes192)).map_err(|e| {
            ManagementKeyError::InvalidMaterial {
                reason: e.to_string(),
            }
        })
    }
}

impl TryFrom<String> for ManagementKey {
    type Error = ManagementKeyError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s.trim()).map_err(|e| ManagementKeyError::InvalidMaterial {
            reason: e.to_string(),
        })?;
        <[u8; 24]>::try_from(bytes.as_slice())
            .map(Self)
            .map_err(|_| ManagementKeyError::InvalidLength {
                actual: bytes.len(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mgmt_key_from_hex() {
        assert!(ManagementKey::try_from("01".repeat(24)).is_ok());
    }

    #[test]
    fn test_mgmt_key_invalid_length() {
        assert_eq!(
            ManagementKey::try_from("01".repeat(16)).unwrap_err(),
            ManagementKeyError::InvalidLength { actual: 16 }
        );
    }

    #[test]
    fn test_mgmt_key_debug_redacted() {
        let debug_str = format!("{:?}", ManagementKey::new([7u8; 24]));
        assert!(debug_str.contains("REDACTED"));
    }
}
