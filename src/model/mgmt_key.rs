use std::convert::TryFrom;
use std::fmt;

use thiserror::Error;

// The PIV management key: 16, 24 or 32 bytes (AES-128, AES-192 or 3DES, AES-256). Which
// algorithm a 24-byte key uses is asked from the YubiKey when authenticating.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagementKey(Vec<u8>);

impl ManagementKey {
    pub const VALID_LENGTHS: [usize; 3] = [16, 24, 32];

    // The factory key, kept by most YubiKeys until someone changes it.
    const FACTORY_DEFAULT: [u8; 24] = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];

    pub fn new(key: Vec<u8>) -> Result<Self, ManagementKeyError> {
        match Self::VALID_LENGTHS.contains(&key.len()) {
            true => Ok(Self(key)),
            false => Err(ManagementKeyError::InvalidLength { actual: key.len() }),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_factory_default(&self) -> bool {
        self.0 == Self::FACTORY_DEFAULT
    }
}

impl fmt::Debug for ManagementKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManagementKey([REDACTED])")
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ManagementKeyError {
    #[error("Management Key must be 16, 24 or 32 bytes (32, 48 or 64 hex digits), got {actual}")]
    InvalidLength { actual: usize },

    #[error("Invalid Management Key material: {reason}")]
    InvalidMaterial { reason: String },
}

// Hex as ykman prints it, or with spaces or line breaks between the digits.
impl TryFrom<String> for ManagementKey {
    type Error = ManagementKeyError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let digits: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        hex::decode(&digits)
            .map_err(|e| ManagementKeyError::InvalidMaterial {
                reason: e.to_string(),
            })
            .and_then(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mgmt_key_from_hex() {
        assert!(ManagementKey::try_from("01".repeat(24)).is_ok());
    }

    // AES-128 and AES-256 keys are as valid as the AES-192 default.
    #[test]
    fn test_every_piv_key_length_is_accepted() {
        [16, 24, 32].into_iter().for_each(|bytes| {
            assert!(
                ManagementKey::try_from("ab".repeat(bytes)).is_ok(),
                "{bytes} bytes"
            );
        });
    }

    #[test]
    fn test_mgmt_key_invalid_length() {
        assert_eq!(
            ManagementKey::try_from("01".repeat(20)).unwrap_err(),
            ManagementKeyError::InvalidLength { actual: 20 }
        );
    }

    #[test]
    fn test_spaces_and_line_breaks_between_digits_are_accepted() {
        let spaced = format!("{}\n", "0102 0304 ".repeat(6));
        assert_eq!(
            ManagementKey::try_from(spaced).unwrap().as_bytes().len(),
            24
        );
    }

    #[test]
    fn test_factory_default_is_recognised() {
        let factory = "010203040506070801020304050607080102030405060708".to_string();
        assert!(ManagementKey::try_from(factory)
            .unwrap()
            .is_factory_default());
        assert!(!ManagementKey::new(vec![7; 24])
            .unwrap()
            .is_factory_default());
    }

    #[test]
    fn test_mgmt_key_debug_redacted() {
        let debug_str = format!("{:?}", ManagementKey::new(vec![7u8; 24]).unwrap());
        assert!(debug_str.contains("REDACTED"));
    }
}
