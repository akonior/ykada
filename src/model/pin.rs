//! PIN (Personal Identification Number) type for YubiKey authentication

use std::fmt;
use thiserror::Error;

/// PIN for YubiKey authentication
///
/// A PIN is a 6-8 digit numeric code used to authenticate to the YubiKey.
/// This type ensures PIN validity at construction time.
#[derive(Clone, PartialEq, Eq)]
pub struct Pin(Vec<u8>);

impl Pin {
    /// Default YubiKey PIN (factory default: "123456")
    pub const DEFAULT: &'static [u8] = b"123456";

    /// Minimum PIN length
    pub const MIN_LENGTH: usize = 6;

    /// Maximum PIN length
    pub const MAX_LENGTH: usize = 8;

    /// Create a new PIN from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the PIN length is not between 6-8 bytes
    pub fn new(pin: Vec<u8>) -> Result<Self, PinError> {
        if pin.len() < Self::MIN_LENGTH {
            return Err(PinError::TooShort);
        }
        if pin.len() > Self::MAX_LENGTH {
            return Err(PinError::TooLong);
        }
        Ok(Self(pin))
    }

    /// Create a PIN from a string
    ///
    /// # Errors
    ///
    /// Returns an error if the PIN length is not between 6-8 characters
    pub fn from_str(pin: &str) -> Result<Self, PinError> {
        Self::new(pin.as_bytes().to_vec())
    }

    /// Get the default PIN
    pub fn default() -> Self {
        Self(Self::DEFAULT.to_vec())
    }

    /// Get the PIN as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pin([REDACTED])")
    }
}

/// Errors that can occur when creating a PIN
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// PIN is too short (less than 6 characters)
    #[error("PIN must be at least {min} characters", min = Pin::MIN_LENGTH)]
    TooShort,

    /// PIN is too long (more than 8 characters)
    #[error("PIN must be at most {max} characters", max = Pin::MAX_LENGTH)]
    TooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_valid() {
        assert!(Pin::from_str("123456").is_ok());
        assert!(Pin::from_str("12345678").is_ok());
    }

    #[test]
    fn test_pin_too_short() {
        assert_eq!(Pin::from_str("12345").unwrap_err(), PinError::TooShort);
    }

    #[test]
    fn test_pin_too_long() {
        assert_eq!(Pin::from_str("123456789").unwrap_err(), PinError::TooLong);
    }

    #[test]
    fn test_pin_default() {
        let pin = Pin::default();
        assert_eq!(pin.as_bytes(), b"123456");
    }

    #[test]
    fn test_pin_debug_redacted() {
        let pin = Pin::default();
        let debug_str = format!("{:?}", pin);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("123456"));
    }
}
