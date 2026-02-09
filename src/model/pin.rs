
use std::fmt;
use thiserror::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct Pin(Vec<u8>);

impl Pin {
    pub const DEFAULT: &'static [u8] = b"123456";

    pub const MIN_LENGTH: usize = 6;

    pub const MAX_LENGTH: usize = 8;

    pub fn new(pin: Vec<u8>) -> Result<Self, PinError> {
        if pin.len() < Self::MIN_LENGTH {
            return Err(PinError::TooShort);
        }
        if pin.len() > Self::MAX_LENGTH {
            return Err(PinError::TooLong);
        }
        Ok(Self(pin))
    }

    pub fn from_str(pin: &str) -> Result<Self, PinError> {
        Self::new(pin.as_bytes().to_vec())
    }

    pub fn default() -> Self {
        Self(Self::DEFAULT.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pin([REDACTED])")
    }
}

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    #[error("PIN must be at least {min} characters", min = Pin::MIN_LENGTH)]
    TooShort,

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
