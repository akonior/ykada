use std::fmt;
use std::str::FromStr;
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

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for Pin {
    type Err = PinError;

    fn from_str(pin: &str) -> Result<Self, Self::Err> {
        Self::new(pin.as_bytes().to_vec())
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pin([REDACTED])")
    }
}

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    #[error("PIN must be at least {min} bytes long", min = Pin::MIN_LENGTH)]
    TooShort,

    // A PIV PIN is 6 to 8 bytes; letters outside ASCII take 2 or more bytes each.
    #[error(
        "PIN must be at most {max} bytes long (each character outside ASCII takes 2 or more)",
        max = Pin::MAX_LENGTH
    )]
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

    // Five letters, ten bytes: the limit is in bytes, and the message must say so.
    #[test]
    fn test_pin_limit_counts_bytes() {
        let err = Pin::from_str("ąęółś").unwrap_err();
        assert_eq!(err, PinError::TooLong);
        assert!(err.to_string().contains("bytes"));
    }

    #[test]
    fn test_pin_debug_redacted() {
        let pin = Pin::from_str("123456").unwrap();
        let debug_str = format!("{:?}", pin);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("123456"));
    }

    use proptest::prelude::*;

    proptest! {
        // The PIV limit is on bytes: 6 to 8, whatever the characters.
        #[test]
        fn prop_a_pin_is_6_to_8_bytes(text in "\\PC{0,12}") {
            prop_assert_eq!(Pin::from_str(&text).is_ok(), (6..=8).contains(&text.len()));
        }
    }
}
