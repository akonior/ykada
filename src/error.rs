//! Error types for ykada library
//!
//! This module defines the error hierarchy for all ykada operations.
//! Errors are organized hierarchically and use thiserror for implementation.

use thiserror::Error;

/// Result type alias for ykada operations
///
/// This is a convenience alias for `Result<T, YkadaError>`.
pub type YkadaResult<T> = Result<T, YkadaError>;

/// Top-level error type for all ykada operations
#[derive(Error, Debug)]
pub enum YkadaError {
    /// YubiKey device errors
    #[error("YubiKey device error: {0}")]
    Device(#[from] DeviceError),

    /// Cryptographic operation errors
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    /// Domain validation errors
    #[error("Domain validation error: {0}")]
    Domain(#[from] DomainError),

    /// Key management errors
    #[error("Key management error: {0}")]
    KeyManagement(#[from] KeyManagementError),
}

/// YubiKey device-related errors
#[derive(Error, Debug)]
pub enum DeviceError {
    /// No YubiKey device found
    #[error("No YubiKey device found - please connect a YubiKey")]
    NotFound,

    /// YubiKey device connection failed
    #[error("Failed to connect to YubiKey device: {reason}")]
    ConnectionFailed { reason: String },

    /// YubiKey authentication failed
    #[error("YubiKey authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    /// PIN verification failed
    #[error("PIN verification failed: {reason}")]
    PinVerificationFailed { reason: String },

    /// Invalid PIN provided
    #[error("Invalid PIN: attempts remaining: {attempts_remaining}")]
    InvalidPin { attempts_remaining: u8 },

    /// YubiKey device is locked
    #[error("YubiKey is locked - too many failed PIN attempts")]
    DeviceLocked,

    /// Underlying yubikey crate error
    #[error("YubiKey library error: {0}")]
    YubikeyLib(String),
}

/// Cryptographic operation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Signature generation failed
    #[error("Failed to generate signature: {reason}")]
    SignatureFailed { reason: String },

    /// Signature verification failed
    #[error("Signature verification failed: {reason}")]
    VerificationFailed { reason: String },

    /// Key generation failed
    #[error("Failed to generate key: {reason}")]
    KeyGenerationFailed { reason: String },

    /// Key import failed
    #[error("Failed to import key: {reason}")]
    KeyImportFailed { reason: String },

    /// Invalid key format
    #[error("Invalid key format: {format}")]
    InvalidKeyFormat { format: String },

    /// Algorithm not supported
    #[error("Algorithm not supported: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    /// Ed25519 specific error
    #[error("Ed25519 error: {0}")]
    Ed25519(String),
}

/// Domain validation errors
#[derive(Error, Debug)]
pub enum DomainError {
    /// PIN validation error
    #[error("PIN validation error: {0}")]
    Pin(#[from] crate::model::PinError),

    /// Slot error
    #[error("Slot error: {0}")]
    Slot(#[from] crate::model::SlotError),

    /// Algorithm error
    #[error("Algorithm error: {0}")]
    Algorithm(#[from] crate::model::AlgorithmError),

    /// Policy error
    #[error("Policy error: {0}")]
    Policy(#[from] crate::model::PolicyError),

    /// Management Key error
    #[error("Management Key error: {0}")]
    ManagementKey(#[from] crate::model::ManagementKeyError),

    /// Seed phrase error
    #[error("Seed phrase error: {0}")]
    SeedPhrase(#[from] crate::model::SeedPhraseError),

    /// Derivation path error
    #[error("Derivation path error: {0}")]
    DerivationPath(#[from] crate::model::DerivationPathError),

    /// Cardano key error
    #[error("Cardano key error: {0}")]
    CardanoKey(#[from] crate::model::CardanoKeyError),
}

/// Key management errors
#[derive(Error, Debug)]
pub enum KeyManagementError {
    /// Slot already occupied
    #[error("Slot already contains a key: {slot}")]
    SlotOccupied { slot: String },

    /// Key not found in slot
    #[error("No key found in slot: {slot}")]
    KeyNotFound { slot: String },

    /// Failed to load key
    #[error("Failed to load key from {location}: {reason}")]
    LoadFailed { location: String, reason: String },

    /// Failed to store key
    #[error("Failed to store key to {destination}: {reason}")]
    StoreFailed { destination: String, reason: String },
}

/// Convert model errors to YkadaError (via DomainError)
impl From<crate::model::SeedPhraseError> for YkadaError {
    fn from(err: crate::model::SeedPhraseError) -> Self {
        YkadaError::Domain(DomainError::SeedPhrase(err))
    }
}

impl From<crate::model::DerivationPathError> for YkadaError {
    fn from(err: crate::model::DerivationPathError) -> Self {
        YkadaError::Domain(DomainError::DerivationPath(err))
    }
}

impl From<crate::model::CardanoKeyError> for YkadaError {
    fn from(err: crate::model::CardanoKeyError) -> Self {
        YkadaError::Domain(DomainError::CardanoKey(err))
    }
}

/// Convert yubikey crate errors to our error type
impl From<yubikey::Error> for YkadaError {
    fn from(err: yubikey::Error) -> Self {
        YkadaError::Device(DeviceError::YubikeyLib(err.to_string()))
    }
}

/// Convert ed25519_dalek signature errors
impl From<ed25519_dalek::SignatureError> for YkadaError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        YkadaError::Crypto(CryptoError::Ed25519(err.to_string()))
    }
}

/// Convert ed25519_dalek pkcs8 errors
impl From<ed25519_dalek::pkcs8::Error> for YkadaError {
    fn from(err: ed25519_dalek::pkcs8::Error) -> Self {
        YkadaError::Crypto(CryptoError::InvalidKeyFormat {
            format: format!("PKCS8: {}", err),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = YkadaError::Device(DeviceError::NotFound);
        assert!(err.to_string().contains("No YubiKey device found"));
    }

    #[test]
    fn test_pin_error_conversion() {
        let pin_err = crate::model::PinError::TooShort;
        let domain_err = DomainError::Pin(pin_err);
        let ykada_err = YkadaError::Domain(domain_err);
        assert!(ykada_err.to_string().contains("PIN"));
    }

    #[test]
    fn test_result_type_alias() {
        let result: YkadaResult<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);

        let result: YkadaResult<i32> = Err(YkadaError::Device(DeviceError::NotFound));
        assert!(result.is_err());
    }
}
