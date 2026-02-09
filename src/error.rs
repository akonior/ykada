
use thiserror::Error;

pub type YkadaResult<T> = Result<T, YkadaError>;

#[derive(Error, Debug)]
pub enum YkadaError {
    #[error("YubiKey device error: {0}")]
    Device(#[from] DeviceError),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Domain validation error: {0}")]
    Domain(#[from] DomainError),

    #[error("Key management error: {0}")]
    KeyManagement(#[from] KeyManagementError),
}

#[derive(Error, Debug)]
pub enum DeviceError {
    #[error("No YubiKey device found - please connect a YubiKey")]
    NotFound,

    #[error("Failed to connect to YubiKey device: {reason}")]
    ConnectionFailed { reason: String },

    #[error("YubiKey authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("PIN verification failed: {reason}")]
    PinVerificationFailed { reason: String },

    #[error("Invalid PIN: attempts remaining: {attempts_remaining}")]
    InvalidPin { attempts_remaining: u8 },

    #[error("YubiKey is locked - too many failed PIN attempts")]
    DeviceLocked,

    #[error("YubiKey library error: {0}")]
    YubikeyLib(String),
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Failed to generate signature: {reason}")]
    SignatureFailed { reason: String },

    #[error("Signature verification failed: {reason}")]
    VerificationFailed { reason: String },

    #[error("Failed to generate key: {reason}")]
    KeyGenerationFailed { reason: String },

    #[error("Failed to import key: {reason}")]
    KeyImportFailed { reason: String },

    #[error("Invalid key format: {format}")]
    InvalidKeyFormat { format: String },

    #[error("Algorithm not supported: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    #[error("Ed25519 error: {0}")]
    Ed25519(String),
}

#[derive(Error, Debug)]
pub enum DomainError {
    #[error("PIN validation error: {0}")]
    Pin(#[from] crate::model::PinError),

    #[error("Slot error: {0}")]
    Slot(#[from] crate::model::SlotError),

    #[error("Algorithm error: {0}")]
    Algorithm(#[from] crate::model::AlgorithmError),

    #[error("Policy error: {0}")]
    Policy(#[from] crate::model::PolicyError),

    #[error("Management Key error: {0}")]
    ManagementKey(#[from] crate::model::ManagementKeyError),

    #[error("Seed phrase error: {0}")]
    SeedPhrase(#[from] crate::model::SeedPhraseError),

    #[error("Derivation path error: {0}")]
    DerivationPath(#[from] crate::model::DerivationPathError),

    #[error("Cardano key error: {0}")]
    CardanoKey(#[from] crate::model::CardanoKeyError),
}

#[derive(Error, Debug)]
pub enum KeyManagementError {
    #[error("Slot already contains a key: {slot}")]
    SlotOccupied { slot: String },

    #[error("No key found in slot: {slot}")]
    KeyNotFound { slot: String },

    #[error("Failed to load key from {location}: {reason}")]
    LoadFailed { location: String, reason: String },

    #[error("Failed to store key to {destination}: {reason}")]
    StoreFailed { destination: String, reason: String },
}

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

impl From<yubikey::Error> for YkadaError {
    fn from(err: yubikey::Error) -> Self {
        YkadaError::Device(DeviceError::YubikeyLib(err.to_string()))
    }
}

impl From<ed25519_dalek::SignatureError> for YkadaError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        YkadaError::Crypto(CryptoError::Ed25519(err.to_string()))
    }
}

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
