use thiserror::Error;

pub type YkadaResult<T> = Result<T, YkadaError>;

#[derive(Error, Debug)]
pub enum YkadaError {
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

    #[error("YubiKey library error: {0}")]
    YubikeyLib(#[from] yubikey::Error),

    #[error("No YubiKey device found - please connect a YubiKey")]
    NotFound,

    #[error("Multiple YubiKeys detected ({count}) - please connect only one")]
    MultipleDevicesFound { count: usize },

    #[error(
        "YubiKey firmware 5.7 or later is required for Ed25519 support (found {}.{}.{})",
        found.0, found.1, found.2
    )]
    FirmwareIncompatible { found: (u8, u8, u8) },

    #[error("YubiKey authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Invalid signature: expected 64 bytes, got {actual}")]
    InvalidSignatureLength { actual: usize },

    #[error("Ed25519 signature error: {0}")]
    Ed25519SignatureError(#[from] ed25519_dalek::SignatureError),

    #[error("Ed25519 PKCS8 error: {0}")]
    Ed25519Pkcs8Error(#[from] ed25519_dalek::pkcs8::Error),

    #[error("Invalid key format: {format}")]
    InvalidKeyFormat { format: String },

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Network error: {0}")]
    UreqError(Box<ureq::Error>),

    #[error("Network error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Bech32 error: {0}")]
    Bech32(#[from] crate::logic::Bech32Error),
}

impl From<ureq::Error> for YkadaError {
    fn from(e: ureq::Error) -> Self {
        YkadaError::UreqError(Box::new(e))
    }
}
