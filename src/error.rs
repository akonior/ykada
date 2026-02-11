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

    #[error("YubiKey authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Ed25519 signature error: {0}")]
    Ed25519SignatureError(#[from] ed25519_dalek::SignatureError),

    #[error("Ed25519 PKCS8 error: {0}")]
    Ed25519Pkcs8Error(#[from] ed25519_dalek::pkcs8::Error),

    #[error("Invalid key format: {format}")]
    InvalidKeyFormat { format: String },
}
