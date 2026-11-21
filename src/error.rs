use thiserror::Error;

pub type YkadaResult<T> = Result<T, YkadaError>;

#[derive(Error, Debug)]
pub enum YkadaError {
    #[error("Policy error: {0}")]
    Policy(#[from] crate::model::PolicyError),

    #[error("Management Key error: {0}")]
    ManagementKey(#[from] crate::model::ManagementKeyError),

    #[error("Seed phrase error: {0}")]
    SeedPhrase(#[from] crate::model::SeedPhraseError),

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

    #[error("Invalid key format: {format}")]
    InvalidKeyFormat { format: String },

    #[error("Transaction error: {0}")]
    Tx(String),

    #[error("insufficient funds: have {have} lovelace, need {need}")]
    InsufficientFunds { have: u64, need: u64 },

    #[error("Wallet error: {0}")]
    WalletState(String),

    #[error("Signature verification failed: device signature does not match the transaction")]
    SignatureVerificationFailed,

    #[error("Network error: {0}")]
    Network(String),

    #[error("Network error: {0}")]
    UreqError(Box<ureq::Error>),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Address error: {0}")]
    Address(#[from] pallas_addresses::Error),
}

impl From<ureq::Error> for YkadaError {
    fn from(e: ureq::Error) -> Self {
        YkadaError::UreqError(Box::new(e))
    }
}
