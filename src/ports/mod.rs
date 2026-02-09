pub(crate) mod contract_tests;
mod device_finder;
mod key_manager;
mod mgmt_key_verifier;
mod pin_verifier;
mod signer;

pub use device_finder::DeviceFinder;
pub use key_manager::{KeyConfig, KeyManager};
pub use mgmt_key_verifier::ManagementKeyVerifier;
pub use pin_verifier::PinVerifier;
pub use signer::Signer;

pub trait YubiKeyOps: PinVerifier + ManagementKeyVerifier + KeyManager + Signer {}

impl<T> YubiKeyOps for T where T: PinVerifier + ManagementKeyVerifier + KeyManager + Signer {}
