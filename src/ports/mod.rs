//! Ports (algebras/traits) for YubiKey operations
//!
//! These traits define the capabilities required for YubiKey operations.
//! They represent ports in hexagonal architecture - the core depends on
//! these abstractions, not concrete implementations.
//!
//! These traits are PIV/OpenPGP agnostic - they define what operations
//! can be performed, not how they are implemented.

mod device_finder;
mod pin_verifier;
mod mgmt_key_verifier;
mod key_manager;
mod signer;

pub use device_finder::DeviceFinder;
pub use pin_verifier::PinVerifier;
pub use mgmt_key_verifier::ManagementKeyVerifier;
pub use key_manager::{KeyConfig, KeyManager};
pub use signer::Signer;

/// Combined trait for all YubiKey operations
///
/// This trait combines all capabilities into a single interface.
/// A device handle typically implements this.
pub trait YubiKeyOps: PinVerifier + ManagementKeyVerifier + KeyManager + Signer {}

// Blanket implementation for types that implement all operation traits
impl<T> YubiKeyOps for T where T: PinVerifier + ManagementKeyVerifier + KeyManager + Signer {}
