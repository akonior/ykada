//! KeyManager trait - capability to manage keys (import, generate)

use crate::error::YkadaResult;
use crate::model::{Algorithm, PinPolicy, Slot, TouchPolicy};
use ed25519_dalek::{SigningKey, VerifyingKey};

/// Configuration for key import/generation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyConfig {
    /// Slot to store the key in
    pub slot: Slot,
    /// Algorithm to use
    pub algorithm: Algorithm,
    /// PIN policy for key usage
    pub pin_policy: PinPolicy,
    /// Touch policy for key usage
    pub touch_policy: TouchPolicy,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            slot: Slot::default_signing(),
            algorithm: Algorithm::default_cardano(),
            pin_policy: PinPolicy::recommended_cardano(),
            touch_policy: TouchPolicy::recommended_cardano(),
        }
    }
}

/// Capability to manage keys (import, generate, list)
///
/// This trait abstracts key management operations on YubiKey.
/// Works with any key storage mechanism (PIV slots, OpenPGP keys, etc.)
pub trait KeyManager {
    /// Import a signing key into the YubiKey
    ///
    /// # Arguments
    ///
    /// * `key` - The signing key to import
    /// * `config` - Configuration for key storage
    ///
    /// # Returns
    ///
    /// The verifying key (public key) corresponding to the imported key
    ///
    /// # Errors
    ///
    /// Returns errors if:
    /// - Device is not authenticated
    /// - Slot is already occupied
    /// - Key import fails
    fn import_key(&mut self, key: SigningKey, config: KeyConfig) -> YkadaResult<VerifyingKey>;

    /// Generate a new keypair on the YubiKey
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for key generation and storage
    ///
    /// # Returns
    ///
    /// The verifying key (public key) of the generated keypair
    ///
    /// # Errors
    ///
    /// Returns errors if:
    /// - Device is not authenticated
    /// - Slot is already occupied
    /// - Key generation fails
    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<VerifyingKey>;
}
