//! Public API for ykada library
//!
//! This module provides high-level, convenient functions for common operations.

use crate::adapters::PivDeviceFinder;
use crate::error::YkadaResult;
use crate::ports::KeyConfig;
use crate::use_cases::{
    generate_key as generate_key_use_case,
    import_private_key_from_seed_phrase as import_private_key_from_seed_phrase_use_case,
    import_private_key_in_der_format as import_private_key_in_der_format_use_case,
};
use ed25519_dalek::VerifyingKey;

pub use crate::model::*;

/// Generate a new Ed25519 keypair on the first available YubiKey
///
/// This is a convenience function that uses default configuration:
/// - Default signing slot (9c)
/// - Ed25519 algorithm (Cardano only)
/// - Recommended Cardano policies (PIN Always, Touch Always)
/// - Default management key
///
/// # Returns
///
/// The verifying key (public key) of the generated keypair
///
/// # Errors
///
/// Returns errors if:
/// - No YubiKey device is found
/// - Authentication fails
/// - Key generation fails (e.g., slot already occupied)
pub fn generate_key() -> YkadaResult<VerifyingKey> {
    generate_key_with_config(KeyConfig::default(), None)
}

/// Generate a new Ed25519 keypair on the first available YubiKey with custom configuration
///
/// Note: Only Ed25519 is supported (Cardano requirement).
///
/// # Arguments
///
/// * `config` - Configuration for key generation (slot, policies). Algorithm is always Ed25519.
/// * `mgmt_key` - Optional management key for authentication (uses default if None)
///
/// # Returns
///
/// The verifying key (public key) of the generated keypair
///
/// # Errors
///
/// Returns errors if:
/// - No YubiKey device is found
/// - Authentication fails
/// - Key generation fails (e.g., slot already occupied)
pub fn generate_key_with_config(
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey> {
    let finder = PivDeviceFinder;
    generate_key_use_case(&finder, config, mgmt_key)
}

pub fn import_private_key_in_der_format(
    der: DerPrivateKey,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey> {
    let finder = PivDeviceFinder;
    import_private_key_in_der_format_use_case(&finder, der, config, mgmt_key)
}

/// Import a private key derived from a BIP39 seed phrase into the first available YubiKey
///
/// This function derives a Cardano key using:
/// - CIP-3 (Icarus) master key generation from the seed phrase
/// - CIP-1852 (BIP32-Ed25519) hierarchical derivation along the specified path
///
/// # Arguments
///
/// * `seed_phrase` - BIP39 mnemonic seed phrase (12, 15, 18, 21, or 24 words)
/// * `passphrase` - Optional passphrase (empty string if none)
/// * `path` - Derivation path (defaults to `m/1852'/1815'/0'/0/0` if None)
/// * `config` - Configuration for key storage (slot, policies)
/// * `mgmt_key` - Optional management key (uses default if None)
///
/// # Returns
///
/// The verifying key (public key) read back from the device
///
/// # Errors
///
/// Returns errors if:
/// - Seed phrase is invalid
/// - Derivation path is invalid
/// - Device authentication fails
/// - Key import fails
/// - Public key verification fails
pub fn import_private_key_from_seed_phrase(
    seed_phrase: &str,
    passphrase: &str,
    path: Option<&str>,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey> {
    let finder = PivDeviceFinder;
    import_private_key_from_seed_phrase_use_case(
        &finder,
        seed_phrase,
        passphrase,
        path,
        config,
        mgmt_key,
    )
}
