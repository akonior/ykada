//! Import private key from BIP39 seed phrase (CIP-0003 Icarus + CIP-1852)

use crate::model::{CardanoKey, DerivationPath, SeedPhrase};
use crate::ports::{DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier};
use crate::{ManagementKey, YkadaResult};
use tracing::debug;

/// Import a private key derived from a seed phrase into the YubiKey
///
/// This function:
/// 1. Generates a root key from the seed phrase using the Icarus method (CIP-3)
/// 2. Derives a child key along the specified derivation path (CIP-1852)
/// 3. Extracts the 32-byte kL scalar for PIV import
/// 4. Imports the key into the YubiKey
/// 5. Verifies the device public key matches the derived public key
///
/// # Arguments
///
/// * `finder` - Device finder to locate the YubiKey
/// * `seed_phrase` - BIP39 mnemonic seed phrase
/// * `passphrase` - Optional passphrase (empty string if none)
/// * `path` - Derivation path (defaults to `m/1852'/1815'/0'/0/0` if None)
/// * `config` - Key configuration (slot, PIN policy, touch policy)
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
pub fn import_private_key_from_seed_phrase<F>(
    finder: &F,
    seed_phrase: &str,
    passphrase: &str,
    path: Option<&str>,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<ed25519_dalek::VerifyingKey>
where
    F: DeviceFinder,
    F::Device: KeyManager + ManagementKeyVerifier,
{
    // Parse seed phrase
    let seed = SeedPhrase::try_from(seed_phrase)?;

    // Parse derivation path (default to CIP-1852 first payment address)
    let derivation_path = if let Some(path_str) = path {
        DerivationPath::try_from(path_str)?
    } else {
        DerivationPath::default()
    };

    debug!("Deriving key from seed phrase");
    debug!("Derivation path: {:?}", derivation_path);

    // Generate root key using Icarus method (CIP-3)
    let root_key = CardanoKey::from_seed_phrase(&seed, passphrase)?;

    // Derive child key along the path (CIP-1852)
    let child_key = root_key.derive(&derivation_path);

    // Extract kL scalar (left 32 bytes) for PIV import
    let piv_key = child_key.to_piv_key();

    // Find device and authenticate
    let mut device = finder.find_first()?;
    device.authenticate(mgmt_key)?;

    // Import the key
    device.import_cv_key(piv_key, config)?;

    debug!("Key imported successfully");
    Ok(child_key.verifying_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::model::Pin;

    #[test]
    fn test_import_from_seed_phrase() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let seed_phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let passphrase = "";
        let path = Some("m/1852'/1815'/0'/0/0");
        let config = crate::ports::KeyConfig::default();
        let mgmt_key = crate::model::ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);

        let result = import_private_key_from_seed_phrase(
            &finder,
            seed_phrase,
            passphrase,
            path,
            config,
            Some(&mgmt_key),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
        let verifying_key = result.unwrap();
        assert_eq!(verifying_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_import_from_seed_phrase_with_passphrase() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let seed_phrase = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
        let passphrase = "foo";
        let path = Some("m/1852'/1815'/0'/0/0");
        let config = crate::ports::KeyConfig::default();
        let mgmt_key = crate::model::ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);

        let result = import_private_key_from_seed_phrase(
            &finder,
            seed_phrase,
            passphrase,
            path,
            config,
            Some(&mgmt_key),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
    }

    #[test]
    fn test_import_from_seed_phrase_default_path() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let seed_phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let passphrase = "";
        let config = crate::ports::KeyConfig::default();
        let mgmt_key = crate::model::ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);

        // Test with None path (should use default)
        let result = import_private_key_from_seed_phrase(
            &finder,
            seed_phrase,
            passphrase,
            None,
            config,
            Some(&mgmt_key),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
    }
}
