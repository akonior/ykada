//! Generate key use case
//!
//! This use case orchestrates key generation on a YubiKey device.
//! It handles device finding, authentication, and key generation.

use crate::error::YkadaResult;
use crate::model::ManagementKey;
use crate::ports::{DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier};
use ed25519_dalek::VerifyingKey;

/// Generate a new Ed25519 keypair on a YubiKey device
///
/// This function orchestrates the complete key generation workflow:
/// 1. Find the first available YubiKey device
/// 2. Authenticate with the management key
/// 3. Generate a new keypair in the specified slot
///
/// # Arguments
///
/// * `finder` - Device finder implementation
/// * `config` - Configuration for key generation (slot, algorithm, policies)
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
pub fn generate_key<F>(
    finder: &F,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey>
where
    F: DeviceFinder,
    F::Device: KeyManager + crate::ports::ManagementKeyVerifier,
{
    // Find device
    let mut device = finder.find_first()?;

    // Authenticate with management key
    device.authenticate(mgmt_key)?;

    // Generate key
    device.generate_key(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::error::DeviceError;
    use crate::model::{ManagementKey, Pin};
    use crate::YkadaError;

    #[test]
    fn test_generate_key_success() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let config = KeyConfig::default();
        let mgmt_key = ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ]);
        let result = generate_key(&finder, config, Some(&mgmt_key));

        assert!(result.is_ok(), "error: {:?}", result.err());
        let verifying_key = result.unwrap();
        assert_eq!(verifying_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_generate_key_device_not_found() {
        let finder = FakeDeviceFinder { device: None };
        let config = KeyConfig::default();
        let result = generate_key(&finder, config, None);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::NotFound)
        ));
    }

    #[test]
    fn test_generate_key_authentication_failed() {
        let pin = Pin::default();
        let device = FakeYubiKey::new(pin);
        let finder = FakeDeviceFinder {
            device: Some(device),
        };

        let config = KeyConfig::default();
        let wrong_mgmt_key = ManagementKey::new([1u8; 24]);
        let result = generate_key(&finder, config, Some(&wrong_mgmt_key));

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }
}
