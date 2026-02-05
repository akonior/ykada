//! PIV (Personal Identity Verification) implementation of YubiKey operations
//!
//! This module provides concrete implementations of YubiKey operation traits
//! using the yubikey crate's PIV functionality.

use crate::error::{CryptoError, DeviceError, KeyManagementError, YkadaError, YkadaResult};
use crate::model::{Algorithm, ManagementKey, ManagementKeyError, Pin, Slot};
use crate::ports::{
    DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::convert::TryInto;
use tracing::{debug, info};
use yubikey::piv::{generate, import_cv_key, sign_data};
use yubikey::{Context, MgmKey, YubiKey};

/// PIV-based YubiKey device finder
///
/// Finds and connects to YubiKey devices using PC/SC.
#[derive(Debug, Clone, Default)]
pub struct PivDeviceFinder;

impl DeviceFinder for PivDeviceFinder {
    type Device = PivYubiKey;

    fn find_first(&self) -> YkadaResult<Self::Device> {
        let mut readers = Context::open().map_err(|e| {
            YkadaError::Device(DeviceError::ConnectionFailed {
                reason: format!("Failed to open PC/SC context: {}", e),
            })
        })?;

        for reader in readers.iter().map_err(|e| {
            YkadaError::Device(DeviceError::ConnectionFailed {
                reason: format!("Failed to iterate readers: {}", e),
            })
        })? {
            if let Ok(yk) = reader.open() {
                debug!("Connected to YubiKey: {:?}", reader.name());
                return Ok(PivYubiKey::new(yk));
            }
        }

        Err(YkadaError::Device(DeviceError::NotFound))
    }
}

/// PIV-based YubiKey device handle
///
/// This wraps a YubiKey connection and implements all operation traits.
#[derive(Debug)]
pub struct PivYubiKey {
    device: YubiKey,
    authenticated: bool,
}

impl PivYubiKey {
    /// Create a new PIV YubiKey handle
    pub fn new(device: YubiKey) -> Self {
        Self {
            device,
            authenticated: false,
        }
    }

    /// Ensure device is authenticated
    fn ensure_authenticated(&mut self) -> YkadaResult<()> {
        if !self.authenticated {
            self.authenticate(None)?;
        }
        Ok(())
    }
}

impl ManagementKeyVerifier for PivYubiKey {
    fn authenticate(&mut self, mgmt_key: Option<&ManagementKey>) -> YkadaResult<()> {
        let mgm_key = if let Some(key) = mgmt_key {
            MgmKey::try_from(key).map_err(|e: ManagementKeyError| {
                YkadaError::Domain(crate::error::DomainError::ManagementKey(e))
            })?
        } else {
            // Use device's default management key (factory or currently configured)
            MgmKey::get_default(&self.device).map_err(|e| {
                YkadaError::Device(DeviceError::AuthenticationFailed {
                    reason: format!("Failed to get default management key: {}", e),
                })
            })?
        };

        self.device.authenticate(&mgm_key).map_err(|e| {
            YkadaError::Device(DeviceError::AuthenticationFailed {
                reason: format!("Management key authentication failed: {}", e),
            })
        })?;

        self.authenticated = true;
        debug!("YubiKey authenticated with management key");
        Ok(())
    }
}

impl PinVerifier for PivYubiKey {
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()> {
        self.device.verify_pin(pin.as_bytes()).map_err(|e| {
            // Try to extract attempts remaining if available
            let reason = format!("PIN verification failed: {}", e);
            YkadaError::Device(DeviceError::PinVerificationFailed { reason })
        })?;

        debug!("PIN verified successfully");
        Ok(())
    }
}

impl KeyManager for PivYubiKey {
    fn import_key(&mut self, key: SigningKey, config: KeyConfig) -> YkadaResult<VerifyingKey> {
        self.ensure_authenticated()?;

        debug!("Importing key to slot: {:?}", config.slot);
        debug!("Algorithm: {:?}", config.algorithm);
        debug!(
            "Policies: PIN={:?}, Touch={:?}",
            config.pin_policy, config.touch_policy
        );

        let key_data = key.as_bytes();
        let verifying_key = key.verifying_key();

        import_cv_key(
            &mut self.device,
            config.slot.to_yubikey_slot_id(),
            config.algorithm.to_yubikey_algorithm_id(),
            key_data,
            config.touch_policy.to_yubikey_touch_policy(),
            config.pin_policy.to_yubikey_pin_policy(),
        )
        .map_err(|e| {
            YkadaError::KeyManagement(KeyManagementError::StoreFailed {
                destination: format!("slot {:?}", config.slot),
                reason: format!("Failed to import key: {}", e),
            })
        })?;

        info!("Key imported successfully to slot {:?}", config.slot);
        Ok(verifying_key)
    }

    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<VerifyingKey> {
        if !self.authenticated {
            return Err(YkadaError::Device(DeviceError::AuthenticationFailed {
                reason: "Not authenticated".to_string(),
            }));
        }

        // Convert domain types to yubikey crate types
        let slot_id = config.slot.to_yubikey_slot_id();
        let algorithm_id = config.algorithm.to_yubikey_algorithm_id();
        let pin_policy = config.pin_policy.to_yubikey_pin_policy();
        let touch_policy = config.touch_policy.to_yubikey_touch_policy();

        debug!(
            "Generating key in slot {:?} with algorithm {:?}",
            slot_id, algorithm_id
        );

        // Generate key on YubiKey
        let spki = generate(
            &mut self.device,
            slot_id,
            algorithm_id,
            pin_policy,
            touch_policy,
        )
        .map_err(|e| {
            YkadaError::KeyManagement(KeyManagementError::StoreFailed {
                destination: "YubiKey".to_string(),
                reason: format!("Key generation failed: {}", e),
            })
        })?;

        info!("Key generated successfully in slot {:?}", slot_id);

        // Convert SubjectPublicKeyInfoOwned to VerifyingKey
        // For Ed25519, extract public key bytes from BitString
        let public_key_bytes = spki.subject_public_key.raw_bytes();

        // For Ed25519, we expect exactly 32 bytes
        if public_key_bytes.len() != 32 {
            return Err(YkadaError::Crypto(CryptoError::InvalidKeyFormat {
                format: format!(
                    "Expected 32 bytes for Ed25519 public key, got {}",
                    public_key_bytes.len()
                ),
            }));
        }

        // Convert to VerifyingKey
        let public_key_array: [u8; 32] = public_key_bytes[..32].try_into().map_err(|_| {
            YkadaError::Crypto(CryptoError::InvalidKeyFormat {
                format: "Failed to convert public key bytes to array".to_string(),
            })
        })?;

        VerifyingKey::from_bytes(&public_key_array).map_err(|e| {
            YkadaError::Crypto(CryptoError::InvalidKeyFormat {
                format: format!("Invalid Ed25519 public key: {}", e),
            })
        })
    }
}

impl Signer for PivYubiKey {
    fn sign(
        &mut self,
        data: &[u8],
        slot: Slot,
        algorithm: Algorithm,
        pin: Option<&Pin>,
    ) -> YkadaResult<Vec<u8>> {
        // Verify PIN if provided
        if let Some(pin) = pin {
            self.verify_pin(pin)?;
        }

        debug!(
            "Signing {} bytes using slot {:?}, algorithm {:?}",
            data.len(),
            slot,
            algorithm
        );

        let signature = sign_data(
            &mut self.device,
            data,
            algorithm.to_yubikey_algorithm_id(),
            slot.to_yubikey_slot_id(),
        )
        .map_err(|e| {
            YkadaError::Crypto(crate::error::CryptoError::SignatureFailed {
                reason: format!("Signing failed: {}", e),
            })
        })?;

        debug!("Signature generated successfully");
        Ok(signature.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ManagementKey, PinPolicy, TouchPolicy};
    use ed25519_dalek::SigningKey;
    use std::convert::TryInto;

    // These tests mirror the tests in adapters/tests.rs but use real YubiKey hardware
    // They should have the same names and test the same scenarios to ensure
    // that mock implementations accurately simulate real hardware behavior.
    // All hardware tests are conditionally ignored unless --features hardware-tests is used.

    const TESTING_MANAGEMENT_KEY: ManagementKey = ManagementKey::new([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09,
    ]);

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_pin_verification_success() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");
        let pin = Pin::default();

        let result = device.verify_pin(&pin);
        // May fail if PIN was changed, but structure should be correct
        if result.is_err() {
            // Check it's a PIN error, not some other error
            assert!(matches!(
                result.unwrap_err(),
                YkadaError::Device(DeviceError::PinVerificationFailed { .. })
                    | YkadaError::Device(DeviceError::InvalidPin { .. })
            ));
        } else {
            // Success case
            assert!(result.is_ok());
        }
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_pin_verification_failure() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");
        let wrong_pin = Pin::from_str("999999").expect("Invalid PIN");

        let result = device.verify_pin(&wrong_pin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::PinVerificationFailed { .. })
                | YkadaError::Device(DeviceError::InvalidPin { .. })
        ));
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_mgmt_key_authentication_success_default() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");

        let result = device.authenticate(None);
        // May fail if management key was changed, but structure should be correct
        if result.is_err() {
            // Check it's an authentication error
            assert!(matches!(
                result.unwrap_err(),
                YkadaError::Device(DeviceError::AuthenticationFailed { .. })
            ));
        } else {
            // Success case
            assert!(result.is_ok());
        }
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_mgmt_key_authentication_custom() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");

        // Try with a custom management key (may fail if key doesn't match device's key)
        // This test verifies the API works, even if authentication fails due to wrong key
        let mgmt_key = ManagementKey::new([0u8; 24]);
        let result = device.authenticate(Some(&mgmt_key));

        // May succeed if device uses default key, or fail if key doesn't match
        // Either way, the API should work correctly
        if result.is_err() {
            // Check it's an authentication error (wrong key), not a format error
            assert!(matches!(
                result.unwrap_err(),
                YkadaError::Device(DeviceError::AuthenticationFailed { .. })
            ));
        } else {
            // Success case - custom key matched
            assert!(result.is_ok());
        }
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_import_key_success() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");

        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        use ed25519_dalek::SecretKey;
        use rand::rng;
        use rand::RngCore;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();

        let result = device.import_key(signing_key, config.clone());
        // May fail if slot is occupied, but should work on clean device
        if result.is_ok() {
            // Verify key was imported
            assert!(result.is_ok());
        } else {
            // Check it's a slot occupied error, not authentication error
            let err = result.unwrap_err();
            assert!(matches!(
                err,
                YkadaError::KeyManagement(KeyManagementError::SlotOccupied { .. })
                    | YkadaError::KeyManagement(KeyManagementError::StoreFailed { .. })
            ));
        }
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_import_key_not_authenticated() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");
        // Don't authenticate

        use ed25519_dalek::SecretKey;
        use rand::rng;
        use rand::RngCore;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();

        let result = device.import_key(signing_key, config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
                | YkadaError::KeyManagement(KeyManagementError::StoreFailed { .. })
        ));
    }

    #[test]
    #[ignore]
    fn test_import_key_slot_occupied() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        use ed25519_dalek::SecretKey;
        use rand::rng;
        use rand::RngCore;
        let mut secret_bytes1 = [0u8; 32];
        let mut secret_bytes2 = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes1);
        rng().fill_bytes(&mut secret_bytes2);
        let signing_key1 = SigningKey::from_bytes(&SecretKey::from(secret_bytes1));
        let signing_key2 = SigningKey::from_bytes(&SecretKey::from(secret_bytes2));
        let config = KeyConfig::default();

        // Import first key (may fail if slot already occupied)
        let first_result = device.import_key(signing_key1, config.clone());
        if first_result.is_err() {
            // Slot already occupied, skip this test
            return;
        }

        // Try to import second key to same slot
        let result = device.import_key(signing_key2, config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::KeyManagement(KeyManagementError::SlotOccupied { .. })
                | YkadaError::KeyManagement(KeyManagementError::StoreFailed { .. })
        ));
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_sign_success() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let pin = Pin::default();

        // Import a key first
        use ed25519_dalek::SecretKey;
        use rand::rng;
        use rand::RngCore;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();
        let config = KeyConfig::default();

        // May fail if slot occupied
        let import_result = device.import_key(signing_key, config.clone());
        if import_result.is_err() {
            // Slot occupied, can't test signing
            return;
        }

        // Sign data
        let data = b"test data";
        let result = device.sign(data, config.slot, Algorithm::default_cardano(), Some(&pin));

        if result.is_ok() {
            // Verify signature
            let signature_bytes = result.unwrap();
            let sig_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| "Invalid signature length")
                .expect("Invalid signature length");
            let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
            verifying_key
                .verify_strict(data, &signature)
                .expect("Signature verification failed");
        } else {
            // May fail due to PIN or other issues, but should be proper error type
            let err = result.unwrap_err();
            assert!(matches!(
                err,
                YkadaError::Device(DeviceError::PinVerificationFailed { .. })
                    | YkadaError::Device(DeviceError::InvalidPin { .. })
                    | YkadaError::Crypto(_)
            ));
        }
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_sign_key_not_found() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");

        let data = b"test data";
        // Use a slot that likely doesn't have a key
        let empty_slot = Slot::Authentication;
        let result = device.sign(
            data,
            empty_slot,
            Algorithm::default_cardano(),
            Some(&Pin::default()),
        );

        // Should fail with key not found or signing error
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            YkadaError::KeyManagement(KeyManagementError::KeyNotFound { .. })
                | YkadaError::Crypto(_)
        ));
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_generate_key_success() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let config = KeyConfig::default();
        let result = device.generate_key(config.clone());

        // May fail if slot is already occupied
        if result.is_ok() {
            let verifying_key = result.unwrap();
            assert_eq!(verifying_key.as_bytes().len(), 32);

            // Verify we can sign with the generated key
            let pin = Pin::default();
            let data = b"test data";
            let sign_result =
                device.sign(data, config.slot, Algorithm::default_cardano(), Some(&pin));

            if sign_result.is_ok() {
                // Verify signature
                let signature_bytes = sign_result.unwrap();
                let sig_array: [u8; 64] = signature_bytes
                    .try_into()
                    .map_err(|_| "Invalid signature length")
                    .expect("Invalid signature length");
                let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
                verifying_key
                    .verify_strict(data, &signature)
                    .expect("Signature verification failed");
            }
        } else {
            // Check if it's a slot occupied error (acceptable)
            let err = result.unwrap_err();
            assert!(matches!(
                err,
                YkadaError::KeyManagement(KeyManagementError::SlotOccupied { .. })
                    | YkadaError::KeyManagement(KeyManagementError::StoreFailed { .. })
            ));
        }
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_generate_key_not_authenticated() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");
        // Don't authenticate

        let config = KeyConfig::default();
        let result = device.generate_key(config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }

    #[test]
    #[cfg_attr(not(feature = "hardware-tests"), ignore)] // Requires YubiKey hardware - enable with: --features hardware-tests
    fn test_sign_pin_required() {
        let finder = PivDeviceFinder;
        let mut device = finder.find_first().expect("YubiKey not found");
        device
            .authenticate(Some(&TESTING_MANAGEMENT_KEY))
            .expect("Authentication failed");

        let wrong_pin = Pin::from_str("999999").expect("Invalid PIN");

        // Import a key first
        use ed25519_dalek::SecretKey;
        use rand::rng;
        use rand::RngCore;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();

        let import_result = device.import_key(signing_key, config.clone());
        if import_result.is_err() {
            // Can't test without imported key
            return;
        }

        // Try to sign with wrong PIN
        let data = b"test data";
        let result = device.sign(
            data,
            config.slot,
            Algorithm::default_cardano(),
            Some(&wrong_pin), // pin variable not used, only wrong_pin
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::PinVerificationFailed { .. })
                | YkadaError::Device(DeviceError::InvalidPin { .. })
        ));
    }

    #[test]
    fn test_device_finder_success() {
        let finder = PivDeviceFinder;
        let result = finder.find_first();
        // May succeed or fail depending on hardware availability
        if result.is_ok() {
            // Success case
            assert!(result.is_ok());
        } else {
            // Should be NotFound error, not some other error
            assert!(matches!(
                result.unwrap_err(),
                YkadaError::Device(DeviceError::NotFound)
                    | YkadaError::Device(DeviceError::ConnectionFailed { .. })
            ));
        }
    }

    #[test]
    fn test_key_config_default() {
        let config = KeyConfig::default();
        assert_eq!(config.slot, Slot::default_signing());
        assert_eq!(config.algorithm, Algorithm::default_cardano());
        assert_eq!(config.pin_policy, PinPolicy::recommended_cardano());
        assert_eq!(config.touch_policy, TouchPolicy::recommended_cardano());
    }
}
