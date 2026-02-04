//! Tests for port traits using mock adapters
//!
//! These tests verify that port traits work correctly with mock implementations.
//! They should mirror the tests in adapters/yubikey_piv.rs which use real hardware.

#[cfg(test)]
mod tests {
    use crate::adapters::mock_yubikey::{MockDeviceFinder, MockYubiKey};
    use crate::error::{DeviceError, KeyManagementError, YkadaError};
    use crate::model::{Algorithm, ManagementKey, Pin, PinPolicy, Slot, TouchPolicy};
    use crate::ports::{DeviceFinder, KeyManager, ManagementKeyVerifier, PinVerifier, Signer};
    use ed25519_dalek::SigningKey;
    use rand::rng;
    use rand::RngCore;
    use std::convert::TryInto;

    #[test]
    fn test_mgmt_key_authentication_success_default() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);

        let result = ManagementKeyVerifier::authenticate(&mut device, None);
        assert!(result.is_ok());
        assert!(device.authenticated);
    }

    #[test]
    fn test_mgmt_key_authentication_success_custom() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        let mgmt_key = ManagementKey::new([0u8; 24]);

        let result = ManagementKeyVerifier::authenticate(&mut device, Some(&mgmt_key));
        assert!(result.is_ok());
        assert!(device.authenticated);
    }

    #[test]
    fn test_mgmt_key_authentication_failure() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        let wrong_mgmt_key = ManagementKey::new([1u8; 24]);

        let result = ManagementKeyVerifier::authenticate(&mut device, Some(&wrong_mgmt_key));
        assert!(result.is_err());
        assert!(!device.authenticated);
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }

    #[test]
    fn test_pin_verification_success() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin.clone());
        device.authenticated = true;

        let result = PinVerifier::verify_pin(&mut device, &pin);
        assert!(result.is_ok());
        assert!(device.pin_verified);
    }

    #[test]
    fn test_pin_verification_failure() {
        let pin = Pin::default();
        let wrong_pin = Pin::from_str("999999").unwrap();
        let mut device = MockYubiKey::new(pin);

        let result = PinVerifier::verify_pin(&mut device, &wrong_pin);
        assert!(result.is_err());
        assert!(!device.pin_verified);
    }

    #[test]
    fn test_import_key_success() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = true;

        use crate::ports::KeyConfig;
        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();

        let result = KeyManager::import_key(&mut device, signing_key, config.clone());
        assert!(result.is_ok());
        assert!(device.keys.contains_key(&config.slot));
    }

    #[test]
    fn test_import_key_not_authenticated() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = false;

        use crate::ports::KeyConfig;
        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();

        let result = KeyManager::import_key(&mut device, signing_key, config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }

    #[test]
    fn test_import_key_slot_occupied() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = true;

        use crate::ports::KeyConfig;
        use ed25519_dalek::SecretKey;
        let mut secret_bytes1 = [0u8; 32];
        let mut secret_bytes2 = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes1);
        rng().fill_bytes(&mut secret_bytes2);
        let signing_key1 = SigningKey::from_bytes(&SecretKey::from(secret_bytes1));
        let signing_key2 = SigningKey::from_bytes(&SecretKey::from(secret_bytes2));
        let config = KeyConfig::default();

        // Import first key
        KeyManager::import_key(&mut device, signing_key1, config.clone()).unwrap();

        // Try to import second key to same slot
        let result = KeyManager::import_key(&mut device, signing_key2, config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::KeyManagement(KeyManagementError::SlotOccupied { .. })
        ));
    }

    #[test]
    fn test_sign_success() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin.clone());
        device.authenticated = true;

        // Import a key
        use crate::ports::KeyConfig;
        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();
        let config = KeyConfig::default();
        KeyManager::import_key(&mut device, signing_key, config.clone()).unwrap();

        // Sign data
        let data = b"test data";
        let result = Signer::sign(
            &mut device,
            data,
            config.slot,
            Algorithm::default_cardano(),
            Some(&pin),
        );
        assert!(result.is_ok());

        // Verify signature
        let signature_bytes = result.unwrap();
        let sig_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| "Invalid signature length")
            .expect("Invalid signature length");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        verifying_key.verify_strict(data, &signature).unwrap();
    }

    #[test]
    fn test_sign_key_not_found() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = true;

        use crate::ports::KeyConfig;
        let data = b"test data";
        let config = KeyConfig::default();
        let result = Signer::sign(
            &mut device,
            data,
            config.slot,
            Algorithm::default_cardano(),
            Some(&Pin::default()),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::KeyManagement(KeyManagementError::KeyNotFound { .. })
        ));
    }

    #[test]
    fn test_sign_pin_required() {
        let pin = Pin::default();
        let wrong_pin = Pin::from_str("999999").unwrap();
        let mut device = MockYubiKey::new(pin.clone());
        device.authenticated = true;

        // Import a key
        use crate::ports::KeyConfig;
        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();
        KeyManager::import_key(&mut device, signing_key, config.clone()).unwrap();

        // Try to sign with wrong PIN
        let data = b"test data";
        let result = Signer::sign(
            &mut device,
            data,
            config.slot,
            Algorithm::default_cardano(),
            Some(&wrong_pin),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::PinVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_device_finder_success() {
        let pin = Pin::default();
        let device = MockYubiKey::new(pin);
        let finder = MockDeviceFinder {
            device: Some(device),
        };

        let result = DeviceFinder::find_first(&finder);
        assert!(result.is_ok());
    }

    #[test]
    fn test_device_finder_not_found() {
        let finder = MockDeviceFinder { device: None };

        let result = DeviceFinder::find_first(&finder);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::NotFound)
        ));
    }

    #[test]
    fn test_key_config_default() {
        use crate::ports::KeyConfig;
        let config = KeyConfig::default();
        assert_eq!(config.slot, Slot::default_signing());
        assert_eq!(config.algorithm, Algorithm::default_cardano());
        assert_eq!(config.pin_policy, PinPolicy::recommended_cardano());
        assert_eq!(config.touch_policy, TouchPolicy::recommended_cardano());
    }

    #[test]
    fn test_generate_key_success() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = true;

        use crate::ports::KeyConfig;
        let config = KeyConfig::default();
        let result = KeyManager::generate_key(&mut device, config.clone());
        assert!(result.is_ok());

        let verifying_key = result.unwrap();
        assert_eq!(verifying_key.as_bytes().len(), 32);
        // Verify key was stored in the slot
        assert!(device.keys.contains_key(&config.slot));
    }

    #[test]
    fn test_generate_key_not_authenticated() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = false;

        use crate::ports::KeyConfig;
        let config = KeyConfig::default();
        let result = KeyManager::generate_key(&mut device, config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::AuthenticationFailed { .. })
        ));
    }

    #[test]
    fn test_generate_key_slot_occupied() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = true;

        use crate::ports::KeyConfig;
        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();

        // Import a key to occupy the slot
        KeyManager::import_key(&mut device, signing_key, config.clone()).unwrap();

        // Try to generate a key in the same slot
        let result = KeyManager::generate_key(&mut device, config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::KeyManagement(KeyManagementError::SlotOccupied { .. })
        ));
    }

    #[test]
    fn test_generate_key_and_sign() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin.clone());
        device.authenticated = true;

        use crate::ports::KeyConfig;
        let config = KeyConfig::default();
        let verifying_key = KeyManager::generate_key(&mut device, config.clone()).unwrap();

        // Sign data with generated key
        let data = b"test data";
        let result = Signer::sign(
            &mut device,
            data,
            config.slot,
            Algorithm::default_cardano(),
            Some(&pin),
        );
        assert!(result.is_ok());

        // Verify signature
        let signature_bytes = result.unwrap();
        let sig_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| "Invalid signature length")
            .expect("Invalid signature length");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        verifying_key.verify_strict(data, &signature).unwrap();
    }
}
