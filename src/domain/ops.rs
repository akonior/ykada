//! YubiKey operation traits (algebras)
//!
//! These traits define the capabilities required for YubiKey operations.
//! They represent ports in hexagonal architecture - the core depends on
//! these abstractions, not concrete implementations.
//!
//! These traits are PIV/OpenPGP agnostic - they define what operations
//! can be performed, not how they are implemented.

use crate::domain::{Algorithm, ManagementKey, Pin, PinPolicy, Slot, TouchPolicy};
use crate::error::YkadaResult;
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

/// Capability to find and connect to YubiKey devices
///
/// This trait abstracts the discovery and connection to YubiKey hardware.
/// It is implementation-agnostic (works with PIV, OpenPGP, etc.)
pub trait DeviceFinder {
    /// The type of device handle returned
    type Device: PinVerifier + ManagementKeyVerifier + KeyManager + Signer;

    /// Find and connect to the first available YubiKey
    ///
    /// # Errors
    ///
    /// Returns `YkadaError::Device(DeviceError::NotFound)` if no YubiKey is found
    fn find_first(&self) -> YkadaResult<Self::Device>;
}

/// Capability to verify PIN
///
/// This trait abstracts PIN verification operations.
pub trait PinVerifier {
    /// Verify PIN on the device
    ///
    /// # Errors
    ///
    /// Returns `YkadaError::Device(DeviceError::PinVerificationFailed)` on failure
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()>;
}

/// Capability to authenticate with Management Key
///
/// This trait abstracts Management Key authentication operations.
/// Management Key authentication is required before key import/generation operations.
pub trait ManagementKeyVerifier {
    /// Authenticate with the Management Key
    ///
    /// # Arguments
    ///
    /// * `mgmt_key` - Optional Management Key. If `None`, the default Management Key is used.
    ///
    /// # Errors
    ///
    /// Returns `YkadaError::Device(DeviceError::AuthenticationFailed)` on failure
    fn authenticate(&mut self, mgmt_key: Option<&ManagementKey>) -> YkadaResult<()>;
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

/// Capability to sign data
///
/// This trait abstracts signing operations using keys stored on YubiKey.
/// Works with any key storage mechanism (PIV slots, OpenPGP keys, etc.)
pub trait Signer {
    /// Sign data using a key in the specified slot
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign
    /// * `slot` - The slot containing the key to use
    /// * `algorithm` - The algorithm to use for signing
    /// * `pin` - PIN for authentication (if required by key policy)
    ///
    /// # Returns
    ///
    /// The signature bytes
    ///
    /// # Errors
    ///
    /// Returns errors if:
    /// - PIN verification fails
    /// - Key not found in slot
    /// - Signing operation fails
    fn sign(
        &mut self,
        data: &[u8],
        slot: Slot,
        algorithm: Algorithm,
        pin: Option<&Pin>,
    ) -> YkadaResult<Vec<u8>>;
}

/// Combined trait for all YubiKey operations
///
/// This trait combines all capabilities into a single interface.
/// A device handle typically implements this.
pub trait YubiKeyOps: PinVerifier + ManagementKeyVerifier + KeyManager + Signer {}

// Blanket implementation for types that implement all operation traits
impl<T> YubiKeyOps for T where T: PinVerifier + ManagementKeyVerifier + KeyManager + Signer {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Pin;
    use crate::error::{DeviceError, KeyManagementError, YkadaError};
    use ed25519_dalek::SigningKey;
    use rand::rng;
    use rand::RngCore;
    use std::collections::HashMap;
    use std::convert::TryInto;

    /// Mock implementation for testing trait behavior
    #[derive(Debug, Clone)]
    pub struct MockYubiKey {
        pub pin: Pin,
        pub mgmt_key: ManagementKey,
        pub keys: HashMap<Slot, (SigningKey, VerifyingKey)>,
        pub authenticated: bool,
        pub pin_verified: bool,
    }

    impl MockYubiKey {
        pub fn new(pin: Pin) -> Self {
            Self {
                pin,
                mgmt_key: ManagementKey::new([0u8; 24]), // Default mock management key
                keys: HashMap::new(),
                authenticated: false,
                pin_verified: false,
            }
        }
    }

    impl PinVerifier for MockYubiKey {
        fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()> {
            if pin.as_bytes() == self.pin.as_bytes() {
                self.pin_verified = true;
                Ok(())
            } else {
                Err(YkadaError::Device(DeviceError::PinVerificationFailed {
                    reason: "Invalid PIN".to_string(),
                }))
            }
        }
    }

    impl ManagementKeyVerifier for MockYubiKey {
        fn authenticate(&mut self, mgmt_key: Option<&ManagementKey>) -> YkadaResult<()> {
            let key_to_check = mgmt_key.unwrap_or(&self.mgmt_key);
            if key_to_check.as_bytes() == self.mgmt_key.as_bytes() {
                self.authenticated = true;
                Ok(())
            } else {
                Err(YkadaError::Device(DeviceError::AuthenticationFailed {
                    reason: "Invalid Management Key".to_string(),
                }))
            }
        }
    }

    impl KeyManager for MockYubiKey {
        fn import_key(&mut self, key: SigningKey, config: KeyConfig) -> YkadaResult<VerifyingKey> {
            if !self.authenticated {
                return Err(YkadaError::Device(DeviceError::AuthenticationFailed {
                    reason: "Not authenticated".to_string(),
                }));
            }

            if self.keys.contains_key(&config.slot) {
                return Err(YkadaError::KeyManagement(
                    KeyManagementError::SlotOccupied {
                        slot: format!("{:?}", config.slot),
                    },
                ));
            }

            let verifying_key = key.verifying_key();
            self.keys.insert(config.slot, (key, verifying_key));
            Ok(verifying_key)
        }

        fn generate_key(&mut self, _config: KeyConfig) -> YkadaResult<VerifyingKey> {
            if !self.authenticated {
                return Err(YkadaError::Device(DeviceError::AuthenticationFailed {
                    reason: "Not authenticated".to_string(),
                }));
            }

            // Generate a random key for testing
            use ed25519_dalek::SecretKey;
            let mut secret_bytes = [0u8; 32];
            rng().fill_bytes(&mut secret_bytes);
            let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
            let verifying_key = signing_key.verifying_key();

            // For mock, we don't actually store it since we don't have a slot in this test
            Ok(verifying_key)
        }
    }

    impl Signer for MockYubiKey {
        fn sign(
            &mut self,
            data: &[u8],
            slot: Slot,
            _algorithm: Algorithm,
            pin: Option<&Pin>,
        ) -> YkadaResult<Vec<u8>> {
            // Verify PIN if provided
            if let Some(pin) = pin {
                self.verify_pin(pin)?;
            }

            // Find key in slot
            let (signing_key, _) = self.keys.get(&slot).ok_or_else(|| {
                YkadaError::KeyManagement(KeyManagementError::KeyNotFound {
                    slot: format!("{:?}", slot),
                })
            })?;

            // Sign the data
            use ed25519_dalek::Signer;
            let signature = signing_key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
    }

    pub struct MockDeviceFinder {
        pub device: Option<MockYubiKey>,
    }

    impl DeviceFinder for MockDeviceFinder {
        type Device = MockYubiKey;

        fn find_first(&self) -> YkadaResult<Self::Device> {
            self.device
                .clone()
                .ok_or_else(|| YkadaError::Device(DeviceError::NotFound))
        }
    }

    // Test suite - these tests should be mirrored in yubikey/piv.rs with real hardware

    #[test]
    fn test_mgmt_key_authentication_success_default() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);

        let result = device.authenticate(None);
        assert!(result.is_ok());
        assert!(device.authenticated);
    }

    #[test]
    fn test_mgmt_key_authentication_success_custom() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        let mgmt_key = ManagementKey::new([0u8; 24]);

        let result = device.authenticate(Some(&mgmt_key));
        assert!(result.is_ok());
        assert!(device.authenticated);
    }

    #[test]
    fn test_mgmt_key_authentication_failure() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        let wrong_mgmt_key = ManagementKey::new([1u8; 24]);

        let result = device.authenticate(Some(&wrong_mgmt_key));
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

        let result = device.verify_pin(&pin);
        assert!(result.is_ok());
        assert!(device.pin_verified);
    }

    #[test]
    fn test_pin_verification_failure() {
        let pin = Pin::default();
        let wrong_pin = Pin::from_str("999999").unwrap();
        let mut device = MockYubiKey::new(pin);

        let result = device.verify_pin(&wrong_pin);
        assert!(result.is_err());
        assert!(!device.pin_verified);
    }

    #[test]
    fn test_import_key_success() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = true;

        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();

        let result = device.import_key(signing_key, config.clone());
        assert!(result.is_ok());
        assert!(device.keys.contains_key(&config.slot));
    }

    #[test]
    fn test_import_key_not_authenticated() {
        let pin = Pin::default();
        let mut device = MockYubiKey::new(pin);
        device.authenticated = false;

        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();

        let result = device.import_key(signing_key, config);
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

        use ed25519_dalek::SecretKey;
        let mut secret_bytes1 = [0u8; 32];
        let mut secret_bytes2 = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes1);
        rng().fill_bytes(&mut secret_bytes2);
        let signing_key1 = SigningKey::from_bytes(&SecretKey::from(secret_bytes1));
        let signing_key2 = SigningKey::from_bytes(&SecretKey::from(secret_bytes2));
        let config = KeyConfig::default();

        // Import first key
        device.import_key(signing_key1, config.clone()).unwrap();

        // Try to import second key to same slot
        let result = device.import_key(signing_key2, config);
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
        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let verifying_key = signing_key.verifying_key();
        let config = KeyConfig::default();
        device.import_key(signing_key, config.clone()).unwrap();

        // Sign data
        let data = b"test data";
        let result = device.sign(data, config.slot, Algorithm::default_cardano(), Some(&pin));
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

        let data = b"test data";
        let config = KeyConfig::default();
        let result = device.sign(
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
        use ed25519_dalek::SecretKey;
        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&SecretKey::from(secret_bytes));
        let config = KeyConfig::default();
        device.import_key(signing_key, config.clone()).unwrap();

        // Try to sign with wrong PIN
        let data = b"test data";
        let result = device.sign(
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

        let result = finder.find_first();
        assert!(result.is_ok());
    }

    #[test]
    fn test_device_finder_not_found() {
        let finder = MockDeviceFinder { device: None };

        let result = finder.find_first();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::Device(DeviceError::NotFound)
        ));
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
