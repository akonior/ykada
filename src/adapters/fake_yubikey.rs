//! Fake YubiKey adapter for testing ports (traits)
//!
//! This module provides a fake implementation of YubiKey operation traits
//! for testing purposes. It is only available in test scope.

#[cfg(test)]
use crate::error::{DeviceError, KeyManagementError, YkadaError, YkadaResult};
#[cfg(test)]
use crate::model::{Algorithm, ManagementKey, Pin, PivEd25519Key, Slot};
#[cfg(test)]
use crate::ports::{
    DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
};
#[cfg(test)]
use ed25519_dalek::{SigningKey, VerifyingKey};
#[cfg(test)]
use rand::rng;
#[cfg(test)]
use rand::RngCore;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]

/// Fake YubiKey implementation for testing trait behavior
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct FakeYubiKey {
    pub pin: Pin,
    pub mgmt_key: ManagementKey,
    pub keys: HashMap<Slot, (SigningKey, VerifyingKey)>,
    pub authenticated: bool, // TOD make priv
    pub pin_verified: bool,
}

#[cfg(test)]
impl FakeYubiKey {
    pub fn new(pin: Pin) -> Self {
        Self {
            pin,
            mgmt_key: ManagementKey::new([
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
            ]),
            keys: HashMap::new(),
            authenticated: false,
            pin_verified: false,
        }
    }
}

#[cfg(test)]
impl PinVerifier for FakeYubiKey {
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

#[cfg(test)]
impl ManagementKeyVerifier for FakeYubiKey {
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

#[cfg(test)]
impl KeyManager for FakeYubiKey {
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

    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<VerifyingKey> {
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

        // Store the generated key in the slot
        self.keys.insert(config.slot, (signing_key, verifying_key));
        Ok(verifying_key)
    }

    fn import_cv_key(&mut self, key: PivEd25519Key, config: KeyConfig) -> YkadaResult<()> {
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

        // Compute public key using ed25519-bip32 (CIP-3 reference implementation)
        use ed25519_bip32::XPrv;
        let mut extended_secret = [0u8; 64];
        extended_secret[..32].copy_from_slice(key.as_array());
        let dummy_chain_code = [0u8; 32];
        let xprv = XPrv::from_extended_and_chaincode(&extended_secret, &dummy_chain_code);
        let xpub = xprv.public();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(xpub.public_key_bytes())
            .expect("XPub public key is valid Ed25519");

        // Store SigningKey for signing operations
        use ed25519_dalek::SecretKey;
        let signing_key = SigningKey::from_bytes(&SecretKey::from(*key.as_array()));

        self.keys.insert(config.slot, (signing_key, verifying_key));
        Ok(())
    }
}

#[cfg(test)]
impl Signer for FakeYubiKey {
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
            YkadaError::Crypto(crate::error::CryptoError::SignatureFailed {
                reason: "Key not found".to_string(),
            })
        })?;

        // Sign the data
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

#[cfg(test)]
pub struct FakeDeviceFinder {
    pub device: Option<FakeYubiKey>,
}

#[cfg(test)]
impl DeviceFinder for FakeDeviceFinder {
    type Device = FakeYubiKey;

    fn find_first(&self) -> YkadaResult<Self::Device> {
        self.device
            .clone()
            .ok_or_else(|| YkadaError::Device(DeviceError::NotFound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_tests_for;
    use crate::ports::contract_tests::yubikey_contract;

    contract_tests_for!(
        fake_yubikey_contract,
        make = || FakeYubiKey::new(Pin::default()),
        tests = {
            test_pin_verification_success => yubikey_contract::test_pin_verification_success,
            test_pin_verification_failure => yubikey_contract::test_pin_verification_failure,
            test_mgmt_key_authentication_success_default => yubikey_contract::test_mgmt_key_authentication_success_default,
            test_mgmt_key_authentication_failure => yubikey_contract::test_mgmt_key_authentication_failure,
            test_import_key_success => yubikey_contract::test_import_key_success,
            test_import_key_fail_not_authenticated => yubikey_contract::test_import_key_fail_not_authenticated,
            test_sign_key_not_found => yubikey_contract::test_sign_key_not_found,
            test_sign_invalid_pin => yubikey_contract::test_sign_invalid_pin,
            test_sign_success => yubikey_contract::test_sign_success,
            test_generate_key_not_authenticated => yubikey_contract::test_generate_key_not_authenticated,
            test_generate_key_success => yubikey_contract::test_generate_key_success,
            test_import_seed_phrase_derived_key => yubikey_contract::test_import_seed_phrase_derived_key,
        }
    );
}
