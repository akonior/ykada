use crate::error::{CryptoError, KeyManagementError, YkadaError, YkadaResult};
use crate::model::{Algorithm, ManagementKey, Pin, Slot};
use crate::ports::{
    DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
};
use crate::{Ed25519PrivateKey, Ed25519PublicKey};
use ed25519_dalek::VerifyingKey;
use std::convert::TryInto;
use tracing::{debug, info};
use yubikey::piv::{generate, import_cv_key, sign_data};
use yubikey::{Context, MgmKey, YubiKey};

#[derive(Debug, Clone, Default)]
pub struct PivDeviceFinder;

impl DeviceFinder for PivDeviceFinder {
    type Device = PivYubiKey;

    fn find_first(&self) -> YkadaResult<Self::Device> {
        let mut readers = Context::open()?;

        for reader in readers.iter()? {
            if let Ok(yk) = reader.open() {
                debug!("Connected to YubiKey: {:?}", reader.name());
                return Ok(PivYubiKey::new(yk));
            }
        }

        Err(YkadaError::NotFound)
    }
}

#[derive(Debug)]
pub struct PivYubiKey {
    device: YubiKey,
    authenticated: bool,
}

impl PivYubiKey {
    pub fn new(device: YubiKey) -> Self {
        Self {
            device,
            authenticated: false,
        }
    }

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
            MgmKey::try_from(key)?
        } else {
            MgmKey::get_default(&self.device)?
        };

        self.device.authenticate(&mgm_key)?;

        self.authenticated = true;
        debug!("YubiKey authenticated with management key");
        Ok(())
    }
}

impl PinVerifier for PivYubiKey {
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()> {
        self.device.verify_pin(pin.as_bytes())?;

        debug!("PIN verified successfully");
        Ok(())
    }
}

impl KeyManager for PivYubiKey {
    fn import_key(&mut self, key: Ed25519PrivateKey, config: KeyConfig) -> YkadaResult<()> {
        self.ensure_authenticated()?;

        let algorithm = Algorithm::default_cardano();

        debug!("Importing key to slot: {:?}", config.slot);
        debug!("Algorithm: {:?}", algorithm);
        debug!(
            "Policies: PIN={:?}, Touch={:?}",
            config.pin_policy, config.touch_policy
        );

        import_cv_key(
            &mut self.device,
            config.slot.to_yubikey_slot_id(),
            algorithm.to_yubikey_algorithm_id(),
            key.as_array(),
            config.touch_policy.to_yubikey_touch_policy(),
            config.pin_policy.to_yubikey_pin_policy(),
        )?;

        info!("Key imported successfully to slot {:?}", config.slot);
        Ok(())
    }

    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<Ed25519PublicKey> {
        if !self.authenticated {
            return Err(YkadaError::AuthenticationFailed {
                reason: "Not authenticated".to_string(),
            });
        }

        let slot_id = config.slot.to_yubikey_slot_id();
        let algorithm_id = Algorithm::default_cardano().to_yubikey_algorithm_id();
        let pin_policy = config.pin_policy.to_yubikey_pin_policy();
        let touch_policy = config.touch_policy.to_yubikey_touch_policy();

        debug!(
            "Generating key in slot {:?} with algorithm {:?}",
            slot_id, algorithm_id
        );

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

        let public_key_bytes = spki.subject_public_key.raw_bytes();

        if public_key_bytes.len() != 32 {
            return Err(YkadaError::Crypto(CryptoError::InvalidKeyFormat {
                format: format!(
                    "Expected 32 bytes for Ed25519 public key, got {}",
                    public_key_bytes.len()
                ),
            }));
        }

        let public_key_array: [u8; 32] = public_key_bytes[..32].try_into().map_err(|_| {
            YkadaError::Crypto(CryptoError::InvalidKeyFormat {
                format: "Failed to convert public key bytes to array".to_string(),
            })
        })?;

        VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| {
                YkadaError::Crypto(CryptoError::InvalidKeyFormat {
                    format: format!("Invalid Ed25519 public key: {}", e),
                })
            })
            .map(Ed25519PublicKey::from)
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
        )?;

        debug!("Signature generated successfully");
        Ok(signature.to_vec())
    }
}

#[cfg(all(test, feature = "hardware-tests"))]
mod tests {
    use super::*;
    use crate::contract_tests_for;
    use crate::ports::contract_tests::yubikey_contract;

    #[test]
    fn test_device_finder_success() {
        let result = PivDeviceFinder.find_first();
        assert!(result.is_ok(), "error: {:?}", result.err());
    }

    contract_tests_for!(
        real_yubikey_contract,
        make = || PivDeviceFinder.find_first().expect("YubiKey not found"),
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
