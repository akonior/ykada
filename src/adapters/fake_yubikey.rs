use crate::error::{YkadaError, YkadaResult};
use crate::model::{Algorithm, ManagementKey, Pin, Slot};
use crate::ports::{
    DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
};
use crate::run_yubikey_contract_tests;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rng;
use rand::RngCore;
use std::collections::HashMap;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct FakeYubiKey {
    pub pin: Pin,
    pub mgmt_key: ManagementKey,
    pub keys: HashMap<Slot, SigningKey>,
    pub authenticated: bool,
    pub pin_verified: bool,
    pub serial: u32,
    pub firmware: (u8, u8, u8),
}

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
            serial: 0,
            firmware: (5, 7, 0),
        }
    }
}

impl PinVerifier for FakeYubiKey {
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()> {
        if pin.as_bytes() == self.pin.as_bytes() {
            self.pin_verified = true;
            Ok(())
        } else {
            Err(YkadaError::YubikeyLib(yubikey::Error::WrongPin {
                tries: 2,
            }))
        }
    }
}

impl ManagementKeyVerifier for FakeYubiKey {
    fn authenticate(&mut self, mgmt_key: Option<&ManagementKey>) -> YkadaResult<()> {
        let key_to_check = mgmt_key.unwrap_or(&self.mgmt_key);
        if key_to_check.as_bytes() == self.mgmt_key.as_bytes() {
            self.authenticated = true;
            Ok(())
        } else {
            Err(YkadaError::YubikeyLib(yubikey::Error::AuthenticationError))
        }
    }
}

impl KeyManager for FakeYubiKey {
    fn import_key(
        &mut self,
        key: SigningKey,
        vk: VerifyingKey,
        config: KeyConfig,
    ) -> YkadaResult<()> {
        if !self.authenticated {
            return Err(YkadaError::YubikeyLib(yubikey::Error::AuthenticationError));
        }
        debug!(
            "FakeYubiKey importing key to slot {:?}: private_key={} vk={}",
            config.slot,
            hex::encode(key.as_bytes()),
            hex::encode(vk.as_bytes()),
        );
        self.keys.insert(config.slot, key);
        info!("FakeYubiKey: key imported to slot {:?}", config.slot);
        Ok(())
    }

    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<VerifyingKey> {
        if !self.authenticated {
            return Err(YkadaError::AuthenticationFailed {
                reason: "Not authenticated".to_string(),
            });
        }

        let mut secret_bytes = [0u8; 32];
        rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        self.keys.insert(config.slot, signing_key);
        Ok(verifying_key)
    }
}

impl Signer for FakeYubiKey {
    fn sign(
        &mut self,
        data: &[u8],
        slot: Slot,
        _algorithm: Algorithm,
        pin: Option<&Pin>,
    ) -> YkadaResult<Vec<u8>> {
        if let Some(pin) = pin {
            self.verify_pin(pin)?;
        }

        debug!(
            "FakeYubiKey signing with slot {:?}: data_len={} data={}",
            slot,
            data.len(),
            hex::encode(data),
        );

        let signing_key = self
            .keys
            .get(&slot)
            .ok_or(YkadaError::YubikeyLib(yubikey::Error::GenericError))?;

        use ed25519_dalek::Signer;
        let signature = signing_key.sign(data);
        let sig_bytes = signature.to_bytes().to_vec();

        debug!("FakeYubiKey signature: {}", hex::encode(&sig_bytes));
        info!(
            "FakeYubiKey: signed {} bytes in slot {:?}",
            data.len(),
            slot
        );

        Ok(sig_bytes)
    }
}

impl DeviceReader for FakeYubiKey {
    fn serial(&self) -> u32 {
        self.serial
    }

    fn firmware_version(&self) -> (u8, u8, u8) {
        self.firmware
    }

    fn read_public_key(&mut self, slot: Slot) -> YkadaResult<Option<VerifyingKey>> {
        Ok(self.keys.get(&slot).map(|key| key.verifying_key()))
    }
}

pub struct FakeDeviceFinder {
    pub device: Option<FakeYubiKey>,
}

impl DeviceFinder for FakeDeviceFinder {
    type Device = FakeYubiKey;

    fn find_first(&self) -> YkadaResult<Self::Device> {
        self.device.clone().ok_or(YkadaError::NotFound)
    }
}

run_yubikey_contract_tests!(
    fake_yubikey_contract,
    make = || FakeYubiKey::new(Pin::default())
);
