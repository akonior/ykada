use crate::error::{YkadaError, YkadaResult};
use crate::model::{ManagementKey, Pin, PinPolicy, Slot, TouchPolicy};
use crate::ports::{
    DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
    SlotPolicyReader,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(crate) struct FakeYubiKey {
    firmware: (u8, u8, u8),
    keys: HashMap<Slot, SigningKey>,
    slot_policies: HashMap<Slot, (PinPolicy, TouchPolicy)>,
    authenticated: bool,
}

impl FakeYubiKey {
    pub(crate) const MGMT_KEY: ManagementKey = ManagementKey::new([8; 24]);

    pub(crate) fn empty() -> Self {
        Self {
            firmware: (5, 7, 0),
            keys: HashMap::new(),
            slot_policies: HashMap::new(),
            authenticated: false,
        }
    }

    pub(crate) fn with_firmware(self, firmware: (u8, u8, u8)) -> Self {
        Self { firmware, ..self }
    }

    pub(crate) fn with_key(self, slot: Slot, key: SigningKey) -> Self {
        Self {
            keys: self.keys.into_iter().chain([(slot, key)]).collect(),
            ..self
        }
    }
}

impl PinVerifier for FakeYubiKey {
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()> {
        match pin.as_bytes() == Pin::DEFAULT {
            true => Ok(()),
            false => Err(yubikey::Error::WrongPin { tries: 2 }.into()),
        }
    }
}

impl ManagementKeyVerifier for FakeYubiKey {
    fn authenticate(&mut self, mgmt_key: Option<&ManagementKey>) -> YkadaResult<()> {
        match mgmt_key.is_none_or(|key| *key == Self::MGMT_KEY) {
            true => {
                self.authenticated = true;
                Ok(())
            }
            false => Err(YkadaError::AuthenticationFailed {
                reason: "wrong management key".into(),
            }),
        }
    }
}

impl KeyManager for FakeYubiKey {
    fn import_key(
        &mut self,
        key: SigningKey,
        _vk: VerifyingKey,
        config: KeyConfig,
    ) -> YkadaResult<()> {
        if !self.authenticated {
            return Err(YkadaError::AuthenticationFailed {
                reason: "management key not authenticated".into(),
            });
        }
        self.slot_policies
            .insert(config.slot, (config.pin_policy, config.touch_policy));
        self.keys.insert(config.slot, key);
        Ok(())
    }
}

impl Signer for FakeYubiKey {
    fn sign(&mut self, data: &[u8], slot: Slot, pin: Option<&Pin>) -> YkadaResult<[u8; 64]> {
        use ed25519_dalek::Signer as _;
        pin.map_or(Ok(()), |pin| self.verify_pin(pin))?;
        self.keys
            .get(&slot)
            .map(|key| key.sign(data).to_bytes())
            .ok_or(YkadaError::YubikeyLib(yubikey::Error::GenericError))
    }
}

impl DeviceReader for FakeYubiKey {
    fn firmware_version(&self) -> (u8, u8, u8) {
        self.firmware
    }

    fn read_public_key(&mut self, slot: Slot) -> YkadaResult<Option<VerifyingKey>> {
        Ok(self.keys.get(&slot).map(SigningKey::verifying_key))
    }
}

impl SlotPolicyReader for FakeYubiKey {
    fn read_slot_policy(&mut self, slot: Slot) -> YkadaResult<(PinPolicy, TouchPolicy)> {
        Ok(self
            .slot_policies
            .get(&slot)
            .copied()
            .unwrap_or((PinPolicy::Never, TouchPolicy::Never)))
    }
}

pub(crate) struct FakeDeviceFinder(pub(crate) FakeYubiKey);

impl DeviceFinder for FakeDeviceFinder {
    type Device = FakeYubiKey;

    fn find_first(&self) -> YkadaResult<Self::Device> {
        Ok(self.0.clone())
    }
}
