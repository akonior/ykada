use crate::error::{YkadaError, YkadaResult};
use crate::model::{ManagementKey, Pin, PinPolicy, Slot, SlotKey, TouchPolicy};
use crate::ports::{
    DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
    SlotPolicyReader,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

// Private keys and ykada's public-key objects are kept apart, as on a real YubiKey, where
// either can exist without the other.
#[derive(Debug, Clone)]
pub(crate) struct FakeYubiKey {
    firmware: (u8, u8, u8),
    keys: HashMap<Slot, SigningKey>,
    public_keys: HashMap<Slot, VerifyingKey>,
    non_ed25519_keys: HashSet<Slot>,
    slot_policies: HashMap<Slot, (PinPolicy, TouchPolicy)>,
    authenticated: bool,
    metadata_fails: bool,
    // Shared by clones, so a test can see what the use case wrote to the device it was given.
    writes: Rc<RefCell<Vec<Slot>>>,
}

impl FakeYubiKey {
    pub(crate) const MGMT_KEY: ManagementKey = ManagementKey::new([8; 24]);

    pub(crate) fn empty() -> Self {
        Self {
            firmware: (5, 7, 0),
            keys: HashMap::new(),
            public_keys: HashMap::new(),
            non_ed25519_keys: HashSet::new(),
            slot_policies: HashMap::new(),
            authenticated: false,
            metadata_fails: false,
            writes: Rc::default(),
        }
    }

    pub(crate) fn with_firmware(self, firmware: (u8, u8, u8)) -> Self {
        Self { firmware, ..self }
    }

    // A slot as ykada provisions it: the private key and its public-key object.
    pub(crate) fn with_key(self, slot: Slot, key: SigningKey) -> Self {
        let vk = key.verifying_key();
        self.with_bare_key(slot, key)
            .with_public_key_object(slot, vk)
    }

    // A private key without ykada's public-key object: made by another tool, or an import
    // that stopped after writing the key.
    pub(crate) fn with_bare_key(self, slot: Slot, key: SigningKey) -> Self {
        Self {
            keys: self.keys.into_iter().chain([(slot, key)]).collect(),
            ..self
        }
    }

    pub(crate) fn with_public_key_object(self, slot: Slot, vk: VerifyingKey) -> Self {
        Self {
            public_keys: self.public_keys.into_iter().chain([(slot, vk)]).collect(),
            ..self
        }
    }

    // An RSA or ECC key, as another PIV tool would leave it.
    pub(crate) fn with_non_ed25519_key(self, slot: Slot) -> Self {
        Self {
            non_ed25519_keys: self.non_ed25519_keys.into_iter().chain([slot]).collect(),
            ..self
        }
    }

    pub(crate) fn with_failing_metadata(self) -> Self {
        Self {
            metadata_fails: true,
            ..self
        }
    }

    pub(crate) fn written_slots(&self) -> Rc<RefCell<Vec<Slot>>> {
        Rc::clone(&self.writes)
    }
}

impl PinVerifier for FakeYubiKey {
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()> {
        match pin.as_bytes() == Pin::DEFAULT {
            true => Ok(()),
            false => Err(YkadaError::WrongPin { tries: 2 }),
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
        vk: VerifyingKey,
        config: KeyConfig,
    ) -> YkadaResult<()> {
        if !self.authenticated {
            return Err(YkadaError::AuthenticationFailed {
                reason: "management key not authenticated".into(),
            });
        }
        self.writes.borrow_mut().push(config.slot);
        self.slot_policies
            .insert(config.slot, (config.pin_policy, config.touch_policy));
        self.keys.insert(config.slot, key);
        self.public_keys.insert(config.slot, vk);
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

    fn slot_key(&mut self, slot: Slot) -> YkadaResult<SlotKey> {
        match (
            self.metadata_fails,
            self.non_ed25519_keys.contains(&slot),
            self.keys.get(&slot),
        ) {
            (true, _, _) => Err(YkadaError::YubikeyLib(yubikey::Error::GenericError)),
            (false, true, _) => Ok(SlotKey::Other),
            (false, false, Some(key)) => Ok(SlotKey::Ed25519(key.verifying_key())),
            (false, false, None) => Ok(SlotKey::Empty),
        }
    }

    fn public_key_object(&mut self, slot: Slot) -> YkadaResult<Option<VerifyingKey>> {
        Ok(self.public_keys.get(&slot).copied())
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

// A computer with no YubiKey connected.
pub(crate) struct NoDevice;

impl DeviceFinder for NoDevice {
    type Device = FakeYubiKey;

    fn find_first(&self) -> YkadaResult<Self::Device> {
        Err(YkadaError::NotFound)
    }
}

pub(crate) struct FakeDeviceFinder(pub(crate) FakeYubiKey);

impl DeviceFinder for FakeDeviceFinder {
    type Device = FakeYubiKey;

    fn find_first(&self) -> YkadaResult<Self::Device> {
        Ok(self.0.clone())
    }
}
