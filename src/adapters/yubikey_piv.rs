use crate::error::{YkadaError, YkadaResult};
use crate::model::{ManagementKey, Pin, PinPolicy, Slot, SlotKey, TouchPolicy};
use crate::ports::{
    DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
    SlotPolicyReader,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use yubikey::piv::{import_cv_key, sign_data, AlgorithmId, SlotAlgorithmId, SlotMetadata};
use yubikey::{Context, MgmKey, ObjectId, YubiKey};

// The verifying key is stored in the slot's PIV certificate data object.
fn slot_to_vk_object_id(slot: Slot) -> ObjectId {
    match slot {
        Slot::Signature => 0x005F_C10A,
        Slot::KeyManagement => 0x005F_C10B,
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PivDeviceFinder;

impl DeviceFinder for PivDeviceFinder {
    type Device = PivYubiKey;

    fn find_first(&self) -> YkadaResult<Self::Device> {
        let mut readers = Context::open()?;

        let devices: Vec<YubiKey> = readers.iter()?.filter_map(|r| r.open().ok()).collect();

        match devices.len() {
            0 => Err(YkadaError::NotFound),
            1 => {
                let yk = devices.into_iter().next().expect("length checked above");
                Ok(PivYubiKey::new(yk))
            }
            count => Err(YkadaError::MultipleDevicesFound { count }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PivYubiKey {
    device: YubiKey,
    authenticated: bool,
}

impl PivYubiKey {
    pub(crate) fn new(device: YubiKey) -> Self {
        Self {
            device,
            authenticated: false,
        }
    }
}

impl ManagementKeyVerifier for PivYubiKey {
    fn authenticate(&mut self, mgmt_key: Option<&ManagementKey>) -> YkadaResult<()> {
        let mgm_key = if let Some(key) = mgmt_key {
            MgmKey::try_from(key)?
        } else {
            MgmKey::get_default(&self.device)?
        };

        self.device.authenticate(&mgm_key).map_err(|e| match e {
            yubikey::Error::AuthenticationError => YkadaError::AuthenticationFailed {
                reason: "wrong management key".into(),
            },
            other => YkadaError::YubikeyLib(other),
        })?;

        self.authenticated = true;
        Ok(())
    }
}

impl PinVerifier for PivYubiKey {
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()> {
        Ok(self.device.verify_pin(pin.as_bytes())?)
    }
}

impl KeyManager for PivYubiKey {
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

        import_cv_key(
            &mut self.device,
            config.slot.to_yubikey_slot_id(),
            AlgorithmId::Ed25519,
            key.as_bytes(),
            config.touch_policy.to_yubikey_touch_policy(),
            config.pin_policy.to_yubikey_pin_policy(),
        )?;

        let mut vk_bytes = *vk.as_bytes();
        self.device
            .save_object(slot_to_vk_object_id(config.slot), &mut vk_bytes)?;
        Ok(())
    }
}

impl DeviceReader for PivYubiKey {
    fn firmware_version(&self) -> (u8, u8, u8) {
        let v = self.device.version();
        (v.major, v.minor, v.patch)
    }

    // GET METADATA answers "reference data not found" only for a slot without a key; any
    // other failure is passed on, so callers never mistake it for an empty slot.
    fn slot_key(&mut self, slot: Slot) -> YkadaResult<SlotKey> {
        match yubikey::piv::metadata(&mut self.device, slot.to_yubikey_slot_id()) {
            Ok(metadata) => slot_key_from_metadata(slot, metadata),
            Err(yubikey::Error::NotFound) => Ok(SlotKey::Empty),
            Err(e) => Err(e.into()),
        }
    }

    fn public_key_object(&mut self, slot: Slot) -> YkadaResult<Option<VerifyingKey>> {
        match self.device.fetch_object(slot_to_vk_object_id(slot)) {
            Ok(bytes) => {
                let arr: [u8; 32] = bytes[..].try_into().map_err(|_| not_ykada_data(slot))?;
                Ok(Some(VerifyingKey::from_bytes(&arr)?))
            }
            Err(yubikey::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn not_ykada_data(slot: Slot) -> YkadaError {
    YkadaError::InvalidKeyFormat {
        format: format!(
            "slot {} holds data not written by ykada (use --force to overwrite)",
            slot.id()
        ),
    }
}

fn slot_key_from_metadata(slot: Slot, metadata: SlotMetadata) -> YkadaResult<SlotKey> {
    let malformed = |what: &str| YkadaError::InvalidKeyFormat {
        format: format!("slot {} reports {what}", slot.id()),
    };
    match (metadata.algorithm, metadata.public) {
        (SlotAlgorithmId::Asymmetric(AlgorithmId::Ed25519), Some(public)) => {
            let bytes: [u8; 32] = public
                .subject_public_key
                .raw_bytes()
                .try_into()
                .map_err(|_| malformed("an Ed25519 public key of the wrong length"))?;
            Ok(SlotKey::Ed25519(VerifyingKey::from_bytes(&bytes)?))
        }
        (SlotAlgorithmId::Asymmetric(AlgorithmId::Ed25519), None) => {
            Err(malformed("an Ed25519 key without its public key"))
        }
        (
            SlotAlgorithmId::Asymmetric(_)
            | SlotAlgorithmId::Management(_)
            | SlotAlgorithmId::PinPuk,
            _,
        ) => Ok(SlotKey::Other),
    }
}

impl SlotPolicyReader for PivYubiKey {
    fn read_slot_policy(&mut self, slot: Slot) -> YkadaResult<(PinPolicy, TouchPolicy)> {
        let md = yubikey::piv::metadata(&mut self.device, slot.to_yubikey_slot_id())?;
        match md.policy {
            None => Ok((PinPolicy::Never, TouchPolicy::Never)),
            Some((yubikey_pin, yubikey_touch)) => {
                let pin_policy = PinPolicy::from_yubikey_pin_policy(yubikey_pin)?;
                let touch_policy = TouchPolicy::from_yubikey_touch_policy(yubikey_touch)?;
                Ok((pin_policy, touch_policy))
            }
        }
    }
}

impl Signer for PivYubiKey {
    fn sign(&mut self, data: &[u8], slot: Slot, pin: Option<&Pin>) -> YkadaResult<[u8; 64]> {
        pin.map_or(Ok(()), |pin| self.verify_pin(pin))?;
        let signature = sign_data(
            &mut self.device,
            data,
            AlgorithmId::Ed25519,
            slot.to_yubikey_slot_id(),
        )?;
        signature
            .as_slice()
            .try_into()
            .map_err(|_| YkadaError::InvalidSignatureLength {
                actual: signature.len(),
            })
    }
}
