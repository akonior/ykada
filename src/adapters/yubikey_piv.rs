use crate::error::{YkadaError, YkadaResult};
use crate::model::{ManagementKey, Pin, PinPolicy, Slot, SlotKey, TouchPolicy};
use crate::ports::{
    DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
    SlotPolicyReader,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use yubikey::piv::{
    import_cv_key, sign_data, AlgorithmId, ManagementSlotId, SlotAlgorithmId, SlotId, SlotMetadata,
};
use yubikey::{Context, MgmAlgorithmId, MgmKey, ObjectId, YubiKey};

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
        let opened: Vec<_> = readers.iter()?.map(|reader| reader.open()).collect();
        pick_device(opened).map(PivYubiKey::new)
    }
}

// Exactly one YubiKey must open. A reader that fails to open is reported rather than counted
// as absent: a YubiKey held by another program (gpg's scdaemon, for one) fails that way.
fn pick_device<T>(opened: Vec<Result<T, yubikey::Error>>) -> YkadaResult<T> {
    let (devices, failures): (Vec<_>, Vec<_>) = opened.into_iter().partition(Result::is_ok);
    let mut devices: Vec<T> = devices.into_iter().filter_map(Result::ok).collect();
    let failures: Vec<yubikey::Error> = failures.into_iter().filter_map(Result::err).collect();
    match (devices.len(), failures.first()) {
        (1, _) => Ok(devices.remove(0)),
        (0, None) => Err(YkadaError::NotFound),
        (0, Some(e)) => Err(YkadaError::DeviceUnavailable {
            reason: e.to_string(),
        }),
        (count, _) => Err(YkadaError::MultipleDevicesFound { count }),
    }
}

// The algorithm of the management key on the device (firmware 5.3+ reports it).
fn management_key_algorithm(device: &mut YubiKey) -> Option<MgmAlgorithmId> {
    let slot = SlotId::Management(ManagementSlotId::Management);
    match yubikey::piv::metadata(device, slot).map(|metadata| metadata.algorithm) {
        Ok(SlotAlgorithmId::Management(algorithm)) => Some(algorithm),
        Ok(SlotAlgorithmId::Asymmetric(_) | SlotAlgorithmId::PinPuk) | Err(_) => None,
    }
}

fn key_length(algorithm: MgmAlgorithmId) -> usize {
    match algorithm {
        MgmAlgorithmId::Aes128 => 16,
        MgmAlgorithmId::Aes192 | MgmAlgorithmId::ThreeDes => 24,
        MgmAlgorithmId::Aes256 => 32,
    }
}

// The algorithm the YubiKey reports, checked against the key's length; without a report, the
// AES variant of that length (AES-192 for 24 bytes, the default since firmware 5.7).
fn mgmt_algorithm(
    reported: Option<MgmAlgorithmId>,
    key: &ManagementKey,
) -> YkadaResult<MgmAlgorithmId> {
    let length = key.as_bytes().len();
    let by_length = match length {
        16 => Some(MgmAlgorithmId::Aes128),
        24 => Some(MgmAlgorithmId::Aes192),
        32 => Some(MgmAlgorithmId::Aes256),
        _other => None,
    };
    match (reported, by_length) {
        (Some(algorithm), _) if key_length(algorithm) == length => Ok(algorithm),
        (Some(algorithm), _) => Err(YkadaError::AuthenticationFailed {
            reason: format!(
                "the YubiKey's management key is {algorithm:?} ({} bytes), but the file holds {length} bytes",
                key_length(algorithm)
            ),
        }),
        (None, Some(algorithm)) => Ok(algorithm),
        (None, None) => Err(YkadaError::AuthenticationFailed {
            reason: format!("a management key can't be {length} bytes"),
        }),
    }
}

// PIN and signing failures in words a user can act on.
pub(crate) fn signing_error(e: yubikey::Error) -> YkadaError {
    match e {
        yubikey::Error::WrongPin { tries } => YkadaError::WrongPin { tries },
        yubikey::Error::PinLocked => YkadaError::PinBlocked,
        yubikey::Error::AuthenticationError => YkadaError::SigningRefused,
        other => YkadaError::YubikeyLib(other),
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
        let mgm_key = match mgmt_key {
            Some(key) => {
                let reported = management_key_algorithm(&mut self.device);
                MgmKey::from_bytes(key.as_bytes(), Some(mgmt_algorithm(reported, key)?))?
            }
            None => MgmKey::get_default(&self.device)?,
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
        self.device
            .verify_pin(pin.as_bytes())
            .map_err(signing_error)
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
        )
        .map_err(signing_error)?;
        signature
            .as_slice()
            .try_into()
            .map_err(|_| YkadaError::InvalidSignatureLength {
                actual: signature.len(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(bytes: usize) -> ManagementKey {
        ManagementKey::new(vec![0x11; bytes]).unwrap()
    }

    #[test]
    fn test_the_reported_management_key_algorithm_is_used() {
        let cases = [
            (MgmAlgorithmId::Aes128, 16),
            (MgmAlgorithmId::Aes192, 24),
            (MgmAlgorithmId::ThreeDes, 24),
            (MgmAlgorithmId::Aes256, 32),
        ];
        cases.into_iter().for_each(|(algorithm, bytes)| {
            assert_eq!(
                mgmt_algorithm(Some(algorithm), &key(bytes)).unwrap(),
                algorithm
            );
        });
    }

    #[test]
    fn test_without_a_report_the_length_picks_aes() {
        assert_eq!(
            mgmt_algorithm(None, &key(16)).unwrap(),
            MgmAlgorithmId::Aes128
        );
        assert_eq!(
            mgmt_algorithm(None, &key(24)).unwrap(),
            MgmAlgorithmId::Aes192
        );
        assert_eq!(
            mgmt_algorithm(None, &key(32)).unwrap(),
            MgmAlgorithmId::Aes256
        );
    }

    #[test]
    fn test_a_key_of_the_wrong_length_for_the_device_is_explained() {
        let msg = mgmt_algorithm(Some(MgmAlgorithmId::Aes256), &key(24))
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("Aes256 (32 bytes), but the file holds 24"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_one_yubikey_is_picked() {
        assert_eq!(pick_device(vec![Ok(7)]).unwrap(), 7);
    }

    // Another reader (a laptop's card slot) failing to open doesn't hide the YubiKey.
    #[test]
    fn test_a_failing_extra_reader_is_ignored() {
        let opened = vec![Err(yubikey::Error::GenericError), Ok(7)];
        assert_eq!(pick_device(opened).unwrap(), 7);
    }

    #[test]
    fn test_no_reader_means_no_yubikey() {
        assert!(matches!(
            pick_device::<u8>(vec![]),
            Err(YkadaError::NotFound)
        ));
    }

    // A YubiKey held by gpg fails to open: say so instead of "no YubiKey found".
    #[test]
    fn test_a_reader_that_fails_to_open_is_reported() {
        let msg = pick_device::<u8>(vec![Err(yubikey::Error::PcscError { inner: None })])
            .unwrap_err()
            .to_string();
        assert!(msg.contains("could not be opened"), "got: {msg}");
        assert!(msg.contains("gpgconf --kill scdaemon"), "got: {msg}");
    }

    #[test]
    fn test_two_yubikeys_are_refused() {
        assert!(matches!(
            pick_device(vec![Ok(1), Ok(2)]),
            Err(YkadaError::MultipleDevicesFound { count: 2 })
        ));
    }

    #[test]
    fn test_wrong_pin_says_how_many_tries_are_left() {
        let msg = signing_error(yubikey::Error::WrongPin { tries: 2 }).to_string();
        assert_eq!(
            msg,
            "wrong PIN: 2 attempt(s) left before the PIN is blocked"
        );
    }

    #[test]
    fn test_blocked_pin_says_how_to_unblock_it() {
        let msg = signing_error(yubikey::Error::PinLocked).to_string();
        assert!(msg.contains("unblock-pin"), "got: {msg}");
    }

    // On the signing path an authentication error means no touch (or no fresh PIN).
    #[test]
    fn test_touch_timeout_is_explained() {
        let msg = signing_error(yubikey::Error::AuthenticationError).to_string();
        assert!(msg.contains("not touched in time"), "got: {msg}");
    }
}
