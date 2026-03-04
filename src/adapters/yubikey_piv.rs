use crate::error::{YkadaError, YkadaResult};
use crate::model::{Algorithm, ManagementKey, Pin, Slot};
use crate::ports::{
    DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier, PinVerifier, Signer,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::convert::TryInto;
use tracing::{debug, info};
use yubikey::piv::{generate, import_cv_key, sign_data};
use yubikey::{Context, MgmKey, ObjectId, YubiKey};

/// YubiKey data-object ID used to store the Cardano verifying key alongside an imported key.
/// Uses the PIV certificate slot object IDs so each active key slot has a companion storage area.
fn slot_to_vk_object_id(slot: Slot) -> ObjectId {
    match slot {
        Slot::Authentication => 0x005F_C105,
        Slot::Signature => 0x005F_C10A,
        Slot::KeyManagement => 0x005F_C10B,
        Slot::CardAuthentication => 0x005F_C101,
    }
}

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

        self.device.authenticate(&mgm_key).map_err(|e| match e {
            yubikey::Error::AuthenticationError => YkadaError::AuthenticationFailed {
                reason: "wrong management key".into(),
            },
            other => YkadaError::YubikeyLib(other),
        })?;

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
    fn import_key(
        &mut self,
        key: SigningKey,
        vk: VerifyingKey,
        config: KeyConfig,
    ) -> YkadaResult<()> {
        self.ensure_authenticated()?;

        let algorithm = Algorithm::default_cardano();

        debug!("Importing key to slot: {:?}", config.slot);
        debug!("Algorithm: {:?}", algorithm);
        debug!(
            "Policies: PIN={:?}, Touch={:?}",
            config.pin_policy, config.touch_policy
        );
        debug!("Private key (seed): {}", hex::encode(key.as_bytes()));
        debug!("Verifying key: {}", hex::encode(vk.as_bytes()));

        import_cv_key(
            &mut self.device,
            config.slot.to_yubikey_slot_id(),
            algorithm.to_yubikey_algorithm_id(),
            key.as_bytes(),
            config.touch_policy.to_yubikey_touch_policy(),
            config.pin_policy.to_yubikey_pin_policy(),
        )?;

        // Store the Cardano verifying key (kL * G) so `read_public_key` can retrieve it.
        // The YubiKey firmware uses standard RFC 8032 Ed25519 (SHA-512 expansion), which
        // produces a different public key than the Cardano one, so metadata() can't be used.
        let mut vk_bytes = *vk.as_bytes();
        self.device
            .save_object(slot_to_vk_object_id(config.slot), &mut vk_bytes)?;

        info!("Key imported successfully to slot {:?}", config.slot);
        Ok(())
    }

    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<VerifyingKey> {
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
        )?;

        info!("Key generated successfully in slot {:?}", slot_id);

        let public_key_bytes = spki.subject_public_key.raw_bytes();

        if public_key_bytes.len() != 32 {
            return Err(YkadaError::InvalidKeyFormat {
                format: format!(
                    "Expected 32 bytes for Ed25519 public key, got {}",
                    public_key_bytes.len()
                ),
            });
        }

        let public_key_array: [u8; 32] =
            public_key_bytes[..32]
                .try_into()
                .map_err(|_| YkadaError::InvalidKeyFormat {
                    format: "Failed to convert public key bytes to array".to_string(),
                })?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_array)?;

        // Store generated public key so read_public_key can retrieve it consistently.
        let mut vk_bytes = *verifying_key.as_bytes();
        self.device
            .save_object(slot_to_vk_object_id(config.slot), &mut vk_bytes)?;

        Ok(verifying_key)
    }
}

impl DeviceReader for PivYubiKey {
    fn serial(&self) -> u32 {
        self.device.serial().0
    }

    fn firmware_version(&self) -> (u8, u8, u8) {
        let v = self.device.version();
        (v.major, v.minor, v.patch)
    }

    fn read_public_key(&mut self, slot: Slot) -> YkadaResult<Option<VerifyingKey>> {
        // Read the Cardano verifying key stored by import_key / generate_key.
        // We do NOT use metadata() because the YubiKey firmware uses standard RFC 8032
        // Ed25519 (SHA-512 seed expansion) to derive its stored public key, which differs
        // from the Cardano public key kL * G that we need for address derivation.
        match self.device.fetch_object(slot_to_vk_object_id(slot)) {
            Ok(bytes) if bytes.len() == 32 => {
                let arr: [u8; 32] =
                    bytes[..]
                        .try_into()
                        .map_err(|_| YkadaError::InvalidKeyFormat {
                            format: "Expected 32-byte stored verifying key".to_string(),
                        })?;
                Ok(Some(VerifyingKey::from_bytes(&arr)?))
            }
            _ => Ok(None),
        }
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
            "Signing {} bytes with YubiKey: slot={:?} algorithm={:?} data={}",
            data.len(),
            slot,
            algorithm,
            hex::encode(data),
        );

        let signature = sign_data(
            &mut self.device,
            data,
            algorithm.to_yubikey_algorithm_id(),
            slot.to_yubikey_slot_id(),
        )?;

        let sig_bytes = signature.to_vec();
        debug!("YubiKey signature: {}", hex::encode(&sig_bytes));
        info!("YubiKey: signed {} bytes in slot {:?}", data.len(), slot);
        Ok(sig_bytes)
    }
}

#[cfg(all(test, feature = "hardware-tests"))]
mod tests {
    use super::*;
    use crate::logic::Bech32Encodable;
    use crate::model::{ManagementKey, Network, SeedPhrase, WalletConfig};
    use crate::run_yubikey_contract_tests;
    use crate::use_cases::{generate_wallet_use_case, wallet_info_use_case};

    const TESTING_MANAGEMENT_KEY: ManagementKey = ManagementKey::new([
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
    ]);

    const KNOWN_PHRASE: &str = "cash antique chimney egg enact blast embody ecology dust fiction hope black crisp thunder tiny fame mixture object text boil odor minor ordinary deer";
    const KNOWN_ADDRESS_MAINNET: &str = "addr1qx2l2ttwpsxc8j4830x7hpz0qgaf2hkt6dn7x940vcneycwcnz39fcfw4xs5elpnpmfmh45vhx2qk3h8q56ma0zg9nnsvzxxtr";

    #[test]
    fn test_device_finder_success() {
        let result = PivDeviceFinder.find_first();
        assert!(result.is_ok(), "error: {:?}", result.err());
    }

    /// Imports the known seed phrase as a Mainnet wallet, then reads the keys back via
    /// wallet_info_use_case and verifies the derived address matches the known correct value.
    /// Requires a YubiKey with the testing management key configured.
    #[test]
    fn test_known_mainnet_address_round_trip() {
        let finder = PivDeviceFinder;
        let seed = SeedPhrase::try_from(KNOWN_PHRASE).expect("Invalid seed phrase");
        let config = WalletConfig {
            network: Network::Mainnet,
            ..WalletConfig::default()
        };

        generate_wallet_use_case(&finder, seed, config, Some(&TESTING_MANAGEMENT_KEY))
            .expect("generate_wallet_use_case failed");

        let info = wallet_info_use_case(
            &finder,
            config.payment_slot,
            config.stake_slot,
            config.network,
        )
        .expect("wallet_info_use_case failed");

        let address = info
            .address
            .expect("address must be Some when both keys are present")
            .to_bech32()
            .expect("bech32 encoding failed");

        assert_eq!(
            address, KNOWN_ADDRESS_MAINNET,
            "address mismatch for known seed phrase"
        );
    }

    run_yubikey_contract_tests!(
        real_yubikey_contract,
        make = || PivDeviceFinder.find_first().expect("YubiKey not found")
    );
}
