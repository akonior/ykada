use crate::logic::derive_key_pair;
use crate::model::{DerivationPath, SeedPhrase};
use crate::ports::{DeviceFinder, KeyConfig, KeyManager, ManagementKeyVerifier};
use crate::{ManagementKey, YkadaResult};
use ed25519_dalek::VerifyingKey;
use tracing::{debug, info};

pub fn import_private_key_from_seed_phrase_use_case<F>(
    finder: &F,
    seed_phrase: &str,
    passphrase: &str,
    path: Option<&str>,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey>
where
    F: DeviceFinder,
    F::Device: KeyManager + ManagementKeyVerifier,
{
    let seed = SeedPhrase::try_from(seed_phrase)?;
    let derivation_path = if let Some(path_str) = path {
        DerivationPath::try_from(path_str)?
    } else {
        DerivationPath::default()
    };

    let slot = config.slot;
    info!(
        "Importing key to slot {:?} (path: {:?})",
        slot, derivation_path
    );

    // derive_key_pair returns (kL, kL*G) — the Cardano private key and its verifying key.
    let (private_key, cardano_vk) = derive_key_pair(&seed, passphrase, &derivation_path)?;
    debug!(
        "Derived private key: {}",
        hex::encode(private_key.as_bytes())
    );
    debug!(
        "Derived verifying key: {}",
        hex::encode(cardano_vk.as_bytes())
    );

    let mut device = finder.find_first()?;
    device.authenticate(mgmt_key)?;
    device.import_key(private_key, cardano_vk, config)?;

    info!("Key imported successfully to slot {:?}", slot);
    Ok(cardano_vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::logic::{Bech32Encodable, StakeVerifyingKey};
    use crate::model::{ManagementKey, Pin, Slot};
    use crate::ports::KeyConfig;

    const TEST_PHRASE: &str =
        "test walk nut penalty hip pave soap entry language right filter choice";
    const PAYMENT_PATH: &str = "m/1852'/1815'/0'/0/0";
    const STAKE_PATH: &str = "m/1852'/1815'/0'/2/0";

    fn make_finder() -> FakeDeviceFinder {
        FakeDeviceFinder {
            device: Some(FakeYubiKey::new(Pin::default())),
        }
    }

    fn make_mgmt_key() -> ManagementKey {
        ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ])
    }

    fn make_config(slot: Slot) -> KeyConfig {
        KeyConfig {
            slot,
            ..KeyConfig::default()
        }
    }

    fn import(finder: &FakeDeviceFinder, path: &str, slot: Slot) -> VerifyingKey {
        import_private_key_from_seed_phrase_use_case(
            finder,
            TEST_PHRASE,
            "",
            Some(path),
            make_config(slot),
            Some(&make_mgmt_key()),
        )
        .expect("import failed")
    }

    #[test]
    fn test_import_from_seed_phrase() {
        let result = import_private_key_from_seed_phrase_use_case(
            &make_finder(),
            TEST_PHRASE,
            "",
            Some(PAYMENT_PATH),
            KeyConfig::default(),
            Some(&make_mgmt_key()),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
        assert_eq!(result.unwrap().as_bytes().len(), 32);
    }

    #[test]
    fn test_import_from_seed_phrase_with_passphrase() {
        let result = import_private_key_from_seed_phrase_use_case(
            &make_finder(),
            "eight country switch draw meat scout mystery blade tip drift useless good keep usage title",
            "foo",
            Some(PAYMENT_PATH),
            KeyConfig::default(),
            Some(&make_mgmt_key()),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
    }

    #[test]
    fn test_import_from_seed_phrase_default_path() {
        let result = import_private_key_from_seed_phrase_use_case(
            &make_finder(),
            TEST_PHRASE,
            "",
            None,
            KeyConfig::default(),
            Some(&make_mgmt_key()),
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
    }

    #[test]
    fn test_import_payment_key_has_addr_vk_prefix() {
        let vk = import(&make_finder(), PAYMENT_PATH, Slot::Signature);

        let encoded = vk.to_bech32().unwrap();
        assert!(encoded.starts_with("addr_vk1"), "got: {}", encoded);
    }

    #[test]
    fn test_import_stake_key_has_stake_vk_prefix() {
        let vk = import(&make_finder(), STAKE_PATH, Slot::KeyManagement);

        let encoded = StakeVerifyingKey(vk).to_bech32().unwrap();
        assert!(encoded.starts_with("stake_vk1"), "got: {}", encoded);
    }

    #[test]
    fn test_payment_and_stake_keys_from_same_seed_differ() {
        let payment_vk = import(&make_finder(), PAYMENT_PATH, Slot::Signature);
        let stake_vk = import(&make_finder(), STAKE_PATH, Slot::KeyManagement);

        assert_ne!(
            payment_vk.as_bytes(),
            stake_vk.as_bytes(),
            "payment and stake keys must differ"
        );
    }

    #[test]
    fn test_import_key_is_deterministic() {
        let vk1 = import(&make_finder(), PAYMENT_PATH, Slot::Signature);
        let vk2 = import(&make_finder(), PAYMENT_PATH, Slot::Signature);

        assert_eq!(
            vk1.as_bytes(),
            vk2.as_bytes(),
            "same seed+path must always produce the same verifying key"
        );
    }
}
