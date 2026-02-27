use crate::error::YkadaResult;
use crate::logic::derive_cardano_address;
use crate::model::{Network, Slot, WalletInfo};
use crate::ports::{DeviceFinder, DeviceReader};

pub fn wallet_info_use_case<F>(
    finder: &F,
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
) -> YkadaResult<WalletInfo>
where
    F: DeviceFinder,
    F::Device: DeviceReader,
{
    let mut device = finder.find_first()?;

    let serial = device.serial();
    let firmware = device.firmware_version();
    let payment_vk = device
        .read_public_key(payment_slot)?
        .map(|pk| pk.to_verifying_key());
    let stake_vk = device
        .read_public_key(stake_slot)?
        .map(|pk| pk.to_verifying_key());
    let address = payment_vk
        .zip(stake_vk)
        .map(|(p, s)| derive_cardano_address(&p, &s, network));

    Ok(WalletInfo {
        serial,
        firmware,
        network,
        payment_vk,
        stake_vk,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::logic::{derive_key_pair, Bech32Encodable};
    use crate::model::{
        DerivationPath, Ed25519PublicKey, ManagementKey, Network, Pin, SeedPhrase, Slot,
        WalletConfig,
    };
    use crate::ports::{KeyConfig, KeyManager};
    use crate::use_cases::generate_wallet_use_case;

    const TEST_PHRASE: &str =
        "test walk nut penalty hip pave soap entry language right filter choice";

    const KNOWN_PHRASE: &str =
        "cash antique chimney egg enact blast embody ecology dust fiction hope black crisp thunder tiny fame mixture object text boil odor minor ordinary deer";

    const KNOWN_ADDRESS_MAINNET: &str =
        "addr1q803e62cfnzevmtakaqsf4fvew4psjhgpl494ywxeuqdv5pjp2g6fyqjqh0l6k3rp90ltutqhxwfgkvg3tkacwvkuwqsx93m47";

    fn make_mgmt_key() -> ManagementKey {
        ManagementKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9,
        ])
    }

    /// Import payment + stake keys from TEST_PHRASE into a FakeYubiKey using the correct Cardano VKs.
    fn finder_with_keys() -> FakeDeviceFinder {
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let payment_path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let stake_path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();
        let (payment_sk, payment_vk) = derive_key_pair(&seed, "", &payment_path).unwrap();
        let (stake_sk, stake_vk) = derive_key_pair(&seed, "", &stake_path).unwrap();

        let config = WalletConfig::default();
        let mut device = FakeYubiKey::new(Pin::default());
        device.authenticated = true;
        device
            .import_key(
                payment_sk,
                Ed25519PublicKey::from(payment_vk),
                KeyConfig {
                    slot: config.payment_slot,
                    pin_policy: config.pin_policy,
                    touch_policy: config.touch_policy,
                },
            )
            .unwrap();
        device
            .import_key(
                stake_sk,
                Ed25519PublicKey::from(stake_vk),
                KeyConfig {
                    slot: config.stake_slot,
                    pin_policy: config.pin_policy,
                    touch_policy: config.touch_policy,
                },
            )
            .unwrap();

        FakeDeviceFinder {
            device: Some(device),
        }
    }

    #[test]
    fn test_info_with_both_keys() {
        let finder = finder_with_keys();
        let result = wallet_info_use_case(
            &finder,
            Slot::Signature,
            Slot::KeyManagement,
            Network::Preview,
        );

        assert!(result.is_ok(), "error: {:?}", result.err());
        let info = result.unwrap();
        assert!(info.payment_vk.is_some());
        assert!(info.stake_vk.is_some());
        assert!(info.address.is_some());
    }

    #[test]
    fn test_info_with_no_keys() {
        let finder = FakeDeviceFinder {
            device: Some(FakeYubiKey::new(Pin::default())),
        };
        let info = wallet_info_use_case(
            &finder,
            Slot::Signature,
            Slot::KeyManagement,
            Network::Preview,
        )
        .unwrap();

        assert!(info.payment_vk.is_none());
        assert!(info.stake_vk.is_none());
        assert!(info.address.is_none());
    }

    #[test]
    fn test_info_with_one_key() {
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let payment_path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let (payment_sk, payment_vk) = derive_key_pair(&seed, "", &payment_path).unwrap();

        let config = WalletConfig::default();
        let mut device = FakeYubiKey::new(Pin::default());
        device.authenticated = true;
        device
            .import_key(
                payment_sk,
                Ed25519PublicKey::from(payment_vk),
                KeyConfig {
                    slot: config.payment_slot,
                    pin_policy: config.pin_policy,
                    touch_policy: config.touch_policy,
                },
            )
            .unwrap();

        let finder = FakeDeviceFinder {
            device: Some(device),
        };
        let info = wallet_info_use_case(
            &finder,
            Slot::Signature,
            Slot::KeyManagement,
            Network::Preview,
        )
        .unwrap();

        assert!(info.payment_vk.is_some());
        assert!(info.stake_vk.is_none());
        assert!(info.address.is_none());
    }

    #[test]
    fn test_address_testnet_prefix() {
        let finder = finder_with_keys();
        let info = wallet_info_use_case(
            &finder,
            Slot::Signature,
            Slot::KeyManagement,
            Network::Preview,
        )
        .unwrap();

        let encoded = info.address.unwrap().to_bech32().unwrap();
        assert!(encoded.starts_with("addr_test1"), "got: {}", encoded);
    }

    #[test]
    fn test_serial_and_firmware_returned() {
        let finder = FakeDeviceFinder {
            device: Some(FakeYubiKey::new(Pin::default())),
        };
        let info = wallet_info_use_case(
            &finder,
            Slot::Signature,
            Slot::KeyManagement,
            Network::Preview,
        )
        .unwrap();

        assert_eq!(info.serial, 0);
        assert_eq!(info.firmware, (5, 4, 3));
    }

    /// wallet_info_use_case (using finder_with_keys) must produce the same address
    /// as generate_wallet_use_case (which derives the address from the seed phrase directly).
    /// Both operations use the same Cardano key derivation, so the addresses must agree.
    #[test]
    fn test_info_address_matches_generate_address() {
        use crate::logic::derive_cardano_address;

        // Derive the expected address the same way generate_wallet_use_case does.
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let payment_path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let stake_path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();
        let (_, payment_vk) = derive_key_pair(&seed, "", &payment_path).unwrap();
        let (_, stake_vk) = derive_key_pair(&seed, "", &stake_path).unwrap();
        let expected_address = derive_cardano_address(&payment_vk, &stake_vk, Network::Preview)
            .to_bech32()
            .unwrap();

        // finder_with_keys() imports the Cardano VKs for TEST_PHRASE into a FakeYubiKey.
        // wallet_info_use_case reads them back and derives the same address.
        let finder = finder_with_keys();
        let info = wallet_info_use_case(
            &finder,
            Slot::Signature,
            Slot::KeyManagement,
            Network::Preview,
        )
        .unwrap();
        let info_address = info.address.unwrap().to_bech32().unwrap();

        assert_eq!(
            expected_address, info_address,
            "generate and info must produce the same address"
        );
    }

    #[test]
    fn test_known_mainnet_address() {
        let finder = FakeDeviceFinder {
            device: Some(FakeYubiKey::new(Pin::default())),
        };
        let seed = SeedPhrase::try_from(KNOWN_PHRASE).unwrap();
        let mgmt_key = make_mgmt_key();
        let config = WalletConfig {
            network: Network::Mainnet,
            ..WalletConfig::default()
        };

        let wallet = generate_wallet_use_case(&finder, seed, config, Some(&mgmt_key)).unwrap();
        let address = wallet.address.to_bech32().unwrap();

        assert_eq!(
            address, KNOWN_ADDRESS_MAINNET,
            "address mismatch for known seed phrase"
        );
    }
}
