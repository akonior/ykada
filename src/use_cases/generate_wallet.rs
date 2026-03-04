use crate::error::YkadaResult;
use crate::logic::{
    check_firmware_version, derive_cardano_address, derive_signing_key, Bech32Encodable,
};
use crate::model::{DerivationPath, GeneratedWallet, ManagementKey, SeedPhrase, WalletConfig};
use crate::ports::{DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier};
use tracing::{debug, info};

pub fn generate_wallet_use_case<F>(
    finder: &F,
    seed: Option<SeedPhrase>,
    config: WalletConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<GeneratedWallet>
where
    F: DeviceFinder,
    F::Device: KeyManager + ManagementKeyVerifier + DeviceReader,
{
    info!("Generating Cardano wallet (network: {:?})", config.network);

    let seed = match seed {
        Some(s) => s,
        None => SeedPhrase::generate()?,
    };

    let payment_path = DerivationPath::try_from("m/1852'/1815'/0'/0/0")?;
    let stake_path = DerivationPath::try_from("m/1852'/1815'/0'/2/0")?;

    let payment_sk = derive_signing_key(&seed, "", &payment_path)?;
    let payment_vk = payment_sk.verifying_key();
    debug!(
        "Payment private key: {}",
        hex::encode(payment_sk.as_bytes())
    );
    debug!(
        "Payment verifying key: {}",
        hex::encode(payment_vk.as_bytes())
    );

    let stake_sk = derive_signing_key(&seed, "", &stake_path)?;
    let stake_vk = stake_sk.verifying_key();
    debug!("Stake private key: {}", hex::encode(stake_sk.as_bytes()));
    debug!("Stake verifying key: {}", hex::encode(stake_vk.as_bytes()));

    let address = derive_cardano_address(&payment_vk, &stake_vk, config.network);
    debug!(
        "Derived address: {}",
        address
            .to_bech32()
            .unwrap_or_else(|_| hex::encode(address.to_bytes()))
    );

    let mut device = finder.find_first()?;
    check_firmware_version(device.firmware_version())?;
    device.authenticate(mgmt_key)?;

    let payment_config = KeyConfig {
        slot: config.payment_slot,
        pin_policy: config.pin_policy,
        touch_policy: config.touch_policy,
    };
    let stake_config = KeyConfig {
        slot: config.stake_slot,
        pin_policy: config.pin_policy,
        touch_policy: config.touch_policy,
    };

    device.import_key(payment_sk, payment_vk, payment_config)?;
    device.import_key(stake_sk, stake_vk, stake_config)?;

    info!(
        "Wallet generated: address={}",
        address
            .to_bech32()
            .unwrap_or_else(|_| hex::encode(address.to_bytes()))
    );

    Ok(GeneratedWallet {
        mnemonic: seed,
        payment_vk,
        stake_vk,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::logic::Bech32Encodable;
    use crate::model::{ManagementKey, Network, Pin};
    use crate::YkadaError;

    const TEST_PHRASE: &str =
        "test walk nut penalty hip pave soap entry language right filter choice";

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

    #[test]
    fn test_happy_path_keys_derived_and_returned() {
        let finder = make_finder();
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let config = WalletConfig::default();
        let mgmt_key = make_mgmt_key();

        let result = generate_wallet_use_case(&finder, Some(seed), config, Some(&mgmt_key));

        assert!(result.is_ok(), "error: {:?}", result.err());
        let wallet = result.unwrap();
        assert_eq!(wallet.payment_vk.as_bytes().len(), 32);
        assert_eq!(wallet.stake_vk.as_bytes().len(), 32);
        assert_ne!(
            wallet.payment_vk.as_bytes(),
            wallet.stake_vk.as_bytes(),
            "payment and stake keys must differ"
        );
        assert_eq!(wallet.mnemonic.phrase(), TEST_PHRASE);
    }

    #[test]
    fn test_address_testnet_prefix() {
        let finder = make_finder();
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let config = WalletConfig {
            network: Network::Preview,
            ..WalletConfig::default()
        };
        let mgmt_key = make_mgmt_key();

        let wallet =
            generate_wallet_use_case(&finder, Some(seed), config, Some(&mgmt_key)).unwrap();
        let encoded = wallet.address.to_bech32().unwrap();
        assert!(encoded.starts_with("addr_test1"), "got: {}", encoded);
    }

    #[test]
    fn test_not_found_when_no_device() {
        let finder = FakeDeviceFinder { device: None };
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let config = WalletConfig::default();

        let result = generate_wallet_use_case(&finder, Some(seed), config, None);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), YkadaError::NotFound));
    }

    #[test]
    fn test_authentication_failed_wrong_mgmt_key() {
        let finder = make_finder();
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let config = WalletConfig::default();
        let wrong_key = ManagementKey::new([1u8; 24]);

        let result = generate_wallet_use_case(&finder, Some(seed), config, Some(&wrong_key));

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YkadaError::AuthenticationFailed { .. }
        ));
    }
}
