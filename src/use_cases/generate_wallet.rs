use crate::error::{YkadaError, YkadaResult};
use crate::logic::{check_firmware_version, derive_wallet_keys, WalletKeys};
use crate::model::{
    GeneratedWallet, ManagementKey, Overwrite, SeedPhrase, WalletConfig, PAYMENT_SLOT, STAKE_SLOT,
};
use crate::ports::{DeviceFinder, DeviceReader, KeyConfig, KeyManager, ManagementKeyVerifier};

// Derive payment + stake keys from `seed` (or a fresh random one) and import them.
pub(crate) fn generate_wallet_use_case<F: DeviceFinder>(
    finder: &F,
    seed: Option<SeedPhrase>,
    config: WalletConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<GeneratedWallet> {
    let seed = match seed {
        Some(s) => s,
        None => SeedPhrase::generate()?,
    };
    let WalletKeys {
        payment_sk,
        stake_sk,
        payment_vk,
        stake_vk,
        address,
    } = derive_wallet_keys(&seed, config.network);

    let mut device = finder.find_first()?;
    check_firmware_version(device.firmware_version())?;
    refuse_overwrite(&mut device, config.overwrite)?;
    device.authenticate(mgmt_key)?;

    let key_config = |slot| KeyConfig {
        slot,
        pin_policy: config.pin_policy,
        touch_policy: config.touch_policy,
    };
    device.import_key(payment_sk, payment_vk, key_config(PAYMENT_SLOT))?;
    device.import_key(stake_sk, stake_vk, key_config(STAKE_SLOT))?;

    Ok(GeneratedWallet {
        mnemonic: seed,
        address,
    })
}

// Never silently replace a wallet whose mnemonic may be the only way to its funds.
fn refuse_overwrite<D: DeviceReader>(device: &mut D, overwrite: Overwrite) -> YkadaResult<()> {
    match overwrite {
        Overwrite::Allow => Ok(()),
        Overwrite::Refuse => match (
            device.read_public_key(PAYMENT_SLOT)?,
            device.read_public_key(STAKE_SLOT)?,
        ) {
            (None, None) => Ok(()),
            _ => Err(YkadaError::WalletState(
                "this YubiKey already holds a wallet; pass --force to overwrite it".into(),
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::model::{Network, PinPolicy, TouchPolicy};
    use crate::test_vectors::{KNOWN_ADDRESS_MAINNET, KNOWN_PHRASE};
    use ed25519_dalek::SigningKey;

    fn import(
        device: FakeYubiKey,
        overwrite: Overwrite,
        mgmt_key: &ManagementKey,
    ) -> YkadaResult<GeneratedWallet> {
        let config = WalletConfig {
            pin_policy: PinPolicy::Always,
            touch_policy: TouchPolicy::Always,
            network: Network::Mainnet,
            overwrite,
        };
        let seed = SeedPhrase::try_from(KNOWN_PHRASE).unwrap();
        generate_wallet_use_case(
            &FakeDeviceFinder(device),
            Some(seed),
            config,
            Some(mgmt_key),
        )
    }

    fn provisioned_device() -> FakeYubiKey {
        FakeYubiKey::empty().with_key(STAKE_SLOT, SigningKey::from_bytes(&[3; 32]))
    }

    #[test]
    fn test_import_returns_known_address() {
        let wallet = import(
            FakeYubiKey::empty(),
            Overwrite::Refuse,
            &FakeYubiKey::MGMT_KEY,
        )
        .unwrap();
        assert_eq!(wallet.address.to_bech32().unwrap(), KNOWN_ADDRESS_MAINNET);
        assert_eq!(wallet.mnemonic.phrase(), KNOWN_PHRASE);
    }

    #[test]
    fn test_refuses_to_overwrite_existing_wallet() {
        let err = import(
            provisioned_device(),
            Overwrite::Refuse,
            &FakeYubiKey::MGMT_KEY,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--force"), "got: {err}");
    }

    #[test]
    fn test_overwrite_allowed_with_force() {
        let wallet = import(
            provisioned_device(),
            Overwrite::Allow,
            &FakeYubiKey::MGMT_KEY,
        );
        assert!(wallet.is_ok(), "error: {:?}", wallet.err());
    }

    #[test]
    fn test_wrong_mgmt_key_is_rejected() {
        let wrong_key = ManagementKey::new([1; 24]);
        assert!(matches!(
            import(FakeYubiKey::empty(), Overwrite::Refuse, &wrong_key).unwrap_err(),
            YkadaError::AuthenticationFailed { .. }
        ));
    }
}
