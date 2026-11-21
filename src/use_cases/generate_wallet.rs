use crate::error::{YkadaError, YkadaResult};
use crate::logic::{check_firmware_version, derive_wallet_keys, WalletKeys};
use crate::model::{
    GeneratedWallet, ManagementKey, Overwrite, SeedPhrase, Slot, SlotKey, WalletConfig,
    PAYMENT_SLOT, STAKE_SLOT,
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

// Never silently replace a key: it may be the only way to a wallet's funds. Both slots are
// checked before anything is written, and a failed check stops the import.
fn refuse_overwrite<D: DeviceReader>(device: &mut D, overwrite: Overwrite) -> YkadaResult<()> {
    match overwrite {
        Overwrite::Allow => Ok(()),
        Overwrite::Refuse => {
            let in_use = [PAYMENT_SLOT, STAKE_SLOT]
                .into_iter()
                .map(|slot| Ok(slot_in_use(device, slot)?.then_some(slot.id())))
                .collect::<YkadaResult<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            match in_use.is_empty() {
                true => Ok(()),
                false => Err(YkadaError::WalletState(format!(
                    "this YubiKey already holds a key in slot {}; pass --force to overwrite it",
                    in_use.join(" and ")
                ))),
            }
        }
    }
}

// A slot is in use when it holds a private key or ykada's public-key object: either can exist
// without the other (a key made by another tool, or an import cut short).
fn slot_in_use<D: DeviceReader>(device: &mut D, slot: Slot) -> YkadaResult<bool> {
    Ok(!matches!(
        (device.slot_key(slot)?, device.public_key_object(slot)?),
        (SlotKey::Empty, None)
    ))
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

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    // Imports into `device` and returns the outcome with the slots that were written.
    fn import_and_watch(
        device: FakeYubiKey,
        overwrite: Overwrite,
    ) -> (YkadaResult<GeneratedWallet>, Vec<Slot>) {
        let writes = device.written_slots();
        let result = import(device, overwrite, &FakeYubiKey::MGMT_KEY);
        let written = writes.borrow().clone();
        (result, written)
    }

    fn assert_refused_untouched(device: FakeYubiKey, slot_id: &str) {
        let (result, written) = import_and_watch(device, Overwrite::Refuse);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("--force"), "got: {err}");
        assert!(err.to_string().contains(slot_id), "got: {err}");
        assert!(written.is_empty(), "wrote {written:?}");
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
    fn test_two_empty_slots_are_both_written() {
        let (result, written) = import_and_watch(FakeYubiKey::empty(), Overwrite::Refuse);
        assert!(result.is_ok(), "error: {:?}", result.err());
        assert_eq!(written, vec![PAYMENT_SLOT, STAKE_SLOT]);
    }

    #[test]
    fn test_refuses_to_overwrite_existing_wallet() {
        assert_refused_untouched(provisioned_device(), "9d");
    }

    #[test]
    fn test_refuses_payment_key_without_public_key_object() {
        assert_refused_untouched(
            FakeYubiKey::empty().with_bare_key(PAYMENT_SLOT, other_key()),
            "9c",
        );
    }

    // The payment slot is free, so a check that stopped at the first slot would write it.
    #[test]
    fn test_refuses_stake_key_without_public_key_object() {
        assert_refused_untouched(
            FakeYubiKey::empty().with_bare_key(STAKE_SLOT, other_key()),
            "9d",
        );
    }

    #[test]
    fn test_refuses_public_key_object_without_private_key() {
        assert_refused_untouched(
            FakeYubiKey::empty().with_public_key_object(PAYMENT_SLOT, other_key().verifying_key()),
            "9c",
        );
    }

    #[test]
    fn test_metadata_read_failure_aborts_before_any_write() {
        let (result, written) = import_and_watch(
            FakeYubiKey::empty().with_failing_metadata(),
            Overwrite::Refuse,
        );
        assert!(
            matches!(result, Err(YkadaError::YubikeyLib(_))),
            "got: {result:?}"
        );
        assert!(written.is_empty(), "wrote {written:?}");
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
    fn test_force_replaces_keys_without_public_key_objects() {
        let device = FakeYubiKey::empty()
            .with_bare_key(PAYMENT_SLOT, other_key())
            .with_bare_key(STAKE_SLOT, other_key());
        let (result, written) = import_and_watch(device, Overwrite::Allow);
        assert!(result.is_ok(), "error: {:?}", result.err());
        assert_eq!(written, vec![PAYMENT_SLOT, STAKE_SLOT]);
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
