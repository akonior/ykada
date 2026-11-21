use ed25519_dalek::VerifyingKey;

use crate::error::{YkadaError, YkadaResult};
use crate::logic::{check_firmware_version, derive_cardano_address};
use crate::model::{Network, Slot, SlotKey, WalletInfo, PAYMENT_SLOT, STAKE_SLOT};
use crate::ports::{DeviceFinder, DeviceReader};

// Read both public keys back from the device (no PIN) and derive the address.
pub(crate) fn wallet_info_use_case<F: DeviceFinder>(
    finder: &F,
    network: Network,
) -> YkadaResult<WalletInfo> {
    let mut device = finder.find_first()?;
    check_firmware_version(device.firmware_version())?;
    let keys = wallet_keys(&mut device)?;
    Ok(WalletInfo {
        payment_vk: keys.map(|(payment, _)| payment),
        address: keys.map(|(payment, stake)| derive_cardano_address(&payment, &stake, network)),
    })
}

// The payment and stake keys as the YubiKey reports them. `None` when both slots are empty; a
// wallet with only one key, or with a key that doesn't match ykada's object, is an error.
pub(crate) fn wallet_keys<D: DeviceReader>(
    device: &mut D,
) -> YkadaResult<Option<(VerifyingKey, VerifyingKey)>> {
    match (
        slot_public_key(device, PAYMENT_SLOT)?,
        slot_public_key(device, STAKE_SLOT)?,
    ) {
        (Some(payment), Some(stake)) => Ok(Some((payment, stake))),
        (None, None) => Ok(None),
        (Some(_), None) => Err(incomplete_wallet(STAKE_SLOT)),
        (None, Some(_)) => Err(incomplete_wallet(PAYMENT_SLOT)),
    }
}

// The address comes from the key itself. ykada's object is only compared with it, because
// anyone with the management key can rewrite an object without the PIN or a touch.
fn slot_public_key<D: DeviceReader>(
    device: &mut D,
    slot: Slot,
) -> YkadaResult<Option<VerifyingKey>> {
    match (device.slot_key(slot)?, device.public_key_object(slot)?) {
        (SlotKey::Empty, _) => Ok(None),
        (SlotKey::Other, _) => Err(YkadaError::WalletState(format!(
            "slot {} holds a key that is not Ed25519, so it is not a ykada wallet",
            slot.id()
        ))),
        (SlotKey::Ed25519(key), Some(object)) if object != key => {
            Err(YkadaError::WalletState(format!(
                "the public key stored for slot {} does not match the key in that slot. \
                 Someone with the PIV management key may have changed it: don't use this \
                 address. Restore the wallet from its mnemonic with `ykada import --force`",
                slot.id()
            )))
        }
        (SlotKey::Ed25519(key), _) => Ok(Some(key)),
    }
}

fn incomplete_wallet(missing: Slot) -> YkadaError {
    YkadaError::WalletState(format!(
        "incomplete wallet: slot {} holds no key. Restore the wallet from its mnemonic with \
         `ykada import --force`",
        missing.id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::logic::derive_wallet_keys;
    use crate::model::SeedPhrase;
    use crate::test_vectors::{KNOWN_ADDRESS_MAINNET, KNOWN_PHRASE};
    use ed25519_dalek::SigningKey;

    fn info(device: FakeYubiKey) -> YkadaResult<WalletInfo> {
        wallet_info_use_case(&FakeDeviceFinder(device), Network::Mainnet)
    }

    fn info_error(device: FakeYubiKey) -> String {
        info(device).unwrap_err().to_string()
    }

    fn known_wallet() -> FakeYubiKey {
        let keys = derive_wallet_keys(
            &SeedPhrase::try_from(KNOWN_PHRASE).unwrap(),
            Network::Mainnet,
        );
        FakeYubiKey::empty()
            .with_key(PAYMENT_SLOT, keys.payment_sk)
            .with_key(STAKE_SLOT, keys.stake_sk)
    }

    fn other_key() -> VerifyingKey {
        SigningKey::from_bytes(&[9; 32]).verifying_key()
    }

    fn address(device: FakeYubiKey) -> String {
        info(device).unwrap().address.unwrap().to_bech32().unwrap()
    }

    #[test]
    fn test_address_is_rebuilt_from_device_keys() {
        assert_eq!(address(known_wallet()), KNOWN_ADDRESS_MAINNET);
    }

    #[test]
    fn test_no_wallet_on_an_empty_device() {
        assert!(info(FakeYubiKey::empty()).unwrap().address.is_none());
    }

    // An object can be rewritten with the management key alone; the address must not follow it.
    #[test]
    fn test_swapped_stake_object_is_refused() {
        let msg = info_error(known_wallet().with_public_key_object(STAKE_SLOT, other_key()));
        assert!(msg.contains("slot 9d does not match"), "got: {msg}");
    }

    #[test]
    fn test_swapped_payment_object_is_refused() {
        let msg = info_error(known_wallet().with_public_key_object(PAYMENT_SLOT, other_key()));
        assert!(msg.contains("slot 9c does not match"), "got: {msg}");
    }

    // Keys without ykada's objects still give the address the keys sign for.
    #[test]
    fn test_address_comes_from_the_keys_without_objects() {
        let keys = derive_wallet_keys(
            &SeedPhrase::try_from(KNOWN_PHRASE).unwrap(),
            Network::Mainnet,
        );
        let device = FakeYubiKey::empty()
            .with_bare_key(PAYMENT_SLOT, keys.payment_sk)
            .with_bare_key(STAKE_SLOT, keys.stake_sk);
        assert_eq!(address(device), KNOWN_ADDRESS_MAINNET);
    }

    #[test]
    fn test_payment_key_alone_is_an_incomplete_wallet() {
        let device = FakeYubiKey::empty().with_key(PAYMENT_SLOT, SigningKey::from_bytes(&[1; 32]));
        let msg = info_error(device);
        assert!(msg.contains("incomplete wallet: slot 9d"), "got: {msg}");
    }

    #[test]
    fn test_stake_key_alone_is_an_incomplete_wallet() {
        let device = FakeYubiKey::empty().with_key(STAKE_SLOT, SigningKey::from_bytes(&[1; 32]));
        let msg = info_error(device);
        assert!(msg.contains("incomplete wallet: slot 9c"), "got: {msg}");
    }

    #[test]
    fn test_objects_without_keys_are_no_wallet() {
        let device = FakeYubiKey::empty()
            .with_public_key_object(PAYMENT_SLOT, other_key())
            .with_public_key_object(STAKE_SLOT, other_key());
        assert!(info(device).unwrap().address.is_none());
    }

    #[test]
    fn test_non_ed25519_key_is_refused() {
        let msg = info_error(known_wallet().with_non_ed25519_key(PAYMENT_SLOT));
        assert!(
            msg.contains("slot 9c holds a key that is not Ed25519"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_metadata_failure_is_an_error_not_an_empty_wallet() {
        assert!(matches!(
            info(known_wallet().with_failing_metadata()),
            Err(YkadaError::YubikeyLib(_))
        ));
    }

    #[test]
    fn test_rejects_old_firmware() {
        let old = FakeYubiKey::empty().with_firmware((5, 6, 0));
        assert!(matches!(
            info(old).unwrap_err(),
            YkadaError::FirmwareIncompatible { found: (5, 6, 0) }
        ));
    }
}
