use crate::error::YkadaResult;
use crate::logic::{check_firmware_version, derive_cardano_address};
use crate::model::{Network, WalletInfo, PAYMENT_SLOT, STAKE_SLOT};
use crate::ports::{DeviceFinder, DeviceReader};

// Read both public keys back from the device (no PIN) and derive the address.
pub(crate) fn wallet_info_use_case<F: DeviceFinder>(
    finder: &F,
    network: Network,
) -> YkadaResult<WalletInfo> {
    let mut device = finder.find_first()?;
    check_firmware_version(device.firmware_version())?;

    let payment_vk = device.read_public_key(PAYMENT_SLOT)?;
    let stake_vk = device.read_public_key(STAKE_SLOT)?;
    let address = payment_vk
        .zip(stake_vk)
        .map(|(p, s)| derive_cardano_address(&p, &s, network));

    Ok(WalletInfo {
        payment_vk,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::logic::derive_wallet_keys;
    use crate::model::SeedPhrase;
    use crate::test_vectors::{KNOWN_ADDRESS_MAINNET, KNOWN_PHRASE};
    use crate::YkadaError;

    fn info(device: FakeYubiKey) -> YkadaResult<WalletInfo> {
        wallet_info_use_case(&FakeDeviceFinder(device), Network::Mainnet)
    }

    #[test]
    fn test_address_is_rebuilt_from_device_keys() {
        let seed = SeedPhrase::try_from(KNOWN_PHRASE).unwrap();
        let keys = derive_wallet_keys(&seed, Network::Mainnet);
        let device = FakeYubiKey::empty()
            .with_key(PAYMENT_SLOT, keys.payment_sk)
            .with_key(STAKE_SLOT, keys.stake_sk);
        let address = info(device).unwrap().address.unwrap();
        assert_eq!(address.to_bech32().unwrap(), KNOWN_ADDRESS_MAINNET);
    }

    #[test]
    fn test_no_address_without_both_keys() {
        let payment_only = FakeYubiKey::empty().with_key(
            PAYMENT_SLOT,
            ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
        );
        assert!(info(FakeYubiKey::empty()).unwrap().address.is_none());
        assert!(info(payment_only).unwrap().address.is_none());
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
