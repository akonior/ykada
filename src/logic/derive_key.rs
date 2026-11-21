use crate::logic::derive_cardano_address;
use crate::model::{CardanoKey, DerivationPath, Network, SeedPhrase};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pallas_addresses::ShelleyAddress;

// Device-free derivation of a ykada wallet: anyone holding the mnemonic can reproduce the
// address with it. The verifying keys are the ones the YubiKey itself produces.
pub(crate) struct WalletKeys {
    pub payment_sk: SigningKey,
    pub stake_sk: SigningKey,
    pub payment_vk: VerifyingKey,
    pub stake_vk: VerifyingKey,
    pub address: ShelleyAddress,
}

pub(crate) fn derive_wallet_keys(seed: &SeedPhrase, network: Network) -> WalletKeys {
    let root = CardanoKey::from_seed_phrase(seed);
    let payment_sk = root.derive(&DerivationPath::PAYMENT).private_key();
    let stake_sk = root.derive(&DerivationPath::STAKE).private_key();
    let payment_vk = payment_sk.verifying_key();
    let stake_vk = stake_sk.verifying_key();
    let address = derive_cardano_address(&payment_vk, &stake_vk, network);
    WalletKeys {
        payment_sk,
        stake_sk,
        payment_vk,
        stake_vk,
        address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{KNOWN_ADDRESS_MAINNET, KNOWN_PHRASE};

    #[test]
    fn test_known_mainnet_address() {
        let seed = SeedPhrase::try_from(KNOWN_PHRASE).unwrap();
        let keys = derive_wallet_keys(&seed, Network::Mainnet);
        assert_eq!(keys.address.to_bech32().unwrap(), KNOWN_ADDRESS_MAINNET);
    }
}
