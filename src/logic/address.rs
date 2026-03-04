use crate::model::{CardanoAddress, Network};
use blake2::digest::consts::U28;
use blake2::{Blake2b, Digest};
use ed25519_dalek::VerifyingKey;

type Blake2b224 = Blake2b<U28>;

pub fn derive_cardano_address(
    payment_vk: &VerifyingKey,
    stake_vk: &VerifyingKey,
    network: Network,
) -> CardanoAddress {
    let payment_hash: [u8; 28] = Blake2b224::digest(payment_vk.as_bytes()).into();
    let stake_hash: [u8; 28] = Blake2b224::digest(stake_vk.as_bytes()).into();
    CardanoAddress::from_key_hashes(payment_hash, stake_hash, network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::Bech32Encodable;
    use ed25519_dalek::SigningKey;

    fn make_verifying_key(seed: u8) -> VerifyingKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        SigningKey::from_bytes(&bytes).verifying_key()
    }

    #[test]
    fn test_hash_is_28_bytes() {
        let payment_vk = make_verifying_key(1);
        let stake_vk = make_verifying_key(2);
        let addr = derive_cardano_address(&payment_vk, &stake_vk, Network::Preview);
        assert_eq!(addr.to_bytes().len(), 57);
    }

    #[test]
    fn test_testnet_address_prefix() {
        let payment_vk = make_verifying_key(1);
        let stake_vk = make_verifying_key(2);
        let addr = derive_cardano_address(&payment_vk, &stake_vk, Network::Preview);
        let encoded = addr.to_bech32().unwrap();
        assert!(encoded.starts_with("addr_test1"), "got: {}", encoded);
    }

    #[test]
    fn test_mainnet_address_prefix() {
        let payment_vk = make_verifying_key(1);
        let stake_vk = make_verifying_key(2);
        let addr = derive_cardano_address(&payment_vk, &stake_vk, Network::Mainnet);
        let encoded = addr.to_bech32().unwrap();
        assert!(encoded.starts_with("addr1"), "got: {}", encoded);
    }
}
