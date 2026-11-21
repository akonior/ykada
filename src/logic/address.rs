use crate::error::{YkadaError, YkadaResult};
use crate::model::Network;
use ed25519_dalek::VerifyingKey;
use pallas_addresses::{
    Address, Network as AddressNetwork, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
};
use pallas_crypto::hash::Hasher;

fn address_network(network: Network) -> AddressNetwork {
    match network {
        Network::Mainnet => AddressNetwork::Mainnet,
        Network::Preprod | Network::Preview => AddressNetwork::Testnet,
    }
}

pub(crate) fn derive_cardano_address(
    payment_vk: &VerifyingKey,
    stake_vk: &VerifyingKey,
    network: Network,
) -> ShelleyAddress {
    ShelleyAddress::new(
        address_network(network),
        ShelleyPaymentPart::key_hash(Hasher::<224>::hash(payment_vk.as_bytes())),
        ShelleyDelegationPart::key_hash(Hasher::<224>::hash(stake_vk.as_bytes())),
    )
}

// Accept only a Shelley payment address on the wallet's own network.
pub(crate) fn parse_recipient(bech32: &str, network: Network) -> YkadaResult<Address> {
    let expected = address_network(network);
    match Address::from_bech32(bech32.trim()) {
        Ok(Address::Shelley(a)) if a.network() == expected => Ok(Address::Shelley(a)),
        Ok(Address::Shelley(a)) => Err(YkadaError::Tx(format!(
            "recipient is a {:?} address but --network is {network:?}",
            a.network()
        ))),
        Ok(_) => Err(YkadaError::Tx(
            "recipient must be a Shelley payment address (addr1… / addr_test1…)".into(),
        )),
        Err(e) => Err(YkadaError::Tx(format!("invalid recipient address: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::RECIPIENT;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_address_prefix_follows_network() {
        let vk = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let prefix = |network| {
            let address = derive_cardano_address(&vk, &vk, network);
            address
                .to_bech32()
                .unwrap()
                .split_once('1')
                .unwrap()
                .0
                .to_owned()
        };
        assert_eq!(prefix(Network::Mainnet), "addr");
        assert_eq!(prefix(Network::Preprod), "addr_test");
        assert_eq!(prefix(Network::Preview), "addr_test");
    }

    #[test]
    fn test_parse_recipient_accepts_matching_network() {
        assert!(parse_recipient(RECIPIENT, Network::Preview).is_ok());
    }

    #[test]
    fn test_parse_recipient_rejects_wrong_network() {
        let msg = parse_recipient(RECIPIENT, Network::Mainnet)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("--network"), "got: {msg}");
    }

    #[test]
    fn test_parse_recipient_rejects_stake_address() {
        use pallas_addresses::{Address, StakeAddress};
        let Ok(Address::Shelley(base)) = Address::from_bech32(RECIPIENT) else {
            panic!("expected a Shelley address");
        };
        let stake = StakeAddress::try_from(base).unwrap().to_bech32().unwrap();
        let msg = parse_recipient(&stake, Network::Preview)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("Shelley payment address"), "got: {msg}");
    }

    #[test]
    fn test_parse_recipient_rejects_garbage() {
        assert!(parse_recipient("not_an_address", Network::Preview).is_err());
    }
}
