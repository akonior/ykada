use crate::error::{YkadaError, YkadaResult};
use crate::model::Network;
use ed25519_dalek::VerifyingKey;
use pallas_addresses::{
    Address, Network as AddressNetwork, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
};
use pallas_crypto::hash::Hasher;

pub(crate) fn address_network(network: Network) -> AddressNetwork {
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

// Accept only a Shelley payment address on the wallet's own network, written exactly as that
// address encodes: the decoder ignores the prefix and any bytes after the key hashes.
pub(crate) fn parse_recipient(bech32: &str, network: Network) -> YkadaResult<Address> {
    let typed = bech32.trim();
    let expected = address_network(network);
    match Address::from_bech32(typed) {
        Ok(Address::Shelley(a)) => match (a.to_bech32()?, a.network() == expected) {
            (canonical, _) if canonical != typed.to_lowercase() => {
                Err(not_canonical(typed, &canonical))
            }
            (_, true) => Ok(Address::Shelley(a)),
            (_, false) => Err(YkadaError::Tx(format!(
                "recipient is a {:?} address but --network is {network:?}",
                a.network()
            ))),
        },
        Ok(_) => Err(YkadaError::Tx(
            "recipient must be a Shelley payment address (addr1… / addr_test1…)".into(),
        )),
        Err(e) => Err(YkadaError::Tx(format!("invalid recipient address: {e}"))),
    }
}

fn not_canonical(typed: &str, canonical: &str) -> YkadaError {
    let prefix = |text: &str| {
        text.rsplit_once('1')
            .map_or("", |(hrp, _)| hrp)
            .to_lowercase()
    };
    match prefix(typed) == prefix(canonical) {
        true => YkadaError::Tx("invalid recipient address: it has extra bytes after the key hashes".into()),
        false => YkadaError::Tx(format!(
            "invalid recipient address: the prefix '{}' doesn't match the address, which starts with '{}1'",
            prefix(typed),
            prefix(canonical)
        )),
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

    // Re-encodes the bytes of `address` under another prefix, with optional extra bytes.
    fn reencoded(address: &str, hrp: &str, extra: &[u8]) -> String {
        let (_, bytes) = bech32::decode(address).unwrap();
        let payload = [bytes.as_slice(), extra].concat();
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse(hrp).unwrap(), &payload).unwrap()
    }

    fn recipient_error(address: &str, network: Network) -> String {
        parse_recipient(address, network).unwrap_err().to_string()
    }

    #[test]
    fn test_rejects_an_unknown_prefix() {
        let msg = recipient_error(&reencoded(RECIPIENT, "foo", &[]), Network::Preview);
        assert!(msg.contains("prefix 'foo'"), "got: {msg}");
    }

    // The text says mainnet, the header says testnet: the funds would go to a testnet address.
    #[test]
    fn test_rejects_a_mainnet_prefix_on_a_testnet_address() {
        let msg = recipient_error(&reencoded(RECIPIENT, "addr", &[]), Network::Preview);
        assert!(msg.contains("prefix 'addr'"), "got: {msg}");
    }

    #[test]
    fn test_rejects_a_testnet_prefix_on_a_mainnet_address() {
        let mainnet = derive_cardano_address(
            &SigningKey::from_bytes(&[1; 32]).verifying_key(),
            &SigningKey::from_bytes(&[2; 32]).verifying_key(),
            Network::Mainnet,
        )
        .to_bech32()
        .unwrap();
        let msg = recipient_error(&reencoded(&mainnet, "addr_test", &[]), Network::Mainnet);
        assert!(msg.contains("prefix 'addr_test'"), "got: {msg}");
    }

    #[test]
    fn test_rejects_a_stake_prefix_on_a_payment_address() {
        let msg = recipient_error(&reencoded(RECIPIENT, "stake_test", &[]), Network::Preview);
        assert!(msg.contains("prefix 'stake_test'"), "got: {msg}");
    }

    #[test]
    fn test_rejects_extra_bytes_after_the_key_hashes() {
        [vec![0u8], vec![1, 2, 3, 4, 5]].iter().for_each(|extra| {
            let msg = recipient_error(&reencoded(RECIPIENT, "addr_test", extra), Network::Preview);
            assert!(msg.contains("extra bytes"), "got: {msg}");
        });
    }

    // Bech32 allows all upper case; it is the same address.
    #[test]
    fn test_accepts_upper_case_and_surrounding_spaces() {
        let upper = format!("  {}\n", RECIPIENT.to_uppercase());
        assert!(parse_recipient(&upper, Network::Preview).is_ok());
    }

    use proptest::prelude::*;

    fn any_key() -> impl Strategy<Value = VerifyingKey> {
        any::<[u8; 32]>().prop_map(|seed| SigningKey::from_bytes(&seed).verifying_key())
    }

    proptest! {
        // Whatever is typed, the answer is an address or an error, never a panic.
        #[test]
        fn prop_any_text_is_answered(text in "\\PC*") {
            let _ = parse_recipient(&text, Network::Preview);
        }

        // Only the address's own encoding passes: the right prefix, no extra bytes, any case.
        #[test]
        fn prop_only_the_exact_encoding_is_accepted(
            payment in any_key(),
            stake in any_key(),
            mainnet in any::<bool>(),
            prefix in prop::sample::select(vec!["addr", "addr_test", "stake", "stake_test", "foo"]),
            extra in prop::collection::vec(any::<u8>(), 0..6),
            upper in any::<bool>(),
        ) {
            let (network, own_prefix) = match mainnet {
                true => (Network::Mainnet, "addr"),
                false => (Network::Preview, "addr_test"),
            };
            let address = derive_cardano_address(&payment, &stake, network).to_bech32().unwrap();
            let text = reencoded(&address, prefix, &extra);
            let typed = match upper {
                true => text.to_uppercase(),
                false => text,
            };
            let exact = prefix == own_prefix && extra.is_empty();
            prop_assert_eq!(parse_recipient(&typed, network).is_ok(), exact);
        }

        #[test]
        fn prop_an_address_is_refused_on_the_other_network(payment in any_key(), stake in any_key()) {
            let address = |network| derive_cardano_address(&payment, &stake, network).to_bech32().unwrap();
            prop_assert!(parse_recipient(&address(Network::Mainnet), Network::Preview).is_err());
            prop_assert!(parse_recipient(&address(Network::Preprod), Network::Mainnet).is_err());
            prop_assert!(parse_recipient(&address(Network::Preprod), Network::Preview).is_ok());
        }
    }
}
