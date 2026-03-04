use crate::logic::Bech32Encodable;
use crate::model::{AccountBalance, CardanoAddress};
use crate::ports::BalanceFetcher;
use crate::YkadaResult;

pub fn fetch_balance_use_case<B: BalanceFetcher>(
    fetcher: &B,
    address: &CardanoAddress,
) -> YkadaResult<AccountBalance> {
    fetcher.fetch_balance(&address.to_bech32()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::derive_cardano_address;
    use crate::logic::derive_key_pair;
    use crate::model::{DerivationPath, Network, SeedPhrase, TokenBalance};

    struct FakeBalanceFetcher {
        balance: AccountBalance,
    }

    impl BalanceFetcher for FakeBalanceFetcher {
        fn fetch_balance(&self, _address: &str) -> YkadaResult<AccountBalance> {
            Ok(AccountBalance {
                lovelace: self.balance.lovelace,
                tokens: self
                    .balance
                    .tokens
                    .iter()
                    .map(|t| TokenBalance {
                        policy_id: t.policy_id.clone(),
                        asset_name: t.asset_name.clone(),
                        quantity: t.quantity,
                    })
                    .collect(),
            })
        }
    }

    const TEST_PHRASE: &str =
        "test walk nut penalty hip pave soap entry language right filter choice";

    fn test_address() -> CardanoAddress {
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let payment_path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let stake_path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();
        let payment_vk = derive_key_pair(&seed, "", &payment_path)
            .unwrap()
            .verifying_key();
        let stake_vk = derive_key_pair(&seed, "", &stake_path)
            .unwrap()
            .verifying_key();
        derive_cardano_address(&payment_vk, &stake_vk, Network::Preview)
    }

    #[test]
    fn test_fetch_balance_returns_ada() {
        let fetcher = FakeBalanceFetcher {
            balance: AccountBalance {
                lovelace: 5_123_456,
                tokens: vec![],
            },
        };
        let address = test_address();
        let result = fetch_balance_use_case(&fetcher, &address).unwrap();
        assert_eq!(result.lovelace, 5_123_456);
        assert!((result.ada() - 5.123456).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fetch_balance_with_tokens() {
        let fetcher = FakeBalanceFetcher {
            balance: AccountBalance {
                lovelace: 2_000_000,
                tokens: vec![TokenBalance {
                    policy_id: "abc123".into(),
                    asset_name: "546f6b656e".into(),
                    quantity: 100,
                }],
            },
        };
        let address = test_address();
        let result = fetch_balance_use_case(&fetcher, &address).unwrap();
        assert_eq!(result.tokens.len(), 1);
        assert_eq!(result.tokens[0].policy_id, "abc123");
        assert_eq!(result.tokens[0].quantity, 100);
    }
}
