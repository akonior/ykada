use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{YkadaError, YkadaResult};
use crate::model::{AccountBalance, Network, TokenBalance};
use crate::ports::BalanceFetcher;

#[derive(Serialize)]
struct AddressRequest<'a> {
    #[serde(rename = "_addresses")]
    addresses: &'a [&'a str],
}

#[derive(Deserialize)]
struct KoiosAddressInfo {
    balance: String,
    utxo_set: Vec<KoiosUtxo>,
}

#[derive(Deserialize)]
struct KoiosUtxo {
    asset_list: Vec<KoiosAsset>,
}

#[derive(Deserialize)]
struct KoiosAsset {
    policy_id: String,
    asset_name: String,
    quantity: String,
}

pub struct KoiosClient {
    base_url: &'static str,
}

impl KoiosClient {
    pub fn for_network(network: Network) -> Self {
        Self {
            base_url: match network {
                Network::Mainnet => "https://api.koios.rest/api/v1",
                Network::Preprod => "https://preprod.koios.rest/api/v1",
                Network::Preview => "https://preview.koios.rest/api/v1",
            },
        }
    }
}

impl BalanceFetcher for KoiosClient {
    fn fetch_balance(&self, address: &str) -> YkadaResult<AccountBalance> {
        let url = format!("{}/address_info", self.base_url);
        let body = AddressRequest {
            addresses: &[address],
        };

        let response: Vec<KoiosAddressInfo> = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| YkadaError::NetworkError(e.to_string()))?
            .into_json()
            .map_err(|e| YkadaError::NetworkError(e.to_string()))?;

        let Some(info) = response.into_iter().next() else {
            return Ok(AccountBalance {
                lovelace: 0,
                tokens: vec![],
            });
        };

        let lovelace = info
            .balance
            .parse::<u64>()
            .map_err(|_| YkadaError::NetworkError("invalid balance in response".into()))?;

        let tokens =
            info.utxo_set
                .into_iter()
                .flat_map(|utxo| utxo.asset_list)
                .map(|a| -> YkadaResult<TokenBalance> {
                    Ok(TokenBalance {
                        policy_id: a.policy_id,
                        asset_name: a.asset_name,
                        quantity: a.quantity.parse::<u64>().map_err(|_| {
                            YkadaError::NetworkError("invalid token quantity".into())
                        })?,
                    })
                })
                .collect::<YkadaResult<Vec<_>>>()?;

        Ok(AccountBalance {
            lovelace,
            tokens: aggregate_tokens(tokens),
        })
    }
}

fn aggregate_tokens(tokens: Vec<TokenBalance>) -> Vec<TokenBalance> {
    tokens
        .into_iter()
        .fold(HashMap::<(String, String), u64>::new(), |mut map, t| {
            *map.entry((t.policy_id, t.asset_name)).or_default() += t.quantity;
            map
        })
        .into_iter()
        .map(|((policy_id, asset_name), quantity)| TokenBalance {
            policy_id,
            asset_name,
            quantity,
        })
        .collect()
}
