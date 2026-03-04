use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{YkadaError, YkadaResult};
use crate::model::{AccountBalance, Network, TokenBalance, Utxo};
use crate::ports::{BalanceFetcher, TipFetcher, TxSubmitter, UtxoFetcher};

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
    tx_hash: String,
    tx_index: u64,
    value: String,
    asset_list: Vec<KoiosAsset>,
}

#[derive(Deserialize)]
struct KoiosAsset {
    policy_id: String,
    asset_name: String,
    quantity: String,
}

#[derive(Deserialize)]
struct KoiosTip {
    abs_slot: u64,
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

    fn fetch_address_info(&self, address: &str) -> YkadaResult<Option<KoiosAddressInfo>> {
        let url = format!("{}/address_info", self.base_url);
        let body = AddressRequest {
            addresses: &[address],
        };
        let response: Vec<KoiosAddressInfo> = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(body)?
            .into_json()?;
        Ok(response.into_iter().next())
    }
}

impl BalanceFetcher for KoiosClient {
    fn fetch_balance(&self, address: &str) -> YkadaResult<AccountBalance> {
        let Some(info) = self.fetch_address_info(address)? else {
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

impl UtxoFetcher for KoiosClient {
    fn fetch_utxos(&self, address: &str) -> YkadaResult<Vec<Utxo>> {
        let Some(info) = self.fetch_address_info(address)? else {
            return Ok(vec![]);
        };

        info.utxo_set
            .into_iter()
            .map(|u| {
                let lovelace = u
                    .value
                    .parse::<u64>()
                    .map_err(|_| YkadaError::NetworkError("invalid UTxO value".into()))?;
                let tokens = u
                    .asset_list
                    .into_iter()
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
                Ok(Utxo {
                    tx_hash: u.tx_hash,
                    tx_index: u.tx_index,
                    lovelace,
                    tokens,
                })
            })
            .collect()
    }
}

impl TipFetcher for KoiosClient {
    fn fetch_tip_slot(&self) -> YkadaResult<u64> {
        let url = format!("{}/tip", self.base_url);
        let response: Vec<KoiosTip> = ureq::get(&url)
            .set("Content-Type", "application/json")
            .call()?
            .into_json()?;
        response
            .into_iter()
            .next()
            .map(|t| t.abs_slot)
            .ok_or_else(|| YkadaError::NetworkError("empty tip response".into()))
    }
}

impl TxSubmitter for KoiosClient {
    fn submit_tx(&self, signed_tx_cbor: &[u8]) -> YkadaResult<String> {
        let url = format!("{}/submittx", self.base_url);
        let response = ureq::post(&url)
            .set("Content-Type", "application/cbor")
            .send_bytes(signed_tx_cbor)
            .map_err(|e| match e {
                ureq::Error::Status(code, resp) => {
                    let body = resp.into_string().unwrap_or_default();
                    YkadaError::NetworkError(format!("HTTP {code}: {body}"))
                }
                other => YkadaError::NetworkError(other.to_string()),
            })?
            .into_string()?;
        Ok(response.trim().trim_matches('"').to_string())
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
