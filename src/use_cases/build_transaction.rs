use pallas_addresses::Address;
use pallas_crypto::hash::Hash;
use pallas_crypto::key::ed25519::PublicKey as PallasPublicKey;
use pallas_txbuilder::{BuildConway, BuiltTransaction, Input, Output, StagingTransaction};

use crate::error::{YkadaError, YkadaResult};
use crate::logic::Bech32Encodable;
use crate::model::{Algorithm, CardanoAddress, Pin, Slot, Utxo};
use crate::ports::{Signer, TipFetcher, TxSubmitter, UtxoFetcher};

pub struct TransactionParams {
    pub recipient_address_bytes: Vec<u8>,
    pub send_lovelace: u64,
    pub fee_lovelace: u64,
    pub change_address: CardanoAddress,
}

pub struct SignAndSubmitParams {
    pub recipient_address_bytes: Vec<u8>,
    pub send_lovelace: u64,
    pub fee_lovelace: u64,
    pub change_address: CardanoAddress,
    pub payment_vkey: [u8; 32],
    pub payment_slot: Slot,
    pub pin: Option<Pin>,
}

pub fn build_transaction_use_case<U, T>(
    utxo_fetcher: &U,
    tip_fetcher: &T,
    params: TransactionParams,
) -> YkadaResult<Vec<u8>>
where
    U: UtxoFetcher,
    T: TipFetcher,
{
    let change_bech32 = params.change_address.to_bech32()?;
    let utxos = utxo_fetcher.fetch_utxos(&change_bech32)?;
    let tip_slot = tip_fetcher.fetch_tip_slot()?;

    let built = build_staged(&utxos, tip_slot, &params)?
        .build_conway_raw()
        .map_err(|e| YkadaError::NetworkError(format!("tx build error: {e}")))?;

    Ok(built.tx_bytes.0)
}

pub fn sign_transaction_use_case<U, T, S>(
    utxo_fetcher: &U,
    tip_fetcher: &T,
    signer: &mut S,
    params: SignAndSubmitParams,
) -> YkadaResult<Vec<u8>>
where
    U: UtxoFetcher,
    T: TipFetcher,
    S: Signer,
{
    build_and_sign(utxo_fetcher, tip_fetcher, signer, params).map(|signed| signed.tx_bytes.0)
}

pub fn sign_and_submit_transaction_use_case<U, T, S, X>(
    utxo_fetcher: &U,
    tip_fetcher: &T,
    signer: &mut S,
    tx_submitter: &X,
    params: SignAndSubmitParams,
) -> YkadaResult<String>
where
    U: UtxoFetcher,
    T: TipFetcher,
    S: Signer,
    X: TxSubmitter,
{
    let signed = build_and_sign(utxo_fetcher, tip_fetcher, signer, params)?;
    tx_submitter.submit_tx(&signed.tx_bytes.0)
}

fn build_and_sign<U, T, S>(
    utxo_fetcher: &U,
    tip_fetcher: &T,
    signer: &mut S,
    params: SignAndSubmitParams,
) -> YkadaResult<BuiltTransaction>
where
    U: UtxoFetcher,
    T: TipFetcher,
    S: Signer,
{
    let core_params = TransactionParams {
        recipient_address_bytes: params.recipient_address_bytes,
        send_lovelace: params.send_lovelace,
        fee_lovelace: params.fee_lovelace,
        change_address: params.change_address,
    };

    let change_bech32 = core_params.change_address.to_bech32()?;
    let utxos = utxo_fetcher.fetch_utxos(&change_bech32)?;
    let tip_slot = tip_fetcher.fetch_tip_slot()?;

    let built = build_staged(&utxos, tip_slot, &core_params)?
        .build_conway_raw()
        .map_err(|e| YkadaError::NetworkError(format!("tx build error: {e}")))?;

    let sig_bytes = signer.sign(
        &built.tx_hash.0,
        params.payment_slot,
        Algorithm::Ed25519,
        params.pin.as_ref(),
    )?;

    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| YkadaError::NetworkError("signature must be 64 bytes".into()))?;

    let pubkey = PallasPublicKey::from(params.payment_vkey);

    built
        .add_signature(pubkey, sig)
        .map_err(|e| YkadaError::NetworkError(format!("add signature error: {e}")))
}

fn build_staged(
    utxos: &[Utxo],
    tip_slot: u64,
    params: &TransactionParams,
) -> YkadaResult<StagingTransaction> {
    let recipient_addr = Address::from_bytes(&params.recipient_address_bytes)
        .map_err(|e| YkadaError::NetworkError(format!("invalid recipient address: {e}")))?;

    let change_addr = Address::from_bytes(&params.change_address.to_bytes())
        .map_err(|e| YkadaError::NetworkError(format!("invalid change address: {e}")))?;

    let required = params.send_lovelace + params.fee_lovelace;
    let (selected_indices, total_input) = select_inputs(utxos, required)?;
    let change_lovelace = total_input - required;

    selected_indices
        .iter()
        .try_fold(StagingTransaction::new(), |tx, &i| {
            parse_tx_hash(&utxos[i].tx_hash)
                .map(|hash| tx.input(Input::new(hash, utxos[i].tx_index)))
        })
        .map(|tx| {
            tx.output(Output::new(recipient_addr, params.send_lovelace))
                .output(Output::new(change_addr, change_lovelace))
                .fee(params.fee_lovelace)
                .invalid_from_slot(tip_slot + 7200)
        })
}

/// Largest-first greedy coin selection.
/// Returns indices into `utxos` (sorted by descending lovelace) and the total lovelace selected.
fn select_inputs(utxos: &[Utxo], required: u64) -> YkadaResult<(Vec<usize>, u64)> {
    let mut indices: Vec<usize> = (0..utxos.len()).collect();
    indices.sort_by(|&a, &b| utxos[b].lovelace.cmp(&utxos[a].lovelace));

    let (selected, total) = indices.into_iter().try_fold(
        (vec![], 0u64),
        |(mut acc, sum), i| -> YkadaResult<(Vec<usize>, u64)> {
            if sum >= required {
                Ok((acc, sum))
            } else {
                acc.push(i);
                Ok((acc, sum + utxos[i].lovelace))
            }
        },
    )?;

    if total < required {
        return Err(YkadaError::NetworkError(format!(
            "insufficient funds: have {total} lovelace, need {required}"
        )));
    }

    Ok((selected, total))
}

fn parse_tx_hash(hex_str: &str) -> YkadaResult<Hash<32>> {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .map_err(|e| YkadaError::NetworkError(format!("invalid tx hash hex: {e}")))?
        .try_into()
        .map_err(|_| YkadaError::NetworkError("tx hash must be 32 bytes".into()))?;
    Ok(Hash::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::{derive_cardano_address, derive_key_pair};
    use crate::model::{DerivationPath, Network, SeedPhrase, TokenBalance};

    const TEST_PHRASE: &str =
        "test walk nut penalty hip pave soap entry language right filter choice";

    // A valid preview testnet bech32 address for the recipient
    const RECIPIENT_BECH32: &str =
        "addr_test1qrfw6ye0m7f2kvqapnkp7jzlfydq0h6j5rnsvj2wm9vlhg0y86x894xrsh5xu8qlm6yld03hp7sx6u552w6uupd799fqz0vpte";

    fn test_change_address() -> CardanoAddress {
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let payment_path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let stake_path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();
        let (_, payment_vk) = derive_key_pair(&seed, "", &payment_path).unwrap();
        let (_, stake_vk) = derive_key_pair(&seed, "", &stake_path).unwrap();
        derive_cardano_address(&payment_vk, &stake_vk, Network::Preview)
    }

    fn recipient_bytes() -> Vec<u8> {
        let (_, data, _) = bech32::decode(RECIPIENT_BECH32).unwrap();
        bech32::convert_bits(&data, 5, 8, false).unwrap()
    }

    struct FakeUtxoFetcher {
        utxos: Vec<Utxo>,
    }

    impl UtxoFetcher for FakeUtxoFetcher {
        fn fetch_utxos(&self, _address: &str) -> YkadaResult<Vec<Utxo>> {
            Ok(self
                .utxos
                .iter()
                .map(|u| Utxo {
                    tx_hash: u.tx_hash.clone(),
                    tx_index: u.tx_index,
                    lovelace: u.lovelace,
                    tokens: u
                        .tokens
                        .iter()
                        .map(|t| TokenBalance {
                            policy_id: t.policy_id.clone(),
                            asset_name: t.asset_name.clone(),
                            quantity: t.quantity,
                        })
                        .collect(),
                })
                .collect())
        }
    }

    struct FakeTipFetcher {
        slot: u64,
    }

    impl TipFetcher for FakeTipFetcher {
        fn fetch_tip_slot(&self) -> YkadaResult<u64> {
            Ok(self.slot)
        }
    }

    struct FakeSigner;

    impl Signer for FakeSigner {
        fn sign(
            &mut self,
            _data: &[u8],
            _slot: Slot,
            _algorithm: Algorithm,
            _pin: Option<&Pin>,
        ) -> YkadaResult<Vec<u8>> {
            Ok(vec![0u8; 64])
        }
    }

    struct FakeTxSubmitter {
        expected_hash: String,
    }

    impl TxSubmitter for FakeTxSubmitter {
        fn submit_tx(&self, _signed_tx_cbor: &[u8]) -> YkadaResult<String> {
            Ok(self.expected_hash.clone())
        }
    }

    fn fake_utxo(tx_hash: &str, lovelace: u64) -> Utxo {
        Utxo {
            tx_hash: tx_hash.into(),
            tx_index: 0,
            lovelace,
            tokens: vec![],
        }
    }

    #[test]
    fn test_build_tx_sufficient_funds() {
        let utxo_fetcher = FakeUtxoFetcher {
            utxos: vec![fake_utxo(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                10_000_000,
            )],
        };
        let tip_fetcher = FakeTipFetcher { slot: 1_000_000 };
        let params = TransactionParams {
            recipient_address_bytes: recipient_bytes(),
            send_lovelace: 2_000_000,
            fee_lovelace: 200_000,
            change_address: test_change_address(),
        };

        let result = build_transaction_use_case(&utxo_fetcher, &tip_fetcher, params);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_build_tx_insufficient_funds() {
        let utxo_fetcher = FakeUtxoFetcher {
            utxos: vec![fake_utxo(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1_000_000,
            )],
        };
        let tip_fetcher = FakeTipFetcher { slot: 1_000_000 };
        let params = TransactionParams {
            recipient_address_bytes: recipient_bytes(),
            send_lovelace: 2_000_000,
            fee_lovelace: 200_000,
            change_address: test_change_address(),
        };

        let result = build_transaction_use_case(&utxo_fetcher, &tip_fetcher, params);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("insufficient funds"), "got: {msg}");
    }

    #[test]
    fn test_coin_selection_picks_minimum() {
        // Three UTxOs: 5 ADA, 3 ADA, 10 ADA — need 6 ADA
        // Largest-first: picks 10 ADA (1 UTxO), total = 10 >= 6
        let utxos = vec![
            fake_utxo(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                5_000_000,
            ),
            fake_utxo(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                3_000_000,
            ),
            fake_utxo(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                10_000_000,
            ),
        ];
        let (selected, total) = select_inputs(&utxos, 6_000_000).unwrap();
        // Only the 10 ADA UTxO (index 2) should be selected
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], 2);
        assert_eq!(total, 10_000_000);
    }

    #[test]
    fn test_sign_and_submit_returns_tx_hash() {
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let payment_path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let (_, payment_vk) = crate::logic::derive_key_pair(&seed, "", &payment_path).unwrap();
        let payment_vkey: [u8; 32] = payment_vk.to_bytes();

        let utxo_fetcher = FakeUtxoFetcher {
            utxos: vec![fake_utxo(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                10_000_000,
            )],
        };
        let tip_fetcher = FakeTipFetcher { slot: 1_000_000 };
        let known_hash = "deadbeefcafe".to_string();
        let tx_submitter = FakeTxSubmitter {
            expected_hash: known_hash.clone(),
        };
        let mut signer = FakeSigner;

        let params = SignAndSubmitParams {
            recipient_address_bytes: recipient_bytes(),
            send_lovelace: 2_000_000,
            fee_lovelace: 200_000,
            change_address: test_change_address(),
            payment_vkey,
            payment_slot: Slot::Signature,
            pin: None,
        };

        let result = sign_and_submit_transaction_use_case(
            &utxo_fetcher,
            &tip_fetcher,
            &mut signer,
            &tx_submitter,
            params,
        );

        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap(), known_hash);
    }
}
