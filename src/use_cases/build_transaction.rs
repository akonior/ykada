use pallas_addresses::{Address, ShelleyAddress};
use pallas_crypto::hash::Hash;
use pallas_txbuilder::{BuildConway, Input, Output, StagingTransaction};

use crate::error::{YkadaError, YkadaResult};
use crate::logic::select_inputs;
use crate::model::Utxo;
use crate::ports::{TipFetcher, UtxoFetcher};

pub(crate) struct TransactionParams {
    pub recipient: Address,
    pub send_lovelace: u64,
    pub fee_lovelace: u64,
    pub change_address: ShelleyAddress,
}

// Build an unsigned Conway transaction paying `recipient` from the wallet's UTxOs.
pub(crate) fn build_transaction_use_case<U, T>(
    utxo_fetcher: &U,
    tip_fetcher: &T,
    params: TransactionParams,
) -> YkadaResult<Vec<u8>>
where
    U: UtxoFetcher,
    T: TipFetcher,
{
    let utxos = utxo_fetcher.fetch_utxos(&params.change_address.to_bech32()?)?;
    let tip_slot = tip_fetcher.fetch_tip_slot()?;
    let built = build_staged(&utxos, tip_slot, &params)?
        .build_conway_raw()
        .map_err(|e| YkadaError::Tx(format!("tx build error: {e}")))?;
    Ok(built.tx_bytes.0)
}

// Conservative ADA-only min-UTxO floor. The exact value derives from the
// protocol's coins_per_utxo_byte; 1 ADA comfortably covers a simple output and
// keeps us from building a tx the node will reject for a dust/zero output.
const MIN_UTXO_LOVELACE: u64 = 1_000_000;

// Validity window (~2h at 1 slot/s): bounds how long a submitted tx can be re-submitted.
const TTL_OFFSET_SLOTS: u64 = 7200;

fn build_staged(
    utxos: &[Utxo],
    tip_slot: u64,
    params: &TransactionParams,
) -> YkadaResult<StagingTransaction> {
    if params.send_lovelace < MIN_UTXO_LOVELACE {
        return Err(YkadaError::Tx(format!(
            "send amount {} lovelace is below the min-UTxO floor of {MIN_UTXO_LOVELACE} lovelace",
            params.send_lovelace
        )));
    }

    let required = params
        .send_lovelace
        .checked_add(params.fee_lovelace)
        .ok_or_else(|| YkadaError::Tx("send amount + fee overflows u64".into()))?;
    let (selected_indices, total_input) = select_inputs(utxos, required)?;
    // select_inputs guarantees total_input >= required.
    let change_lovelace = total_input - required;

    if change_lovelace > 0 && change_lovelace < MIN_UTXO_LOVELACE {
        return Err(YkadaError::Tx(format!(
            "change {change_lovelace} lovelace is below the min-UTxO floor of {MIN_UTXO_LOVELACE}; raise --fee or the send amount to absorb the dust"
        )));
    }

    let ttl_slot = tip_slot
        .checked_add(TTL_OFFSET_SLOTS)
        .ok_or_else(|| YkadaError::Tx("chain tip slot + TTL offset overflows u64".into()))?;

    let staged = selected_indices
        .iter()
        .try_fold(StagingTransaction::new(), |tx, &i| {
            parse_tx_hash(&utxos[i].tx_hash)
                .map(|hash| tx.input(Input::new(hash, utxos[i].tx_index)))
        })?
        .output(Output::new(params.recipient.clone(), params.send_lovelace))
        .fee(params.fee_lovelace)
        .invalid_from_slot(ttl_slot);

    // A zero-value change output is invalid on Cardano; only emit change when present.
    Ok(if change_lovelace == 0 {
        staged
    } else {
        staged.output(Output::new(
            Address::Shelley(params.change_address.clone()),
            change_lovelace,
        ))
    })
}

fn parse_tx_hash(hex_str: &str) -> YkadaResult<Hash<32>> {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .map_err(|e| YkadaError::Tx(format!("invalid tx hash hex: {e}")))?
        .try_into()
        .map_err(|_| YkadaError::Tx("tx hash must be 32 bytes".into()))?;
    Ok(Hash::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_chain::FakeChain;
    use crate::logic::derive_wallet_keys;
    use crate::model::{Network, SeedPhrase};
    use crate::test_vectors::{RECIPIENT, TEST_PHRASE};
    use pallas_primitives::{conway, Fragment};

    fn build(utxos: &[u64], send_lovelace: u64) -> YkadaResult<Vec<u8>> {
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let chain = FakeChain::new(utxos);
        build_transaction_use_case(
            &chain,
            &chain,
            TransactionParams {
                recipient: Address::from_bech32(RECIPIENT).unwrap(),
                send_lovelace,
                fee_lovelace: 200_000,
                change_address: derive_wallet_keys(&seed, Network::Preview).address,
            },
        )
    }

    fn build_error(utxos: &[u64], send_lovelace: u64) -> String {
        build(utxos, send_lovelace).unwrap_err().to_string()
    }

    fn body(cbor: &[u8]) -> conway::TransactionBody<'_> {
        conway::Tx::decode_fragment(cbor)
            .unwrap()
            .transaction_body
            .unwrap()
    }

    #[test]
    fn test_build_with_change() {
        let cbor = build(&[10_000_000], 2_000_000).unwrap();
        assert_eq!(body(&cbor).outputs.len(), 2);
    }

    #[test]
    fn test_build_sets_fee_and_validity_window() {
        let cbor = build(&[10_000_000], 2_000_000).unwrap();
        assert_eq!(body(&cbor).fee, 200_000);
        assert_eq!(body(&cbor).ttl, Some(1_000_000 + TTL_OFFSET_SLOTS));
    }

    #[test]
    fn test_zero_change_omits_change_output() {
        let cbor = build(&[2_200_000], 2_000_000).unwrap();
        assert_eq!(body(&cbor).outputs.len(), 1);
    }

    #[test]
    fn test_insufficient_funds() {
        let msg = build_error(&[1_000_000], 2_000_000);
        assert!(msg.contains("insufficient funds"), "got: {msg}");
    }

    #[test]
    fn test_sub_min_change_errors() {
        let msg = build_error(&[2_700_000], 2_000_000);
        assert!(msg.contains("min-UTxO"), "got: {msg}");
    }

    #[test]
    fn test_send_below_min_utxo_errors() {
        let msg = build_error(&[10_000_000], 500_000);
        assert!(msg.contains("min-UTxO"), "got: {msg}");
    }

    #[test]
    fn test_ttl_overflow_errors() {
        let utxos = [10_000_000].map(|lovelace| Utxo {
            tx_hash: "00".repeat(32),
            tx_index: 0,
            lovelace,
            has_tokens: false,
        });
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let params = TransactionParams {
            recipient: Address::from_bech32(RECIPIENT).unwrap(),
            send_lovelace: 2_000_000,
            fee_lovelace: 200_000,
            change_address: derive_wallet_keys(&seed, Network::Preview).address,
        };
        let msg = build_staged(&utxos, u64::MAX, &params)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("overflows"), "got: {msg}");
    }

    #[test]
    fn test_required_overflow_errors() {
        let msg = build_error(&[10_000_000], u64::MAX);
        assert!(msg.contains("overflows"), "got: {msg}");
    }
}
