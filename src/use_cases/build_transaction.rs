use pallas_addresses::{Address, ShelleyAddress};
use pallas_crypto::hash::Hash;
use pallas_txbuilder::{BuildConway, Input, Output, StagingTransaction};

use crate::error::{YkadaError, YkadaResult};
use crate::logic::select_inputs;
use crate::model::Utxo;
use crate::ports::{TipFetcher, UtxoFetcher};
use crate::use_cases::sign_external_tx::{signed_size, MAX_TX_SIZE};

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
    check_size_and_fee(&built.tx_bytes.0, params.fee_lovelace)?;
    Ok(built.tx_bytes.0)
}

// The amounts alone, before the device or the network is used.
pub(crate) fn check_amounts(send_lovelace: u64, fee_lovelace: u64) -> YkadaResult<()> {
    match (
        send_lovelace < MIN_UTXO_LOVELACE,
        fee_lovelace > MAX_FEE_LOVELACE,
    ) {
        (true, _) => Err(YkadaError::Tx(format!(
            "send amount {send_lovelace} lovelace is below the min-UTxO floor of {MIN_UTXO_LOVELACE} lovelace"
        ))),
        (false, true) => Err(YkadaError::Tx(format!(
            "--fee {fee_lovelace} lovelace is more than 1 ADA ({MAX_FEE_LOVELACE} lovelace), \
             which no payment ykada builds can need; check the value"
        ))),
        (false, false) => Ok(()),
    }
}

// Mainnet, PreProd and Preview use the same fee parameters: fee >= a * size + b.
const MIN_FEE_A: u64 = 44;
const MIN_FEE_B: u64 = 155_381;

// The largest transaction the ledger accepts (16 KiB) needs 0.88 ADA, so a higher --fee is a typo.
const MAX_FEE_LOVELACE: u64 = 1_000_000;
const _: () = assert!(MIN_FEE_A * MAX_TX_SIZE + MIN_FEE_B <= MAX_FEE_LOVELACE);

// Catch what a node would reject before the YubiKey signs: a transaction over the size limit
// (MaxTxSizeUTxO), or a fee too small for its size (FeeTooSmallUTxO).
fn check_size_and_fee(unsigned: &[u8], fee_lovelace: u64) -> YkadaResult<()> {
    let size = signed_size(unsigned)? as u64;
    let needed = MIN_FEE_A * size + MIN_FEE_B;
    match (size > MAX_TX_SIZE, fee_lovelace >= needed) {
        (true, _) => Err(YkadaError::Tx(format!(
            "the signed transaction would be {size} bytes, more than the {MAX_TX_SIZE} bytes a \
             node accepts, because it spends many small UTxOs; send a smaller amount, which \
             needs fewer of them"
        ))),
        (false, true) => Ok(()),
        (false, false) => Err(YkadaError::Tx(format!(
            "the fee {fee_lovelace} lovelace is below the {needed} lovelace this {size}-byte \
             transaction needs; pass --fee {}",
            needed.div_ceil(1000) * 1000
        ))),
    }
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
    let required = params
        .send_lovelace
        .checked_add(params.fee_lovelace)
        .ok_or_else(|| YkadaError::Tx("send amount + fee overflows u64".into()))?;
    let (selected_indices, total_input) = select_inputs(utxos, required, MIN_UTXO_LOVELACE)?;
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

    // 465 inputs make a 17,583-byte signed payment: the fee would cover it, the node would not.
    #[test]
    fn oversized_signed_payment_is_refused_even_when_the_fee_covers_it() {
        let tx = (0..465u64)
            .fold(StagingTransaction::new(), |tx, index| {
                tx.input(Input::new(Hash::new([1; 32]), index))
            })
            .output(Output::new(
                Address::from_bech32(RECIPIENT).unwrap(),
                2_000_000,
            ))
            .fee(MAX_FEE_LOVELACE)
            .build_conway_raw()
            .unwrap();
        let unsigned = &tx.tx_bytes.0;
        let size = signed_size(unsigned).unwrap() as u64;
        assert!(size > MAX_TX_SIZE);
        assert!(size * MIN_FEE_A + MIN_FEE_B <= MAX_FEE_LOVELACE);
        let msg = check_size_and_fee(unsigned, MAX_FEE_LOVELACE)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("more than the 16384 bytes"), "got: {msg}");
    }

    // The same through send: 500 UTxOs of 1.1 ADA pay exactly 549 ADA and a 1 ADA fee.
    #[test]
    fn a_payment_from_too_many_utxos_is_refused_before_signing() {
        let msg = build_with(&[1_100_000; 600], 549_000_000, MAX_FEE_LOVELACE)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("send a smaller amount"), "got: {msg}");
    }

    #[test]
    fn another_spendable_input_can_cover_dust_change() {
        let cbor = build(&[5_000_000, 2_000_000], 4_300_000)
            .expect("both inputs pay 4.3 ADA plus the fee and leave 2.5 ADA in change");
        let summary = crate::use_cases::decode_tx::summarize_cbor(&cbor).unwrap();
        assert_eq!(summary.inputs.len(), 2);
        assert_eq!(summary.fee, 200_000);
        assert_eq!(summary.outputs[0].lovelace, 4_300_000);
        assert_eq!(summary.outputs[1].lovelace, 2_500_000);
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
        let msg = check_amounts(999_999, 200_000).unwrap_err().to_string();
        assert!(msg.contains("min-UTxO"), "got: {msg}");
        assert!(check_amounts(MIN_UTXO_LOVELACE, 200_000).is_ok());
    }

    // An extra zero in --fee must not burn ADA.
    #[test]
    fn test_fee_above_one_ada_is_refused() {
        let msg = check_amounts(2_000_000, 2_000_000).unwrap_err().to_string();
        assert!(msg.contains("more than 1 ADA"), "got: {msg}");
        assert!(check_amounts(2_000_000, MAX_FEE_LOVELACE).is_ok());
    }

    // Many small UTxOs make a large transaction that the default fee doesn't cover.
    #[test]
    fn test_fee_too_small_for_the_size_is_refused_with_the_fee_to_use() {
        let utxos = [2_000_000; 40];
        let msg = build_error(&utxos, 58_000_000);
        assert!(msg.contains("transaction needs; pass --fee"), "got: {msg}");
        let fee: u64 = msg.rsplit(' ').next().unwrap().parse().unwrap();
        let seed = SeedPhrase::try_from(TEST_PHRASE).unwrap();
        let chain = FakeChain::new(&utxos);
        let params = TransactionParams {
            recipient: Address::from_bech32(RECIPIENT).unwrap(),
            send_lovelace: 58_000_000,
            fee_lovelace: fee,
            change_address: derive_wallet_keys(&seed, Network::Preview).address,
        };
        assert!(build_transaction_use_case(&chain, &chain, params).is_ok());
    }

    // A fee the chain accepted must pass the check too: the formula must not overestimate.
    #[test]
    fn test_min_fee_formula_accepts_a_confirmed_transaction() {
        let tx = hex::decode(crate::test_vectors::ON_CHAIN_TX_CBOR).unwrap();
        assert!(MIN_FEE_A * tx.len() as u64 + MIN_FEE_B <= 200_000);
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

    use crate::use_cases::decode_tx::summarize_cbor;
    use proptest::prelude::*;

    // A fixed key, not a mnemonic: deriving from a mnemonic is slow by design.
    fn build_with(utxos: &[u64], send_lovelace: u64, fee_lovelace: u64) -> YkadaResult<Vec<u8>> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let chain = FakeChain::new(utxos);
        let params = TransactionParams {
            recipient: Address::from_bech32(RECIPIENT).unwrap(),
            send_lovelace,
            fee_lovelace,
            change_address: crate::logic::derive_cardano_address(&key, &key, Network::Preview),
        };
        check_amounts(send_lovelace, fee_lovelace)
            .and_then(|()| build_transaction_use_case(&chain, &chain, params))
    }

    proptest! {
        // Whatever the wallet holds and is asked to send: a clear error, or a transaction in
        // which the inputs pay exactly the outputs plus the fee, every output holds at least
        // 1 ADA, the payment is the amount asked for, and the fee is one a node accepts.
        #[test]
        fn prop_a_built_transaction_balances(
            utxos in prop::collection::vec(1u64..100_000_000, 1..40),
            send in 0u64..300_000_000,
            fee in 0u64..1_200_000,
        ) {
            let Ok(cbor) = build_with(&utxos, send, fee) else {
                return Ok(());
            };
            // FakeChain gives UTxO n (counting from 1) the tx hash [n; 32].
            let spent: u64 = body(&cbor)
                .inputs
                .iter()
                .map(|input| utxos[usize::from(input.transaction_id[0]) - 1])
                .sum();
            let outputs: Vec<u64> = summarize_cbor(&cbor)
                .unwrap()
                .outputs
                .iter()
                .map(|o| o.lovelace)
                .collect();
            prop_assert_eq!(spent, outputs.iter().sum::<u64>() + fee);
            prop_assert_eq!(outputs[0], send);
            prop_assert!(outputs.iter().all(|&lovelace| lovelace >= MIN_UTXO_LOVELACE));
            let size = signed_size(&cbor).unwrap() as u64;
            prop_assert!(fee >= MIN_FEE_A * size + MIN_FEE_B && fee <= MAX_FEE_LOVELACE);
            prop_assert!(size <= MAX_TX_SIZE);
        }
    }
}
