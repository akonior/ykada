use pallas_addresses::Address;
use pallas_primitives::{alonzo, conway, NetworkId, Nullable};

use super::sign_external_tx::{body_hash, decode_tx, parse_tx_input};
use crate::error::YkadaResult;
use crate::logic::verify_signature;

pub struct TxOutputSummary {
    pub address: String,
    pub lovelace: u64,
    pub has_tokens: bool,
    // A datum or datum hash, or a reference script, attached to the output.
    pub has_datum: bool,
    pub has_script: bool,
}

// Read-only summary of a (possibly signed) transaction, plus local verification
// of any vkey witnesses against the body hash.
pub struct TxSummary {
    pub body_hash_hex: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<TxOutputSummary>,
    pub fee: u64,
    pub validity_start: Option<u64>,
    pub ttl: Option<u64>,
    // Everything beyond a plain payment (certificates, mint, …), for review before signing.
    pub extras: Vec<String>,
    // false means the scripts are expected to fail and the collateral is taken instead.
    pub is_valid: bool,
    pub witness_count: usize,
    pub witnesses_verified: usize,
}

pub(crate) fn summarize_tx(content: &str) -> YkadaResult<TxSummary> {
    summarize_cbor(&parse_tx_input(content)?)
}

pub(crate) fn summarize_cbor(cbor: &[u8]) -> YkadaResult<TxSummary> {
    let tx = decode_tx(cbor)?;
    let hash = *body_hash(&tx).as_bytes();
    let body = &tx.transaction_body;
    let witnesses = tx
        .transaction_witness_set
        .vkeywitness
        .clone()
        .map(|set| set.to_vec())
        .unwrap_or_default();

    Ok(TxSummary {
        body_hash_hex: hex::encode(hash),
        inputs: body
            .inputs
            .iter()
            .map(|i| format!("{}#{}", hex::encode(i.transaction_id), i.index))
            .collect(),
        outputs: body.outputs.iter().map(summarize_output).collect(),
        fee: body.fee,
        validity_start: body.validity_interval_start,
        ttl: body.ttl,
        extras: extras(&tx),
        is_valid: tx.success,
        witness_count: witnesses.len(),
        witnesses_verified: witnesses
            .iter()
            .filter(|w| witness_verifies(w, &hash))
            .count(),
    })
}

fn extras(tx: &conway::Tx<'_>) -> Vec<String> {
    let body = &tx.transaction_body;
    let witnesses = &tx.transaction_witness_set;
    let count = |name: &str, n: usize| format!("{name} ({n})");
    let mint = body.mint.as_ref().map(|policies| {
        let assets: Vec<i64> = policies
            .values()
            .flat_map(|assets| assets.values().map(i64::from))
            .collect();
        format!(
            "mint/burn ({} assets: {} minted, {} burned)",
            assets.len(),
            assets.iter().filter(|q| **q > 0).count(),
            assets.iter().filter(|q| **q < 0).count()
        )
    });
    let scripts = body.script_data_hash.is_some()
        || witnesses.native_script.is_some()
        || witnesses.plutus_v1_script.is_some()
        || witnesses.plutus_v2_script.is_some()
        || witnesses.plutus_v3_script.is_some();
    [
        body.certificates
            .as_ref()
            .map(|c| count("certificates", c.len())),
        body.withdrawals.as_ref().map(|w| {
            format!(
                "withdrawals ({} lovelace)",
                w.values().fold(0u128, |sum, coin| sum + u128::from(*coin))
            )
        }),
        mint,
        scripts.then(|| "scripts".to_string()),
        body.collateral
            .as_ref()
            .map(|c| count("collateral inputs", c.len())),
        body.total_collateral
            .map(|coin| format!("total collateral ({coin} lovelace)")),
        body.collateral_return.as_ref().map(|o| {
            format!(
                "collateral return ({} lovelace)",
                summarize_output(o).lovelace
            )
        }),
        body.required_signers
            .as_ref()
            .map(|s| count("required signers", s.len())),
        body.reference_inputs
            .as_ref()
            .map(|r| count("reference inputs", r.len())),
        body.voting_procedures
            .as_ref()
            .map(|v| count("votes", v.len())),
        body.proposal_procedures
            .as_ref()
            .map(|p| count("governance proposals", p.len())),
        (body.treasury_value.is_some() || body.donation.is_some()).then(|| "treasury".to_string()),
        matches!(tx.auxiliary_data, Nullable::Some(_)).then(|| "metadata".to_string()),
        witnesses
            .bootstrap_witness
            .as_ref()
            .map(|b| count("Byron witnesses, not verified", b.len())),
        body.network_id.map(|id| match id {
            NetworkId::Mainnet => "network ID mainnet".to_string(),
            NetworkId::Testnet => "network ID testnet".to_string(),
        }),
    ]
    .into_iter()
    .flatten()
    .collect()
}

pub(crate) fn output_address<'a>(output: &'a conway::TransactionOutput<'_>) -> &'a [u8] {
    match output {
        conway::TransactionOutput::Legacy(o) => &o.address,
        conway::TransactionOutput::PostAlonzo(o) => &o.address,
    }
}

fn summarize_output(output: &conway::TransactionOutput<'_>) -> TxOutputSummary {
    let (lovelace, has_tokens, has_datum, has_script) = match output {
        conway::TransactionOutput::Legacy(o) => match &o.amount {
            alonzo::Value::Coin(c) => (*c, false, o.datum_hash.is_some(), false),
            alonzo::Value::Multiasset(c, _) => (*c, true, o.datum_hash.is_some(), false),
        },
        conway::TransactionOutput::PostAlonzo(o) => {
            let (has_datum, has_script) = (o.datum_option.is_some(), o.script_ref.is_some());
            match &o.value {
                conway::Value::Coin(c) => (*c, false, has_datum, has_script),
                conway::Value::Multiasset(c, _) => (*c, true, has_datum, has_script),
            }
        }
    };
    TxOutputSummary {
        address: readable_address(output_address(output)),
        lovelace,
        has_tokens,
        has_datum,
        has_script,
    }
}

// Shelley addresses in bech32, Byron addresses in base58, as wallets show them.
fn readable_address(bytes: &[u8]) -> String {
    match Address::from_bytes(bytes) {
        Ok(Address::Byron(byron)) => byron.to_base58(),
        Ok(address) => address
            .to_bech32()
            .unwrap_or_else(|_| format!("<undecodable {}>", hex::encode(bytes))),
        Err(_) => format!("<undecodable {}>", hex::encode(bytes)),
    }
}

fn witness_verifies(witness: &conway::VKeyWitness, body_hash: &[u8; 32]) -> bool {
    match (
        <[u8; 32]>::try_from(witness.vkey.as_slice()),
        <[u8; 64]>::try_from(witness.signature.as_slice()),
    ) {
        (Ok(vkey), Ok(sig)) => verify_signature(&vkey, body_hash, &sig).is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{ON_CHAIN_TX_CBOR, ON_CHAIN_TX_ID};
    use crate::use_cases::sign_external_tx::tests::sample_unsigned_tx;

    #[test]
    fn summarizes_unsigned_tx() {
        let summary = summarize_tx(&hex::encode(sample_unsigned_tx(0xAB, 2_000_000))).unwrap();
        assert_eq!(summary.inputs.len(), 1);
        assert!(summary.inputs[0].ends_with("#0"));
        assert_eq!(summary.outputs.len(), 1);
        assert_eq!(summary.outputs[0].lovelace, 2_000_000);
        assert!(summary.outputs[0].address.starts_with("addr_test1"));
        assert_eq!(summary.fee, 200_000);
        assert_eq!(summary.witness_count, 0);
        assert!(summary.extras.is_empty());
        assert_eq!(summary.body_hash_hex.len(), 64);
    }

    // The body hash must equal the ID the chain gave this transaction.
    #[test]
    fn verifies_transaction_confirmed_on_preview() {
        let summary = summarize_tx(ON_CHAIN_TX_CBOR).unwrap();
        assert_eq!(summary.body_hash_hex, ON_CHAIN_TX_ID);
        assert_eq!(summary.witness_count, 1);
        assert_eq!(summary.witnesses_verified, 1);
    }

    #[test]
    fn rejects_garbage() {
        assert!(summarize_tx("not a transaction").is_err());
    }

    use crate::test_vectors::RECIPIENT;
    use pallas_crypto::hash::Hash;
    use pallas_txbuilder::{BuildConway, Input, Output, StagingTransaction};

    fn summary_of(tx: StagingTransaction) -> TxSummary {
        let cbor = tx.build_conway_raw().unwrap().tx_bytes.0;
        summarize_cbor(&cbor).unwrap()
    }

    fn payment() -> StagingTransaction {
        StagingTransaction::new()
            .input(Input::new(Hash::new([1; 32]), 0))
            .output(Output::new(
                Address::from_bech32(RECIPIENT).unwrap(),
                2_000_000,
            ))
            .fee(200_000)
    }

    // Everything that changes what a signature authorizes must be visible before signing.
    #[test]
    fn shows_everything_beyond_a_plain_payment() {
        let recipient = Address::from_bech32(RECIPIENT).unwrap();
        let tx = payment()
            .valid_from_slot(100)
            .reference_input(Input::new(Hash::new([2; 32]), 0))
            .collateral_input(Input::new(Hash::new([3; 32]), 0))
            .collateral_output(Output::new(recipient, 4_000_000))
            .disclosed_signer(Hash::new([4; 28]))
            .network_id(0)
            .add_auxiliary_data(vec![0xa1, 0x00, 0x61, 0x78])
            .mint_asset(Hash::new([5; 28]), b"A".to_vec(), 3)
            .unwrap()
            .mint_asset(Hash::new([5; 28]), b"B".to_vec(), -1)
            .unwrap();
        let summary = summary_of(tx);
        assert_eq!(summary.validity_start, Some(100));
        [
            "mint/burn (2 assets: 1 minted, 1 burned)",
            "collateral inputs (1)",
            "collateral return (4000000 lovelace)",
            "required signers (1)",
            "reference inputs (1)",
            "metadata",
            "network ID testnet",
        ]
        .iter()
        .for_each(|extra| {
            assert!(
                summary.extras.contains(&extra.to_string()),
                "missing {extra}: {:?}",
                summary.extras
            )
        });
    }

    #[test]
    fn a_plain_payment_has_no_extras() {
        let summary = summary_of(payment());
        assert!(summary.extras.is_empty(), "{:?}", summary.extras);
        assert!(summary.is_valid);
        assert_eq!(summary.validity_start, None);
    }

    #[test]
    fn shows_datum_and_script_on_outputs() {
        let recipient = Address::from_bech32(RECIPIENT).unwrap();
        let output = Output::new(recipient, 2_000_000)
            .set_datum_hash(Hash::new([6; 32]))
            .set_inline_script(pallas_txbuilder::ScriptKind::PlutusV3, vec![0x01]);
        let summary = summary_of(payment().output(output));
        assert!(summary.outputs[1].has_datum && summary.outputs[1].has_script);
        assert!(!summary.outputs[0].has_datum && !summary.outputs[0].has_script);
    }

    // is_valid = false forfeits the collateral; the flag must not pass unnoticed.
    #[test]
    fn reports_a_transaction_marked_invalid() {
        let mut cbor = payment().build_conway_raw().unwrap().tx_bytes.0;
        let flag = cbor.len() - 2;
        assert_eq!(cbor[flag], 0xf5, "is_valid = true before the change");
        cbor[flag] = 0xf4;
        assert!(!summarize_cbor(&cbor).unwrap().is_valid);
    }

    #[test]
    fn shows_byron_addresses_in_base58() {
        let byron = "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi";
        let tx = payment().output(Output::new(byron.parse::<Address>().unwrap(), 2_000_000));
        assert_eq!(summary_of(tx).outputs[1].address, byron);
    }
}
