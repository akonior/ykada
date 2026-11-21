use pallas_addresses::Address;
use pallas_primitives::{alonzo, conway};

use super::sign_external_tx::{body_hash, decode_tx, parse_tx_input};
use crate::error::YkadaResult;
use crate::logic::verify_signature;

pub struct TxOutputSummary {
    pub address: String,
    pub lovelace: u64,
    pub has_tokens: bool,
}

// Read-only summary of a (possibly signed) transaction, plus local verification
// of any vkey witnesses against the body hash.
pub struct TxSummary {
    pub body_hash_hex: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<TxOutputSummary>,
    pub fee: u64,
    pub ttl: Option<u64>,
    // Body features beyond a plain payment (certificates, mint, …), for review before signing.
    pub extras: Vec<&'static str>,
    pub witness_count: usize,
    pub witnesses_verified: usize,
}

pub(crate) fn summarize_tx(content: &str) -> YkadaResult<TxSummary> {
    let cbor = parse_tx_input(content)?;
    let tx = decode_tx(&cbor)?;
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
        ttl: body.ttl,
        extras: body_extras(body),
        witness_count: witnesses.len(),
        witnesses_verified: witnesses
            .iter()
            .filter(|w| witness_verifies(w, &hash))
            .count(),
    })
}

fn body_extras(body: &conway::MintedTransactionBody<'_>) -> Vec<&'static str> {
    [
        (body.certificates.is_some(), "certificates"),
        (body.withdrawals.is_some(), "withdrawals"),
        (body.mint.is_some(), "mint/burn"),
        (body.script_data_hash.is_some(), "scripts"),
        (body.collateral.is_some(), "collateral"),
        (body.required_signers.is_some(), "required signers"),
        (body.voting_procedures.is_some(), "votes"),
        (body.proposal_procedures.is_some(), "governance proposals"),
        (
            body.treasury_value.is_some() || body.donation.is_some(),
            "treasury",
        ),
    ]
    .into_iter()
    .filter_map(|(present, name)| present.then_some(name))
    .collect()
}

fn summarize_output(output: &conway::MintedTransactionOutput<'_>) -> TxOutputSummary {
    let (address, lovelace, has_tokens) = match output {
        conway::PseudoTransactionOutput::Legacy(o) => match &o.amount {
            alonzo::Value::Coin(c) => (&o.address, *c, false),
            alonzo::Value::Multiasset(c, _) => (&o.address, *c, true),
        },
        conway::PseudoTransactionOutput::PostAlonzo(o) => match &o.value {
            conway::Value::Coin(c) => (&o.address, *c, false),
            conway::Value::Multiasset(c, _) => (&o.address, *c, true),
        },
    };
    TxOutputSummary {
        address: Address::from_bytes(address)
            .ok()
            .and_then(|a| a.to_bech32().ok())
            .unwrap_or_else(|| format!("<undecodable {}>", hex::encode(address.as_slice()))),
        lovelace,
        has_tokens,
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
}
