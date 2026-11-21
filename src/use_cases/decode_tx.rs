use pallas_addresses::Address;
use pallas_primitives::{alonzo, conway, AssetName, NetworkId, Nullable, PolicyId};

use super::sign_external_tx::{body_hash, decode_tx, parse_tx_input};
use crate::error::YkadaResult;
use crate::logic::verify_signature;

// One native token amount, as cardano-cli writes it: quantity, policy ID and hex asset name.
pub struct AssetAmount {
    pub policy_id: String,
    pub asset_name: String,
    // Negative for a burn.
    pub quantity: i128,
    // The asset name as text, when it is plain printable ASCII.
    pub readable_name: Option<String>,
}

impl AssetAmount {
    fn new(policy: &PolicyId, name: &AssetName, quantity: i128) -> Self {
        let printable = !name.is_empty() && name.iter().all(|b| (0x20..0x7f).contains(b));
        Self {
            policy_id: hex::encode(policy),
            asset_name: hex::encode(name.as_slice()),
            quantity,
            readable_name: printable.then(|| String::from_utf8_lossy(name).into_owned()),
        }
    }
}

impl std::fmt::Display for AssetAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match &self.readable_name {
            Some(text) => format!(" (\"{text}\")"),
            None => String::new(),
        };
        write!(
            f,
            "{} {}.{}{name}",
            self.quantity, self.policy_id, self.asset_name
        )
    }
}

fn asset_amounts<A>(
    multiasset: &conway::Multiasset<A>,
    quantity: fn(&A) -> i128,
) -> Vec<AssetAmount> {
    multiasset
        .iter()
        .flat_map(|(policy, assets)| {
            assets
                .iter()
                .map(move |(name, amount)| AssetAmount::new(policy, name, quantity(amount)))
        })
        .collect()
}

pub struct TxOutputSummary {
    pub address: String,
    pub lovelace: u64,
    pub tokens: Vec<AssetAmount>,
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
    // Where the collateral's remainder goes if the scripts fail.
    pub collateral_return: Option<TxOutputSummary>,
    pub fee: u64,
    pub validity_start: Option<u64>,
    pub ttl: Option<u64>,
    // Tokens minted (positive) or burned (negative).
    pub mint: Vec<AssetAmount>,
    // Everything else beyond a plain payment (certificates, treasury, …), for review before signing.
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
        collateral_return: body.collateral_return.as_ref().map(summarize_output),
        fee: body.fee,
        validity_start: body.validity_interval_start,
        ttl: body.ttl,
        mint: body
            .mint
            .as_ref()
            .map(|mint| asset_amounts(mint, |q| i64::from(q).into()))
            .unwrap_or_default(),
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
        scripts.then(|| "scripts".to_string()),
        body.collateral
            .as_ref()
            .map(|c| count("collateral inputs", c.len())),
        body.total_collateral
            .map(|coin| format!("total collateral ({coin} lovelace)")),
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
        body.donation
            .map(|coin| format!("treasury donation ({} lovelace)", u64::from(coin))),
        body.treasury_value
            .map(|coin| format!("current treasury value ({coin} lovelace)")),
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
    let (lovelace, tokens, has_datum, has_script) = match output {
        conway::TransactionOutput::Legacy(o) => match &o.amount {
            alonzo::Value::Coin(c) => (*c, vec![], o.datum_hash.is_some(), false),
            alonzo::Value::Multiasset(c, assets) => (
                *c,
                asset_amounts(assets, |q| (*q).into()),
                o.datum_hash.is_some(),
                false,
            ),
        },
        conway::TransactionOutput::PostAlonzo(o) => {
            let (has_datum, has_script) = (o.datum_option.is_some(), o.script_ref.is_some());
            match &o.value {
                conway::Value::Coin(c) => (*c, vec![], has_datum, has_script),
                conway::Value::Multiasset(c, assets) => (
                    *c,
                    asset_amounts(assets, |q| u64::from(q).into()),
                    has_datum,
                    has_script,
                ),
            }
        }
    };
    TxOutputSummary {
        address: readable_address(output_address(output)),
        lovelace,
        tokens,
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

pub(crate) fn witness_verifies(witness: &conway::VKeyWitness, body_hash: &[u8; 32]) -> bool {
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
        let returned = summary.collateral_return.as_ref().unwrap();
        assert_eq!(
            (returned.lovelace, returned.address.as_str()),
            (4_000_000, RECIPIENT)
        );
        [
            "collateral inputs (1)",
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

    // Which tokens a signature mints or burns, asset by asset: a count would hide a swap.
    #[test]
    fn shows_each_minted_and_burned_asset() {
        let tx = payment()
            .mint_asset(Hash::new([5; 28]), b"A".to_vec(), 3)
            .unwrap()
            .mint_asset(Hash::new([5; 28]), b"B".to_vec(), -1)
            .unwrap();
        let mint: Vec<String> = summary_of(tx).mint.iter().map(|a| a.to_string()).collect();
        let policy = hex::encode([5; 28]);
        assert_eq!(
            mint,
            [
                format!("3 {policy}.41 (\"A\")"),
                format!("-1 {policy}.42 (\"B\")")
            ]
        );
    }

    // Before the PIN, every token an output receives must be visible with its amount.
    #[test]
    fn shows_every_token_on_an_output() {
        let recipient = Address::from_bech32(RECIPIENT).unwrap();
        let output = Output::new(recipient, 2_000_000)
            .add_asset(Hash::new([7; 28]), b"HOSKY".to_vec(), 1_000_000)
            .unwrap()
            .add_asset(Hash::new([8; 28]), vec![0x00, 0xff], 2)
            .unwrap();
        let summary = summary_of(payment().output(output));
        let tokens: Vec<String> = summary.outputs[1]
            .tokens
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(
            tokens,
            [
                format!("1000000 {}.484f534b59 (\"HOSKY\")", hex::encode([7; 28])),
                format!("2 {}.00ff", hex::encode([8; 28])),
            ]
        );
        assert!(summary.outputs[0].tokens.is_empty());
    }

    // [body, {}, true, null] with a treasury donation (22) and the treasury value (21).
    fn donating_tx() -> Vec<u8> {
        let address = Address::from_bech32(RECIPIENT).unwrap().to_vec();
        let mut e = pallas_codec::minicbor::Encoder::new(Vec::new());
        e.array(4).unwrap().map(5).unwrap();
        e.u8(0).unwrap().array(1).unwrap().array(2).unwrap();
        e.bytes(&[1; 32]).unwrap().u8(0).unwrap();
        e.u8(1).unwrap().array(1).unwrap().array(2).unwrap();
        e.bytes(&address).unwrap().u64(2_000_000).unwrap();
        e.u8(2).unwrap().u64(200_000).unwrap();
        e.u8(21).unwrap().u64(1_500_000_000_000).unwrap();
        e.u8(22).unwrap().u64(25_000_000).unwrap();
        e.map(0).unwrap().bool(true).unwrap().null().unwrap();
        e.into_writer()
    }

    #[test]
    fn shows_the_treasury_donation_and_value() {
        let summary = summarize_cbor(&donating_tx()).unwrap();
        assert!(summary
            .extras
            .contains(&"treasury donation (25000000 lovelace)".to_string()));
        assert!(summary
            .extras
            .contains(&"current treasury value (1500000000000 lovelace)".to_string()));
    }

    // Plain ASCII only: other bytes could imitate a known token's name.
    #[test]
    fn asset_names_are_shown_as_text_only_when_plain_ascii() {
        let policy = Hash::new([9; 28]);
        let named =
            |bytes: &[u8]| AssetAmount::new(&policy, &bytes.to_vec().into(), 1).readable_name;
        assert_eq!(named(b"MIN"), Some("MIN".to_string()));
        assert_eq!(named("ÄDA".as_bytes()), None);
        assert_eq!(named(b"A\nB"), None);
        assert_eq!(named(b""), None);
    }

    #[test]
    fn a_plain_payment_has_no_extras() {
        let summary = summary_of(payment());
        assert!(summary.extras.is_empty(), "{:?}", summary.extras);
        assert!(summary.mint.is_empty());
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
