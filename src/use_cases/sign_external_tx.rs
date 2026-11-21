use pallas_addresses::{Address, Network as AddressNetwork};
use pallas_codec::minicbor;
use pallas_crypto::hash::Hasher;
use pallas_primitives::{conway, NetworkId};

use crate::error::{YkadaError, YkadaResult};
use crate::logic::{address_network, attach_witness, map_keys, verify_signature};
use crate::model::{Network, Pin, PreparedTx, SendMode, SendOutcome, TxHash, PAYMENT_SLOT};
use crate::ports::{DeviceFinder, Signer, TxSubmitter};
use crate::use_cases::decode_tx::{output_address, summarize_cbor};
use crate::use_cases::{wallet_keys, TxSummary};

#[derive(serde::Deserialize)]
struct TxFileExport {
    #[serde(rename = "cborHex")]
    cbor_hex: String,
}

// Accept either an Eternl/cardano-cli JSON export (with a `cborHex` field) or bare CBOR hex.
pub(crate) fn parse_tx_input(content: &str) -> YkadaResult<Vec<u8>> {
    let text = content.trim_start_matches('\u{feff}').trim();
    match text.starts_with('{') {
        true => serde_json::from_str::<TxFileExport>(text)
            .map_err(|e| YkadaError::Tx(format!("invalid transaction JSON: {e}")))
            .and_then(|export| decode_hex(&export.cbor_hex, "invalid CBOR hex in cborHex")),
        false => decode_hex(text, "input is neither transaction JSON nor CBOR hex"),
    }
}

// Hex as tools print it: either case, `0x`-prefixed or wrapped across lines.
fn decode_hex(text: &str, failure: &str) -> YkadaResult<Vec<u8>> {
    let digits: String = text
        .strip_prefix("0x")
        .unwrap_or(text)
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    hex::decode(digits).map_err(|e| YkadaError::Tx(format!("{failure}: {e}")))
}

// The whole input must be one transaction: bytes after it would make a "verified" result
// describe something a node rejects.
pub(crate) fn decode_tx(tx_cbor: &[u8]) -> YkadaResult<conway::Tx<'_>> {
    let mut decoder = minicbor::Decoder::new(tx_cbor);
    let tx: conway::Tx = decoder
        .decode()
        .map_err(|e| YkadaError::Tx(format!("invalid transaction CBOR: {e}")))?;
    match tx_cbor.len() - decoder.position() {
        0 => check_body_fields(tx.transaction_body.raw_cbor()).map(|()| tx),
        extra => Err(YkadaError::Tx(format!(
            "invalid transaction CBOR: {extra} bytes after the end of the transaction"
        ))),
    }
}

// The Conway transaction body fields.
const BODY_FIELDS: [u64; 20] = [
    0, 1, 2, 3, 4, 5, 7, 8, 9, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
];

// The decoder skips unknown body fields and keeps the last of a repeated one, so the summary
// would not show them. A node rejects both, so such a transaction is refused here too.
fn check_body_fields(body: &[u8]) -> YkadaResult<()> {
    let keys =
        map_keys(body).map_err(|e| YkadaError::Tx(format!("invalid transaction CBOR: {e}")))?;
    let unknown = keys.iter().find(|key| !BODY_FIELDS.contains(key));
    let repeated = keys
        .iter()
        .enumerate()
        .find_map(|(i, key)| keys[..i].contains(key).then_some(key));
    match (unknown, repeated) {
        (Some(key), _) => Err(YkadaError::Tx(format!(
            "the transaction body has an unknown field {key}, which a node would reject"
        ))),
        (None, Some(key)) => Err(YkadaError::Tx(format!(
            "the transaction body has field {key} twice, which a node would reject"
        ))),
        (None, None) => Ok(()),
    }
}

// Blake2b-256 over the body bytes exactly as they appear in the transaction.
pub(crate) fn body_hash(tx: &conway::Tx<'_>) -> TxHash {
    TxHash::new(*Hasher::<256>::hash(tx.transaction_body.raw_cbor()))
}

pub(crate) fn hash_tx_body(tx_cbor: &[u8]) -> YkadaResult<TxHash> {
    decode_tx(tx_cbor).map(|tx| body_hash(&tx))
}

pub(super) struct SignTxParams {
    pub payment_vkey: [u8; 32],
    pub pin: Option<Pin>,
}

// Sign the body hash on the device and attach the vkey witness. The body and auxiliary
// data are copied byte-for-byte, so the tx ID and any existing witnesses stay valid.
pub(super) fn sign_tx<S: Signer>(
    signer: &mut S,
    tx_cbor: &[u8],
    params: SignTxParams,
) -> YkadaResult<Vec<u8>> {
    let tx = decode_tx(tx_cbor)?;
    let hash = body_hash(&tx);
    let sig = signer.sign(hash.as_ref(), PAYMENT_SLOT, params.pin.as_ref())?;
    verify_signature(&params.payment_vkey, hash.as_ref(), &sig)?;

    let ours = conway::VKeyWitness {
        vkey: params.payment_vkey.to_vec().into(),
        signature: sig.to_vec().into(),
    };
    attach_witness(tx_cbor, &ours)
}

// The size the transaction will have once the YubiKey's witness is added, for the fee check.
pub(crate) fn signed_size(unsigned: &[u8]) -> YkadaResult<usize> {
    let placeholder = conway::VKeyWitness {
        vkey: vec![0; 32].into(),
        signature: vec![0; 64].into(),
    };
    attach_witness(unsigned, &placeholder).map(|signed| signed.len())
}

pub(crate) struct FinishTxParams {
    pub mode: SendMode,
    pub pin: Option<Pin>,
}

// Shared tail of `send` and `sign-tx`: stop unsigned, sign, or sign and submit.
pub(crate) fn finish_tx<F, X>(
    finder: &F,
    submitter: &X,
    tx: PreparedTx,
    params: FinishTxParams,
) -> YkadaResult<SendOutcome>
where
    F: DeviceFinder,
    X: TxSubmitter,
{
    let sign_params = SignTxParams {
        payment_vkey: tx.payment_vkey,
        pin: params.pin,
    };
    match params.mode {
        SendMode::DryRun => Ok(SendOutcome::Cbor(tx.cbor)),
        SendMode::SignOnly => {
            sign_tx(&mut finder.find_first()?, &tx.cbor, sign_params).map(SendOutcome::Cbor)
        }
        SendMode::SignAndSubmit => {
            let signed = sign_tx(&mut finder.find_first()?, &tx.cbor, sign_params)?;
            submitter
                .submit_tx(&signed)
                .map_err(|e| YkadaError::NotSubmitted(e.to_string()))?;
            // Report the locally computed ID rather than trusting the API's echo.
            hash_tx_body(&signed).map(|h| SendOutcome::TxHash(hex::encode(h)))
        }
    }
}

// A testnet transaction can't pay a mainnet address (or the other way round), so the outputs
// and the network_id field show which network a transaction is for.
fn check_network(tx: &conway::Tx<'_>, network: Network) -> YkadaResult<()> {
    let expected = address_network(network);
    let body = &tx.transaction_body;
    let declared = body.network_id.map(|id| match id {
        NetworkId::Mainnet => AddressNetwork::Mainnet,
        NetworkId::Testnet => AddressNetwork::Testnet,
    });
    let paid = body
        .outputs
        .iter()
        .filter_map(|o| Address::from_bytes(output_address(o)).ok()?.network());
    match declared.into_iter().chain(paid).find(|n| *n != expected) {
        None => Ok(()),
        Some(found) => Err(YkadaError::Tx(format!(
            "this transaction is for {found:?}, but --network is {network:?}"
        ))),
    }
}

// Read a transaction built elsewhere and the key that will sign it, all before the PIN.
pub(crate) fn prepare_external_tx_use_case<F: DeviceFinder>(
    finder: &F,
    content: &str,
    network: Network,
) -> YkadaResult<(PreparedTx, TxSummary)> {
    let cbor = parse_tx_input(content)?;
    check_network(&decode_tx(&cbor)?, network)?;
    let summary = summarize_cbor(&cbor)?;
    let (payment_vk, _) = wallet_keys(&mut finder.find_first()?)?.ok_or_else(|| {
        YkadaError::WalletState("no wallet on YubiKey — import or generate first".into())
    })?;
    let tx = PreparedTx {
        cbor,
        payment_vkey: payment_vk.to_bytes(),
        network,
    };
    Ok((tx, summary))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::adapters::fake_chain::FakeChain;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::test_vectors::RECIPIENT;
    use crate::use_cases::summarize_tx;
    use ed25519_dalek::SigningKey;
    use pallas_addresses::Address;
    use pallas_crypto::{hash::Hash, key::ed25519::PublicKey};
    use pallas_txbuilder::{BuildConway, BuiltTransaction, Input, Output, StagingTransaction};

    fn built_tx(input_seed: u8, lovelace: u64) -> BuiltTransaction {
        StagingTransaction::new()
            .input(Input::new(Hash::new([input_seed; 32]), 0))
            .output(Output::new(
                Address::from_bech32(RECIPIENT).unwrap(),
                lovelace,
            ))
            .fee(200_000)
            .invalid_from_slot(1_007_200)
            .build_conway_raw()
            .unwrap()
    }

    pub(crate) fn sample_unsigned_tx(input_seed: u8, lovelace: u64) -> Vec<u8> {
        built_tx(input_seed, lovelace).tx_bytes.0
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn device(seed: u8) -> FakeYubiKey {
        FakeYubiKey::empty()
            .with_key(PAYMENT_SLOT, key(seed))
            .with_key(crate::model::STAKE_SLOT, key(seed.wrapping_add(1)))
    }

    fn sign_with(seed: u8, tx_cbor: &[u8]) -> Vec<u8> {
        let params = SignTxParams {
            payment_vkey: key(seed).verifying_key().to_bytes(),
            pin: None,
        };
        sign_tx(&mut device(seed), tx_cbor, params).unwrap()
    }

    fn verified_witnesses(tx_cbor: &[u8]) -> (usize, usize) {
        let summary = summarize_tx(&hex::encode(tx_cbor)).unwrap();
        (summary.witnesses_verified, summary.witness_count)
    }

    #[test]
    fn test_hash_rejects_invalid_cbor() {
        let msg = hash_tx_body(&[0xFF, 0xFF, 0x00]).unwrap_err().to_string();
        assert!(msg.contains("invalid transaction CBOR"), "got: {msg}");
    }

    #[test]
    fn test_parse_tx_input_json_and_bare_hex() {
        let cbor = sample_unsigned_tx(0xAA, 2_000_000);
        let json = format!(
            r#"{{"type":"Tx ConwayEra","cborHex":"{}"}}"#,
            hex::encode(&cbor)
        );
        assert_eq!(parse_tx_input(&json).unwrap(), cbor);
        assert_eq!(
            parse_tx_input(&format!("  {}\n", hex::encode(&cbor))).unwrap(),
            cbor
        );
    }

    #[test]
    fn test_parse_tx_input_rejects_garbage() {
        let msg = parse_tx_input("not json and not hex")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("neither transaction JSON nor CBOR hex"),
            "got: {msg}"
        );
        let msg = parse_tx_input(r#"{"cborHex":"zzzz"}"#)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("invalid CBOR hex"), "got: {msg}");
    }

    // A broken JSON file is reported as JSON, not as a hex digit problem.
    #[test]
    fn test_parse_tx_input_reports_json_errors() {
        let cases = [
            r#"{"cborHex": "84a4"#,
            r#"{"cborHex": 123}"#,
            r#"{"type": "Tx"}"#,
        ];
        cases.iter().for_each(|json| {
            let msg = parse_tx_input(json).unwrap_err().to_string();
            assert!(msg.contains("invalid transaction JSON"), "{json}: {msg}");
        });
    }

    // Hex as other tools and editors leave it: BOM, CRLF, wrapped lines, 0x, upper case.
    #[test]
    fn test_parse_tx_input_accepts_hex_as_tools_write_it() {
        let cbor = sample_unsigned_tx(0xAA, 2_000_000);
        let hexed = hex::encode(&cbor);
        let wrapped = hexed
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        [
            format!("\u{feff}{hexed}"),
            wrapped,
            format!("0x{hexed}"),
            hexed.to_uppercase(),
            format!("\u{feff}{{\"cborHex\": \"{hexed}\"}}\n"),
        ]
        .iter()
        .for_each(|input| assert_eq!(parse_tx_input(input).unwrap(), cbor, "{input}"));
    }

    // Adds a field at the end of the body of a transaction built with 4 body fields.
    fn with_body_field(tx: &[u8], field: &[u8]) -> Vec<u8> {
        let mut d = minicbor::Decoder::new(tx);
        d.array().unwrap();
        d.skip().unwrap();
        let body_end = d.position();
        assert_eq!(tx[1], 0xa4, "a body of 4 fields");
        [&[tx[0], 0xa5], &tx[2..body_end], field, &tx[body_end..]].concat()
    }

    #[test]
    fn test_decode_rejects_an_unknown_body_field() {
        let tx = with_body_field(&sample_unsigned_tx(0xAA, 2_000_000), &[0x18, 0x63, 0x00]);
        let msg = decode_tx(&tx).unwrap_err().to_string();
        assert!(msg.contains("unknown field 99"), "got: {msg}");
    }

    // With the fee twice, the summary would show only the last one.
    #[test]
    fn test_decode_rejects_a_repeated_body_field() {
        let second_fee = [0x02, 0x1a, 0x05, 0xf5, 0xe1, 0x00];
        let tx = with_body_field(&sample_unsigned_tx(0xAA, 2_000_000), &second_fee);
        let msg = decode_tx(&tx).unwrap_err().to_string();
        assert!(msg.contains("field 2 twice"), "got: {msg}");
    }

    #[test]
    fn test_decode_rejects_bytes_after_the_transaction() {
        let signed = sign_with(42, &sample_unsigned_tx(0xAA, 2_000_000));
        [vec![0xff], vec![0; 1000], signed.clone()]
            .iter()
            .for_each(|extra| {
                let msg = decode_tx(&[signed.as_slice(), extra].concat())
                    .unwrap_err()
                    .to_string();
                assert!(msg.contains("bytes after the end"), "got: {msg}");
            });
        assert!(decode_tx(&signed).is_ok());
    }

    #[test]
    fn test_sign_preserves_body_bytes_and_adds_valid_witness() {
        let unsigned = sample_unsigned_tx(0xAA, 2_000_000);
        let signed = sign_with(42, &unsigned);
        assert_eq!(
            decode_tx(&unsigned).unwrap().transaction_body.raw_cbor(),
            decode_tx(&signed).unwrap().transaction_body.raw_cbor()
        );
        assert_eq!(verified_witnesses(&signed), (1, 1));
    }

    // Same bytes as pallas-txbuilder's own signing.
    #[test]
    fn test_sign_matches_txbuilder_add_signature() {
        use ed25519_dalek::Signer as _;
        let built = built_tx(0xAA, 2_000_000);
        let ours = sign_with(42, &built.tx_bytes.0);
        let vkey = PublicKey::from(key(42).verifying_key().to_bytes());
        let sig = key(42).sign(&built.tx_hash.0).to_bytes();
        let reference = built.add_signature(vkey, sig).unwrap();
        assert_eq!(ours, reference.tx_bytes.0);
    }

    #[test]
    fn test_resign_replaces_own_witness_and_keeps_others() {
        let unsigned = sample_unsigned_tx(0xAA, 2_000_000);
        let both = sign_with(2, &sign_with(1, &unsigned));
        let again = sign_with(1, &both);
        assert_eq!(verified_witnesses(&both), (2, 2));
        assert_eq!(verified_witnesses(&again), (2, 2));
    }

    #[test]
    fn test_sign_rejects_wrong_payment_key() {
        let params = SignTxParams {
            payment_vkey: key(7).verifying_key().to_bytes(),
            pin: None,
        };
        let unsigned = sample_unsigned_tx(0xAA, 2_000_000);
        assert!(matches!(
            sign_tx(&mut device(42), &unsigned, params).unwrap_err(),
            YkadaError::SignatureVerificationFailed
        ));
    }

    fn sign_file(
        device: FakeYubiKey,
        chain: &FakeChain,
        mode: SendMode,
    ) -> YkadaResult<SendOutcome> {
        let finder = FakeDeviceFinder(device);
        let content = hex::encode(sample_unsigned_tx(0xAA, 2_000_000));
        let (tx, _) = prepare_external_tx_use_case(&finder, &content, Network::Preview)?;
        finish_tx(&finder, chain, tx, FinishTxParams { mode, pin: None })
    }

    fn prepare_error(tx: StagingTransaction, network: Network) -> String {
        let content = hex::encode(tx.build_conway_raw().unwrap().tx_bytes.0);
        prepare_external_tx_use_case(&FakeDeviceFinder(device(42)), &content, network)
            .err()
            .expect("the transaction must be refused")
            .to_string()
    }

    fn paying(address: Address) -> StagingTransaction {
        StagingTransaction::new()
            .input(Input::new(Hash::new([0xAA; 32]), 0))
            .output(Output::new(address, 2_000_000))
            .fee(200_000)
    }

    #[test]
    fn test_refuses_a_mainnet_transaction_on_a_testnet() {
        let mainnet = crate::logic::derive_cardano_address(
            &key(1).verifying_key(),
            &key(2).verifying_key(),
            Network::Mainnet,
        );
        let msg = prepare_error(paying(Address::Shelley(mainnet)), Network::Preview);
        assert!(
            msg.contains("for Mainnet, but --network is Preview"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_refuses_a_testnet_transaction_on_mainnet() {
        let testnet = Address::from_bech32(RECIPIENT).unwrap();
        let msg = prepare_error(paying(testnet), Network::Mainnet);
        assert!(
            msg.contains("for Testnet, but --network is Mainnet"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_refuses_a_mainnet_network_id_on_a_testnet() {
        let testnet = Address::from_bech32(RECIPIENT).unwrap();
        let msg = prepare_error(paying(testnet).network_id(1), Network::Preprod);
        assert!(msg.contains("for Mainnet"), "got: {msg}");
    }

    #[test]
    fn test_testnet_transaction_is_accepted_on_both_testnets() {
        let content = hex::encode(sample_unsigned_tx(0xAA, 2_000_000));
        let finder = FakeDeviceFinder(device(42));
        [Network::Preview, Network::Preprod]
            .into_iter()
            .for_each(|network| {
                assert!(prepare_external_tx_use_case(&finder, &content, network).is_ok());
            });
    }

    // The fee check must count the witness the YubiKey will add, to the byte.
    #[test]
    fn test_signed_size_is_the_size_after_signing() {
        let unsigned = sample_unsigned_tx(0xAA, 2_000_000);
        assert_eq!(
            signed_size(&unsigned).unwrap(),
            sign_with(42, &unsigned).len()
        );
        let signed = sign_with(42, &unsigned);
        assert_eq!(signed_size(&signed).unwrap(), sign_with(43, &signed).len());
    }

    #[test]
    fn test_a_failed_submission_says_the_tx_was_not_submitted() {
        struct Rejecting;
        impl TxSubmitter for Rejecting {
            fn submit_tx(&self, _: &[u8]) -> YkadaResult<()> {
                Err(YkadaError::Network("HTTP 400: rejected".into()))
            }
        }
        let finder = FakeDeviceFinder(device(42));
        let content = hex::encode(sample_unsigned_tx(0xAA, 2_000_000));
        let (tx, _) = prepare_external_tx_use_case(&finder, &content, Network::Preview).unwrap();
        let params = FinishTxParams {
            mode: SendMode::SignAndSubmit,
            pin: None,
        };
        let msg = finish_tx(&finder, &Rejecting, tx, params)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("signed but not submitted"), "got: {msg}");
    }

    #[test]
    fn test_sign_file_without_send_does_not_submit() {
        let chain = FakeChain::new(&[]);
        let SendOutcome::Cbor(signed) = sign_file(device(42), &chain, SendMode::SignOnly).unwrap()
        else {
            panic!("expected CBOR");
        };
        assert_eq!(verified_witnesses(&signed), (1, 1));
        assert!(chain.submitted().is_empty());
    }

    #[test]
    fn test_sign_file_with_send_submits_the_signed_transaction() {
        let chain = FakeChain::new(&[]);
        sign_file(device(42), &chain, SendMode::SignAndSubmit).unwrap();
        let [submitted] = &chain.submitted()[..] else {
            panic!("expected exactly one submission");
        };
        assert_eq!(verified_witnesses(submitted), (1, 1));
    }

    #[test]
    fn test_sign_file_requires_a_payment_key() {
        assert!(matches!(
            sign_file(
                FakeYubiKey::empty(),
                &FakeChain::new(&[]),
                SendMode::SignOnly
            ),
            Err(YkadaError::WalletState(_))
        ));
    }
}
