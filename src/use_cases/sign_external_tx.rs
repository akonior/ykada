use pallas_crypto::hash::Hasher;
use pallas_primitives::{conway, Fragment, NonEmptySet};

use crate::error::{YkadaError, YkadaResult};
use crate::logic::verify_signature;
use crate::model::{Pin, SendMode, SendOutcome, TxHash, PAYMENT_SLOT};
use crate::ports::{DeviceFinder, DeviceReader, Signer, TxSubmitter};

#[derive(serde::Deserialize)]
struct TxFileExport {
    #[serde(rename = "cborHex")]
    cbor_hex: String,
}

// Accept either an Eternl/cardano-cli JSON export (with a `cborHex` field) or bare CBOR hex.
pub(crate) fn parse_tx_input(content: &str) -> YkadaResult<Vec<u8>> {
    let trimmed = content.trim();
    match serde_json::from_str::<TxFileExport>(trimmed) {
        Ok(export) => hex::decode(&export.cbor_hex)
            .map_err(|e| YkadaError::Tx(format!("invalid CBOR hex: {e}"))),
        Err(_) => hex::decode(trimmed)
            .map_err(|e| YkadaError::Tx(format!("input is neither tx JSON nor CBOR hex: {e}"))),
    }
}

pub(crate) fn decode_tx(tx_cbor: &[u8]) -> YkadaResult<conway::Tx<'_>> {
    conway::Tx::decode_fragment(tx_cbor)
        .map_err(|e| YkadaError::Tx(format!("invalid transaction CBOR: {e}")))
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
    let mut tx = decode_tx(tx_cbor)?;
    let hash = body_hash(&tx);
    let sig = signer.sign(hash.as_ref(), PAYMENT_SLOT, params.pin.as_ref())?;
    verify_signature(&params.payment_vkey, hash.as_ref(), &sig)?;

    let ours = conway::VKeyWitness {
        vkey: params.payment_vkey.to_vec().into(),
        signature: sig.to_vec().into(),
    };
    // Mutating the witness set drops only its raw bytes, so only it is re-encoded.
    let witness_set = &mut *tx.transaction_witness_set;
    witness_set.vkeywitness = Some(with_witness(witness_set.vkeywitness.take(), ours));

    tx.encode_fragment()
        .map_err(|e| YkadaError::Tx(format!("failed to encode signed tx: {e}")))
}

// Append our witness, replacing an earlier one for the same key (re-signing is idempotent).
fn with_witness(
    existing: Option<NonEmptySet<conway::VKeyWitness>>,
    ours: conway::VKeyWitness,
) -> NonEmptySet<conway::VKeyWitness> {
    let our_vkey = ours.vkey.clone();
    let witnesses = existing
        .map(|set| set.to_vec())
        .unwrap_or_default()
        .into_iter()
        .filter(|w| w.vkey != our_vkey)
        .chain(std::iter::once(ours))
        .collect();
    NonEmptySet::from_vec(witnesses).expect("contains at least our witness")
}

pub(crate) struct FinishTxParams {
    pub payment_vkey: [u8; 32],
    pub pin: Option<Pin>,
    pub mode: SendMode,
}

// Shared tail of `send` and `sign-tx`: stop unsigned, sign, or sign and submit.
pub(crate) fn finish_tx<F, X>(
    finder: &F,
    submitter: &X,
    unsigned: Vec<u8>,
    params: FinishTxParams,
) -> YkadaResult<SendOutcome>
where
    F: DeviceFinder,
    X: TxSubmitter,
{
    let sign_params = SignTxParams {
        payment_vkey: params.payment_vkey,
        pin: params.pin,
    };
    match params.mode {
        SendMode::DryRun => Ok(SendOutcome::Cbor(unsigned)),
        SendMode::SignOnly => {
            sign_tx(&mut finder.find_first()?, &unsigned, sign_params).map(SendOutcome::Cbor)
        }
        SendMode::SignAndSubmit => {
            let signed = sign_tx(&mut finder.find_first()?, &unsigned, sign_params)?;
            submitter.submit_tx(&signed)?;
            // Report the locally computed ID rather than trusting the API's echo.
            hash_tx_body(&signed).map(|h| SendOutcome::TxHash(hex::encode(h)))
        }
    }
}

pub(crate) struct SignTxFileParams {
    pub tx_file_content: String,
    pub mode: SendMode,
    pub pin: Option<Pin>,
}

pub(crate) fn sign_tx_file_use_case<F, X>(
    finder: &F,
    submitter: &X,
    params: SignTxFileParams,
) -> YkadaResult<SendOutcome>
where
    F: DeviceFinder,
    X: TxSubmitter,
{
    let unsigned = parse_tx_input(&params.tx_file_content)?;
    let payment_vkey = finder
        .find_first()?
        .read_public_key(PAYMENT_SLOT)?
        .ok_or_else(|| {
            YkadaError::WalletState("no payment key on YubiKey — import a wallet first".into())
        })?
        .to_bytes();
    finish_tx(
        finder,
        submitter,
        unsigned,
        FinishTxParams {
            payment_vkey,
            pin: params.pin,
            mode: params.mode,
        },
    )
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
        FakeYubiKey::empty().with_key(PAYMENT_SLOT, key(seed))
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
        assert!(msg.contains("neither tx JSON nor CBOR hex"), "got: {msg}");
        let msg = parse_tx_input(r#"{"cborHex":"zzzz"}"#)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("invalid CBOR hex"), "got: {msg}");
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
        sign_tx_file_use_case(
            &FakeDeviceFinder(device),
            chain,
            SignTxFileParams {
                tx_file_content: hex::encode(sample_unsigned_tx(0xAA, 2_000_000)),
                mode,
                pin: None,
            },
        )
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
