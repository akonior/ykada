use pallas_crypto::hash::Hasher;
use pallas_primitives::{conway, Fragment, NonEmptySet};
use tracing::{debug, info};

use super::sign_data::{sign_data_use_case, SignDataParams};
use crate::error::{YkadaError, YkadaResult};
use crate::model::{Network, Pin, SendMode, SendOutcome, Slot};
use crate::ports::{DeviceFinder, DeviceReader, Signer, TxSubmitter};
use crate::use_cases::wallet_info_use_case;

#[derive(serde::Deserialize)]
struct TxFileExport {
    #[serde(rename = "cborHex")]
    cbor_hex: String,
}

pub fn parse_tx_file_json(json_content: &str) -> YkadaResult<Vec<u8>> {
    let export: TxFileExport = serde_json::from_str(json_content)
        .map_err(|e| YkadaError::NetworkError(format!("invalid transaction JSON: {e}")))?;
    hex::decode(&export.cbor_hex)
        .map_err(|e| YkadaError::NetworkError(format!("invalid CBOR hex: {e}")))
}

pub struct SignExternalTxParams {
    pub payment_vkey: [u8; 32],
    pub payment_slot: Slot,
    pub pin: Option<Pin>,
}

pub fn sign_external_tx_use_case<S: Signer>(
    signer: &mut S,
    unsigned_tx_cbor: &[u8],
    params: SignExternalTxParams,
) -> YkadaResult<Vec<u8>> {
    let mut tx = conway::Tx::decode_fragment(unsigned_tx_cbor)
        .map_err(|e| YkadaError::NetworkError(format!("invalid transaction CBOR: {e}")))?;

    let body_bytes = tx
        .transaction_body
        .encode_fragment()
        .map_err(|e| YkadaError::NetworkError(format!("failed to encode tx body: {e}")))?;
    let tx_hash: [u8; 32] = *Hasher::<256>::hash(&body_bytes);

    info!("Transaction body hash: {}", hex::encode(tx_hash));

    let sig = sign_data_use_case(
        signer,
        &tx_hash,
        SignDataParams {
            slot: params.payment_slot,
            pin: params.pin,
        },
    )?;

    debug!("Signature ({} bytes): {}", sig.len(), hex::encode(sig));

    let mut vkey_witnesses = tx
        .transaction_witness_set
        .vkeywitness
        .map(|x| x.to_vec())
        .unwrap_or_default();

    vkey_witnesses.push(conway::VKeyWitness {
        vkey: Vec::from(params.payment_vkey.as_ref()).into(),
        signature: Vec::from(sig.as_ref()).into(),
    });

    tx.transaction_witness_set.vkeywitness = Some(NonEmptySet::from_vec(vkey_witnesses).unwrap());

    let signed_bytes = tx
        .encode_fragment()
        .map_err(|e| YkadaError::NetworkError(format!("failed to encode signed tx: {e}")))?;

    info!("Signed transaction ({} bytes)", signed_bytes.len());
    debug!("Signed CBOR: {}", hex::encode(&signed_bytes));

    Ok(signed_bytes)
}

pub fn sign_tx_use_case<S, X>(
    signer: &mut S,
    tx_submitter: &X,
    unsigned_cbor: &[u8],
    params: SignExternalTxParams,
    mode: SendMode,
) -> YkadaResult<SendOutcome>
where
    S: Signer,
    X: TxSubmitter,
{
    match mode {
        SendMode::SignOnly => {
            sign_external_tx_use_case(signer, unsigned_cbor, params).map(SendOutcome::Cbor)
        }
        SendMode::SignAndSubmit => {
            sign_and_submit_external_tx_use_case(signer, tx_submitter, unsigned_cbor, params)
                .map(SendOutcome::TxHash)
        }
        SendMode::DryRun => Err(YkadaError::NetworkError(
            "DryRun is not valid for sign-tx".into(),
        )),
    }
}

pub fn sign_and_submit_external_tx_use_case<S: Signer, X: TxSubmitter>(
    signer: &mut S,
    tx_submitter: &X,
    unsigned_tx_cbor: &[u8],
    params: SignExternalTxParams,
) -> YkadaResult<String> {
    let signed_bytes = sign_external_tx_use_case(signer, unsigned_tx_cbor, params)?;
    info!("Submitting transaction to network");
    let tx_hash = tx_submitter.submit_tx(&signed_bytes)?;
    info!("Transaction submitted: {}", tx_hash);
    Ok(tx_hash)
}

pub struct SignTxFileParams {
    pub tx_file_content: String,
    pub payment_slot: Slot,
    pub stake_slot: Slot,
    pub network: Network,
    pub mode: SendMode,
    pub pin: Option<Pin>,
}

pub fn sign_tx_file_use_case<F, X>(
    finder: &F,
    tx_submitter: &X,
    params: SignTxFileParams,
) -> YkadaResult<SendOutcome>
where
    F: DeviceFinder,
    F::Device: Signer + DeviceReader,
    X: TxSubmitter,
{
    let unsigned_cbor = parse_tx_file_json(&params.tx_file_content)?;
    let info = wallet_info_use_case(
        finder,
        params.payment_slot,
        params.stake_slot,
        params.network,
    )?;
    let payment_vkey = info
        .payment_vk
        .ok_or_else(|| {
            YkadaError::NetworkError("no payment key on YubiKey — import a wallet first".into())
        })?
        .to_bytes();
    let mut yubikey = finder.find_first()?;
    sign_tx_use_case(
        &mut yubikey,
        tx_submitter,
        &unsigned_cbor,
        SignExternalTxParams {
            payment_vkey,
            payment_slot: params.payment_slot,
            pin: params.pin,
        },
        params.mode,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Algorithm;

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

    fn build_sample_unsigned_tx() -> Vec<u8> {
        use crate::logic::{derive_cardano_address, derive_signing_key};
        use crate::model::{DerivationPath, Network, SeedPhrase};
        use pallas_addresses::Address;
        use pallas_crypto::hash::Hash;
        use pallas_txbuilder::{BuildConway, Input, Output, StagingTransaction};

        let seed = SeedPhrase::try_from(
            "test walk nut penalty hip pave soap entry language right filter choice",
        )
        .unwrap();
        let payment_path = DerivationPath::try_from("m/1852'/1815'/0'/0/0").unwrap();
        let stake_path = DerivationPath::try_from("m/1852'/1815'/0'/2/0").unwrap();
        let payment_vk = derive_signing_key(&seed, "", &payment_path)
            .unwrap()
            .verifying_key();
        let stake_vk = derive_signing_key(&seed, "", &stake_path)
            .unwrap()
            .verifying_key();
        let addr = derive_cardano_address(&payment_vk, &stake_vk, Network::Preview);
        let pallas_addr = Address::from_bytes(&addr.to_bytes()).unwrap();

        let tx_hash_bytes: [u8; 32] = [0xAA; 32];
        let input_hash = Hash::new(tx_hash_bytes);

        StagingTransaction::new()
            .input(Input::new(input_hash, 0))
            .output(Output::new(pallas_addr, 2_000_000))
            .fee(200_000)
            .build_conway_raw()
            .unwrap()
            .tx_bytes
            .0
    }

    fn sample_eternl_json() -> String {
        let cbor_hex = hex::encode(build_sample_unsigned_tx());
        format!(
            r#"{{"type":"Tx ConwayEra","description":"Downloaded through Eternl Wallet","cborHex":"{cbor_hex}"}}"#,
        )
    }

    #[test]
    fn test_parse_tx_file_json_extracts_cbor_hex() {
        let json = sample_eternl_json();
        let result = parse_tx_file_json(&json);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_parse_tx_file_json_invalid_json() {
        let result = parse_tx_file_json("not json");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid transaction JSON"));
    }

    #[test]
    fn test_parse_tx_file_json_invalid_hex() {
        let json = r#"{"cborHex":"zzzz"}"#;
        let result = parse_tx_file_json(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid CBOR hex"));
    }

    #[test]
    fn test_sign_external_tx_produces_longer_output() {
        let unsigned_cbor = build_sample_unsigned_tx();
        let mut signer = FakeSigner;
        let params = SignExternalTxParams {
            payment_vkey: [0xAA; 32],
            payment_slot: Slot::Signature,
            pin: None,
        };

        let result = sign_external_tx_use_case(&mut signer, &unsigned_cbor, params);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        let signed = result.unwrap();
        assert!(
            signed.len() > unsigned_cbor.len(),
            "signed tx ({}) should be longer than unsigned ({})",
            signed.len(),
            unsigned_cbor.len()
        );
    }

    #[test]
    fn test_sign_external_tx_invalid_cbor() {
        let mut signer = FakeSigner;
        let params = SignExternalTxParams {
            payment_vkey: [0xAA; 32],
            payment_slot: Slot::Signature,
            pin: None,
        };

        let result = sign_external_tx_use_case(&mut signer, &[0xFF, 0xFF], params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid transaction CBOR"));
    }

    #[test]
    fn test_sign_and_submit_returns_tx_hash() {
        let unsigned_cbor = build_sample_unsigned_tx();
        let mut signer = FakeSigner;
        let submitter = FakeTxSubmitter {
            expected_hash: "deadbeef".into(),
        };
        let params = SignExternalTxParams {
            payment_vkey: [0xAA; 32],
            payment_slot: Slot::Signature,
            pin: None,
        };

        let result =
            sign_and_submit_external_tx_use_case(&mut signer, &submitter, &unsigned_cbor, params);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap(), "deadbeef");
    }

    #[test]
    fn test_signed_output_is_valid_cbor() {
        let unsigned_cbor = build_sample_unsigned_tx();
        let mut signer = FakeSigner;
        let params = SignExternalTxParams {
            payment_vkey: [0xAA; 32],
            payment_slot: Slot::Signature,
            pin: None,
        };

        let signed = sign_external_tx_use_case(&mut signer, &unsigned_cbor, params).unwrap();
        // Should be parseable as a valid Conway transaction
        let tx = conway::Tx::decode_fragment(&signed);
        assert!(
            tx.is_ok(),
            "signed output should be valid CBOR: {:?}",
            tx.err()
        );
        // Should have exactly one vkey witness
        let witnesses = tx.unwrap().transaction_witness_set.vkeywitness.unwrap();
        assert_eq!(witnesses.len(), 1);
    }
}
