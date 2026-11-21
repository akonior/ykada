use crate::adapters::{KoiosClient, PivDeviceFinder};
use crate::error::{YkadaError, YkadaResult};
pub use crate::model::{
    GeneratedWallet, ManagementKey, Network, Overwrite, Pin, PinPolicy, SeedPhrase, SendMode,
    SendOutcome, TouchPolicy, WalletConfig, WalletInfo,
};
use crate::model::{Utxo, PAYMENT_SLOT};
use crate::ports::{DeviceFinder, SlotPolicyReader, UtxoFetcher};
use crate::use_cases::{
    generate_wallet_use_case, send_ada_use_case, sign_tx_file_use_case, summarize_tx,
    wallet_info_use_case, SignTxFileParams,
};
pub use crate::use_cases::{SendAdaParams, TxOutputSummary, TxSummary};
use pallas_addresses::ShelleyAddress;

// `seed: None` generates a fresh random mnemonic.
pub fn generate_or_import_wallet(
    seed: Option<SeedPhrase>,
    config: WalletConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<GeneratedWallet> {
    generate_wallet_use_case(&PivDeviceFinder, seed, config, mgmt_key)
}

pub fn wallet_info(network: Network) -> YkadaResult<WalletInfo> {
    wallet_info_use_case(&PivDeviceFinder, network)
}

// Total lovelace at the address, including UTxOs that also hold tokens.
pub fn fetch_balance(address: &ShelleyAddress, network: Network) -> YkadaResult<u64> {
    KoiosClient::for_network(network)
        .fetch_utxos(&address.to_bech32()?)
        .and_then(|utxos| total_lovelace(&utxos))
}

fn total_lovelace(utxos: &[Utxo]) -> YkadaResult<u64> {
    utxos
        .iter()
        .try_fold(0u64, |sum, utxo| sum.checked_add(utxo.lovelace))
        .ok_or_else(|| YkadaError::Tx("balance overflows u64".into()))
}

pub fn send_ada(params: SendAdaParams) -> YkadaResult<SendOutcome> {
    send_ada_use_case(
        &PivDeviceFinder,
        &KoiosClient::for_network(params.network),
        params,
    )
}

pub fn sign_tx(
    tx_file_content: &str,
    network: Network,
    mode: SendMode,
    pin: Option<Pin>,
) -> YkadaResult<SendOutcome> {
    sign_tx_file_use_case(
        &PivDeviceFinder,
        &KoiosClient::for_network(network),
        SignTxFileParams {
            tx_file_content: tx_file_content.to_owned(),
            mode,
            pin,
        },
    )
}

pub fn payment_slot_policy() -> YkadaResult<(PinPolicy, TouchPolicy)> {
    PivDeviceFinder.find_first()?.read_slot_policy(PAYMENT_SLOT)
}

// Decode a transaction (JSON with cborHex, or bare CBOR hex) and verify any witnesses.
pub fn decode_tx(content: &str) -> YkadaResult<TxSummary> {
    summarize_tx(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utxo(lovelace: u64) -> Utxo {
        Utxo {
            tx_hash: "00".repeat(32),
            tx_index: 0,
            lovelace,
            has_tokens: false,
        }
    }

    #[test]
    fn test_total_lovelace_sums_all_utxos() {
        let utxos = [1_500_000, 2_000_000].map(utxo);
        assert_eq!(total_lovelace(&utxos).unwrap(), 3_500_000);
    }

    #[test]
    fn test_total_lovelace_overflow_errors() {
        let msg = total_lovelace(&[u64::MAX, 1].map(utxo))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("overflows"), "got: {msg}");
    }
}
