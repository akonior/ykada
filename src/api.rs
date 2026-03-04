use crate::adapters::{KoiosClient, PivDeviceFinder};
use crate::error::{YkadaError, YkadaResult};
pub use crate::logic::{Bech32Encodable, Bech32Error, StakeVerifyingKey};
pub use crate::model::*;
use crate::ports::{DeviceFinder, KeyConfig};
use crate::use_cases::{
    build_transaction_use_case, fetch_balance_use_case, generate_key_use_case,
    generate_wallet_use_case, import_private_key_from_seed_phrase_use_case,
    import_private_key_in_der_format_use_case, parse_tx_file_json,
    sign_and_submit_external_tx_use_case, sign_and_submit_transaction_use_case,
    sign_external_tx_use_case, sign_transaction_use_case, wallet_info_use_case,
    SignAndSubmitParams, SignExternalTxParams, TransactionParams,
};
use ed25519_dalek::VerifyingKey;

pub fn generate_key() -> YkadaResult<VerifyingKey> {
    generate_key_with_config(KeyConfig::default(), None)
}

pub fn generate_key_with_config(
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey> {
    let finder = PivDeviceFinder;
    generate_key_use_case(&finder, config, mgmt_key)
}

pub fn import_private_key_in_der_format(
    der: DerPrivateKey,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey> {
    let finder = PivDeviceFinder;
    import_private_key_in_der_format_use_case(&finder, der, config, mgmt_key)
}

pub fn import_wallet(
    seed: SeedPhrase,
    config: WalletConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<GeneratedWallet> {
    let finder = PivDeviceFinder;
    generate_wallet_use_case(&finder, seed, config, mgmt_key)
}

pub fn generate_wallet(
    config: WalletConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<GeneratedWallet> {
    import_wallet(SeedPhrase::generate()?, config, mgmt_key)
}

pub fn wallet_info(
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
) -> YkadaResult<WalletInfo> {
    let finder = PivDeviceFinder;
    wallet_info_use_case(&finder, payment_slot, stake_slot, network)
}

pub fn fetch_balance(address: &CardanoAddress, network: Network) -> YkadaResult<AccountBalance> {
    let client = KoiosClient::for_network(network);
    fetch_balance_use_case(&client, address)
}

pub fn build_transaction(
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
    recipient: &str,
    send_lovelace: u64,
    fee_lovelace: u64,
) -> YkadaResult<Vec<u8>> {
    let info = wallet_info(payment_slot, stake_slot, network)?;
    let change_address = info.address.ok_or_else(|| {
        YkadaError::NetworkError("no address on YubiKey — import a wallet first".into())
    })?;

    let recipient_bytes = decode_bech32_address(recipient)?;
    let client = KoiosClient::for_network(network);

    build_transaction_use_case(
        &client,
        &client,
        TransactionParams {
            recipient_address_bytes: recipient_bytes,
            send_lovelace,
            fee_lovelace,
            change_address,
        },
    )
}

pub fn sign_transaction(
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
    recipient: &str,
    send_lovelace: u64,
    fee_lovelace: u64,
    pin: Option<Pin>,
) -> YkadaResult<Vec<u8>> {
    let info = wallet_info(payment_slot, stake_slot, network)?;
    let change_address = info.address.ok_or_else(|| {
        YkadaError::NetworkError("no address on YubiKey — import a wallet first".into())
    })?;
    let payment_vkey: [u8; 32] = info
        .payment_vk
        .ok_or_else(|| {
            YkadaError::NetworkError("no payment key on YubiKey — import a wallet first".into())
        })?
        .to_bytes();
    let recipient_address_bytes = decode_bech32_address(recipient)?;
    let client = KoiosClient::for_network(network);
    let finder = PivDeviceFinder;
    let mut yubikey = finder.find_first()?;
    sign_transaction_use_case(
        &client,
        &client,
        &mut yubikey,
        SignAndSubmitParams {
            recipient_address_bytes,
            send_lovelace,
            fee_lovelace,
            change_address,
            payment_vkey,
            payment_slot,
            pin,
        },
    )
}

pub fn send_transaction(
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
    recipient: &str,
    send_lovelace: u64,
    fee_lovelace: u64,
    pin: Option<Pin>,
) -> YkadaResult<String> {
    let info = wallet_info(payment_slot, stake_slot, network)?;
    let change_address = info.address.ok_or_else(|| {
        YkadaError::NetworkError("no address on YubiKey — import a wallet first".into())
    })?;
    let payment_vkey: [u8; 32] = info
        .payment_vk
        .ok_or_else(|| {
            YkadaError::NetworkError("no payment key on YubiKey — import a wallet first".into())
        })?
        .to_bytes();
    let recipient_address_bytes = decode_bech32_address(recipient)?;
    let client = KoiosClient::for_network(network);
    let finder = PivDeviceFinder;
    let mut yubikey = finder.find_first()?;
    sign_and_submit_transaction_use_case(
        &client,
        &client,
        &mut yubikey,
        &client,
        SignAndSubmitParams {
            recipient_address_bytes,
            send_lovelace,
            fee_lovelace,
            change_address,
            payment_vkey,
            payment_slot,
            pin,
        },
    )
}

fn decode_bech32_address(bech32_str: &str) -> YkadaResult<Vec<u8>> {
    let (_, data, _) = bech32::decode(bech32_str)
        .map_err(|e| YkadaError::NetworkError(format!("invalid bech32 address: {e}")))?;
    bech32::convert_bits(&data, 5, 8, false)
        .map_err(|e| YkadaError::NetworkError(format!("bech32 conversion error: {e}")))
}

pub fn import_private_key_from_seed_phrase(
    seed_phrase: &str,
    passphrase: &str,
    path: Option<&str>,
    config: KeyConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<VerifyingKey> {
    let finder = PivDeviceFinder;
    import_private_key_from_seed_phrase_use_case(
        &finder,
        seed_phrase,
        passphrase,
        path,
        config,
        mgmt_key,
    )
}

pub fn sign_external_tx(
    tx_file_content: &str,
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
    pin: Option<Pin>,
) -> YkadaResult<Vec<u8>> {
    let unsigned_cbor = parse_tx_file_json(tx_file_content)?;
    let info = wallet_info(payment_slot, stake_slot, network)?;
    let payment_vkey: [u8; 32] = info
        .payment_vk
        .ok_or_else(|| {
            YkadaError::NetworkError("no payment key on YubiKey — import a wallet first".into())
        })?
        .to_bytes();

    let finder = PivDeviceFinder;
    let mut yubikey = finder.find_first()?;
    sign_external_tx_use_case(
        &mut yubikey,
        &unsigned_cbor,
        SignExternalTxParams {
            payment_vkey,
            payment_slot,
            pin,
        },
    )
}

pub fn sign_and_send_external_tx(
    tx_file_content: &str,
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
    pin: Option<Pin>,
) -> YkadaResult<String> {
    let unsigned_cbor = parse_tx_file_json(tx_file_content)?;
    let info = wallet_info(payment_slot, stake_slot, network)?;
    let payment_vkey: [u8; 32] = info
        .payment_vk
        .ok_or_else(|| {
            YkadaError::NetworkError("no payment key on YubiKey — import a wallet first".into())
        })?
        .to_bytes();

    let finder = PivDeviceFinder;
    let mut yubikey = finder.find_first()?;
    let client = KoiosClient::for_network(network);
    sign_and_submit_external_tx_use_case(
        &mut yubikey,
        &client,
        &unsigned_cbor,
        SignExternalTxParams {
            payment_vkey,
            payment_slot,
            pin,
        },
    )
}
