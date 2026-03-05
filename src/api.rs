use crate::adapters::{KoiosClient, PivDeviceFinder};
use crate::error::{YkadaError, YkadaResult};
pub use crate::logic::{
    banner, decode_bech32_address, Bech32Encodable, Bech32Error, StakeVerifyingKey,
};
pub use crate::model::*;
use crate::ports::{DeviceFinder, KeyConfig};
use crate::use_cases::{
    fetch_balance_use_case, generate_key_use_case, generate_wallet_use_case,
    import_private_key_from_seed_phrase_use_case, import_private_key_in_der_format_use_case,
    parse_tx_file_json, send_ada_use_case, sign_tx_use_case, wallet_info_use_case, SendAdaParams,
    SignExternalTxParams,
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
    generate_wallet_use_case(&finder, Some(seed), config, mgmt_key)
}

pub fn generate_or_import_wallet(
    seed: Option<SeedPhrase>,
    config: WalletConfig,
    mgmt_key: Option<&ManagementKey>,
) -> YkadaResult<GeneratedWallet> {
    let finder = PivDeviceFinder;
    generate_wallet_use_case(&finder, seed, config, mgmt_key)
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

#[allow(clippy::too_many_arguments)]
pub fn send_ada(
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
    recipient: &str,
    send_lovelace: u64,
    fee_lovelace: u64,
    mode: SendMode,
    pin: Option<Pin>,
) -> YkadaResult<SendOutcome> {
    let finder = PivDeviceFinder;
    let client = KoiosClient::for_network(network);
    let wallet = wallet_info_use_case(&finder, payment_slot, stake_slot, network)?;
    let recipient_bytes = decode_bech32_address(recipient)?;
    send_ada_use_case(
        &finder,
        &client,
        &client,
        &client,
        SendAdaParams {
            wallet,
            recipient_bytes,
            send_lovelace,
            fee_lovelace,
            payment_slot,
            mode,
            pin,
        },
    )
}

pub fn sign_tx_file(
    tx_file_content: &str,
    payment_slot: Slot,
    stake_slot: Slot,
    network: Network,
    mode: SendMode,
    pin: Option<Pin>,
) -> YkadaResult<SendOutcome> {
    let unsigned_cbor = parse_tx_file_json(tx_file_content)?;
    let finder = PivDeviceFinder;
    let info = wallet_info_use_case(&finder, payment_slot, stake_slot, network)?;
    let payment_vkey = info
        .payment_vk
        .ok_or_else(|| {
            YkadaError::NetworkError("no payment key on YubiKey — import a wallet first".into())
        })?
        .to_bytes();
    let mut yubikey = finder.find_first()?;
    let client = KoiosClient::for_network(network);
    sign_tx_use_case(
        &mut yubikey,
        &client,
        &unsigned_cbor,
        SignExternalTxParams {
            payment_vkey,
            payment_slot,
            pin,
        },
        mode,
    )
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
