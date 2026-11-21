use crate::adapters::{KoiosClient, PivDeviceFinder};
use crate::error::YkadaResult;
pub use crate::logic::{
    banner, decode_bech32_address, Bech32Encodable, Bech32Error, StakeVerifyingKey,
};
pub use crate::model::*;
use crate::ports::{DeviceFinder, SlotPolicyReader};
use crate::use_cases::{
    fetch_balance_use_case, generate_wallet_use_case, send_ada_use_case, sign_tx_file_use_case,
    wallet_info_use_case, SendAdaParams, SignTxFileParams,
};

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
    send_ada_use_case(
        &finder,
        &client,
        &client,
        &client,
        SendAdaParams {
            payment_slot,
            stake_slot,
            network,
            recipient: recipient.to_owned(),
            send_lovelace,
            fee_lovelace,
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
    let finder = PivDeviceFinder;
    let client = KoiosClient::for_network(network);
    sign_tx_file_use_case(
        &finder,
        &client,
        SignTxFileParams {
            tx_file_content: tx_file_content.to_owned(),
            payment_slot,
            stake_slot,
            network,
            mode,
            pin,
        },
    )
}

pub fn read_slot_policy(slot: Slot) -> YkadaResult<(PinPolicy, TouchPolicy)> {
    PivDeviceFinder.find_first()?.read_slot_policy(slot)
}
