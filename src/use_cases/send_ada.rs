use crate::error::{YkadaError, YkadaResult};
use crate::logic::decode_bech32_address;
use crate::model::{Network, Pin, SendMode, SendOutcome, Slot};
use crate::ports::{DeviceFinder, DeviceReader, Signer, TipFetcher, TxSubmitter, UtxoFetcher};
use crate::use_cases::build_transaction::{
    sign_and_submit_transaction_use_case, sign_transaction_use_case, SignAndSubmitParams,
    TransactionParams,
};
use crate::use_cases::{build_transaction_use_case, wallet_info_use_case};

pub(crate) struct SendAdaParams {
    pub payment_slot: Slot,
    pub stake_slot: Slot,
    pub network: Network,
    pub recipient: String,
    pub send_lovelace: u64,
    pub fee_lovelace: u64,
    pub mode: SendMode,
    pub pin: Option<Pin>,
}

pub(crate) fn send_ada_use_case<F, U, T, X>(
    finder: &F,
    utxo_fetcher: &U,
    tip_fetcher: &T,
    tx_submitter: &X,
    params: SendAdaParams,
) -> YkadaResult<SendOutcome>
where
    F: DeviceFinder,
    F::Device: Signer + DeviceReader,
    U: UtxoFetcher,
    T: TipFetcher,
    X: TxSubmitter,
{
    let wallet = wallet_info_use_case(
        finder,
        params.payment_slot,
        params.stake_slot,
        params.network,
    )?;
    let recipient_bytes = decode_bech32_address(&params.recipient)?;

    let SendAdaParams {
        send_lovelace,
        fee_lovelace,
        payment_slot,
        mode,
        pin,
        ..
    } = params;

    let change_address = wallet.address.ok_or_else(|| {
        YkadaError::NetworkError("no wallet on YubiKey — import or generate first".into())
    })?;
    let payment_vkey_opt = wallet.payment_vk.map(|vk| vk.to_bytes());

    let tx_params = TransactionParams {
        recipient_address_bytes: recipient_bytes,
        send_lovelace,
        fee_lovelace,
        change_address,
    };

    match mode {
        SendMode::DryRun => {
            build_transaction_use_case(utxo_fetcher, tip_fetcher, tx_params).map(SendOutcome::Cbor)
        }

        SendMode::SignOnly => {
            let payment_vkey = extract_payment_vkey(payment_vkey_opt)?;
            let mut device = finder.find_first()?;
            sign_transaction_use_case(
                utxo_fetcher,
                tip_fetcher,
                &mut device,
                into_sign_params(tx_params, payment_vkey, payment_slot, pin),
            )
            .map(SendOutcome::Cbor)
        }

        SendMode::SignAndSubmit => {
            let payment_vkey = extract_payment_vkey(payment_vkey_opt)?;
            let mut device = finder.find_first()?;
            sign_and_submit_transaction_use_case(
                utxo_fetcher,
                tip_fetcher,
                &mut device,
                tx_submitter,
                into_sign_params(tx_params, payment_vkey, payment_slot, pin),
            )
            .map(SendOutcome::TxHash)
        }
    }
}

fn extract_payment_vkey(vkey_opt: Option<[u8; 32]>) -> YkadaResult<[u8; 32]> {
    vkey_opt.ok_or_else(|| YkadaError::NetworkError("no payment key on YubiKey".into()))
}

fn into_sign_params(
    tx: TransactionParams,
    payment_vkey: [u8; 32],
    payment_slot: Slot,
    pin: Option<Pin>,
) -> SignAndSubmitParams {
    SignAndSubmitParams {
        recipient_address_bytes: tx.recipient_address_bytes,
        send_lovelace: tx.send_lovelace,
        fee_lovelace: tx.fee_lovelace,
        change_address: tx.change_address,
        payment_vkey,
        payment_slot,
        pin,
    }
}
