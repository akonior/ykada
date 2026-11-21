use crate::error::{YkadaError, YkadaResult};
use crate::logic::parse_recipient;
use crate::model::{Network, PreparedTx};
use crate::ports::{DeviceFinder, TipFetcher, UtxoFetcher};
use crate::use_cases::build_transaction::{check_amounts, TransactionParams};
use crate::use_cases::{build_transaction_use_case, wallet_info_use_case};

pub struct PaymentParams {
    pub network: Network,
    pub recipient: String,
    pub send_lovelace: u64,
    pub fee_lovelace: u64,
}

// Build the payment. Checks that need neither the YubiKey nor the network come first, so a
// typo fails at once, before the device, the network or a PIN prompt.
pub(crate) fn prepare_payment_use_case<F, C>(
    finder: &F,
    chain: &C,
    params: PaymentParams,
) -> YkadaResult<PreparedTx>
where
    F: DeviceFinder,
    C: UtxoFetcher + TipFetcher,
{
    let recipient = parse_recipient(&params.recipient, params.network)?;
    check_amounts(params.send_lovelace, params.fee_lovelace)?;
    let wallet = wallet_info_use_case(finder, params.network)?;
    let (Some(change_address), Some(payment_vk)) = (wallet.address, wallet.payment_vk) else {
        return Err(YkadaError::WalletState(
            "no wallet on YubiKey — import or generate first".into(),
        ));
    };

    let cbor = build_transaction_use_case(
        chain,
        chain,
        TransactionParams {
            recipient,
            send_lovelace: params.send_lovelace,
            fee_lovelace: params.fee_lovelace,
            change_address,
        },
    )?;
    Ok(PreparedTx {
        cbor,
        payment_vkey: payment_vk.to_bytes(),
        network: params.network,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_chain::FakeChain;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey, NoDevice};
    use crate::model::{SendMode, SendOutcome, PAYMENT_SLOT, STAKE_SLOT};
    use crate::test_vectors::RECIPIENT;
    use crate::use_cases::sign_external_tx::{finish_tx, FinishTxParams};
    use crate::use_cases::{summarize_tx, TxSummary};
    use ed25519_dalek::SigningKey;

    fn wallet() -> FakeYubiKey {
        FakeYubiKey::empty()
            .with_key(PAYMENT_SLOT, SigningKey::from_bytes(&[1; 32]))
            .with_key(STAKE_SLOT, SigningKey::from_bytes(&[2; 32]))
    }

    fn payment(recipient: &str, send_lovelace: u64, fee_lovelace: u64) -> PaymentParams {
        PaymentParams {
            network: Network::Preview,
            recipient: recipient.into(),
            send_lovelace,
            fee_lovelace,
        }
    }

    fn send(
        device: FakeYubiKey,
        chain: &FakeChain,
        mode: SendMode,
        pin: &str,
    ) -> YkadaResult<SendOutcome> {
        let finder = FakeDeviceFinder(device);
        let tx = prepare_payment_use_case(&finder, chain, payment(RECIPIENT, 2_000_000, 200_000))?;
        let params = FinishTxParams {
            mode,
            pin: Some(pin.parse().unwrap()),
        };
        finish_tx(&finder, chain, tx, params)
    }

    // The error a payment gets on a computer with no YubiKey at all.
    fn error_without_device(params: PaymentParams) -> String {
        prepare_payment_use_case(&NoDevice, &FakeChain::new(&[10_000_000]), params)
            .err()
            .expect("the payment must be refused")
            .to_string()
    }

    fn decoded(outcome: SendOutcome) -> TxSummary {
        match outcome {
            SendOutcome::Cbor(cbor) => summarize_tx(&hex::encode(cbor)).unwrap(),
            SendOutcome::TxHash(hash) => panic!("expected CBOR, got {hash}"),
        }
    }

    #[test]
    fn test_dry_run_neither_signs_nor_submits() {
        let chain = FakeChain::new(&[10_000_000]);
        let outcome = send(wallet(), &chain, SendMode::DryRun, "123456").unwrap();
        assert_eq!(decoded(outcome).witness_count, 0);
        assert!(chain.submitted().is_empty());
    }

    #[test]
    fn test_sign_only_signs_but_does_not_submit() {
        let chain = FakeChain::new(&[10_000_000]);
        let outcome = send(wallet(), &chain, SendMode::SignOnly, "123456").unwrap();
        assert_eq!(decoded(outcome).witnesses_verified, 1);
        assert!(chain.submitted().is_empty());
    }

    #[test]
    fn test_submits_the_signed_transaction_and_reports_its_id() {
        let chain = FakeChain::new(&[10_000_000]);
        let outcome = send(wallet(), &chain, SendMode::SignAndSubmit, "123456").unwrap();
        let [submitted] = &chain.submitted()[..] else {
            panic!("expected exactly one submission");
        };
        let summary = summarize_tx(&hex::encode(submitted)).unwrap();
        assert_eq!(summary.witnesses_verified, 1);
        assert!(matches!(outcome, SendOutcome::TxHash(id) if id == summary.body_hash_hex));
    }

    #[test]
    fn test_wrong_pin_submits_nothing() {
        let chain = FakeChain::new(&[10_000_000]);
        assert!(send(wallet(), &chain, SendMode::SignAndSubmit, "999999").is_err());
        assert!(chain.submitted().is_empty());
    }

    #[test]
    fn test_requires_a_wallet() {
        let chain = FakeChain::new(&[10_000_000]);
        assert!(matches!(
            send(FakeYubiKey::empty(), &chain, SendMode::DryRun, "123456"),
            Err(YkadaError::WalletState(_))
        ));
    }

    #[test]
    fn test_bad_recipient_fails_before_the_device() {
        let msg = error_without_device(payment("addr_test1bogus", 2_000_000, 200_000));
        assert!(msg.contains("recipient"), "got: {msg}");
    }

    #[test]
    fn test_fee_above_the_cap_fails_before_the_device() {
        let msg = error_without_device(payment(RECIPIENT, 2_000_000, 50_000_000));
        assert!(msg.contains("--fee"), "got: {msg}");
    }

    #[test]
    fn test_amount_below_min_utxo_fails_before_the_device() {
        let msg = error_without_device(payment(RECIPIENT, 999_999, 200_000));
        assert!(msg.contains("min-UTxO"), "got: {msg}");
    }

    // A valid payment gets as far as looking for the YubiKey.
    #[test]
    fn test_valid_payment_then_needs_the_device() {
        let msg = error_without_device(payment(RECIPIENT, 2_000_000, 200_000));
        assert!(msg.contains("No YubiKey"), "got: {msg}");
    }
}
