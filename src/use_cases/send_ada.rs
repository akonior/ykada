use crate::error::{YkadaError, YkadaResult};
use crate::logic::parse_recipient;
use crate::model::{Network, Pin, SendMode, SendOutcome};
use crate::ports::{DeviceFinder, TipFetcher, TxSubmitter, UtxoFetcher};
use crate::use_cases::build_transaction::TransactionParams;
use crate::use_cases::sign_external_tx::{finish_tx, FinishTxParams};
use crate::use_cases::{build_transaction_use_case, wallet_info_use_case};

pub struct SendAdaParams {
    pub network: Network,
    pub recipient: String,
    pub send_lovelace: u64,
    pub fee_lovelace: u64,
    pub mode: SendMode,
    pub pin: Option<Pin>,
}

pub(crate) fn send_ada_use_case<F, C>(
    finder: &F,
    chain: &C,
    params: SendAdaParams,
) -> YkadaResult<SendOutcome>
where
    F: DeviceFinder,
    C: UtxoFetcher + TipFetcher + TxSubmitter,
{
    let recipient = parse_recipient(&params.recipient, params.network)?;
    let wallet = wallet_info_use_case(finder, params.network)?;
    let (Some(change_address), Some(payment_vk)) = (wallet.address, wallet.payment_vk) else {
        return Err(YkadaError::WalletState(
            "no wallet on YubiKey — import or generate first".into(),
        ));
    };

    let unsigned = build_transaction_use_case(
        chain,
        chain,
        TransactionParams {
            recipient,
            send_lovelace: params.send_lovelace,
            fee_lovelace: params.fee_lovelace,
            change_address,
        },
    )?;

    finish_tx(
        finder,
        chain,
        unsigned,
        FinishTxParams {
            payment_vkey: payment_vk.to_bytes(),
            pin: params.pin,
            mode: params.mode,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_chain::FakeChain;
    use crate::adapters::fake_yubikey::{FakeDeviceFinder, FakeYubiKey};
    use crate::model::{PAYMENT_SLOT, STAKE_SLOT};
    use crate::test_vectors::RECIPIENT;
    use crate::use_cases::{summarize_tx, TxSummary};
    use ed25519_dalek::SigningKey;

    fn wallet() -> FakeYubiKey {
        FakeYubiKey::empty()
            .with_key(PAYMENT_SLOT, SigningKey::from_bytes(&[1; 32]))
            .with_key(STAKE_SLOT, SigningKey::from_bytes(&[2; 32]))
    }

    fn send(
        device: FakeYubiKey,
        chain: &FakeChain,
        mode: SendMode,
        pin: &str,
    ) -> YkadaResult<SendOutcome> {
        send_ada_use_case(
            &FakeDeviceFinder(device),
            chain,
            SendAdaParams {
                network: Network::Preview,
                recipient: RECIPIENT.into(),
                send_lovelace: 2_000_000,
                fee_lovelace: 200_000,
                mode,
                pin: Some(pin.parse().unwrap()),
            },
        )
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
}
