use crate::error::YkadaResult;
use crate::model::Utxo;
use crate::ports::{SubmitFailure, TipFetcher, TxSubmitter, UtxoFetcher};
use std::cell::RefCell;

// One ADA-only UTxO per entry; records every submitted transaction.
pub(crate) struct FakeChain {
    utxos: Vec<u64>,
    submitted: RefCell<Vec<Vec<u8>>>,
}

impl FakeChain {
    pub(crate) fn new(utxos: &[u64]) -> Self {
        Self {
            utxos: utxos.to_vec(),
            submitted: RefCell::new(vec![]),
        }
    }

    pub(crate) fn submitted(&self) -> Vec<Vec<u8>> {
        self.submitted.borrow().clone()
    }
}

impl UtxoFetcher for FakeChain {
    fn fetch_utxos(&self, _address: &str) -> YkadaResult<Vec<Utxo>> {
        Ok((1u8..)
            .zip(&self.utxos)
            .map(|(id, &lovelace)| Utxo {
                tx_hash: hex::encode([id; 32]),
                tx_index: 0,
                lovelace,
                has_tokens: false,
            })
            .collect())
    }
}

impl TipFetcher for FakeChain {
    fn fetch_tip_slot(&self) -> YkadaResult<u64> {
        Ok(1_000_000)
    }
}

impl TxSubmitter for FakeChain {
    fn submit_tx(&self, signed_tx_cbor: &[u8]) -> Result<(), SubmitFailure> {
        self.submitted.borrow_mut().push(signed_tx_cbor.to_vec());
        Ok(())
    }
}
