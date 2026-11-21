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
        // UTxO n (from 0) is output n / 250 of the transaction [n % 250 + 1; 32], so up to 250
        // UTxOs all have index 0 and a hash that starts with their number counting from 1.
        Ok(self
            .utxos
            .iter()
            .enumerate()
            .map(|(n, &lovelace)| Utxo {
                tx_hash: hex::encode([(n % 250) as u8 + 1; 32]),
                tx_index: (n / 250) as u64,
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
