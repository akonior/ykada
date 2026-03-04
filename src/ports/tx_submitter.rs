use crate::error::YkadaResult;

pub trait TxSubmitter {
    fn submit_tx(&self, signed_tx_cbor: &[u8]) -> YkadaResult<String>;
}
