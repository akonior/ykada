use crate::error::YkadaResult;

pub(crate) trait TxSubmitter {
    fn submit_tx(&self, signed_tx_cbor: &[u8]) -> YkadaResult<String>;
}
