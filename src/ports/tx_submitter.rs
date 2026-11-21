// Why a submission failed, as far as the client can tell.
#[derive(Debug)]
pub(crate) enum SubmitFailure {
    // The transaction did not reach a node, or a node refused it: it is not on its way.
    NotSubmitted(String),
    // The request was sent but no answer came back: a node may have accepted it.
    OutcomeUnknown(String),
}

pub(crate) trait TxSubmitter {
    fn submit_tx(&self, signed_tx_cbor: &[u8]) -> Result<(), SubmitFailure>;
}
