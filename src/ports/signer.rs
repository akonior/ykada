use crate::error::YkadaResult;
use crate::model::{Pin, Slot};

pub(crate) trait Signer {
    fn sign(&mut self, data: &[u8], slot: Slot, pin: Option<&Pin>) -> YkadaResult<Vec<u8>>;
}
