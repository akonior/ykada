use crate::error::YkadaResult;
use crate::model::{Algorithm, Pin, Slot};

pub trait Signer {
    fn sign(
        &mut self,
        data: &[u8],
        slot: Slot,
        algorithm: Algorithm,
        pin: Option<&Pin>,
    ) -> YkadaResult<Vec<u8>>;
}
