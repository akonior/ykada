
use crate::error::YkadaResult;
use crate::model::Pin;

pub trait PinVerifier {
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()>;
}
