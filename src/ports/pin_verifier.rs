use crate::error::YkadaResult;
use crate::model::Pin;

pub(crate) trait PinVerifier {
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()>;
}
