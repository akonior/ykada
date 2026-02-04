//! PinVerifier trait - capability to verify PIN

use crate::error::YkadaResult;
use crate::model::Pin;

/// Capability to verify PIN
///
/// This trait abstracts PIN verification operations.
pub trait PinVerifier {
    /// Verify PIN on the device
    ///
    /// # Errors
    ///
    /// Returns `YkadaError::Device(DeviceError::PinVerificationFailed)` on failure
    fn verify_pin(&mut self, pin: &Pin) -> YkadaResult<()>;
}
