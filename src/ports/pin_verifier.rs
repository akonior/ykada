//! PinVerifier trait - capability to verify PIN

use crate::model::Pin;
use crate::error::YkadaResult;

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
