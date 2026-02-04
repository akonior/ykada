//! ManagementKeyVerifier trait - capability to authenticate with Management Key

use crate::model::ManagementKey;
use crate::error::YkadaResult;

/// Capability to authenticate with Management Key
///
/// This trait abstracts Management Key authentication operations.
/// Management Key authentication is required before key import/generation operations.
pub trait ManagementKeyVerifier {
    /// Authenticate with the Management Key
    ///
    /// # Arguments
    ///
    /// * `mgmt_key` - Optional Management Key. If `None`, the default Management Key is used.
    ///
    /// # Errors
    ///
    /// Returns `YkadaError::Device(DeviceError::AuthenticationFailed)` on failure
    fn authenticate(&mut self, mgmt_key: Option<&ManagementKey>) -> YkadaResult<()>;
}
