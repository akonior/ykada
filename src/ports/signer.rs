//! Signer trait - capability to sign data

use crate::model::{Algorithm, Pin, Slot};
use crate::error::YkadaResult;

/// Capability to sign data
///
/// This trait abstracts signing operations using keys stored on YubiKey.
/// Works with any key storage mechanism (PIV slots, OpenPGP keys, etc.)
pub trait Signer {
    /// Sign data using a key in the specified slot
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign
    /// * `slot` - The slot containing the key to use
    /// * `algorithm` - The algorithm to use for signing
    /// * `pin` - PIN for authentication (if required by key policy)
    ///
    /// # Returns
    ///
    /// The signature bytes
    ///
    /// # Errors
    ///
    /// Returns errors if:
    /// - PIN verification fails
    /// - Key not found in slot
    /// - Signing operation fails
    fn sign(
        &mut self,
        data: &[u8],
        slot: Slot,
        algorithm: Algorithm,
        pin: Option<&Pin>,
    ) -> YkadaResult<Vec<u8>>;
}
