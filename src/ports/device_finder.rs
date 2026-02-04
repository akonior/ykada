//! DeviceFinder trait - capability to find and connect to YubiKey devices

use crate::error::YkadaResult;
use super::{KeyManager, ManagementKeyVerifier, PinVerifier, Signer};

/// Capability to find and connect to YubiKey devices
///
/// This trait abstracts the discovery and connection to YubiKey hardware.
/// It is implementation-agnostic (works with PIV, OpenPGP, etc.)
pub trait DeviceFinder {
    /// The type of device handle returned
    type Device: PinVerifier + ManagementKeyVerifier + KeyManager + Signer;

    /// Find and connect to the first available YubiKey
    ///
    /// # Errors
    ///
    /// Returns `YkadaError::Device(DeviceError::NotFound)` if no YubiKey is found
    fn find_first(&self) -> YkadaResult<Self::Device>;
}
