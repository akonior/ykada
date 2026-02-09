use super::{KeyManager, ManagementKeyVerifier, PinVerifier, Signer};
use crate::error::YkadaResult;

pub trait DeviceFinder {
    type Device: PinVerifier + ManagementKeyVerifier + KeyManager + Signer;

    fn find_first(&self) -> YkadaResult<Self::Device>;
}
