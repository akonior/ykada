use super::{
    DeviceReader, KeyManager, ManagementKeyVerifier, PinVerifier, Signer, SlotPolicyReader,
};
use crate::error::YkadaResult;

pub(crate) trait DeviceFinder {
    type Device: PinVerifier
        + ManagementKeyVerifier
        + KeyManager
        + Signer
        + DeviceReader
        + SlotPolicyReader;

    fn find_first(&self) -> YkadaResult<Self::Device>;
}
