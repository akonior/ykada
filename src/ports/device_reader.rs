use crate::model::Slot;
use crate::YkadaResult;
use ed25519_dalek::VerifyingKey;

pub trait DeviceReader {
    fn serial(&self) -> u32;
    fn firmware_version(&self) -> (u8, u8, u8);
    fn read_public_key(&mut self, slot: Slot) -> YkadaResult<Option<VerifyingKey>>;
}
