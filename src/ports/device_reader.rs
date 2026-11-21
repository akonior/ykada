use crate::model::Slot;
use crate::YkadaResult;
use ed25519_dalek::VerifyingKey;

pub(crate) trait DeviceReader {
    fn firmware_version(&self) -> (u8, u8, u8);
    fn read_public_key(&mut self, slot: Slot) -> YkadaResult<Option<VerifyingKey>>;
}
