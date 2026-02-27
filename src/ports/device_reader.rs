use crate::model::Slot;
use crate::{Ed25519PublicKey, YkadaResult};

pub trait DeviceReader {
    fn serial(&self) -> u32;
    fn firmware_version(&self) -> (u8, u8, u8);
    fn read_public_key(&mut self, slot: Slot) -> YkadaResult<Option<Ed25519PublicKey>>;
}
