use crate::model::{Slot, SlotKey};
use crate::YkadaResult;
use ed25519_dalek::VerifyingKey;

pub(crate) trait DeviceReader {
    fn firmware_version(&self) -> (u8, u8, u8);
    // The key in the slot, from the key's own metadata: the source of truth for the address.
    fn slot_key(&mut self, slot: Slot) -> YkadaResult<SlotKey>;
    // The public key ykada stored next to the private key. Anyone with the management key can
    // rewrite it, so it only cross-checks `slot_key`; a slot can hold a key without it.
    fn public_key_object(&mut self, slot: Slot) -> YkadaResult<Option<VerifyingKey>>;
}
