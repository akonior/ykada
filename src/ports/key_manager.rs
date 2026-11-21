use crate::error::YkadaResult;
use crate::model::{PinPolicy, Slot, TouchPolicy};
use ed25519_dalek::{SigningKey, VerifyingKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyConfig {
    pub slot: Slot,
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
}

pub(crate) trait KeyManager {
    // Import `key` and store `vk` next to it, as `DeviceReader::public_key_object`.
    fn import_key(
        &mut self,
        key: SigningKey,
        vk: VerifyingKey,
        config: KeyConfig,
    ) -> YkadaResult<()>;
}
