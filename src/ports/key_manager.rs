use crate::error::YkadaResult;
use crate::model::{PinPolicy, Slot, TouchPolicy};
use crate::{Ed25519PrivateKey, Ed25519PublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyConfig {
    pub slot: Slot,
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            slot: Slot::default_signing(),
            pin_policy: PinPolicy::recommended_cardano(),
            touch_policy: TouchPolicy::recommended_cardano(),
        }
    }
}

pub trait KeyManager {
    /// Import a private key into the device.
    /// `vk` is the Cardano verifying key (`kL * G`) associated with `key`;
    /// the adapter stores it so it can be retrieved later by `DeviceReader::read_public_key`.
    fn import_key(
        &mut self,
        key: Ed25519PrivateKey,
        vk: Ed25519PublicKey,
        config: KeyConfig,
    ) -> YkadaResult<()>;

    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<Ed25519PublicKey>;
}
