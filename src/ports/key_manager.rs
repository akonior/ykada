
use crate::error::YkadaResult;
use crate::model::{PinPolicy, Slot, TouchPolicy};
use ed25519_dalek::{SecretKey, VerifyingKey};

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
    fn import_key(&mut self, key: SecretKey, config: KeyConfig) -> YkadaResult<()>;

    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<VerifyingKey>;
}
