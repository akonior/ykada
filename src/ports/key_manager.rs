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
    fn import_key(&mut self, key: Ed25519PrivateKey, config: KeyConfig) -> YkadaResult<()>;

    fn generate_key(&mut self, config: KeyConfig) -> YkadaResult<Ed25519PublicKey>;
}
