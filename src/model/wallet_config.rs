use crate::model::{Network, PinPolicy, Slot, TouchPolicy};

pub struct WalletConfig {
    pub payment_slot: Slot,
    pub stake_slot: Slot,
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
    pub network: Network,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            payment_slot: Slot::Signature,
            stake_slot: Slot::KeyManagement,
            pin_policy: PinPolicy::recommended_cardano(),
            touch_policy: TouchPolicy::recommended_cardano(),
            network: Network::default(),
        }
    }
}
