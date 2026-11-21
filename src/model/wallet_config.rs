use crate::model::{Network, PinPolicy, TouchPolicy};

// What to do when the YubiKey already holds a wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    Refuse,
    Allow,
}

#[derive(Debug, Clone, Copy)]
pub struct WalletConfig {
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
    pub network: Network,
    pub overwrite: Overwrite,
}
