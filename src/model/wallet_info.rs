use crate::model::{CardanoAddress, Network};
use ed25519_dalek::VerifyingKey;

pub struct WalletInfo {
    pub serial: u32,
    pub firmware: (u8, u8, u8),
    pub network: Network,
    pub payment_vk: Option<VerifyingKey>,
    pub stake_vk: Option<VerifyingKey>,
    pub address: Option<CardanoAddress>,
}
